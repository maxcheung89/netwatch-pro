"""
NetWatch Pro — Main Application v8
Engines: Capture → Protocol → Discovery → Flows → Alerts → Topology → Suricata
"""
import os, re, time, threading, subprocess, logging, sys, ipaddress
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_socketio import SocketIO
from flask_cors import CORS

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    datefmt='%H:%M:%S', stream=sys.stdout)
log = logging.getLogger('netwatch')
log.info("="*52)
log.info("  NetWatch Pro — Starting")
log.info("="*52)

from capture   import CaptureEngine
from protocol  import ProtocolAnalyzer
from discovery import AssetInventory
from flows     import FlowMonitor
from alerts    import AlertEngine, _is_ignored_ip
from topology  import TopologyEngine
from suricata  import SuricataEngine, EVE_LOG_PATH
from settings  import settings
from auth      import auth
from eventlog  import event_log, EV_JOINED, EV_LEFT, EV_SCAN, EV_ALERT, EV_SYSTEM
from datastore import datastore
from pihole    import pihole_engine
from incidents import incident_engine
from health    import health_engine
from geoip     import geoip_engine
from export    import (devices_to_csv, alerts_to_csv, flows_to_csv,
                       suricata_alerts_to_csv, events_to_csv)

# Pre-load OUI vendor DB from nmap/arp-scan system files
try:
    from oui_fetch import init_oui_cache
    n = init_oui_cache()
    log.info(f"OUI cache: {n} vendor entries loaded")
except Exception as e:
    log.warning(f"OUI cache: {e}")

app = Flask(__name__, static_folder='/app/frontend', static_url_path='')
import os as _os
app.config['SECRET_KEY'] = _os.environ.get('SECRET_KEY', 'netwatch-pro-' + __import__('secrets').token_hex(16))
CORS(app)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading',
                    logger=False, engineio_logger=False)

# ── Engine instances ────────────────────────────────────────────
proto_analyzer  = ProtocolAnalyzer()
asset_inventory = AssetInventory('/app/data/devices.db')
flow_monitor    = FlowMonitor()
topo_engine     = TopologyEngine()
def _on_alert_emit(ev, data):
    socketio.emit(ev, data)
    if ev == 'alert':
        try:
            inc = incident_engine.ingest(data)
            if inc:
                socketio.emit('incident_update', inc.to_dict())
        except Exception as _ie:
            log.debug(f"Incident ingest: {_ie}")
    if ev == 'live_stats':
        try:
            for ip, bps in data.get('top_talkers', {}).items():
                health_engine.update_bps(ip, bps)
        except Exception:
            pass

alert_engine    = AlertEngine('/app/data/devices.db', emit_fn=_on_alert_emit)
suricata_engine = SuricataEngine(
    emit_fn=lambda ev, data: socketio.emit(ev, data),
    db_path='/app/data/devices.db',
)

# ── Toast dedup ─────────────────────────────────────────────────
_join_toast_ts: dict = {}

def _should_toast(mac: str, is_new: bool, was_offline: bool) -> bool:
    cooldown = settings.get('device_rejoin_mins', 10) * 60
    now = time.time()
    if is_new:
        _join_toast_ts[mac] = now
        return True
    if was_offline and (now - _join_toast_ts.get(mac, 0)) > cooldown:
        _join_toast_ts[mac] = now
        return True
    _join_toast_ts[mac] = now
    return False


# ── Central packet handler ──────────────────────────────────────
def on_packet(pkt):
    try:
        if _is_ignored_ip(pkt.src_ip) and _is_ignored_ip(pkt.dst_ip):
            return

        # 1. Asset discovery
        result = asset_inventory.process_packet(pkt)
        if result:
            fp, is_new, was_offline = result
            if is_new or was_offline:
                # Always emit to frontend (dashboard event log sees all joins)
                socketio.emit('device_joined', fp.to_dict())
                # Toast only when cooldown allows
                if _should_toast(fp.mac, is_new, was_offline):
                    socketio.emit('device_toast', fp.to_dict())
                alert_engine.on_device_joined(fp, is_new, was_offline)
                # Persist to event log DB
                label = fp.label or fp.hostname or fp.dhcp_hostname or fp.ip or fp.mac
                event_log.add(EV_JOINED,
                    f"{'New' if is_new else 'Reconnected'}: {label}",
                    ip=fp.ip, mac=fp.mac,
                    hostname=label,
                    vendor=fp.vendor or '',
                    device_type=fp.device_type or '',
                    detail=f"MAC: {fp.mac} | {'New device' if is_new else 'Was offline'}",
                )

        # 2. Protocol DPI
        proto_results = proto_analyzer.analyze(pkt)

        app_proto = ''
        if   'tls'  in proto_results: app_proto = 'TLS'
        elif 'dns'  in proto_results: app_proto = 'DNS'
        elif 'http' in proto_results: app_proto = 'HTTP'

        # 3. Flow monitor
        flow_monitor.process_packet(pkt, app_proto)

        # 4. Topology graph
        topo_engine.add_packet(pkt)

        # 5. WebSocket DPI events
        if 'dns' in proto_results:
            d = proto_results['dns']
            if d.questions:
                q = d.questions[0]
                socketio.emit('dns_query', {
                    'ts': d.ts, 'src': d.src_ip, 'query': q,
                    'is_response': d.is_response,
                    'answers': [a.get('value','') for a in d.answers[:3]],
                })
                if not d.is_response and not q.endswith('.local'):
                    alert_engine.on_dns_query(d.src_ip, q, d.ts)
                # Log to persistent history
                datastore.log_dns(
                    ts=d.ts, src_ip=d.src_ip, query=q,
                    qtype=d.questions[0].split(':')[0] if ':' in d.questions[0] else 'A',
                    is_resp=d.is_response,
                    answer=', '.join(a.get('value','') for a in d.answers[:3]),
                )

        if 'tls' in proto_results:
            t = proto_results['tls']
            socketio.emit('tls_session', {
                'ts': t.ts, 'src': t.src_ip, 'dst': t.dst_ip,
                'sni': t.sni, 'ja3': t.ja3, 'port': t.dst_port,
            })
            datastore.log_tls(
                ts=t.ts, src_ip=t.src_ip, dst_ip=t.dst_ip,
                sni=t.sni, ja3=t.ja3, port=t.dst_port,
            )

        # 6. Security detection
        if pkt.arp_sender_mac and pkt.arp_sender_ip:
            alert_engine.on_arp(pkt.arp_sender_ip, pkt.arp_sender_mac, pkt.ts)

        if pkt.is_tcp_syn and pkt.src_ip and pkt.dst_ip:
            alert_engine.on_tcp_syn(pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.ts)
            alert_engine.track_connection(pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.ts)

    except Exception as e:
        log.debug(f"Packet handler: {e}")


capture_engine = CaptureEngine(callback=on_packet)


# ── Network helpers ─────────────────────────────────────────────
def _default_iface():
    """Return primary LAN interface — always prefer eth0, never wlan/docker/veth."""
    import os
    # Manual override
    env = os.environ.get('CAPTURE_INTERFACES','').split(',')[0].strip()
    if env: return env

    SKIP = ('lo','wlan','docker','veth','br-','virbr','tun','tap')
    try:
        # First: check default route
        out = subprocess.run(['ip','route','show','default'],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            m = re.search(r'dev (\S+)', line)
            if m:
                iface = m.group(1)
                if not any(iface.startswith(p) for p in SKIP):
                    return iface
        # Second: first UP non-virtual interface
        out2 = subprocess.run(['ip','-o','link','show'],
                              capture_output=True, text=True).stdout
        for line in out2.splitlines():
            m = re.match(r'\d+: (\S+?)[@:]', line)
            if m:
                iface = m.group(1)
                if not any(iface.startswith(p) for p in SKIP):
                    if 'UP' in line and 'LOWER_UP' in line:
                        return iface
    except Exception: pass
    return 'eth0'

def _net_range(iface=None):
    nr = settings.get('network_range', 'auto')
    if nr != 'auto': return nr
    iface = iface or _default_iface()
    try:
        out = subprocess.run(['ip','-o','-f','inet','addr','show', iface],
                             capture_output=True, text=True).stdout
        m = re.search(r'inet (\S+)', out)
        if m: return m.group(1)
    except: pass
    return '192.168.1.0/24'


# ── Active scanner ──────────────────────────────────────────────
def active_scan():
    try:
        if settings.get('passive_only', False):
            log.info("Passive-only mode — skipping active scan")
            return
        iface = _default_iface()
        net_range = _net_range(iface)
        log.info(f"Active scan: {net_range}")
        found_macs = set()

        try:
            result = subprocess.run(
                ['nmap','-sn','--send-ip', net_range],
                capture_output=True, text=True,
                timeout=120)  # nmap timeout fixed at 2 min
            current = {}
            for line in result.stdout.splitlines():
                if line.startswith('Nmap scan report for'):
                    if current.get('mac'):
                        found_macs.add(current['mac'])
                        asset_inventory.process_dhcp(current['mac'], current.get('ip',''), source='nmap')
                    parts = line.split()
                    current = {'ip': parts[-1].strip('()'),
                               'hostname': parts[4] if len(parts) > 5 else ''}
                elif 'MAC Address:' in line:
                    m = re.search(r'MAC Address: ([0-9A-Fa-f:]+)', line)
                    if m: current['mac'] = m.group(1).lower()
            if current.get('mac'): found_macs.add(current['mac'])
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.warning(f"nmap: {e}")

        try:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == '0x2':
                        ip, mac = parts[0], parts[3].lower()
                        if mac not in ('00:00:00:00:00:00','') and not _is_ignored_ip(ip):
                            found_macs.add(mac)
                            asset_inventory.process_dhcp(mac, ip, source='arp-table')
        except Exception as e: log.debug(f"ARP table: {e}")

        try:
            result = subprocess.run(
                ['arp-scan','--localnet','--interface', iface],
                capture_output=True, text=True, timeout=60)
            for line in result.stdout.splitlines():
                parts = line.split('\t')
                if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                    ip, mac = parts[0].strip(), parts[1].strip().lower()
                    if mac and not _is_ignored_ip(ip):
                        found_macs.add(mac)
                        asset_inventory.process_dhcp(mac, ip, source='arp-scan')
        except (subprocess.TimeoutExpired, FileNotFoundError): pass

        asset_inventory.mark_offline(found_macs)
        asset_inventory.resolve_hostnames()
        socketio.emit('scan_complete', {'ts': time.time(), 'found': len(found_macs), 'network': net_range})
        event_log.add(EV_SCAN, f"Scan complete: {len(found_macs)} devices on {net_range}",
                      detail=f"Network: {net_range}")
        # Snapshot current flows to history DB
        try:
            datastore.snapshot_flows(flow_monitor.get_flows(limit=5000))
        except Exception as _e:
            log.debug(f"Flow snapshot: {_e}")
        log.info(f"Scan done: {len(found_macs)} devices")

    except Exception as e:
        log.error(f"Scan error: {e}")


def scan_loop():
    time.sleep(10)
    while True:
        active_scan()
        time.sleep(settings.get('scan_interval', 60))


# ── Broadcast loop ──────────────────────────────────────────────
def broadcast_loop():
    while True:
        try:
            live = flow_monitor.get_live_stats()
            cap  = capture_engine.get_stats()
            socketio.emit('live_stats', {
                'bps':          live['bps'],
                'pps':          live['pps'],
                'active_flows': live['active_flows'],
                'captured':     cap['captured'],
                'dropped':      cap['dropped'],
                'capture_mbps': round(cap['mbps'], 4),
                'alert_unread': alert_engine.unread_count(),
            })
            talkers = flow_monitor.get_top_talkers(10)
            for t in talkers:
                bps = t['bytes'] * 8
                alert_engine.on_bandwidth(t['ip'], bps, time.time())
                health_engine.update_bps(t['ip'], bps)
        except Exception as e:
            log.debug(f"Broadcast: {e}")
        time.sleep(1)


# ══════════════════════════════════════════════════════════════════
# REST API
# ══════════════════════════════════════════════════════════════════

# ── Auth routes (public — no auth required) ──────────────────────────
@app.route('/auth/login', methods=['POST'])
def login(): return auth.handle_login()

@app.route('/auth/logout', methods=['POST'])
def logout(): return auth.handle_logout()

@app.route('/auth/check')
def auth_check(): return auth.handle_check()

@app.route('/login')
def login_page(): return send_from_directory('/app/frontend', 'login.html')

@app.route('/')
@auth.require_auth
def index(): return send_from_directory('/app/frontend', 'index.html')

@app.route('/health')
def health(): return jsonify({'status': 'ok', 'ts': time.time()})

# Protect all /api/* routes
@app.before_request
def protect_api():
    if request.path.startswith('/api/'):
        # Auth routes and health are always public
        if request.path in ('/auth/login', '/auth/logout', '/auth/check', '/health'):
            return None
        token = request.cookies.get('nw_session', '')
        if not auth.validate_session(token):
            return jsonify({'ok': False, 'error': 'Not authenticated',
                            'login_required': True}), 401
    return None


# ── Devices ────────────────────────────────────────────────────
@app.route('/api/devices')
def api_devices(): return jsonify(asset_inventory.get_all())

@app.route('/api/devices/<mac>', methods=['PATCH'])
def api_device_update(mac):
    data = request.json or {}
    asset_inventory.update_device(mac, **{k: v for k, v in data.items()
                                          if k in ('label','hostname','device_type','alert_on_join')})
    return jsonify({'ok': True})

@app.route('/api/import/devices', methods=['POST'])
def api_import_devices():
    import csv, io as _io
    file = request.files.get('file')
    if not file:
        return jsonify({'ok': False, 'error': 'No file — use multipart/form-data, field name "file"'}), 400
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'ok': False, 'error': 'Must be a .csv file'}), 400
    try:
        text   = file.read().decode('utf-8-sig')
        reader = csv.DictReader(_io.StringIO(text))
        rows   = list(reader)
    except Exception as e:
        return jsonify({'ok': False, 'error': f'CSV parse error: {e}'}), 400

    if not rows:
        return jsonify({'ok': False, 'error': 'CSV is empty'}), 400

    def norm(d):
        return {k.strip().lower(): (v.strip() if isinstance(v, str) else v) for k, v in d.items()}
    rows = [norm(r) for r in rows]

    all_devs  = asset_inventory.get_all()
    mac_index = {d['mac'].lower().replace('-',':'): d for d in all_devs}
    ip_index  = {d['ip']: d['mac'].lower() for d in all_devs if d.get('ip')}

    updated, skipped, not_found = 0, 0, []

    for row in rows:
        raw_mac = row.get('mac','').lower().replace('-',':').strip()
        raw_ip  = row.get('ip','').strip()
        target  = None
        if raw_mac and raw_mac in mac_index:
            target = raw_mac
        elif raw_ip and raw_ip in ip_index:
            target = ip_index[raw_ip]
        if not target:
            not_found.append(raw_mac or raw_ip or '?')
            continue
        updates = {}
        for field in ('label', 'hostname', 'device_type'):
            val = row.get(field, '').strip()
            if val and val not in ('--', '-', 'None', 'none', ''):
                updates[field] = val
        if not updates:
            skipped += 1
            continue
        ok = asset_inventory.update_device(target, **updates)
        if ok: updated += 1
        else:  not_found.append(target)

    return jsonify({
        'ok': True, 'updated': updated, 'skipped': skipped,
        'not_found': not_found[:20], 'total': len(rows),
        'message': f'Updated {updated} of {len(rows)} devices. {skipped} unchanged, {len(not_found)} not found.',
    })

@app.route('/api/devices/<ip>/history')
def api_device_history(ip):
    """Connection history for a specific device IP."""
    return jsonify({
        'connections': topo_engine.get_device_connections(ip),
        'flows':       flow_monitor.get_ip_stats(ip),
        'events':      [e for e in asset_inventory.get_events(200)
                        if e.get('ip') == ip],
    })


# ── Flows ──────────────────────────────────────────────────────
@app.route('/api/flows')
def api_flows(): return jsonify(flow_monitor.get_flows(sort_by=request.args.get('sort','bytes')))

@app.route('/api/flows/ip/<ip>')
def api_ip_flows(ip): return jsonify(flow_monitor.get_ip_stats(ip))


# ── Bandwidth ──────────────────────────────────────────────────
@app.route('/api/bandwidth')
def api_bandwidth():
    return jsonify(flow_monitor.get_bandwidth_series(int(request.args.get('n', 60))))

@app.route('/api/bandwidth/<ip>')
def api_ip_bandwidth(ip): return jsonify(flow_monitor.get_ip_bandwidth(ip))


# ── Protocol / DPI ─────────────────────────────────────────────
@app.route('/api/protocols')
def api_protocols(): return jsonify(flow_monitor.get_protocol_distribution())

@app.route('/api/talkers')
def api_talkers(): return jsonify(flow_monitor.get_top_talkers())

@app.route('/api/dpi')
def api_dpi(): return jsonify(proto_analyzer.get_summary())


# ── Events & History ───────────────────────────────────────────
@app.route('/api/events')
def api_events():
    return jsonify(asset_inventory.get_events(int(request.args.get('n', 100))))

@app.route('/api/events/history')
def api_events_history():
    """Persistent event history with search and pagination."""
    return jsonify(event_log.query(
        limit     = min(int(request.args.get('limit', 500)), 10000),
        offset    = int(request.args.get('offset', 0)),
        ev_type   = request.args.get('type'),
        ip        = request.args.get('ip'),
        mac       = request.args.get('mac'),
        search    = request.args.get('q'),
        since_ts  = float(request.args.get('since', 0)) or None,
        until_ts  = float(request.args.get('until', 0)) or None,
        severity  = request.args.get('severity'),
    ))

@app.route('/api/events/stats')
def api_events_stats():
    return jsonify(event_log.get_stats())

@app.route('/api/events/clear', methods=['POST'])
def api_events_clear():
    event_log.clear()
    return jsonify({'ok': True})


# ── Topology ───────────────────────────────────────────────────
@app.route('/api/topology')
def api_topology():
    # Build device label lookup from inventory
    devices = asset_inventory.get_all()
    labels  = {d['ip']: d.get('label') or d.get('hostname') or d['ip'] for d in devices}
    return jsonify(topo_engine.get_graph(device_lookup=labels))

@app.route('/api/topology/device/<ip>')
def api_topo_device(ip):
    return jsonify(topo_engine.get_device_connections(ip))


# ── Stats ──────────────────────────────────────────────────────
@app.route('/api/stats')
def api_stats():
    return jsonify({
        'devices':       asset_inventory.stats(),
        'capture':       capture_engine.get_stats(),
        'flows':         flow_monitor.get_live_stats(),
        'network':       _net_range(),
        'scan_interval': settings.get('scan_interval', 60),
        'alerts':        alert_engine.stats(),
        'suricata':      {'available': suricata_engine.is_available},
        'pihole':        pihole_engine.get_summary(),
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    threading.Thread(target=active_scan, daemon=True).start()
    return jsonify({'ok': True})


# ── Alerts ─────────────────────────────────────────────────────
@app.route('/api/alerts')
def api_alerts():
    return jsonify(alert_engine.get_alerts(
        limit=int(request.args.get('limit', 1000)),
        sev=request.args.get('sev'),
        cat=request.args.get('cat'),
        unread_only=request.args.get('unread') == '1',
    ))

@app.route('/api/alerts/<alert_id>/dismiss', methods=['POST'])
def api_dismiss(alert_id):
    alert_engine.dismiss(alert_id); return jsonify({'ok': True})

@app.route('/api/alerts/dismiss_all', methods=['POST'])
def api_dismiss_all():
    alert_engine.dismiss_all(); return jsonify({'ok': True})

@app.route('/api/alerts/clear_all', methods=['POST'])
def api_clear_all():
    with alert_engine._lock:
        alert_engine._alerts.clear()
        alert_engine._last_fired.clear()
    try:
        conn = alert_engine._conn()
        conn.execute('DELETE FROM alerts')
        conn.commit(); conn.close()
    except Exception: pass
    return jsonify({'ok': True})


# ── Suricata ───────────────────────────────────────────────────
@app.route('/api/suricata/summary')
def api_sur_summary(): return jsonify(suricata_engine.get_summary())

@app.route('/api/suricata/alerts')
def api_sur_alerts():
    return jsonify(suricata_engine.get_alerts(
        limit=int(request.args.get('limit', 1000)),
        sev=request.args.get('sev'),
        cat=request.args.get('cat'),
    ))

@app.route('/api/suricata/flows')
def api_sur_flows():
    return jsonify(suricata_engine.get_flows(int(request.args.get('limit', 100))))

@app.route('/api/suricata/dns')
def api_sur_dns():
    return jsonify(suricata_engine.get_dns(int(request.args.get('limit', 100))))

@app.route('/api/suricata/tls')
def api_sur_tls():
    return jsonify(suricata_engine.get_tls(int(request.args.get('limit', 100))))

@app.route('/api/suricata/http')
def api_sur_http():
    return jsonify(suricata_engine.get_http(int(request.args.get('limit', 100))))

@app.route('/api/suricata/series')
def api_sur_series(): return jsonify(suricata_engine.get_traffic_series())

@app.route('/api/suricata/sources')
def api_sur_sources(): return jsonify(suricata_engine.get_top_sources())

@app.route('/api/suricata/dests')
def api_sur_dests(): return jsonify(suricata_engine.get_top_dests())

@app.route('/api/suricata/clear', methods=['POST'])
def api_sur_clear():
    suricata_engine.clear(); return jsonify({'ok': True})


# ── Settings ───────────────────────────────────────────────────
@app.route('/api/settings')
def api_settings_get():
    return jsonify(settings.get_all())

@app.route('/api/settings', methods=['POST'])
def api_settings_update():
    data = request.json or {}
    updated = settings.update(data)
    socketio.emit('settings_changed', updated)
    return jsonify({'ok': True, 'settings': updated})

@app.route('/api/settings/reset', methods=['POST'])
def api_settings_reset():
    return jsonify({'ok': True, 'settings': settings.reset()})


# ── Export ─────────────────────────────────────────────────────
# ── L2/L4 History API ──────────────────────────────────────────
@app.route('/api/history/dns')
def api_hist_dns():
    return jsonify(datastore.query_dns(
        range_str = request.args.get('range', '1d'),
        ip        = request.args.get('ip', ''),
        q         = request.args.get('q', ''),
        limit     = min(int(request.args.get('limit', 500)), 5000),
        offset    = int(request.args.get('offset', 0)),
    ))

@app.route('/api/history/tls')
def api_hist_tls():
    return jsonify(datastore.query_tls(
        range_str = request.args.get('range', '1d'),
        ip        = request.args.get('ip', ''),
        sni       = request.args.get('sni', ''),
        limit     = min(int(request.args.get('limit', 500)), 5000),
        offset    = int(request.args.get('offset', 0)),
    ))

@app.route('/api/history/flows')
def api_hist_flows():
    return jsonify(datastore.query_flows(
        range_str = request.args.get('range', '1d'),
        ip        = request.args.get('ip', ''),
        port      = request.args.get('port', ''),
        proto     = request.args.get('proto', ''),
        limit     = min(int(request.args.get('limit', 500)), 5000),
        offset    = int(request.args.get('offset', 0)),
    ))

@app.route('/api/history/stats')
def api_hist_stats():
    return jsonify(datastore.get_db_stats())

@app.route('/api/archive')
def api_archive_index():
    return jsonify(datastore.get_archive_index())

@app.route('/api/archive/<month>/<filename>')
def api_archive_file(month, filename):
    data = datastore.get_archive_file(month, filename)
    if not data:
        return jsonify({'error': 'Not found'}), 404
    return data, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename={month}_{filename}',
    }

@app.route('/api/archive/trigger', methods=['POST'])
def api_archive_trigger():
    """Manually trigger archive for testing."""
    threading.Thread(target=datastore._run_nightly, daemon=True).start()
    return jsonify({'ok': True, 'message': 'Archive job started'})

@app.route('/api/export/devices.csv')
def export_devices():
    data = devices_to_csv(asset_inventory.get_all())
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=netwatch_devices.csv'})

@app.route('/api/export/alerts.csv')
def export_alerts():
    data = alerts_to_csv(alert_engine.get_alerts(limit=5000))
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=netwatch_alerts.csv'})

@app.route('/api/export/flows.csv')
def export_flows():
    data = flows_to_csv(flow_monitor.get_flows(limit=5000))
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=netwatch_flows.csv'})

@app.route('/api/export/suricata.csv')
def export_suricata():
    data = suricata_alerts_to_csv(suricata_engine.get_alerts(limit=5000))
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=netwatch_suricata.csv'})

@app.route('/api/export/events.csv')
def export_events():
    data = events_to_csv(asset_inventory.get_events(limit=5000))
    return Response(data, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=netwatch_events.csv'})

@app.route('/api/export/full.json')
def export_full_json():
    import json as _json
    payload = {
        'exported_at':  time.time(),
        'devices':      asset_inventory.get_all(),
        'alerts':       alert_engine.get_alerts(limit=5000),
        'flows':        flow_monitor.get_flows(limit=5000),
        'suricata':     suricata_engine.get_alerts(limit=5000),
        'events':       asset_inventory.get_events(limit=5000),
        'topology':     topo_engine.get_graph(),
    }
    return Response(_json.dumps(payload, indent=2), mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename=netwatch_full.json'})


# ── Health Score ──────────────────────────────────────────────
@app.route('/api/health')
def api_health():
    incidents  = incident_engine.get_incidents()
    pihole     = pihole_engine.get_summary()
    devices    = asset_inventory.get_all()
    sur_ok     = suricata_engine.is_available
    score      = health_engine.calculate_score(incidents, pihole, devices, sur_ok)
    return jsonify(score)

@app.route('/api/health/anomalies')
def api_anomalies():
    anomalies = health_engine.check_anomalies(
        emit_fn=lambda ev, data: socketio.emit(ev, data)
    )
    return jsonify(anomalies)

@app.route('/api/health/device/<ip>')
def api_device_health(ip):
    return jsonify(health_engine.get_device_baseline(ip))


# ── Incidents ──────────────────────────────────────────────────
@app.route('/api/incidents')
def api_incidents():
    active_only = request.args.get('active', '0') == '1'
    return jsonify(incident_engine.get_incidents(active_only=active_only))

@app.route('/api/incidents/stats')
def api_incidents_stats():
    return jsonify(incident_engine.stats())

@app.route('/api/incidents/<inc_id>/dismiss', methods=['POST'])
def api_incident_dismiss(inc_id):
    incident_engine.dismiss(inc_id)
    return jsonify({'ok': True})

@app.route('/api/incidents/dismiss_all', methods=['POST'])
def api_incidents_dismiss_all():
    incident_engine.dismiss_all()
    return jsonify({'ok': True})


# ── GeoIP ──────────────────────────────────────────────────────
@app.route('/api/geoip/<ip>')
def api_geoip(ip):
    # Try cache first (instant), then async lookup
    cached = geoip_engine.get_cached(ip)
    if cached:
        return jsonify({'ok': True, 'data': cached})
    # Start async lookup and return pending status
    geoip_engine.lookup(ip, async_ok=True)
    return jsonify({'ok': False, 'pending': True})

@app.route('/api/geoip/bulk', methods=['POST'])
def api_geoip_bulk():
    ips  = (request.json or {}).get('ips', [])
    data = geoip_engine.bulk_lookup(ips[:30])   # cap at 30
    return jsonify(data)

@app.route('/api/geoip/stats')
def api_geoip_stats():
    return jsonify(geoip_engine.stats())


# ── Block / Action ─────────────────────────────────────────────
@app.route('/api/action/block_ip', methods=['POST'])
def api_block_ip():
    """
    Block an IP via Pi-hole custom DNS blacklist.
    Also returns the iptables command to run on the router.
    """
    data = request.json or {}
    ip   = data.get('ip', '').strip()
    note = data.get('note', 'Blocked via NetWatch Pro').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'}), 400

    results = {'ip': ip}

    # Pi-hole: add to custom blocklist via API
    ph_result = pihole_engine.action(f'block:{ip}')
    results['pihole'] = ph_result

    # Provide router/iptables commands for manual action
    results['commands'] = {
        'iptables_drop':   f'iptables -I FORWARD -s {ip} -j DROP',
        'iptables_reject': f'iptables -I FORWARD -s {ip} -j REJECT',
        'iptables_undo':   f'iptables -D FORWARD -s {ip} -j DROP',
        'nftables_drop':   f'nft add rule inet filter forward ip saddr {ip} drop',
    }
    results['note'] = note
    results['ok']   = True

    event_log.add(EV_SYSTEM, f"Block action: {ip}",
                  ip=ip, detail=f"Blocked via NetWatch UI. Note: {note}",
                  severity='warning')

    return jsonify(results)

@app.route('/api/action/unblock_ip', methods=['POST'])
def api_unblock_ip():
    data = request.json or {}
    ip   = data.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'}), 400
    ph_result = pihole_engine.action(f'unblock:{ip}')
    event_log.add(EV_SYSTEM, f"Unblock action: {ip}", ip=ip, severity='info')
    return jsonify({'ok': True, 'ip': ip, 'pihole': ph_result})


# ── Pi-hole Routes ──────────────────────────────────────────────────

@app.route('/api/pihole/summary')
def api_pihole_summary():
    return jsonify(pihole_engine.get_summary())

@app.route('/api/pihole/test')
def api_pihole_test():
    return jsonify(pihole_engine.debug_info())

@app.route('/api/pihole/full')
def api_pihole_full():
    return jsonify(pihole_engine.get_full())

@app.route('/api/pihole/top')
def api_pihole_top():
    return jsonify(pihole_engine.get_top_data())

@app.route('/api/pihole/overtime')
def api_pihole_overtime():
    return jsonify(pihole_engine.get_overtime())

@app.route('/api/pihole/query_types')
def api_pihole_qtypes():
    return jsonify(pihole_engine.get_query_types())

@app.route('/api/pihole/action/<cmd>', methods=['POST'])
def api_pihole_action(cmd):
    if cmd not in ('enable', 'disable', 'disable=30', 'disable=60', 'disable=300'):
        return jsonify({'ok': False, 'error': 'Invalid command'}), 400
    return jsonify(pihole_engine.action(cmd))

@app.route('/api/pihole/config', methods=['POST'])
def api_pihole_config():
    data     = request.json or {}
    url      = data.get('url',      '').strip()
    password = data.get('password', '').strip()
    token    = data.get('token',    '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'}), 400
    public_url = data.get('public_url', '').strip() or url
    pihole_engine.set_credentials(url, password=password, token=token, public_url=public_url)
    settings.update({'pihole_url': url, 'pihole_public_url': public_url,
                     'pihole_password': password, 'pihole_token': token})
    # Sync NetWatch login password with Pi-hole password if NETWATCH_PASSWORD not set explicitly
    import os as _os2
    if not _os2.environ.get('NETWATCH_PASSWORD') and password:
        auth.set_password(password)
    # Reset API version so it re-detects on next poll
    pihole_engine._api_version = 0
    return jsonify({'ok': True, 'message': 'Pi-hole config updated'})

# ── WebSocket ──────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    if not auth.require_auth_ws(request.sid):
        return False   # Reject WebSocket connection
    log.info(f"WS client: {request.sid}")

@socketio.on('disconnect')
def on_disconnect(): log.info(f"WS gone: {request.sid}")


# ── Entry point ─────────────────────────────────────────────────
if __name__ == '__main__':
    capture_engine.start()
    suricata_engine.start(settings.get('suricata_eve_path', EVE_LOG_PATH))
    # Load Pi-hole URL/token — prefer persisted settings, fall back to env var
    _ph_url      = settings.get('pihole_url')        or os.environ.get('PIHOLE_URL',        'http://127.0.0.1:8888')
    _ph_pub_url  = settings.get('pihole_public_url') or os.environ.get('PIHOLE_PUBLIC_URL', 'http://10.10.32.12:8888')
    _ph_password = settings.get('pihole_password')   or os.environ.get('PIHOLE_PASSWORD',   '')
    _ph_token    = settings.get('pihole_token')      or os.environ.get('PIHOLE_API_TOKEN',   '')
    pihole_engine.set_credentials(_ph_url, password=_ph_password, token=_ph_token, public_url=_ph_pub_url)
    pihole_engine.start()
    # Rebuild incident state from existing alerts
    try:
        existing = alert_engine.get_alerts(limit=5000)
        incident_engine.rebuild_from_alerts(existing)
    except Exception as _ie:
        log.warning(f"Incident rebuild: {_ie}")
    log.info(f"Pi-hole: {_ph_url} | token={'set' if _ph_token else 'not set'}")
    threading.Thread(target=scan_loop,      daemon=True, name='scanner').start()
    threading.Thread(target=broadcast_loop, daemon=True, name='broadcast').start()
    log.info("All engines started — binding 0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False,
                 use_reloader=False, allow_unsafe_werkzeug=True)
