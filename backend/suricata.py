"""
╔══════════════════════════════════════════════════════════════════════╗
║  NetWatch Pro — Suricata Integration Engine                          ║
║                                                                      ║
║  Tails /var/log/suricata/eve.json in real time                      ║
║  Parses: alert, flow, dns, tls, http, stats event types             ║
║  Emits WebSocket events and serves REST API data                    ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os, json, time, threading, logging, sqlite3, hashlib, re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable

log = logging.getLogger(__name__)

# ── Default EVE log path (overridable via env) ─────────────────────────
EVE_LOG_PATH = os.environ.get('SURICATA_EVE_LOG', '/var/log/suricata/eve.json')

# ── Severity mapping from Suricata priority → label ───────────────────
PRIORITY_SEV = {1: 'critical', 2: 'high', 3: 'warning', 4: 'info'}
SEV_COLOR    = {'critical': '#ff3b7a', 'high': '#ff9500', 'warning': '#ffd60a', 'info': '#00d4ff'}

# ── Known benign signature categories to suppress from live feed ───────
BENIGN_CATEGORIES = {
    'Generic Protocol Command Decode',
    'Not Suspicious Traffic',
    'Unknown Traffic',
    'Potential Corporate Privacy Violation',
}

# ── GeoIP placeholder (returns region from RFC-1918 or unknown) ────────
RFC1918 = [
    ('10.0.0.0',    'ff000000', 'Private (10.x.x.x)'),
    ('172.16.0.0',  'fff00000', 'Private (172.16–31.x)'),
    ('192.168.0.0', 'ffff0000', 'Private (192.168.x.x)'),
    ('127.0.0.0',   'ff000000', 'Loopback'),
    ('169.254.0.0', 'ffff0000', 'Link-local'),
    ('172.17.0.0',  'ffff0000', 'Docker (172.17.x)'),
]

def _geo_label(ip: str) -> str:
    """Minimal GeoIP: classify private/public without external calls."""
    if not ip: return 'Unknown'
    try:
        parts = ip.split('.')
        if len(parts) != 4: return 'IPv6 / Unknown'
        a, b = int(parts[0]), int(parts[1])
        if a == 10: return 'Private LAN'
        if a == 172 and 16 <= b <= 31: return 'Private LAN'
        if a == 192 and b == 168: return 'Private LAN'
        if a == 127: return 'Loopback'
        if a == 169 and b == 254: return 'Link-Local'
        if a == 172 and b == 17: return 'Docker Network'
        # Public IP — return octets as placeholder (real GeoIP needs mmdb)
        return f'Public ({a}.{b}.x.x)'
    except Exception:
        return 'Unknown'


# ─────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class SuricataAlert:
    id:          str
    ts:          float
    timestamp:   str
    sev:         str        # critical / high / warning / info
    priority:    int
    signature:   str
    sig_id:      int
    category:    str
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    proto:       str
    action:      str        # allowed / blocked
    flow_id:     int
    app_proto:   str        # http / dns / tls / ssh / etc.
    payload_b64: str        # raw payload if available

    def to_dict(self) -> dict:
        return {
            'id':        self.id,
            'ts':        self.ts,
            'timestamp': self.timestamp,
            'sev':       self.sev,
            'priority':  self.priority,
            'signature': self.signature,
            'sig_id':    self.sig_id,
            'category':  self.category,
            'src_ip':    self.src_ip,
            'dst_ip':    self.dst_ip,
            'src_port':  self.src_port,
            'dst_port':  self.dst_port,
            'proto':     self.proto,
            'action':    self.action,
            'flow_id':   self.flow_id,
            'app_proto': self.app_proto,
            'src_geo':   _geo_label(self.src_ip),
            'dst_geo':   _geo_label(self.dst_ip),
        }


@dataclass
class SuricataFlow:
    ts:           float
    flow_id:      int
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    proto:        str
    app_proto:    str
    bytes_toserv: int
    bytes_toclient: int
    pkts_toserv:  int
    pkts_toclient: int
    state:        str
    reason:       str
    duration_ms:  int

    @property
    def total_bytes(self): return self.bytes_toserv + self.bytes_toclient
    @property
    def total_pkts(self):  return self.pkts_toserv + self.pkts_toclient

    def to_dict(self) -> dict:
        return {
            'ts': self.ts, 'flow_id': self.flow_id,
            'src_ip': self.src_ip, 'dst_ip': self.dst_ip,
            'src_port': self.src_port, 'dst_port': self.dst_port,
            'proto': self.proto, 'app_proto': self.app_proto,
            'bytes': self.total_bytes, 'pkts': self.total_pkts,
            'bytes_toserv': self.bytes_toserv, 'bytes_toclient': self.bytes_toclient,
            'state': self.state, 'reason': self.reason,
            'duration_ms': self.duration_ms,
        }


# ─────────────────────────────────────────────────────────────────────────
# EVE JSON Parser
# ─────────────────────────────────────────────────────────────────────────

def _parse_ts(ts_str: str) -> float:
    """Parse Suricata ISO8601 timestamp → unix float."""
    try:
        # e.g. "2024-01-15T14:32:01.123456+0000"
        clean = ts_str[:19]  # "2024-01-15T14:32:01"
        import datetime
        dt = datetime.datetime.strptime(clean, '%Y-%m-%dT%H:%M:%S')
        return dt.timestamp()
    except Exception:
        return time.time()


def _event_id(event: dict) -> str:
    key = f"{event.get('timestamp','')}{event.get('flow_id','')}{event.get('event_type','')}"
    if 'alert' in event:
        key += str(event['alert'].get('signature_id',''))
    return hashlib.md5(key.encode()).hexdigest()[:12]


def parse_eve_line(line: str) -> Optional[dict]:
    """Parse a single EVE JSON line. Returns structured dict or None."""
    line = line.strip()
    if not line:
        return None
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return None

    etype = ev.get('event_type', '')
    ts    = _parse_ts(ev.get('timestamp', ''))
    evid  = _event_id(ev)

    src_ip   = ev.get('src_ip', '')
    dst_ip   = ev.get('dest_ip', '')
    src_port = ev.get('src_port', 0)
    dst_port = ev.get('dest_port', 0)
    proto    = ev.get('proto', '')
    flow_id  = ev.get('flow_id', 0)
    app_proto= ev.get('app_proto', '')

    result = {
        'id':         evid,
        'ts':         ts,
        'timestamp':  ev.get('timestamp', ''),
        'event_type': etype,
        'src_ip':     src_ip,
        'dst_ip':     dst_ip,
        'src_port':   src_port,
        'dst_port':   dst_port,
        'proto':      proto,
        'flow_id':    flow_id,
        'app_proto':  app_proto,
        'iface':      ev.get('iface', ''),
        'raw':        ev,
    }

    # ── Alert ─────────────────────────────────────────────────
    if etype == 'alert':
        a = ev.get('alert', {})
        priority = a.get('severity', a.get('priority', 3))
        sev      = PRIORITY_SEV.get(priority, 'info')
        category = a.get('category', 'Unknown')

        result.update({
            'alert': {
                'id':         evid,
                'ts':         ts,
                'timestamp':  ev.get('timestamp', ''),
                'sev':        sev,
                'priority':   priority,
                'signature':  a.get('signature', 'Unknown Signature'),
                'sig_id':     a.get('signature_id', 0),
                'category':   category,
                'src_ip':     src_ip,
                'dst_ip':     dst_ip,
                'src_port':   src_port,
                'dst_port':   dst_port,
                'proto':      proto,
                'action':     a.get('action', 'allowed'),
                'flow_id':    flow_id,
                'app_proto':  app_proto,
                'src_geo':    _geo_label(src_ip),
                'dst_geo':    _geo_label(dst_ip),
                'payload_b64': ev.get('payload', ''),
            }
        })

    # ── Flow ──────────────────────────────────────────────────
    elif etype == 'flow':
        f = ev.get('flow', {})
        result.update({
            'flow': {
                'ts':            ts,
                'flow_id':       flow_id,
                'src_ip':        src_ip,
                'dst_ip':        dst_ip,
                'src_port':      src_port,
                'dst_port':      dst_port,
                'proto':         proto,
                'app_proto':     app_proto,
                'bytes_toserv':  f.get('bytes_toserver', 0),
                'bytes_toclient':f.get('bytes_toclient', 0),
                'pkts_toserv':   f.get('pkts_toserver', 0),
                'pkts_toclient': f.get('pkts_toclient', 0),
                'state':         f.get('state', ''),
                'reason':        f.get('reason', ''),
                'alerted':       f.get('alerted', False),
                'start':         f.get('start', ''),
                'duration_ms':   0,
            }
        })

    # ── DNS ───────────────────────────────────────────────────
    elif etype == 'dns':
        d = ev.get('dns', {})
        result.update({
            'dns': {
                'ts':        ts,
                'src_ip':    src_ip,
                'dst_ip':    dst_ip,
                'query':     d.get('rrname', ''),
                'type':      d.get('type', ''),
                'rrtype':    d.get('rrtype', ''),
                'rcode':     d.get('rcode', ''),
                'answers':   [r.get('rdata', '') for r in d.get('answers', [])],
                'ttl':       d.get('ttl', 0),
            }
        })

    # ── TLS ───────────────────────────────────────────────────
    elif etype == 'tls':
        t = ev.get('tls', {})
        result.update({
            'tls': {
                'ts':       ts,
                'src_ip':   src_ip,
                'dst_ip':   dst_ip,
                'sni':      t.get('sni', ''),
                'version':  t.get('version', ''),
                'subject':  t.get('subject', ''),
                'issuer':   t.get('issuerdn', ''),
                'ja3':      t.get('ja3', {}).get('hash', ''),
                'ja3s':     t.get('ja3s', {}).get('hash', ''),
                'notbefore':t.get('notbefore', ''),
                'notafter': t.get('notafter', ''),
            }
        })

    # ── HTTP ──────────────────────────────────────────────────
    elif etype == 'http':
        h = ev.get('http', {})
        result.update({
            'http': {
                'ts':           ts,
                'src_ip':       src_ip,
                'dst_ip':       dst_ip,
                'hostname':     h.get('hostname', ''),
                'url':          h.get('url', ''),
                'method':       h.get('http_method', ''),
                'user_agent':   h.get('http_user_agent', ''),
                'status':       h.get('status', 0),
                'length':       h.get('length', 0),
                'content_type': h.get('http_content_type', ''),
            }
        })

    # ── SSH ───────────────────────────────────────────────────
    elif etype == 'ssh':
        s = ev.get('ssh', {})
        result.update({
            'ssh': {
                'ts':       ts,
                'src_ip':   src_ip,
                'dst_ip':   dst_ip,
                'client':   s.get('client', {}).get('software_version', ''),
                'server':   s.get('server', {}).get('software_version', ''),
                'proto_version': s.get('client', {}).get('proto_version', ''),
            }
        })

    # ── Stats ─────────────────────────────────────────────────
    elif etype == 'stats':
        s = ev.get('stats', {})
        result.update({
            'stats': {
                'ts':           ts,
                'uptime':       s.get('uptime', 0),
                'capture_pkts': s.get('capture', {}).get('kernel_packets', 0),
                'capture_drop': s.get('capture', {}).get('kernel_drops', 0),
                'decoder_pkts': s.get('decoder', {}).get('pkts', 0),
                'decoder_bytes':s.get('decoder', {}).get('bytes', 0),
                'alert_count':  s.get('alert', {}).get('total', 0),
                'flow_count':   s.get('flow', {}).get('total', 0),
                'tcp_sessions': s.get('flow', {}).get('tcp', 0),
                'udp_sessions': s.get('flow', {}).get('udp', 0),
                'app_layers':   s.get('app_layer', {}).get('flow', {}),
            }
        })

    return result


# ─────────────────────────────────────────────────────────────────────────
# EVE Log Tailer
# ─────────────────────────────────────────────────────────────────────────

class EveTailer:
    """
    Efficiently tails eve.json in a background thread.
    On startup: reads the last N lines (backfill).
    While running: follows new lines as they are written.
    Calls on_event(parsed_dict) for every new event.
    """

    BACKFILL_LINES = 500   # How many historical lines to load on start
    POLL_INTERVAL  = 0.25  # seconds between file checks

    def __init__(self, path: str, on_event: Callable):
        self.path     = path
        self.on_event = on_event
        self._stop    = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._file_size = 0
        self._inode     = 0
        self._available = False

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name='suricata-tailer')
        self._thread.start()
        log.info(f"Suricata EVE tailer started — watching {self.path}")

    def stop(self):
        self._stop.set()

    @property
    def is_available(self) -> bool:
        return self._available

    def _backfill(self, f):
        """Read last BACKFILL_LINES lines from the current file position."""
        try:
            f.seek(0, 2)  # seek to end
            end = f.tell()
            buf_size = min(end, 512 * 1024)  # 512 KB max backfill read
            f.seek(max(0, end - buf_size))
            raw = f.read(buf_size)
            lines = raw.decode('utf-8', errors='replace').splitlines()
            lines = lines[-self.BACKFILL_LINES:]
            count = 0
            for line in lines:
                ev = parse_eve_line(line)
                if ev:
                    self.on_event(ev)
                    count += 1
            log.info(f"Suricata backfill: {count} events loaded from last {len(lines)} lines")
            # Position at end so we only tail new events
            f.seek(0, 2)
            return f.tell()
        except Exception as e:
            log.warning(f"Suricata backfill error: {e}")
            return 0

    def _run(self):
        while not self._stop.is_set():
            if not os.path.exists(self.path):
                if self._available:
                    log.warning(f"Suricata EVE log disappeared: {self.path}")
                    self._available = False
                time.sleep(3)
                continue

            try:
                stat = os.stat(self.path)
                self._available = True
                self._inode     = stat.st_ino
                self._file_size = stat.st_size

                with open(self.path, 'rb') as f:
                    pos = self._backfill(f)
                    log.info(f"Suricata tailer following at byte {pos}")

                    while not self._stop.is_set():
                        line = f.readline()

                        if line:
                            ev = parse_eve_line(line.decode('utf-8', errors='replace'))
                            if ev:
                                self.on_event(ev)
                            continue

                        # No new data — check for log rotation
                        try:
                            new_stat = os.stat(self.path)
                            if new_stat.st_ino != self._inode:
                                log.info("Suricata EVE log rotated — reopening")
                                break
                            if new_stat.st_size < f.tell():
                                log.info("Suricata EVE log truncated — rewinding")
                                f.seek(0)
                        except FileNotFoundError:
                            log.warning("Suricata EVE log removed")
                            break

                        time.sleep(self.POLL_INTERVAL)

            except PermissionError:
                log.error(f"No read permission: {self.path} — check container volume mount")
                self._available = False
                time.sleep(10)
            except Exception as e:
                log.error(f"Suricata tailer error: {e}")
                self._available = False
                time.sleep(5)


# ─────────────────────────────────────────────────────────────────────────
# Suricata Stats Engine
# ─────────────────────────────────────────────────────────────────────────

class SuricataEngine:
    """
    Maintains in-memory state for all Suricata event types.
    Provides REST API data and feeds WebSocket events.
    """

    MAX_ALERTS   = 10_000
    MAX_FLOWS    = 1000
    MAX_DNS      = 500
    MAX_TLS      = 500
    MAX_HTTP     = 500
    SERIES_LEN   = 300   # 5 min at 1-second resolution

    def __init__(self, emit_fn: Callable = None, db_path: str = '/app/data/devices.db'):
        self._emit    = emit_fn
        self.db_path  = db_path
        self._lock    = threading.RLock()

        # Live event buffers
        self._alerts: List[dict] = []
        self._flows:  List[dict] = []
        self._dns:    List[dict] = []
        self._tls:    List[dict] = []
        self._http:   List[dict] = []

        # Statistics
        self._alert_cats:   Dict[str, int] = defaultdict(int)
        self._alert_sigs:   Dict[str, int] = defaultdict(int)
        self._proto_counts: Dict[str, int] = defaultdict(int)
        self._app_protos:   Dict[str, int] = defaultdict(int)
        self._src_ips:      Dict[str, int] = defaultdict(int)
        self._dst_ips:      Dict[str, int] = defaultdict(int)

        # Severity counters
        self._sev_counts = {'critical': 0, 'high': 0, 'warning': 0, 'info': 0}

        # Traffic time series (1-second buckets)
        self._bytes_series: deque = deque(maxlen=self.SERIES_LEN)
        self._pkts_series:  deque = deque(maxlen=self.SERIES_LEN)
        self._alert_series: deque = deque(maxlen=self.SERIES_LEN)
        self._cur_ts    = int(time.time())
        self._cur_bytes = 0
        self._cur_pkts  = 0
        self._cur_alerts= 0

        # Suricata engine stats (from stats events)
        self._engine_stats: dict = {}

        # Dedup for alert events
        self._seen_alert_ids: deque = deque(maxlen=5000)

        # Start series ticker
        threading.Thread(target=self._series_tick, daemon=True, name='suricata-series').start()

        self._tailer: Optional[EveTailer] = None

    def start(self, eve_path: str = EVE_LOG_PATH):
        self._tailer = EveTailer(eve_path, self._on_event)
        self._tailer.start()

    @property
    def is_available(self) -> bool:
        return self._tailer is not None and self._tailer.is_available

    def _series_tick(self):
        """Advance the 1-second time series buckets."""
        while True:
            time.sleep(1)
            now = int(time.time())
            with self._lock:
                self._bytes_series.append({'ts': now, 'v': self._cur_bytes})
                self._pkts_series.append({'ts': now, 'v': self._cur_pkts})
                self._alert_series.append({'ts': now, 'v': self._cur_alerts})
                self._cur_bytes  = 0
                self._cur_pkts   = 0
                self._cur_alerts = 0
                self._cur_ts     = now

    def _on_event(self, ev: dict):
        """Central event handler — routes by event_type."""
        etype = ev.get('event_type', '')

        if etype == 'alert':
            self._handle_alert(ev)
        elif etype == 'flow':
            self._handle_flow(ev)
        elif etype == 'dns':
            self._handle_dns(ev)
        elif etype == 'tls':
            self._handle_tls(ev)
        elif etype == 'http':
            self._handle_http(ev)
        elif etype == 'stats':
            self._handle_stats(ev)

        # Count protocols from all events
        proto = ev.get('proto', '')
        app   = ev.get('app_proto', '')
        if proto:
            with self._lock:
                self._proto_counts[proto] += 1
        if app and app not in ('failed', 'unknown', ''):
            with self._lock:
                self._app_protos[app] += 1

    def _handle_alert(self, ev: dict):
        a = ev.get('alert', {})
        if not a: return

        aid = a.get('id', ev.get('id', ''))
        if not aid: return

        # Dedup by ID
        if aid in self._seen_alert_ids: return
        self._seen_alert_ids.append(aid)

        # Filter benign categories
        cat = a.get('category', '')
        if cat in BENIGN_CATEGORIES:
            return

        sev = a.get('sev', 'info')

        with self._lock:
            self._alerts.insert(0, a)
            if len(self._alerts) > self.MAX_ALERTS:
                self._alerts.pop()
            self._alert_cats[cat] += 1
            self._alert_sigs[a.get('signature', '')]  += 1
            self._sev_counts[sev] = self._sev_counts.get(sev, 0) + 1
            self._cur_alerts += 1
            src = a.get('src_ip', '')
            dst = a.get('dst_ip', '')
            if src: self._src_ips[src] += 1
            if dst: self._dst_ips[dst] += 1

        if self._emit:
            try:
                self._emit('suricata_alert', a)
            except Exception as e:
                log.debug(f"Suricata alert emit: {e}")

    def _handle_flow(self, ev: dict):
        f = ev.get('flow', {})
        if not f: return
        b = f.get('bytes_toserv', 0) + f.get('bytes_toclient', 0)
        p = f.get('pkts_toserv', 0) + f.get('pkts_toclient', 0)
        with self._lock:
            self._flows.insert(0, f)
            if len(self._flows) > self.MAX_FLOWS:
                self._flows.pop()
            self._cur_bytes += b
            self._cur_pkts  += p

        if self._emit:
            try:
                self._emit('suricata_flow', f)
            except Exception: pass

    def _handle_dns(self, ev: dict):
        d = ev.get('dns', {})
        if not d or d.get('type') != 'query': return
        with self._lock:
            self._dns.insert(0, d)
            if len(self._dns) > self.MAX_DNS:
                self._dns.pop()

    def _handle_tls(self, ev: dict):
        t = ev.get('tls', {})
        if not t: return
        with self._lock:
            self._tls.insert(0, t)
            if len(self._tls) > self.MAX_TLS:
                self._tls.pop()

    def _handle_http(self, ev: dict):
        h = ev.get('http', {})
        if not h: return
        with self._lock:
            self._http.insert(0, h)
            if len(self._http) > self.MAX_HTTP:
                self._http.pop()

    def _handle_stats(self, ev: dict):
        s = ev.get('stats', {})
        if not s: return
        with self._lock:
            self._engine_stats = s
        if self._emit:
            try:
                self._emit('suricata_stats', s)
            except Exception: pass

    # ── Public API ──────────────────────────────────────────────────────

    def get_alerts(self, limit: int = 200, sev: str = None, cat: str = None) -> List[dict]:
        with self._lock:
            alerts = self._alerts[:]
        if sev: alerts = [a for a in alerts if a.get('sev') == sev]
        if cat: alerts = [a for a in alerts if cat.lower() in a.get('category','').lower()]
        return alerts[:limit]

    def get_flows(self, limit: int = 100) -> List[dict]:
        with self._lock: return list(self._flows[:limit])

    def get_dns(self, limit: int = 100) -> List[dict]:
        with self._lock: return list(self._dns[:limit])

    def get_tls(self, limit: int = 100) -> List[dict]:
        with self._lock: return list(self._tls[:limit])

    def get_http(self, limit: int = 100) -> List[dict]:
        with self._lock: return list(self._http[:limit])

    def get_traffic_series(self) -> dict:
        with self._lock:
            return {
                'bytes': list(self._bytes_series),
                'pkts':  list(self._pkts_series),
                'alerts':list(self._alert_series),
            }

    def get_top_sources(self, n: int = 10) -> List[dict]:
        with self._lock:
            top = sorted(self._src_ips.items(), key=lambda x: -x[1])[:n]
        return [{'ip': ip, 'count': c, 'geo': _geo_label(ip)} for ip, c in top]

    def get_top_dests(self, n: int = 10) -> List[dict]:
        with self._lock:
            top = sorted(self._dst_ips.items(), key=lambda x: -x[1])[:n]
        return [{'ip': ip, 'count': c, 'geo': _geo_label(ip)} for ip, c in top]

    def get_summary(self) -> dict:
        with self._lock:
            total_alerts = len(self._alerts)
            total_flows  = len(self._flows)
            cats = sorted(self._alert_cats.items(),  key=lambda x: -x[1])[:12]
            sigs = sorted(self._alert_sigs.items(),  key=lambda x: -x[1])[:10]
            apps = sorted(self._app_protos.items(),  key=lambda x: -x[1])[:12]
            protos = sorted(self._proto_counts.items(), key=lambda x: -x[1])[:8]
            sev_counts = dict(self._sev_counts)
            engine     = dict(self._engine_stats)

        return {
            'available':     self.is_available,
            'eve_path':      EVE_LOG_PATH,
            'total_alerts':  total_alerts,
            'total_flows':   total_flows,
            'sev_counts':    sev_counts,
            'alert_cats':    [{'cat': c, 'count': n} for c, n in cats],
            'top_sigs':      [{'sig': s, 'count': n} for s, n in sigs],
            'app_protos':    [{'proto': p, 'count': n} for p, n in apps],
            'net_protos':    [{'proto': p, 'count': n} for p, n in protos],
            'engine_stats':  engine,
        }

    def clear(self):
        with self._lock:
            self._alerts.clear(); self._flows.clear()
            self._dns.clear();    self._tls.clear()
            self._http.clear()
            self._alert_cats.clear(); self._alert_sigs.clear()
            self._proto_counts.clear(); self._app_protos.clear()
            self._src_ips.clear(); self._dst_ips.clear()
            self._sev_counts = {'critical': 0, 'high': 0, 'warning': 0, 'info': 0}
            self._seen_alert_ids.clear()
