"""
NetWatch Pro — Alerting & Security Detection Engine
Fixed:
- Toast cooldown: new-device toast only once per session (never repeats unless truly NEW)
- mDNS/ARP whitelist: no false positives from normal LAN traffic
- Proper baseline tracking before alerting on spikes
- Docker/loopback network filtering
- Sane thresholds to avoid alert fatigue
"""

import time, threading, logging, sqlite3, hashlib, ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional

log = logging.getLogger(__name__)

SEV_INFO   = 'info'
SEV_WARN   = 'warning'
SEV_HIGH   = 'high'
SEV_CRIT   = 'critical'
CAT_NETWORK  = 'network'
CAT_SECURITY = 'security'
CAT_TRAFFIC  = 'traffic'


# ── Networks to IGNORE (Docker bridges, loopback, link-local) ──
IGNORE_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),    # loopback
    ipaddress.ip_network('169.254.0.0/16'),  # link-local / APIPA
    ipaddress.ip_network('172.16.0.0/12'),   # Docker default bridge range
    ipaddress.ip_network('::1/128'),          # IPv6 loopback
    ipaddress.ip_network('fe80::/10'),        # IPv6 link-local
]

def _is_ignored_ip(ip: str) -> bool:
    """Return True for IPs that should never trigger alerts."""
    if not ip: return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in IGNORE_NETWORKS)
    except ValueError:
        return True

def _is_private_ip(ip: str) -> bool:
    """Return True for RFC-1918 private addresses (valid LAN)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ── Aggressive whitelist for DNS — these are 100% normal ───────
DNS_WHITELIST_SUFFIXES = {
    # Reverse DNS lookups — completely normal, never a C2 signal
    'in-addr.arpa', 'ip6.arpa', 'arpa',
    # Connectivity checks (OS background tasks)
    'connectivitycheck.gstatic.com', 'connectivitycheck.android.com',
    'captive.apple.com', 'www.apple.com', 'mesu.apple.com',
    'detectportal.firefox.com', 'firefox.com',
    'msftconnecttest.com', 'msftncsi.com',
    # NTP
    'pool.ntp.org', 'time.apple.com', 'time.windows.com',
    'time.google.com', 'time.cloudflare.com', 'time.aws.com',
    # OCSP / certificate validation
    'ocsp.apple.com', 'ocsp.digicert.com', 'ocsp.verisign.com',
    'ocsp.pki.goog', 'pki.goog', 'crl.apple.com',
    # Push / telemetry (normal device background traffic)
    'push.apple.com', 'courier.push.apple.com', 'icloud.com',
    'apple-dns.net', 'apple.com', 'aaplimg.com',
    'googleapis.com', 'google.com', 'gstatic.com', 'gvt1.com',
    'doubleclick.net', 'googleadservices.com',
    'microsoft.com', 'windows.com', 'windowsupdate.com',
    'office.com', 'office365.com', 'live.com', 'msn.com',
    'amazon.com', 'amazonaws.com', 'amazon-adsystem.com',
    # CDNs
    'akamai.com', 'akamaiedge.net', 'akamaihd.net',
    'cloudfront.net', 'fastly.net', 'cloudflare.com',
    'edgekey.net', 'edgesuite.net',
    # Ads / tracking (annoyingly common, not malicious)
    'advertising.com', 'ads.com', 'analytics.google.com',
    # mDNS / local discovery — ALWAYS ignore
    'local', 'localhost', 'localdomain', 'lan', 'home', 'internal',
    # CDN / streaming commonly flagged
    'wsdvs.com', 'volcfcdndvs.com', 'douyincdn.com',
    'argotunnel.com', 'cloudflareresearch.com',
    # Discord — common app
    'discord.com', 'discordapp.com', 'discord.gg',
    # Common streaming
    'netflix.com', 'nflxext.com', 'nflximg.net',
    'spotify.com', 'scdn.co', 'youtube.com', 'ytimg.com',
    'twitch.tv', 'twitchapps.com',
}

DNS_WHITELIST_TLD_SAFE = {'.local', '.localhost', '.localdomain', '.lan', '.home', '.internal'}

def _is_whitelisted_dns(query: str) -> bool:
    """Return True if this DNS query is completely normal and should be ignored."""
    if not query: return True
    q = query.lower().rstrip('.')
    # mDNS / local domains — always safe
    for safe_tld in DNS_WHITELIST_TLD_SAFE:
        if q.endswith(safe_tld): return True
    # Exact match or suffix match against whitelist
    for safe in DNS_WHITELIST_SUFFIXES:
        if q == safe or q.endswith('.' + safe): return True
    return False


# ── ARP whitelist: these ARP patterns are completely normal ─────
def _is_normal_arp(ip: str, mac: str) -> bool:
    """Gratuitous ARP, broadcast, etc. — all normal."""
    if not ip or not mac: return True
    if mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'): return True
    if ip in ('0.0.0.0', '255.255.255.255'): return True
    return False


@dataclass
class Alert:
    id:        str
    ts:        float
    sev:       str
    cat:       str
    title:     str
    detail:    str
    src_ip:    str  = ''
    dst_ip:    str  = ''
    mac:       str  = ''
    dismissed: bool = False

    def to_dict(self):
        return {'id':self.id,'ts':self.ts,'sev':self.sev,'cat':self.cat,
                'title':self.title,'detail':self.detail,'src_ip':self.src_ip,
                'dst_ip':self.dst_ip,'mac':self.mac,'dismissed':self.dismissed}


def _aid(prefix: str, key: str) -> str:
    return prefix + '_' + hashlib.md5(key.encode()).hexdigest()[:8]


BRUTE_PORTS = {22:'SSH', 3389:'RDP', 21:'FTP', 23:'Telnet',
               5900:'VNC', 3306:'MySQL', 5432:'PostgreSQL', 1433:'MSSQL'}


class AlertEngine:
    MAX_ALERTS = 1000

    def __init__(self, db_path='/app/data/devices.db', emit_fn=None):
        self._alerts: List[Alert] = []
        self._lock   = threading.Lock()
        self._emit   = emit_fn
        self.db_path = db_path

        # Dedup: alert_id -> last_fired_ts
        self._last_fired: Dict[str, float] = {}

        # ── Toast / UI dedup (separate from alert dedup) ──────
        # Tracks which MACs have had a "device joined" TOAST shown this session.
        # A toast is shown ONLY when:
        #   1. The device has NEVER been seen before (truly new MAC)
        #   2. OR the device was offline for > REJOIN_TOAST_SECONDS
        # This prevents the passive ARP sniffer from spamming toasts for
        # devices that are online and occasionally send ARP packets.
        self._toast_shown:     Set[str]         = set()   # macs that got a toast this session
        self._device_online_ts: Dict[str, float] = {}      # mac -> time we first saw it online
        self.REJOIN_TOAST_SECONDS = 600   # 10 min offline before we show join toast again

        # Per-IP DNS tracker
        self._dns_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # ARP table ip -> mac (for spoof detection)
        self._arp_table: Dict[str, str] = {}
        self._arp_lock  = threading.Lock()

        # Brute-force tracker: key -> deque of timestamps
        self._syn_tracker: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Port scan tracker: src->dst -> set of ports in window
        self._scan_ports:  Dict[str, set]   = defaultdict(set)
        self._scan_reset:  Dict[str, float] = {}

        # Bandwidth baseline (needs 2 min of data before alerting)
        self._bw_samples:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=120))
        self._bw_ts:       Dict[str, float] = {}

        self._init_db()
        self._load_db()

    # ── DB ────────────────────────────────────────────────────
    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=5)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        try:
            conn = self._conn()
            conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, ts REAL, sev TEXT, cat TEXT,
                title TEXT, detail TEXT, src_ip TEXT, dst_ip TEXT,
                mac TEXT, dismissed INTEGER DEFAULT 0)''')
            conn.commit(); conn.close()
        except Exception as e: log.warning(f"Alert DB: {e}")

    def _load_db(self):
        try:
            conn = self._conn()
            rows = conn.execute('SELECT * FROM alerts ORDER BY ts DESC LIMIT 500').fetchall()
            conn.close()
            with self._lock:
                self._alerts = [Alert(
                    id=r['id'], ts=r['ts'], sev=r['sev'], cat=r['cat'],
                    title=r['title'], detail=r['detail'], src_ip=r['src_ip'] or '',
                    dst_ip=r['dst_ip'] or '', mac=r['mac'] or '',
                    dismissed=bool(r['dismissed'])
                ) for r in rows]
            log.info(f"Loaded {len(self._alerts)} alerts from DB")
        except Exception as e: log.debug(f"Alert load: {e}")

    def _save(self, a: Alert):
        try:
            conn = self._conn()
            conn.execute('''INSERT OR REPLACE INTO alerts
                (id,ts,sev,cat,title,detail,src_ip,dst_ip,mac,dismissed)
                VALUES(?,?,?,?,?,?,?,?,?,?)''',
                (a.id,a.ts,a.sev,a.cat,a.title,a.detail,
                 a.src_ip,a.dst_ip,a.mac,int(a.dismissed)))
            conn.commit(); conn.close()
        except Exception as e: log.debug(f"Alert save: {e}")

    # ── Fire (with dedup) ─────────────────────────────────────
    def _fire(self, alert: Alert, cooldown: float = 300.0):
        """
        Fire an alert with cooldown-based dedup.
        cooldown=300 means: same alert ID won't fire again for 5 minutes.
        Set cooldown=0 to fire always (but still deduped per-second).
        """
        now = time.time()
        last = self._last_fired.get(alert.id, 0)
        if now - last < cooldown:
            return
        self._last_fired[alert.id] = now

        with self._lock:
            self._alerts.insert(0, alert)
            if len(self._alerts) > self.MAX_ALERTS:
                self._alerts.pop()

        threading.Thread(target=self._save, args=(alert,), daemon=True).start()

        if self._emit:
            try:
                self._emit('alert', alert.to_dict())
            except Exception as e:
                log.debug(f"Alert emit: {e}")

        log.info(f"ALERT [{alert.sev.upper()}] {alert.title} | {alert.detail[:100]}")

        # Persist to event log (fire-and-forget)
        try:
            from eventlog import event_log, EV_ALERT
            event_log.add(EV_ALERT, alert.title,
                ip=alert.src_ip, detail=alert.detail,
                severity=alert.sev)
        except Exception:
            pass

    # ── Device join/leave ─────────────────────────────────────
    def should_emit_join_toast(self, mac: str, is_new: bool, was_offline: bool) -> bool:
        """
        Decides whether the UI should show a toast notification for a device joining.

        Rules:
        - Truly new MAC (never seen before): YES, always show toast
        - Was offline and came back:
            - If it went offline > REJOIN_TOAST_SECONDS ago: YES show toast
            - Otherwise: NO (device was just momentarily absent, e.g. sleep/wake)
        - Device is already online and just sent another ARP: NO (this is the spam case)
        """
        now = time.time()
        if is_new:
            # First time we've ever seen this MAC — always show
            self._toast_shown.add(mac)
            self._device_online_ts[mac] = now
            return True

        if was_offline:
            # Device came back — check how long it was gone
            last_seen_online = self._device_online_ts.get(mac, 0)
            offline_duration = now - last_seen_online
            self._device_online_ts[mac] = now
            if offline_duration > self.REJOIN_TOAST_SECONDS:
                return True
            else:
                # Was only briefly offline (e.g., scan cycle, sleep/wake)
                return False

        # Device was already online — update timestamp but no toast
        self._device_online_ts[mac] = now
        return False

    def on_device_joined(self, fp, is_new: bool, was_offline: bool):
        """Called when a device is seen joining. Fires an alert (in alert feed)
        but only shows a toast for genuinely new/returning devices."""
        now = time.time()

        if _is_ignored_ip(fp.ip):
            return   # Skip Docker/loopback addresses

        label = fp.label or fp.hostname or fp.dhcp_hostname or fp.ip or fp.mac
        vendor = fp.vendor or 'Unknown'
        dtype  = fp.device_type or 'Unknown'

        if is_new:
            self._fire(Alert(
                id=_aid('new_device', fp.mac), ts=now,
                sev=SEV_WARN, cat=CAT_NETWORK,
                title='New Device Detected',
                detail=f"{label} | IP: {fp.ip} | MAC: {fp.mac} | Vendor: {vendor} | Type: {dtype}",
                src_ip=fp.ip, mac=fp.mac,
            ), cooldown=86400)  # Only fire once per day per MAC
        elif was_offline:
            # Only fire a "reconnected" alert if it was offline a long time
            last_seen = self._device_online_ts.get(fp.mac, 0)
            if now - last_seen > self.REJOIN_TOAST_SECONDS:
                self._fire(Alert(
                    id=_aid('rejoined', fp.mac), ts=now,
                    sev=SEV_INFO, cat=CAT_NETWORK,
                    title='Device Reconnected',
                    detail=f"{label} | IP: {fp.ip} | MAC: {fp.mac}",
                    src_ip=fp.ip, mac=fp.mac,
                ), cooldown=self.REJOIN_TOAST_SECONDS)

    def on_device_left(self, mac: str, ip: str):
        if _is_ignored_ip(ip): return
        self._fire(Alert(
            id=_aid('left', mac), ts=time.time(),
            sev=SEV_INFO, cat=CAT_NETWORK,
            title='Device Left Network',
            detail=f"MAC: {mac} | Last IP: {ip}",
            src_ip=ip, mac=mac,
        ), cooldown=120)

    # ── DNS security ──────────────────────────────────────────
    def on_dns_query(self, src_ip: str, query: str, ts: float):
        if not query or not src_ip: return
        if _is_ignored_ip(src_ip): return
        if _is_whitelisted_dns(query): return   # Skip all normal queries

        now = ts or time.time()
        self._dns_tracker[src_ip].append((now, query))

        q = query.lower().rstrip('.')

        # 1. DNS tunneling: extremely long query (>80 chars total)
        if len(q) > 80:
            self._fire(Alert(
                id=_aid('dns_tunnel', src_ip + q[:20]), ts=now,
                sev=SEV_HIGH, cat=CAT_SECURITY,
                title='Possible DNS Tunneling',
                detail=f"Very long DNS query ({len(q)} chars) from {src_ip}: {q[:60]}...",
                src_ip=src_ip,
            ), cooldown=300)
            return   # Don't also fire label-length alert for the same query

        # 2. Very long single label (>40 chars) — possible base64 exfil
        labels = q.split('.')
        max_label = max((len(l) for l in labels), default=0)
        if max_label > 40:
            self._fire(Alert(
                id=_aid('dns_label', src_ip + q[:20]), ts=now,
                sev=SEV_WARN, cat=CAT_SECURITY,
                title='Suspicious DNS Label Length',
                detail=f"Label of {max_label} chars in query from {src_ip}: {q[:60]}",
                src_ip=src_ip,
            ), cooldown=300)

        # 3. DGA: >50% digits in the second-level domain (not in well-known TLDs)
        if len(labels) >= 2:
            sld = labels[-2]  # second-level domain
            if len(sld) > 8:
                digit_ratio = sum(c.isdigit() for c in sld) / len(sld)
                if digit_ratio > 0.5:
                    self._fire(Alert(
                        id=_aid('dga', src_ip + sld), ts=now,
                        sev=SEV_WARN, cat=CAT_SECURITY,
                        title='Possible DGA Domain',
                        detail=f"High digit ratio ({digit_ratio:.0%}) in domain '{sld}' from {src_ip}",
                        src_ip=src_ip,
                    ), cooldown=600)

        # 4. Beaconing: >30 queries to SAME non-whitelisted domain in 60 sec
        domain = '.'.join(labels[-2:]) if len(labels) >= 2 else q
        recent_same = [t for t, dq in self._dns_tracker[src_ip]
                       if now - t < 60 and '.'.join(dq.lower().rstrip('.').split('.')[-2:]) == domain]
        if len(recent_same) >= 50:   # Raised from 30 — normal apps query often
            self._fire(Alert(
                id=_aid('beacon', src_ip + domain), ts=now,
                sev=SEV_HIGH, cat=CAT_SECURITY,
                title='Beaconing / C2 Pattern',
                detail=f"{src_ip} queried '{domain}' {len(recent_same)}× in 60s — possible C2 callback",
                src_ip=src_ip,
            ), cooldown=600)

        # 5. DNS flood: >200 total queries from one IP in 10 seconds
        burst = [t for t, _ in self._dns_tracker[src_ip] if now - t < 10]
        if len(burst) >= 200:
            self._fire(Alert(
                id=_aid('dns_flood', src_ip), ts=now,
                sev=SEV_HIGH, cat=CAT_SECURITY,
                title='DNS Flood',
                detail=f"{src_ip} sent {len(burst)} DNS queries in 10 seconds",
                src_ip=src_ip,
            ), cooldown=120)

    # ── ARP spoofing ──────────────────────────────────────────
    @staticmethod
    def _is_randomized_mac(mac: str) -> bool:
        """Locally-administered MACs (random/privacy) change often — not spoofing."""
        try:
            first_byte = int(mac.split(':')[0].replace('-',''), 16)
            return bool(first_byte & 0x02)  # locally-administered bit
        except Exception:
            return False

    def on_arp(self, ip: str, mac: str, ts: float):
        if not ip or not mac: return
        if _is_normal_arp(ip, mac): return
        if _is_ignored_ip(ip): return
        # Skip randomized/privacy MACs — they change by design
        if self._is_randomized_mac(mac): return

        with self._arp_lock:
            known = self._arp_table.get(ip)
            if known is None:
                self._arp_table[ip] = mac
                return
            if known == mac:
                return
            # Both old and new are randomized — not spoofing, just MAC rotation
            if self._is_randomized_mac(known):
                self._arp_table[ip] = mac
                return
            old_mac = known
            self._arp_table[ip] = mac

        self._fire(Alert(
            id=_aid('arp_spoof', ip), ts=ts or time.time(),
            sev=SEV_CRIT, cat=CAT_SECURITY,
            title='ARP Spoofing / MITM Detected',
            detail=f"IP {ip} changed MAC: {old_mac} → {mac} — possible ARP poisoning",
            src_ip=ip, mac=mac,
        ), cooldown=300)

    # ── Brute-force ───────────────────────────────────────────
    def on_tcp_syn(self, src_ip: str, dst_ip: str, dst_port: int, ts: float):
        if dst_port not in BRUTE_PORTS: return
        if _is_ignored_ip(src_ip) or _is_ignored_ip(dst_ip): return

        now = ts or time.time()
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        self._syn_tracker[key].append(now)
        # >20 SYNs in 10 seconds = brute-force (raised from 10 to reduce false positives)
        recent = [t for t in self._syn_tracker[key] if now - t < 10]
        if len(recent) >= 20:
            svc = BRUTE_PORTS[dst_port]
            self._fire(Alert(
                id=_aid('brute', key), ts=now,
                sev=SEV_HIGH, cat=CAT_SECURITY,
                title=f'Brute-Force Attempt — {svc}',
                detail=f"{src_ip} → {dst_ip}:{dst_port} ({svc}) | {len(recent)} SYNs in 10s",
                src_ip=src_ip, dst_ip=dst_ip,
            ), cooldown=120)

    # ── Port scan ─────────────────────────────────────────────
    def track_connection(self, src_ip: str, dst_ip: str, dst_port: int, ts: float):
        if _is_ignored_ip(src_ip) or _is_ignored_ip(dst_ip): return
        # Skip if src and dst are on same Docker network
        if not _is_private_ip(src_ip): return

        now = ts or time.time()
        key = f"{src_ip}->{dst_ip}"

        # Reset port set every 5 seconds
        if now - self._scan_reset.get(key, 0) > 5:
            self._scan_ports[key] = set()
            self._scan_reset[key] = now

        self._scan_ports[key].add(dst_port)
        port_count = len(self._scan_ports[key])

        # >30 unique ports in 5 seconds = port scan
        if port_count >= 30:
            self._fire(Alert(
                id=_aid('portscan', key), ts=now,
                sev=SEV_HIGH, cat=CAT_SECURITY,
                title='Port Scan Detected',
                detail=f"{src_ip} scanned {port_count} ports on {dst_ip} in 5 seconds",
                src_ip=src_ip, dst_ip=dst_ip,
            ), cooldown=120)

    # ── Bandwidth spike ───────────────────────────────────────
    def on_bandwidth(self, ip: str, bps: float, ts: float):
        if _is_ignored_ip(ip): return
        now = ts or time.time()

        # Sample at most once per second
        if now - self._bw_ts.get(ip, 0) < 1.0: return
        self._bw_ts[ip] = now
        self._bw_samples[ip].append(bps)

        # Need at least 2 minutes of baseline before alerting
        if len(self._bw_samples[ip]) < 120: return

        samples = list(self._bw_samples[ip])
        avg = sum(samples[:-10]) / max(len(samples) - 10, 1)  # Exclude recent 10s from baseline
        current = sum(samples[-10:]) / 10  # 10-second moving average

        # Spike: >8× average AND >25 Mbps sustained
        if avg > 0 and current > avg * 8 and current > 25_000_000:
            self._fire(Alert(
                id=_aid('bw_spike', ip), ts=now,
                sev=SEV_WARN, cat=CAT_TRAFFIC,
                title='Bandwidth Spike',
                detail=f"{ip} using {current/1e6:.1f} Mbps — {current/max(avg,1):.1f}× above baseline ({avg/1e6:.1f} Mbps avg)",
                src_ip=ip,
            ), cooldown=300)

    # ── Public API ────────────────────────────────────────────
    def get_alerts(self, limit=200, sev=None, cat=None, unread_only=False):
        with self._lock: alerts = self._alerts[:]
        if sev:         alerts = [a for a in alerts if a.sev == sev]
        if cat:         alerts = [a for a in alerts if a.cat == cat]
        if unread_only: alerts = [a for a in alerts if not a.dismissed]
        return [a.to_dict() for a in alerts[:limit]]

    def dismiss(self, alert_id: str):
        with self._lock:
            for a in self._alerts:
                if a.id == alert_id:
                    a.dismissed = True
                    threading.Thread(target=self._save, args=(a,), daemon=True).start()
                    break

    def dismiss_all(self):
        with self._lock:
            for a in self._alerts: a.dismissed = True
        try:
            conn = self._conn(); conn.execute('UPDATE alerts SET dismissed=1'); conn.commit(); conn.close()
        except Exception: pass

    def unread_count(self):
        with self._lock: return sum(1 for a in self._alerts if not a.dismissed)

    def stats(self):
        with self._lock:
            total  = len(self._alerts)
            unread = sum(1 for a in self._alerts if not a.dismissed)
            by_sev = {}
            for a in self._alerts:
                by_sev[a.sev] = by_sev.get(a.sev, 0) + 1
        return {'total': total, 'unread': unread, 'by_sev': by_sev}
