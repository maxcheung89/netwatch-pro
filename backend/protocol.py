"""
╔══════════════════════════════════════════════════════════════╗
║  NetWatch Pro — Layer 2: Protocol Analysis Engine (DPI)      ║
║  DNS parser, TLS/JA3 fingerprinting, HTTP session parser     ║
║  Session reconstruction, application-layer identification    ║
╚══════════════════════════════════════════════════════════════╝
"""

import re, struct, hashlib, time, threading, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger(__name__)


# ── Port → Application Protocol Map ───────────────────────────
PORT_PROTO: Dict[int, str] = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP',     53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP',    110: 'POP3', 123: 'NTP', 143: 'IMAP',
    161: 'SNMP',   162: 'SNMP-TRAP',
    443: 'HTTPS',  445: 'SMB',  465: 'SMTPS',
    514: 'Syslog', 587: 'SMTP-TLS', 636: 'LDAPS',
    853: 'DNS-TLS', 993: 'IMAPS', 995: 'POP3S',
    1194: 'OpenVPN', 1433: 'MSSQL', 1883: 'MQTT',
    3306: 'MySQL', 3389: 'RDP', 5353: 'mDNS',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8883: 'MQTT-TLS',
    9200: 'Elasticsearch', 27017: 'MongoDB',
}

def port_to_proto(port: int) -> str:
    return PORT_PROTO.get(port, '')


# ╔══════════════════════════════════════════════════════════════╗
# ║  DNS Parser                                                  ║
# ╚══════════════════════════════════════════════════════════════╝

@dataclass
class DnsRecord:
    ts: float
    src_ip: str
    dst_ip: str
    query_id: int
    is_response: bool
    rcode: int = 0
    questions: List[str] = field(default_factory=list)
    answers: List[dict] = field(default_factory=list)


def _dns_name(data: bytes, offset: int, depth: int = 0):
    """Decode a DNS name with pointer compression support."""
    if depth > 16:
        return '', offset
    parts = []
    start_offset = offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:           # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = _dns_name(data, ptr, depth + 1)
            parts.append(name)
            offset += 2
            return '.'.join(filter(None, parts)), offset
        offset += 1
        end = offset + length
        if end > len(data):
            break
        parts.append(data[offset:end].decode('ascii', errors='replace'))
        offset = end
    return '.'.join(filter(None, parts)), offset


def parse_dns(pkt) -> Optional[DnsRecord]:
    """Parse DNS from UDP port-53 payload."""
    try:
        data = pkt.raw
        # Locate DNS payload: Eth(14) + IP(ihl) + UDP(8)
        ip_offset  = 14
        ihl        = (data[ip_offset] & 0x0F) * 4
        udp_offset = ip_offset + ihl
        dns        = data[udp_offset + 8:]
        if len(dns) < 12:
            return None

        qid      = struct.unpack('!H', dns[0:2])[0]
        flags    = struct.unpack('!H', dns[2:4])[0]
        is_resp  = bool(flags & 0x8000)
        rcode    = flags & 0x000F
        qdcount  = struct.unpack('!H', dns[4:6])[0]
        ancount  = struct.unpack('!H', dns[6:8])[0]

        rec = DnsRecord(ts=pkt.ts, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                        query_id=qid, is_response=is_resp, rcode=rcode)

        offset = 12
        # Questions
        for _ in range(min(qdcount, 8)):
            if offset >= len(dns): break
            name, offset = _dns_name(dns, offset)
            if offset + 4 > len(dns): break
            offset += 4          # qtype(2) + qclass(2)
            rec.questions.append(name)

        # Answers (responses only)
        if is_resp:
            for _ in range(min(ancount, 15)):
                if offset >= len(dns): break
                name, offset = _dns_name(dns, offset)
                if offset + 10 > len(dns): break
                rtype  = struct.unpack('!H', dns[offset:offset+2])[0]
                rdlen  = struct.unpack('!H', dns[offset+8:offset+10])[0]
                rstart = offset + 10
                rdata  = dns[rstart:rstart+rdlen]
                ans    = {'name': name, 'type': rtype, 'value': ''}
                if rtype == 1 and rdlen == 4:          # A
                    ans['value'] = '.'.join(str(b) for b in rdata)
                elif rtype == 28 and rdlen == 16:       # AAAA
                    ans['value'] = ':'.join(
                        f'{struct.unpack("!H", rdata[i:i+2])[0]:04x}'
                        for i in range(0, 16, 2)
                    )
                elif rtype == 5:                        # CNAME
                    cname, _ = _dns_name(dns, rstart)
                    ans['value'] = cname
                elif rtype == 28:
                    ans['value'] = f'(type {rtype})'
                rec.answers.append(ans)
                offset = rstart + rdlen
        return rec
    except Exception:
        return None


# ╔══════════════════════════════════════════════════════════════╗
# ║  TLS / JA3 Fingerprinting                                    ║
# ╚══════════════════════════════════════════════════════════════╝

# GREASE values to exclude from JA3 (RFC 8701)
GREASE: set = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

TLS_VERSIONS: Dict[int, str] = {
    0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
}


@dataclass
class TlsHandshake:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sni: str = ''
    tls_version: str = ''
    raw_version: int = 0
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    elliptic_curves: List[int] = field(default_factory=list)
    ec_formats: List[int] = field(default_factory=list)
    ja3: str = ''
    ja3_raw: str = ''


def parse_tls(pkt) -> Optional[TlsHandshake]:
    """
    Parse TLS ClientHello and compute JA3 fingerprint.
    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECFormats)
    """
    try:
        data = pkt.raw
        ip_offset  = 14
        ihl        = (data[ip_offset] & 0x0F) * 4
        tcp_offset = ip_offset + ihl
        doff       = (data[tcp_offset + 12] >> 4) * 4
        payload    = data[tcp_offset + doff:]

        if len(payload) < 6: return None
        if payload[0] != 0x16: return None    # TLS Handshake record
        if len(payload) < 9:   return None

        # TLS record: type(1) version(2) length(2) | handshake type(1) length(3) ...
        if payload[5] != 0x01: return None    # ClientHello

        hs = payload[5:]
        if len(hs) < 38: return None

        offset = 4   # skip hs_type(1) + length(3)
        ver    = struct.unpack('!H', hs[offset:offset+2])[0]
        offset += 2 + 32   # version + random

        # Session ID
        sid_len = hs[offset]; offset += 1 + sid_len

        # Cipher Suites
        cs_len = struct.unpack('!H', hs[offset:offset+2])[0]; offset += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if offset + i + 2 > len(hs): break
            cs = struct.unpack('!H', hs[offset+i:offset+i+2])[0]
            if cs not in GREASE:
                ciphers.append(cs)
        offset += cs_len

        # Compression methods
        comp_len = hs[offset]; offset += 1 + comp_len

        rec = TlsHandshake(
            ts=pkt.ts, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
            src_port=pkt.src_port, dst_port=pkt.dst_port,
            raw_version=ver,
            tls_version=TLS_VERSIONS.get(ver, f'0x{ver:04x}'),
            cipher_suites=ciphers,
        )

        # Extensions
        if offset + 2 > len(hs): pass
        else:
            ext_total = struct.unpack('!H', hs[offset:offset+2])[0]
            offset += 2
            ext_end = offset + ext_total
            while offset + 4 <= ext_end and offset + 4 <= len(hs):
                ext_type = struct.unpack('!H', hs[offset:offset+2])[0]
                ext_len  = struct.unpack('!H', hs[offset+2:offset+4])[0]
                ext_data = hs[offset+4:offset+4+ext_len]
                if ext_type not in GREASE:
                    rec.extensions.append(ext_type)
                # SNI (type 0)
                if ext_type == 0 and len(ext_data) > 5:
                    sni_len = struct.unpack('!H', ext_data[3:5])[0]
                    rec.sni = ext_data[5:5+sni_len].decode('ascii', errors='replace')
                # Supported groups / elliptic curves (type 10)
                if ext_type == 10 and len(ext_data) >= 2:
                    grp_len = struct.unpack('!H', ext_data[0:2])[0]
                    for i in range(0, grp_len, 2):
                        if 2 + i + 2 > len(ext_data): break
                        g = struct.unpack('!H', ext_data[2+i:4+i])[0]
                        if g not in GREASE:
                            rec.elliptic_curves.append(g)
                # EC point formats (type 11)
                if ext_type == 11 and len(ext_data) >= 1:
                    for b in ext_data[1:ext_data[0]+1]:
                        rec.ec_formats.append(b)
                offset += 4 + ext_len

        # Compute JA3
        raw = (
            f'{ver},'
            f'{"-".join(str(c) for c in rec.cipher_suites)},'
            f'{"-".join(str(e) for e in rec.extensions)},'
            f'{"-".join(str(g) for g in rec.elliptic_curves)},'
            f'{"-".join(str(f) for f in rec.ec_formats)}'
        )
        rec.ja3_raw = raw
        rec.ja3     = hashlib.md5(raw.encode()).hexdigest()
        return rec
    except Exception:
        return None


# ╔══════════════════════════════════════════════════════════════╗
# ║  HTTP Parser                                                 ║
# ╚══════════════════════════════════════════════════════════════╝

@dataclass
class HttpSession:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    method: str = ''
    host: str = ''
    path: str = ''
    http_version: str = ''
    status: int = 0
    status_text: str = ''
    user_agent: str = ''
    content_type: str = ''
    content_length: int = 0
    is_request: bool = True


def parse_http(pkt) -> Optional[HttpSession]:
    """Parse HTTP/1.x requests and responses from TCP payload."""
    try:
        data = pkt.raw
        ip_offset  = 14
        ihl        = (data[ip_offset] & 0x0F) * 4
        tcp_offset = ip_offset + ihl
        doff       = (data[tcp_offset + 12] >> 4) * 4
        payload    = data[tcp_offset + doff:]
        if len(payload) < 16: return None

        # Limit parsing window
        text  = payload[:4096].decode('latin-1', errors='replace')
        lines = text.split('\r\n')
        if not lines: return None

        rec = HttpSession(ts=pkt.ts, src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                          src_port=pkt.src_port, dst_port=pkt.dst_port)

        # Request line: METHOD PATH HTTP/version
        req = re.match(
            r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) (HTTP/[\d.]+)',
            lines[0]
        )
        if req:
            rec.is_request   = True
            rec.method       = req.group(1)
            rec.path         = req.group(2)
            rec.http_version = req.group(3)
            for line in lines[1:]:
                ll = line.lower()
                if ll.startswith('host:'):
                    rec.host = line.split(':', 1)[1].strip()
                elif ll.startswith('user-agent:'):
                    rec.user_agent = line.split(':', 1)[1].strip()
            return rec

        # Response line: HTTP/version STATUS text
        resp = re.match(r'^(HTTP/[\d.]+) (\d+)(.*)', lines[0])
        if resp:
            rec.is_request   = False
            rec.http_version = resp.group(1)
            rec.status       = int(resp.group(2))
            rec.status_text  = resp.group(3).strip()
            for line in lines[1:]:
                ll = line.lower()
                if ll.startswith('content-type:'):
                    rec.content_type = line.split(':', 1)[1].strip()
                elif ll.startswith('content-length:'):
                    try: rec.content_length = int(line.split(':', 1)[1].strip())
                    except ValueError: pass
            return rec

        return None
    except Exception:
        return None


# ╔══════════════════════════════════════════════════════════════╗
# ║  Protocol Analyzer — central dispatcher                      ║
# ╚══════════════════════════════════════════════════════════════╝

class ProtocolAnalyzer:
    """
    Receives ParsedPackets and dispatches to the correct parser.
    Maintains rolling in-memory logs for the dashboard.
    """

    MAX_LOG = 1000

    def __init__(self):
        self.dns_log:  List[DnsRecord]    = []
        self.tls_log:  List[TlsHandshake] = []
        self.http_log: List[HttpSession]  = []
        self._lock = threading.Lock()

    def analyze(self, pkt) -> dict:
        """
        Returns dict with keys 'dns', 'tls', 'http' for any
        successfully parsed application-layer results.
        """
        results = {}
        if not pkt.src_ip:
            return results

        # DNS — UDP port 53 or 5353 (mDNS)
        if pkt.proto == 17 and pkt.src_port in (53, 5353) or pkt.dst_port in (53, 5353):
            dns = parse_dns(pkt)
            if dns:
                with self._lock:
                    self.dns_log.append(dns)
                    if len(self.dns_log) > self.MAX_LOG:
                        self.dns_log.pop(0)
                results['dns'] = dns

        # TLS — common HTTPS/encrypted ports
        if pkt.proto == 6 and pkt.dst_port in (443, 8443, 853, 993, 995, 465, 587, 636):
            if pkt.payload_len > 50:
                tls = parse_tls(pkt)
                if tls:
                    with self._lock:
                        self.tls_log.append(tls)
                        if len(self.tls_log) > self.MAX_LOG:
                            self.tls_log.pop(0)
                    results['tls'] = tls

        # HTTP — port 80, 8080, 8000 etc.
        if pkt.proto == 6:
            if pkt.dst_port in (80, 8080, 8000) or pkt.src_port in (80, 8080, 8000):
                http = parse_http(pkt)
                if http:
                    with self._lock:
                        self.http_log.append(http)
                        if len(self.http_log) > self.MAX_LOG:
                            self.http_log.pop(0)
                    results['http'] = http

        return results

    def get_summary(self) -> dict:
        with self._lock:
            dns_out = [
                {
                    'ts':         d.ts,
                    'src':        d.src_ip,
                    'query':      d.questions[0] if d.questions else '',
                    'is_response': d.is_response,
                    'rcode':      d.rcode,
                    'answers':    [a.get('value', '') for a in d.answers[:5]],
                }
                for d in reversed(self.dns_log[-100:])
            ]
            tls_out = [
                {
                    'ts':      t.ts,
                    'src':     t.src_ip,
                    'dst':     t.dst_ip,
                    'sni':     t.sni,
                    'version': t.tls_version,
                    'ja3':     t.ja3,
                    'port':    t.dst_port,
                }
                for t in reversed(self.tls_log[-100:])
            ]
            http_out = [
                {
                    'ts':      h.ts,
                    'src':     h.src_ip,
                    'dst':     h.dst_ip,
                    'method':  h.method,
                    'host':    h.host,
                    'path':    h.path,
                    'status':  h.status,
                    'ua':      h.user_agent[:80],
                }
                for h in reversed(self.http_log[-100:])
            ]
        return {'dns': dns_out, 'tls': tls_out, 'http': http_out}
