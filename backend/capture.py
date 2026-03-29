"""
╔══════════════════════════════════════════════════════════════╗
║  NetWatch Pro — Layer 1: Packet Capture Engine               ║
║  Raw AF_PACKET socket, promiscuous mode, ring buffers,       ║
║  multi-interface, L2→L4 binary parser                        ║
╚══════════════════════════════════════════════════════════════╝
"""

import os, time, struct, socket, threading, logging, queue, fcntl
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Callable, List

log = logging.getLogger(__name__)

# ── EtherType / Protocol constants ────────────────────────────
ETH_P_ALL   = 0x0003
ETH_P_IP    = 0x0800
ETH_P_ARP   = 0x0806
ETH_P_8021Q = 0x8100   # VLAN tagged
ETH_P_IPV6  = 0x86DD
IPPROTO_TCP  = 6
IPPROTO_UDP  = 17
IPPROTO_ICMP = 1


# ── Data structures ────────────────────────────────────────────

@dataclass
class RawPacket:
    ts: float
    iface: str
    data: bytes
    length: int


@dataclass
class ParsedPacket:
    ts: float
    iface: str
    # Layer 2
    src_mac: str = ''
    dst_mac: str = ''
    eth_type: int = 0
    vlan_id: int = 0
    # Layer 3
    src_ip: str = ''
    dst_ip: str = ''
    ttl: int = 0
    proto: int = 0
    ip_len: int = 0
    # Layer 4
    src_port: int = 0
    dst_port: int = 0
    flags: int = 0
    seq: int = 0
    ack: int = 0
    payload_len: int = 0
    # ARP fields
    arp_op: int = 0
    arp_sender_mac: str = ''
    arp_sender_ip: str = ''
    arp_target_ip: str = ''
    # Raw data
    raw: bytes = field(default_factory=bytes)

    @property
    def proto_name(self) -> str:
        return {
            0:  'HOPOPT', 1:  'ICMP',   2:  'IGMP',   6:  'TCP',
            17: 'UDP',    41: 'IPv6',   47: 'GRE',    50: 'ESP',
            51: 'AH',     58: 'ICMPv6', 89: 'OSPF',   132:'SCTP',
        }.get(self.proto, f'IP/{self.proto}')

    @property
    def flow_key(self):
        if self.src_ip and self.dst_ip:
            a = (self.src_ip, self.src_port)
            b = (self.dst_ip, self.dst_port)
            return (min(a, b), max(a, b), self.proto)
        return None

    @property
    def is_arp(self) -> bool:
        return self.eth_type == ETH_P_ARP

    @property
    def is_tcp_syn(self) -> bool:
        return self.proto == IPPROTO_TCP and bool(self.flags & 0x02) and not bool(self.flags & 0x10)

    @property
    def is_tcp_syn_ack(self) -> bool:
        return self.proto == IPPROTO_TCP and bool(self.flags & 0x02) and bool(self.flags & 0x10)


# ── Ring Buffer ────────────────────────────────────────────────

class RingBuffer:
    """
    Fixed-capacity ring buffer for packets.
    Thread-safe. Oldest entry evicted when full (zero packet loss strategy:
    drop oldest rather than newest).
    """
    def __init__(self, maxlen: int = 200_000):
        self._buf = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self.dropped = 0
        self.total = 0

    def push(self, pkt):
        with self._lock:
            self.total += 1
            if len(self._buf) == self._buf.maxlen:
                self.dropped += 1
            self._buf.append(pkt)

    def snapshot(self, n: int = None) -> list:
        with self._lock:
            buf = list(self._buf)
        return buf[-n:] if n else buf

    def since(self, ts: float) -> list:
        with self._lock:
            return [p for p in self._buf if p.ts >= ts]

    def clear(self):
        with self._lock:
            self._buf.clear()

    def __len__(self) -> int:
        return len(self._buf)


# ── Packet Parser ──────────────────────────────────────────────

def _mac(raw: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in raw)

def _ip4(raw: bytes) -> str:
    return '.'.join(str(b) for b in raw)


def parse_packet(raw_pkt: RawPacket) -> Optional[ParsedPacket]:
    """
    Parse raw Ethernet frame into a structured ParsedPacket.
    Handles: Ethernet II, VLAN 802.1Q, IPv4, ARP, TCP, UDP, ICMP.
    """
    data = raw_pkt.data
    if len(data) < 14:
        return None

    p = ParsedPacket(ts=raw_pkt.ts, iface=raw_pkt.iface, raw=data)
    p.dst_mac  = _mac(data[0:6])
    p.src_mac  = _mac(data[6:12])
    eth_type   = struct.unpack('!H', data[12:14])[0]
    p.eth_type = eth_type
    offset     = 14

    # Handle VLAN 802.1Q tag
    if eth_type == ETH_P_8021Q and len(data) >= offset + 4:
        vlan_tag   = struct.unpack('!H', data[offset:offset+2])[0]
        p.vlan_id  = vlan_tag & 0x0FFF
        eth_type   = struct.unpack('!H', data[offset+2:offset+4])[0]
        p.eth_type = eth_type
        offset    += 4

    # ARP
    if eth_type == ETH_P_ARP:
        if len(data) < offset + 28:
            return p
        arp = data[offset:]
        p.arp_op         = struct.unpack('!H', arp[6:8])[0]
        p.arp_sender_mac = _mac(arp[8:14])
        p.arp_sender_ip  = _ip4(arp[14:18])
        p.arp_target_ip  = _ip4(arp[24:28])
        # Mirror as L3 src for easier processing
        p.src_mac = p.arp_sender_mac
        p.src_ip  = p.arp_sender_ip
        return p

    # IPv4
    if eth_type == ETH_P_IP:
        if len(data) < offset + 20:
            return p
        ip     = data[offset:]
        ihl    = (ip[0] & 0x0F) * 4
        p.ip_len    = struct.unpack('!H', ip[2:4])[0]
        p.ttl       = ip[8]
        p.proto     = ip[9]
        p.src_ip    = _ip4(ip[12:16])
        p.dst_ip    = _ip4(ip[16:20])
        l4 = ip[ihl:]
        p.payload_len = len(l4)

        if p.proto == IPPROTO_TCP and len(l4) >= 20:
            p.src_port = struct.unpack('!H', l4[0:2])[0]
            p.dst_port = struct.unpack('!H', l4[2:4])[0]
            p.seq      = struct.unpack('!I', l4[4:8])[0]
            p.ack      = struct.unpack('!I', l4[8:12])[0]
            p.flags    = struct.unpack('!H', l4[12:14])[0] & 0x01FF

        elif p.proto == IPPROTO_UDP and len(l4) >= 8:
            p.src_port = struct.unpack('!H', l4[0:2])[0]
            p.dst_port = struct.unpack('!H', l4[2:4])[0]

        return p

    return p  # Unknown EtherType — return partial


# ── Capture Engine ─────────────────────────────────────────────

class CaptureEngine:
    """
    Multi-interface raw packet capture engine.

    Features:
    - AF_PACKET raw socket (no libpcap dependency)
    - Promiscuous mode via SIOCGIFFLAGS/SIOCSIFFLAGS
    - Dual ring buffers (raw + parsed)
    - Lock-free queue between capture and parser threads
    - Configurable ring size and parser thread count
    - Per-interface capture threads
    """

    def __init__(
        self,
        interfaces: List[str] = None,
        ring_size: int = 200_000,
        callback: Callable = None,
        parser_threads: int = 2,
    ):
        self.interfaces    = interfaces or self._detect_interfaces()
        self.ring_raw      = RingBuffer(ring_size)
        self.ring_parsed   = RingBuffer(ring_size)
        self.callback      = callback
        self._parser_count = parser_threads
        self._stop         = threading.Event()
        self._queue        = queue.Queue(maxsize=100_000)
        self._threads      = []
        self._stats = {
            'captured': 0,
            'parsed':   0,
            'dropped':  0,
            'bytes':    0,
            'start_ts': time.time(),
        }

    # ── Interface detection ────────────────────────────────────

    @staticmethod
    def _detect_interfaces() -> List[str]:
        """
        Return the primary physical LAN interface only.
        Priority: use CAPTURE_INTERFACES env var if set, otherwise
        pick the first UP ethernet interface (eth*, en*).
        Explicitly skips: lo, wlan*, docker*, veth*, br-*, virbr*
        """
        import os, subprocess, re
        # Allow manual override via environment variable
        env_ifaces = os.environ.get('CAPTURE_INTERFACES', '').strip()
        if env_ifaces:
            return [i.strip() for i in env_ifaces.split(',') if i.strip()]

        SKIP_PREFIXES = ('lo', 'wlan', 'docker', 'veth', 'br-', 'virbr',
                         'tun', 'tap', 'dummy', 'bond', 'ovs')
        try:
            out = subprocess.run(['ip', '-o', 'link', 'show'],
                                 capture_output=True, text=True).stdout
            # Prefer UP interfaces
            up_ifaces, all_ifaces = [], []
            for line in out.splitlines():
                m = re.match(r'\d+: (\S+?)[@:]', line)
                if not m: continue
                name = m.group(1)
                if any(name.startswith(p) for p in SKIP_PREFIXES): continue
                all_ifaces.append(name)
                if 'UP' in line and 'LOWER_UP' in line:
                    up_ifaces.append(name)
            result = up_ifaces or all_ifaces
            if result:
                log.info(f"Auto-detected capture interfaces: {result}")
                return result
        except Exception as e:
            log.warning(f"Interface detection error: {e}")
        log.info("Falling back to eth0")
        return ['eth0']

    # ── Promiscuous mode ───────────────────────────────────────

    @staticmethod
    def _set_promisc(sock_fd: int, iface: str, enable: bool = True):
        SIOCGIFFLAGS = 0x8913
        SIOCSIFFLAGS = 0x8914
        IFF_PROMISC  = 0x100
        try:
            ifr = struct.pack('16sH', iface.encode()[:15], 0) + b'\x00' * 22
            flags = struct.unpack('16sH', fcntl.ioctl(sock_fd, SIOCGIFFLAGS, ifr)[:18])[1]
            new_flags = (flags | IFF_PROMISC) if enable else (flags & ~IFF_PROMISC)
            ifr = struct.pack('16sH', iface.encode()[:15], new_flags) + b'\x00' * 22
            fcntl.ioctl(sock_fd, SIOCSIFFLAGS, ifr)
            log.info(f"Promiscuous mode {'ON' if enable else 'OFF'}: {iface}")
        except Exception as e:
            log.warning(f"Promisc failed on {iface}: {e}")

    # ── Capture thread (one per interface) ────────────────────

    def _capture_iface(self, iface: str):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            s.bind((iface, 0))
            self._set_promisc(s.fileno(), iface, True)
            s.settimeout(1.0)
            log.info(f"Capturing on interface: {iface}")

            while not self._stop.is_set():
                try:
                    data, _ = s.recvfrom(65535)
                    ts  = time.time()
                    raw = RawPacket(ts=ts, iface=iface, data=data, length=len(data))
                    self.ring_raw.push(raw)
                    self._stats['captured'] += 1
                    self._stats['bytes']    += len(data)
                    try:
                        self._queue.put_nowait(raw)
                    except queue.Full:
                        self._stats['dropped'] += 1
                except socket.timeout:
                    continue
                except OSError as e:
                    log.debug(f"recv error [{iface}]: {e}")
                    time.sleep(0.1)

            # Restore non-promisc on shutdown
            self._set_promisc(s.fileno(), iface, False)
            s.close()

        except PermissionError:
            log.error(f"Permission denied: raw socket on {iface} — need NET_RAW capability")
        except Exception as e:
            log.error(f"Capture thread failed [{iface}]: {e}")

    # ── Parser worker thread ───────────────────────────────────

    def _parser_worker(self):
        while not self._stop.is_set():
            try:
                raw = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                pkt = parse_packet(raw)
                if pkt:
                    self.ring_parsed.push(pkt)
                    self._stats['parsed'] += 1
                    if self.callback:
                        self.callback(pkt)
            except Exception as e:
                log.debug(f"Parser error: {e}")

    # ── Public API ─────────────────────────────────────────────

    def start(self):
        self._stop.clear()
        # Parser threads
        for _ in range(self._parser_count):
            t = threading.Thread(target=self._parser_worker, daemon=True, name='nw-parser')
            t.start()
            self._threads.append(t)
        # Capture threads
        for iface in self.interfaces:
            t = threading.Thread(target=self._capture_iface, args=(iface,),
                                 daemon=True, name=f'nw-cap-{iface}')
            t.start()
            self._threads.append(t)
        log.info(f"CaptureEngine started — interfaces: {self.interfaces}")

    def stop(self):
        self._stop.set()
        log.info("CaptureEngine stopped")

    def get_stats(self) -> dict:
        uptime   = time.time() - self._stats['start_ts']
        captured = self._stats['captured']
        return {
            **self._stats,
            'uptime_s':   round(uptime, 1),
            'pps':        round(captured / max(uptime, 1), 1),
            'mbps':       round((self._stats['bytes'] * 8) / max(uptime, 1) / 1_000_000, 4),
            'ring_size':  len(self.ring_parsed),
            'queue_size': self._queue.qsize(),
            'interfaces': self.interfaces,
        }

    def recent_packets(self, seconds: float = 5.0, max_pkts: int = 500) -> list:
        since = time.time() - seconds
        pkts  = self.ring_parsed.since(since)
        return pkts[-max_pkts:]
