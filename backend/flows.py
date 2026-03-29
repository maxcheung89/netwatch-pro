"""
╔══════════════════════════════════════════════════════════════╗
║  NetWatch Pro — Layer 4: Traffic Analysis & Flow Monitoring  ║
║  Per-flow byte/packet counters, TCP RTT/jitter,              ║
║  bandwidth series, top talkers, protocol distribution        ║
╚══════════════════════════════════════════════════════════════╝
"""

import time, threading, logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

log = logging.getLogger(__name__)

FlowKey = Tuple  # (src_ip, src_port, dst_ip, dst_port, proto)


# ╔══════════════════════════════════════════════════════════════╗
# ║  Flow Record                                                  ║
# ╚══════════════════════════════════════════════════════════════╝

@dataclass
class Flow:
    key:        tuple
    src_ip:     str
    dst_ip:     str
    src_port:   int
    dst_port:   int
    proto:      int
    proto_name: str
    app_proto:  str = ''

    # Byte / packet counters (bidirectional)
    pkts_fwd:   int = 0
    pkts_rev:   int = 0
    bytes_fwd:  int = 0
    bytes_rev:  int = 0

    # Timestamps
    start_ts:   float = field(default_factory=time.time)
    last_ts:    float = field(default_factory=time.time)

    # TCP state
    established: bool  = False
    fin_seen:    bool  = False
    _syn_ts:     float = 0.0

    # RTT samples (milliseconds)
    rtt_samples: deque = field(default_factory=lambda: deque(maxlen=20))

    @property
    def duration(self)    -> float: return self.last_ts - self.start_ts
    @property
    def total_bytes(self) -> int:   return self.bytes_fwd + self.bytes_rev
    @property
    def total_pkts(self)  -> int:   return self.pkts_fwd  + self.pkts_rev

    @property
    def rtt_avg_ms(self) -> float:
        return sum(self.rtt_samples) / len(self.rtt_samples) if self.rtt_samples else 0.0

    @property
    def jitter_ms(self) -> float:
        s = self.rtt_samples
        if len(s) < 2: return 0.0
        diffs = [abs(s[i] - s[i-1]) for i in range(1, len(s))]
        return sum(diffs) / len(diffs)

    def to_dict(self) -> dict:
        return {
            'src_ip':     self.src_ip,
            'dst_ip':     self.dst_ip,
            'src_port':   self.src_port,
            'dst_port':   self.dst_port,
            'proto':      self.proto_name,
            'app':        self.app_proto,
            'pkts':       self.total_pkts,
            'bytes':      self.total_bytes,
            'bytes_fwd':  self.bytes_fwd,
            'bytes_rev':  self.bytes_rev,
            'duration':   round(self.duration, 2),
            'rtt_ms':     round(self.rtt_avg_ms, 2),
            'jitter_ms':  round(self.jitter_ms,  2),
            'last_seen':  self.last_ts,
            'established':self.established,
        }


# ╔══════════════════════════════════════════════════════════════╗
# ║  Bandwidth Series (rolling 1-second buckets)                 ║
# ╚══════════════════════════════════════════════════════════════╝

class BandwidthSeries:
    """
    Maintains a rolling window of 1-second bandwidth/pps buckets.
    Thread-safe. Default window = 300 seconds (5 minutes).
    """

    def __init__(self, window: int = 300):
        self._window        = window
        self._buckets: deque = deque(maxlen=window)  # (ts, bytes, pkts)
        self._cur_ts:   int  = int(time.time())
        self._cur_bytes: int = 0
        self._cur_pkts:  int = 0
        self._lock = threading.Lock()

    def add(self, nbytes: int, npkts: int = 1):
        now = int(time.time())
        with self._lock:
            if now != self._cur_ts:
                # Flush current bucket
                self._buckets.append((self._cur_ts, self._cur_bytes, self._cur_pkts))
                # Fill any time gaps with zeros
                for gap in range(self._cur_ts + 1, now):
                    self._buckets.append((gap, 0, 0))
                self._cur_ts    = now
                self._cur_bytes = 0
                self._cur_pkts  = 0
            self._cur_bytes += nbytes
            self._cur_pkts  += npkts

    def series(self, last_n: int = 60) -> List[dict]:
        with self._lock:
            data = list(self._buckets)[-last_n:]
        return [{'ts': t, 'bps': b * 8, 'pps': p} for t, b, p in data]

    def current_bps(self) -> float:
        with self._lock:
            if not self._buckets: return 0.0
            return self._buckets[-1][1] * 8

    def current_pps(self) -> float:
        with self._lock:
            if not self._buckets: return 0.0
            return self._buckets[-1][2]


# ╔══════════════════════════════════════════════════════════════╗
# ║  Flow Monitor                                                ║
# ╚══════════════════════════════════════════════════════════════╝

class FlowMonitor:
    """
    Maintains bidirectional flow table with:
    - Per-flow byte/packet counters
    - TCP RTT via SYN / SYN-ACK timing
    - Per-IP bandwidth series
    - Global bandwidth series
    - Protocol distribution counters
    - Automatic stale-flow expiry
    """

    def __init__(self, flow_timeout: int = 120):
        self._flows:    Dict[tuple, Flow] = {}
        self._lock      = threading.RLock()
        self._timeout   = flow_timeout

        # Bandwidth tracking
        self._global_bw = BandwidthSeries()
        self._ip_bw:    Dict[str, BandwidthSeries] = defaultdict(BandwidthSeries)

        # Protocol distribution
        self._proto_bytes: Dict[str, int] = defaultdict(int)
        self._proto_pkts:  Dict[str, int] = defaultdict(int)

        # Start cleanup
        threading.Thread(target=self._cleanup_loop, daemon=True, name='nw-flow-gc').start()

    # ── Canonical flow key ─────────────────────────────────────

    @staticmethod
    def _key(pkt) -> Optional[tuple]:
        if not pkt.src_ip or not pkt.dst_ip: return None
        a = (pkt.src_ip, pkt.src_port)
        b = (pkt.dst_ip, pkt.dst_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return (lo[0], lo[1], hi[0], hi[1], pkt.proto)

    # ── Packet processing ──────────────────────────────────────

    def process_packet(self, pkt, app_proto: str = ''):
        if not pkt.src_ip:
            return

        pkt_len = len(pkt.raw) if pkt.raw else (pkt.payload_len or 64)

        # Global + per-IP bandwidth
        self._global_bw.add(pkt_len)
        self._ip_bw[pkt.src_ip].add(pkt_len)

        # Protocol label
        label = app_proto or pkt.proto_name
        with self._lock:
            self._proto_bytes[label] += pkt_len
            self._proto_pkts[label]  += 1

        fkey = self._key(pkt)
        if not fkey: return

        with self._lock:
            flow       = self._flows.get(fkey)
            is_forward = (pkt.src_ip == fkey[0])

            if flow is None:
                from protocol import port_to_proto
                ap = (app_proto
                      or port_to_proto(pkt.dst_port)
                      or port_to_proto(pkt.src_port))
                flow = Flow(
                    key=fkey,
                    src_ip=fkey[0], src_port=fkey[1],
                    dst_ip=fkey[2], dst_port=fkey[3],
                    proto=pkt.proto,
                    proto_name=pkt.proto_name,
                    app_proto=ap,
                    start_ts=pkt.ts,
                    last_ts=pkt.ts,
                )
                self._flows[fkey] = flow

            flow.last_ts = pkt.ts
            if is_forward:
                flow.pkts_fwd  += 1
                flow.bytes_fwd += pkt_len
            else:
                flow.pkts_rev  += 1
                flow.bytes_rev += pkt_len

            # TCP RTT measurement via SYN timing
            if pkt.proto == 6:
                SYN = 0x02; ACK = 0x10; FIN = 0x01
                if (pkt.flags & SYN) and not (pkt.flags & ACK):
                    flow._syn_ts = pkt.ts
                elif (pkt.flags & SYN) and (pkt.flags & ACK):
                    if flow._syn_ts > 0:
                        rtt_ms = (pkt.ts - flow._syn_ts) * 1000.0
                        if 0.0 < rtt_ms < 10_000.0:
                            flow.rtt_samples.append(rtt_ms)
                        flow._syn_ts = 0.0
                    flow.established = True
                elif pkt.flags & FIN:
                    flow.fin_seen = True

    # ── Cleanup ────────────────────────────────────────────────

    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            cutoff = time.time() - self._timeout
            with self._lock:
                stale = [k for k, f in self._flows.items() if f.last_ts < cutoff]
                for k in stale:
                    del self._flows[k]
            if stale:
                log.debug(f"Expired {len(stale)} stale flows")

    # ── Public API ─────────────────────────────────────────────

    def get_flows(self, limit: int = 300, sort_by: str = 'bytes') -> List[dict]:
        with self._lock:
            flows = list(self._flows.values())
        key_fn = (lambda f: f.total_bytes) if sort_by == 'bytes' else (lambda f: f.last_ts)
        flows.sort(key=key_fn, reverse=True)
        return [f.to_dict() for f in flows[:limit]]

    def get_top_talkers(self, n: int = 20) -> List[dict]:
        with self._lock:
            ip_bytes = {}
            for ip, bw in self._ip_bw.items():
                total = sum(b[1] for b in bw._buckets) + bw._cur_bytes
                ip_bytes[ip] = total
        top = sorted(ip_bytes.items(), key=lambda x: -x[1])[:n]
        return [{'ip': ip, 'bytes': b, 'mbps': round(b * 8 / 1_000_000, 4)} for ip, b in top]

    def get_bandwidth_series(self, last_n: int = 60) -> List[dict]:
        return self._global_bw.series(last_n)

    def get_ip_bandwidth(self, ip: str, last_n: int = 60) -> List[dict]:
        if ip not in self._ip_bw: return []
        return self._ip_bw[ip].series(last_n)

    def get_protocol_distribution(self) -> List[dict]:
        with self._lock:
            total = sum(self._proto_bytes.values()) or 1
            items = sorted(self._proto_bytes.items(), key=lambda x: -x[1])[:16]
        return [
            {
                'proto': p,
                'bytes': b,
                'pkts':  self._proto_pkts[p],
                'pct':   round(b / total * 100, 1),
            }
            for p, b in items
        ]

    def get_live_stats(self) -> dict:
        with self._lock:
            flow_count = len(self._flows)
        return {
            'bps':          round(self._global_bw.current_bps(), 0),
            'pps':          round(self._global_bw.current_pps(), 0),
            'active_flows': flow_count,
            'tracked_ips':  len(self._ip_bw),
        }

    def get_ip_stats(self, ip: str) -> dict:
        series = self.get_ip_bandwidth(ip)
        with self._lock:
            ip_flows = [
                f.to_dict() for f in self._flows.values()
                if f.src_ip == ip or f.dst_ip == ip
            ]
        return {
            'ip':     ip,
            'series': series,
            'flows':  ip_flows[:100],
        }
