"""
NetWatch Pro — Topology Engine
Builds a graph of IP communication pairs from flow data.
Detects network segments, gateway candidates, and isolated devices.
"""

import time, threading, logging
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import ipaddress

log = logging.getLogger(__name__)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def _is_ignored(ip: str) -> bool:
    """Skip Docker bridges and loopback."""
    if not ip: return True
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback: return True
        # Docker 172.17-31 range
        if str(addr).startswith('172.1'): return True
        if str(addr).startswith('172.2'): return True
        if str(addr).startswith('172.3'): return True
    except Exception:
        return True
    return False

def _subnet(ip: str) -> str:
    """Return /24 subnet string."""
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return 'unknown'


class TopologyEngine:
    """
    Maintains a live communication graph from observed flows.
    Nodes = IP addresses
    Edges = observed communication pairs (with byte/packet counts)
    """

    MAX_NODES = 200
    MAX_EDGES = 1000
    EDGE_TIMEOUT = 300   # Remove edges not seen in 5 minutes

    def __init__(self):
        self._lock   = threading.RLock()
        # node_ip -> {label, first_seen, last_seen, bytes_in, bytes_out, pkt_in, pkt_out, connections}
        self._nodes: Dict[str, dict] = {}
        # (ip_a, ip_b) -> {bytes, pkts, last_seen, ports}
        self._edges: Dict[Tuple, dict] = {}
        # port scan / high-degree detection
        self._degree: Dict[str, Set[str]] = defaultdict(set)

    def add_flow(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 bytes_fwd: int = 0, bytes_rev: int = 0,
                 pkts_fwd: int = 0, pkts_rev: int = 0):
        """Record a flow between two IPs."""
        if _is_ignored(src_ip) or _is_ignored(dst_ip): return
        if src_ip == dst_ip: return

        now = time.time()

        with self._lock:
            # Add/update nodes
            for ip in (src_ip, dst_ip):
                if ip not in self._nodes:
                    if len(self._nodes) >= self.MAX_NODES: continue
                    self._nodes[ip] = {
                        'ip':          ip,
                        'first_seen':  now,
                        'last_seen':   now,
                        'bytes_in':    0,
                        'bytes_out':   0,
                        'pkt_in':      0,
                        'pkt_out':     0,
                        'connections': 0,
                        'subnet':      _subnet(ip),
                        'is_private':  _is_private(ip),
                    }
                else:
                    self._nodes[ip]['last_seen'] = now

            if src_ip in self._nodes:
                self._nodes[src_ip]['bytes_out']  += bytes_fwd
                self._nodes[src_ip]['pkt_out']    += pkts_fwd
            if dst_ip in self._nodes:
                self._nodes[dst_ip]['bytes_in']   += bytes_rev
                self._nodes[dst_ip]['pkt_in']     += pkts_rev

            # Add/update edge (canonical order)
            key = (min(src_ip, dst_ip), max(src_ip, dst_ip))
            if key not in self._edges:
                if len(self._edges) >= self.MAX_EDGES:
                    # Evict oldest edge
                    oldest = min(self._edges, key=lambda k: self._edges[k]['last_seen'])
                    del self._edges[oldest]
                self._edges[key] = {
                    'src': src_ip, 'dst': dst_ip,
                    'bytes': 0, 'pkts': 0,
                    'ports': set(),
                    'first_seen': now, 'last_seen': now,
                }

            e = self._edges[key]
            e['bytes']    += bytes_fwd + bytes_rev
            e['pkts']     += pkts_fwd  + pkts_rev
            e['last_seen'] = now
            if dst_port: e['ports'].add(dst_port)

            # Degree tracking
            self._degree[src_ip].add(dst_ip)
            self._degree[dst_ip].add(src_ip)
            if src_ip in self._nodes:
                self._nodes[src_ip]['connections'] = len(self._degree[src_ip])
            if dst_ip in self._nodes:
                self._nodes[dst_ip]['connections'] = len(self._degree[dst_ip])

    def add_packet(self, pkt):
        """Feed directly from capture engine packets."""
        if not pkt.src_ip or not pkt.dst_ip: return
        self.add_flow(
            pkt.src_ip, pkt.dst_ip,
            pkt.src_port, pkt.dst_port,
            bytes_fwd=len(pkt.raw) if pkt.raw else pkt.payload_len or 0,
        )

    def _cleanup(self):
        """Remove stale edges and orphaned nodes."""
        now = time.time()
        cutoff = now - self.EDGE_TIMEOUT
        with self._lock:
            stale_edges = [k for k, e in self._edges.items() if e['last_seen'] < cutoff]
            for k in stale_edges:
                del self._edges[k]
            # Remove nodes with no recent edges
            active_ips = set()
            for a, b in self._edges:
                active_ips.add(a); active_ips.add(b)
            stale_nodes = [ip for ip in self._nodes if ip not in active_ips]
            for ip in stale_nodes:
                del self._nodes[ip]
                self._degree.pop(ip, None)

    def get_graph(self, device_lookup: Dict[str, str] = None) -> dict:
        """
        Return graph data for the frontend.
        device_lookup: mac->label dict to enrich node labels.
        """
        self._cleanup()
        with self._lock:
            nodes = []
            for ip, n in self._nodes.items():
                label = (device_lookup or {}).get(ip, ip)
                # Classify node role
                role = 'endpoint'
                conns = n.get('connections', 0)
                if conns >= 10:
                    role = 'hub'
                elif not n.get('is_private', True):
                    role = 'external'
                elif conns == 0:
                    role = 'isolated'

                nodes.append({
                    'id':         ip,
                    'label':      label,
                    'ip':         ip,
                    'subnet':     n['subnet'],
                    'role':       role,
                    'connections':conns,
                    'bytes_in':   n['bytes_in'],
                    'bytes_out':  n['bytes_out'],
                    'last_seen':  n['last_seen'],
                    'is_private': n['is_private'],
                })

            edges = []
            for (a, b), e in self._edges.items():
                edges.append({
                    'source':     e['src'],
                    'target':     e['dst'],
                    'bytes':      e['bytes'],
                    'pkts':       e['pkts'],
                    'ports':      sorted(list(e['ports']))[:10],
                    'last_seen':  e['last_seen'],
                    'width':      max(1, min(8, int(e['bytes'] / 50000))),
                })

            # Subnet groups
            subnets = defaultdict(list)
            for n in nodes:
                subnets[n['subnet']].append(n['ip'])

        return {
            'nodes':   sorted(nodes, key=lambda n: -n['connections']),
            'edges':   sorted(edges, key=lambda e: -e['bytes'])[:500],
            'subnets': {k: v for k, v in subnets.items()},
            'stats': {
                'node_count': len(nodes),
                'edge_count': len(edges),
                'subnet_count': len(subnets),
            }
        }

    def get_device_connections(self, ip: str) -> dict:
        """Get all connections for a specific IP."""
        with self._lock:
            connected = []
            for (a, b), e in self._edges.items():
                if a == ip or b == ip:
                    peer = b if a == ip else a
                    connected.append({
                        'peer':      peer,
                        'bytes':     e['bytes'],
                        'pkts':      e['pkts'],
                        'ports':     sorted(list(e['ports']))[:10],
                        'last_seen': e['last_seen'],
                        'direction': 'out' if e['src'] == ip else 'in',
                    })
            node = self._nodes.get(ip, {})
        return {
            'ip':          ip,
            'connections': sorted(connected, key=lambda x: -x['bytes']),
            'node':        node,
        }
