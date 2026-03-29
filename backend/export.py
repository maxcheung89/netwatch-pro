"""
NetWatch Pro — Export Engine
Generates CSV and JSON exports for devices, alerts, flows, DNS, Suricata.
"""

import csv, io, json, time, logging
from datetime import datetime

log = logging.getLogger(__name__)


def _ts(unix_ts: float) -> str:
    if not unix_ts: return ''
    try:
        return datetime.fromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def devices_to_csv(devices: list) -> str:
    buf = io.StringIO()
    fields = ['ip','mac','hostname','vendor','device_type','os_guess',
              'is_online','confidence','first_seen','last_seen','label']
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for d in devices:
        row = dict(d)
        row['is_online']   = 'Yes' if d.get('is_online') else 'No'
        row['first_seen']  = _ts(d.get('first_seen', 0))
        row['last_seen']   = _ts(d.get('last_seen', 0))
        row['hostname']    = d.get('label') or d.get('hostname') or d.get('dhcp_hostname','')
        w.writerow(row)
    return buf.getvalue()


def alerts_to_csv(alerts: list) -> str:
    buf = io.StringIO()
    fields = ['ts','sev','cat','title','detail','src_ip','dst_ip','mac']
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for a in alerts:
        row = dict(a)
        row['ts'] = _ts(a.get('ts', 0))
        w.writerow(row)
    return buf.getvalue()


def flows_to_csv(flows: list) -> str:
    buf = io.StringIO()
    fields = ['src_ip','src_port','dst_ip','dst_port','proto','app',
              'bytes','pkts','rtt_ms','jitter_ms','duration','established']
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for f in flows:
        w.writerow(f)
    return buf.getvalue()


def suricata_alerts_to_csv(alerts: list) -> str:
    buf = io.StringIO()
    fields = ['timestamp','sev','priority','signature','category',
              'src_ip','src_port','dst_ip','dst_port','proto','app_proto','action']
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for a in alerts:
        row = dict(a)
        row['timestamp'] = _ts(a.get('ts', 0))
        w.writerow(row)
    return buf.getvalue()


def events_to_csv(events: list) -> str:
    buf = io.StringIO()
    fields = ['timestamp','mac','ip','event_type','details']
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for e in events:
        row = dict(e)
        row['timestamp'] = _ts(e.get('timestamp', 0))
        w.writerow(row)
    return buf.getvalue()
