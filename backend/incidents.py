"""
NetWatch Pro — Incident Engine
Collapses repeated/related alerts into meaningful incidents.

Instead of "1,628 ARP Spoofing alerts", you see:
  "Incident: MAC Randomization Storm — Device 10.10.32.16
   42 events over 3 hours | ACTIVE"

Grouping rules:
  - Same alert type + same src_ip within 1 hour → one incident
  - Incident severity = max severity of constituent alerts
  - Incident count tracks how many times it fired
  - Incidents auto-close after 30 min of silence
"""

import time, threading, hashlib, logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional

log = logging.getLogger(__name__)

INCIDENT_WINDOW  = 3600   # seconds — alerts within this window are grouped
INCIDENT_CLOSE   = 1800   # seconds of silence before incident closes
MAX_INCIDENTS    = 200


@dataclass
class Incident:
    id:          str
    title:       str
    device_ip:   str
    device_mac:  str
    category:    str
    severity:    str
    first_seen:  float
    last_seen:   float
    count:       int        = 1
    active:      bool       = True
    dismissed:   bool       = False
    alert_ids:   List[str]  = field(default_factory=list)
    detail:      str        = ''

    def to_dict(self):
        duration = self.last_seen - self.first_seen
        return {
            'id':         self.id,
            'title':      self.title,
            'device_ip':  self.device_ip,
            'device_mac': self.device_mac,
            'category':   self.category,
            'severity':   self.severity,
            'first_seen': self.first_seen,
            'last_seen':  self.last_seen,
            'count':      self.count,
            'active':     self.active,
            'dismissed':  self.dismissed,
            'duration_s': round(duration),
            'detail':     self.detail,
            'alert_count': len(self.alert_ids),
        }


# Severity ordering for comparison
SEV_ORDER = {'info': 0, 'warning': 1, 'high': 2, 'critical': 3}


class IncidentEngine:
    def __init__(self):
        self._lock      = threading.Lock()
        self._incidents: Dict[str, Incident] = {}   # incident_key → Incident
        self._by_id:     Dict[str, Incident] = {}   # incident.id → Incident

        # Start maintenance thread
        threading.Thread(target=self._maintenance_loop, daemon=True,
                         name='incidents').start()

    def _incident_key(self, alert: dict) -> str:
        """Canonical key for grouping: alert_type + src_ip."""
        title  = alert.get('title', '').split('—')[0].strip()  # strip device detail
        src_ip = alert.get('src_ip', '')
        return hashlib.md5(f"{title}|{src_ip}".encode()).hexdigest()[:12]

    def _make_id(self) -> str:
        return 'inc_' + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def ingest(self, alert: dict) -> Optional[Incident]:
        """
        Ingest a single alert dict. Returns the Incident it belongs to.
        Creates a new incident or increments an existing one.
        """
        now = time.time()
        key = self._incident_key(alert)
        sev = alert.get('sev', 'info')

        with self._lock:
            inc = self._incidents.get(key)

            if inc and now - inc.last_seen < INCIDENT_WINDOW:
                # Update existing incident
                inc.last_seen = now
                inc.count    += 1
                inc.active    = True
                # Escalate severity if needed
                if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(inc.severity, 0):
                    inc.severity = sev
                aid = alert.get('id', '')
                if aid and aid not in inc.alert_ids:
                    inc.alert_ids.append(aid)
                    if len(inc.alert_ids) > 500:
                        inc.alert_ids = inc.alert_ids[-500:]
                inc.detail = alert.get('detail', inc.detail)
                return inc
            else:
                # Create new incident
                inc = Incident(
                    id          = self._make_id(),
                    title       = self._clean_title(alert.get('title', 'Unknown Alert')),
                    device_ip   = alert.get('src_ip', ''),
                    device_mac  = alert.get('mac', ''),
                    category    = alert.get('cat', 'security'),
                    severity    = sev,
                    first_seen  = now,
                    last_seen   = now,
                    count       = 1,
                    active      = True,
                    dismissed   = False,
                    alert_ids   = [alert.get('id', '')] if alert.get('id') else [],
                    detail      = alert.get('detail', ''),
                )
                self._incidents[key] = inc
                self._by_id[inc.id]  = inc

                # Cap total incidents
                if len(self._incidents) > MAX_INCIDENTS:
                    # Remove oldest closed incident
                    oldest_key = min(
                        (k for k, v in self._incidents.items() if not v.active),
                        key=lambda k: self._incidents[k].last_seen,
                        default=None,
                    )
                    if oldest_key:
                        del self._by_id[self._incidents[oldest_key].id]
                        del self._incidents[oldest_key]

                return inc

    def _clean_title(self, title: str) -> str:
        """Strip per-device details from alert titles to make good incident titles."""
        # Remove IP addresses and MAC addresses from titles
        import re
        title = re.sub(r'\b\d+\.\d+\.\d+\.\d+\b', 'Device', title)
        title = re.sub(r'\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b', '', title, flags=re.I)
        return title.strip(' |—-')

    def dismiss(self, incident_id: str):
        with self._lock:
            inc = self._by_id.get(incident_id)
            if inc:
                inc.dismissed = True

    def dismiss_all(self):
        with self._lock:
            for inc in self._incidents.values():
                inc.dismissed = True

    def get_incidents(self, active_only=False, include_dismissed=False) -> List[dict]:
        with self._lock:
            incs = list(self._incidents.values())
        result = []
        for inc in sorted(incs, key=lambda x: -x.last_seen):
            if active_only and not inc.active:
                continue
            if not include_dismissed and inc.dismissed:
                continue
            result.append(inc.to_dict())
        return result

    def stats(self) -> dict:
        with self._lock:
            active    = sum(1 for i in self._incidents.values() if i.active and not i.dismissed)
            total     = len(self._incidents)
            by_sev    = {}
            for i in self._incidents.values():
                if i.active and not i.dismissed:
                    by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
        return {'active': active, 'total': total, 'by_severity': by_sev}

    def _maintenance_loop(self):
        """Mark incidents inactive after silence window."""
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                for inc in self._incidents.values():
                    if inc.active and (now - inc.last_seen) > INCIDENT_CLOSE:
                        inc.active = False

    def rebuild_from_alerts(self, alerts: list):
        """Rebuild incident state from existing alert list (called on startup)."""
        # Sort by timestamp ascending so we process in order
        for alert in sorted(alerts, key=lambda a: a.get('ts', 0)):
            self.ingest(alert)
        log.info(f"Incidents rebuilt: {len(self._incidents)} from {len(alerts)} alerts")


incident_engine = IncidentEngine()
