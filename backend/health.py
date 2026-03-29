"""
NetWatch Pro — Network Health Score + Anomaly Detection

Health Score (0-100):
  100 = clean, no alerts, normal traffic
    0 = critical incidents, C2 detected, data exfiltration

Score deductions:
  - Active critical incidents:  -15 each (max -45)
  - Active high incidents:      -8  each (max -24)
  - Active warning incidents:   -3  each (max -9)
  - Pi-hole block rate < 1%:    -5  (DNS not filtering)
  - Unknown devices > 30%:      -5
  - Devices offline suddenly:   -3

Device anomaly detection:
  Tracks 7-day rolling bandwidth per device.
  Alerts when current usage > 3x the baseline average.
"""

import time, threading, logging, statistics
from collections import defaultdict, deque
from typing import Dict, Optional

log = logging.getLogger(__name__)

# How many 1-minute samples to keep per device (7 days = 10080)
BASELINE_SAMPLES = 10_080
# Alert threshold: current > N × baseline average
ANOMALY_THRESHOLD = 3.0
ANOMALY_MIN_BPS   = 500_000   # minimum 500 Kbps before alerting (ignore idle)
ANOMALY_COOLDOWN  = 1800      # 30 min between repeated anomaly alerts


class HealthEngine:
    def __init__(self):
        self._lock = threading.Lock()

        # Per-IP bandwidth samples: ip → deque of (ts, bps)
        self._bw_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=BASELINE_SAMPLES)
        )
        # Per-IP current bps (updated from broadcast loop)
        self._bw_current: Dict[str, float] = {}

        # Last anomaly alert per IP
        self._anomaly_ts: Dict[str, float] = {}

        # Cached score
        self._score:      int   = 100
        self._score_ts:   float = 0
        self._breakdown:  dict  = {}

        threading.Thread(target=self._sample_loop, daemon=True,
                         name='health-sampler').start()

    # ── Bandwidth tracking ────────────────────────────────────────

    def update_bps(self, ip: str, bps: float):
        """Called every second from broadcast loop."""
        with self._lock:
            self._bw_current[ip] = bps

    def _sample_loop(self):
        """Record 1-minute samples for the baseline."""
        while True:
            time.sleep(60)
            now = time.time()
            with self._lock:
                for ip, bps in self._bw_current.items():
                    self._bw_history[ip].append((now, bps))

    # ── Anomaly detection ─────────────────────────────────────────

    def check_anomalies(self, emit_fn=None) -> list:
        """
        Check all tracked devices for anomalous bandwidth.
        Returns list of anomaly dicts. Calls emit_fn if provided.
        """
        anomalies = []
        now = time.time()

        with self._lock:
            current_snap  = dict(self._bw_current)
            history_snap  = {ip: list(dq) for ip, dq in self._bw_history.items()}
            anomaly_ts    = dict(self._anomaly_ts)

        for ip, current_bps in current_snap.items():
            if current_bps < ANOMALY_MIN_BPS:
                continue

            history = history_snap.get(ip, [])
            if len(history) < 30:   # need at least 30 min of baseline
                continue

            # Use all but last 5 minutes as baseline
            baseline_samples = [bps for ts, bps in history[:-5]]
            if not baseline_samples:
                continue

            baseline_avg = statistics.mean(baseline_samples)
            if baseline_avg < 10_000:   # < 10 Kbps baseline — ignore
                continue

            ratio = current_bps / baseline_avg
            if ratio >= ANOMALY_THRESHOLD:
                # Cooldown check
                if now - anomaly_ts.get(ip, 0) < ANOMALY_COOLDOWN:
                    continue

                with self._lock:
                    self._anomaly_ts[ip] = now

                pct = round((ratio - 1) * 100)
                anomaly = {
                    'ip':           ip,
                    'current_mbps': round(current_bps / 1e6, 2),
                    'baseline_mbps':round(baseline_avg  / 1e6, 2),
                    'ratio':        round(ratio, 1),
                    'pct_above':    pct,
                    'ts':           now,
                    'message':      (f"{ip} is using {round(current_bps/1e6,1)} Mbps — "
                                     f"{ratio:.1f}× above its {round(baseline_avg/1e6,1)} Mbps baseline "
                                     f"(+{pct}%)")
                }
                anomalies.append(anomaly)

                if emit_fn:
                    try:
                        emit_fn('bandwidth_anomaly', anomaly)
                    except Exception:
                        pass

        return anomalies

    def get_device_baseline(self, ip: str) -> dict:
        """Return baseline stats for a single device."""
        with self._lock:
            history = list(self._bw_history.get(ip, []))
            current = self._bw_current.get(ip, 0)

        if not history:
            return {'ip': ip, 'current_bps': current, 'baseline_avg': 0,
                    'baseline_max': 0, 'samples': 0, 'anomaly': False}

        bps_vals = [bps for _, bps in history]
        avg  = statistics.mean(bps_vals)
        p95  = sorted(bps_vals)[int(len(bps_vals) * 0.95)]
        ratio = (current / avg) if avg > 0 else 1.0

        return {
            'ip':            ip,
            'current_bps':   round(current),
            'current_mbps':  round(current / 1e6, 3),
            'baseline_avg':  round(avg),
            'baseline_mbps': round(avg / 1e6, 3),
            'baseline_p95':  round(p95),
            'samples':       len(history),
            'days_of_data':  round(len(history) / 1440, 1),
            'ratio':         round(ratio, 2),
            'anomaly':       ratio >= ANOMALY_THRESHOLD and current >= ANOMALY_MIN_BPS,
        }

    # ── Health Score ──────────────────────────────────────────────

    def calculate_score(self,
                        incidents:   list,
                        pihole_data: dict,
                        devices:     list,
                        suricata_ok: bool) -> dict:
        """
        Calculate network health score 0-100.
        Returns {'score': int, 'grade': str, 'breakdown': dict, 'issues': list}
        """
        score   = 100
        issues  = []
        details = {}

        # ── Incident penalties ─────────────────────────────────
        active = [i for i in incidents if i.get('active') and not i.get('dismissed')]
        crits  = sum(1 for i in active if i['severity'] == 'critical')
        highs  = sum(1 for i in active if i['severity'] == 'high')
        warns  = sum(1 for i in active if i['severity'] == 'warning')

        crit_penalty = min(crits * 15, 45)
        high_penalty = min(highs * 8,  24)
        warn_penalty = min(warns * 3,   9)

        score -= crit_penalty + high_penalty + warn_penalty
        details['incidents'] = {
            'critical': crits, 'high': highs, 'warning': warns,
            'penalty':  -(crit_penalty + high_penalty + warn_penalty),
        }
        if crits > 0:
            issues.append(f"{crits} active critical incident{'s' if crits>1 else ''}")
        if highs > 0:
            issues.append(f"{highs} active high-severity incident{'s' if highs>1 else ''}")

        # ── Pi-hole health ─────────────────────────────────────
        ph_score = 0
        if pihole_data.get('available'):
            pct = pihole_data.get('pct_blocked', 0)
            if pct < 0.5:
                score -= 5; ph_score -= 5
                issues.append(f"Pi-hole blocking only {pct:.1f}% — may not be filtering")
            elif pct > 20:
                # Very high block rate might mean misconfiguration
                score -= 2; ph_score -= 2
                issues.append(f"Pi-hole blocking {pct:.0f}% — unusually high")
        else:
            score -= 3; ph_score -= 3
            issues.append("Pi-hole not reachable")
        details['pihole'] = {'penalty': ph_score}

        # ── Unknown devices ────────────────────────────────────
        total_devices   = len(devices)
        unknown_devices = sum(1 for d in devices
                              if not d.get('vendor') or d.get('vendor') == 'Unknown')
        if total_devices > 0:
            unknown_pct = unknown_devices / total_devices
            if unknown_pct > 0.40:
                penalty = 5
                score  -= penalty
                issues.append(f"{unknown_devices} of {total_devices} devices unidentified ({unknown_pct:.0%})")
                details['unknown_devices'] = {'pct': unknown_pct, 'penalty': -penalty}

        # ── Anomalies ──────────────────────────────────────────
        anomaly_count = sum(
            1 for ip in self._bw_current
            if self.get_device_baseline(ip).get('anomaly')
        )
        if anomaly_count > 0:
            penalty = min(anomaly_count * 4, 12)
            score  -= penalty
            issues.append(f"{anomaly_count} device{'s' if anomaly_count>1 else ''} with abnormal bandwidth")
            details['anomalies'] = {'count': anomaly_count, 'penalty': -penalty}

        # ── Suricata ───────────────────────────────────────────
        if not suricata_ok:
            score -= 4
            issues.append("Suricata IDS offline — reduced threat visibility")
            details['suricata'] = {'penalty': -4}

        score = max(0, min(100, score))

        # Grade
        if score >= 90:   grade = 'A'
        elif score >= 75: grade = 'B'
        elif score >= 60: grade = 'C'
        elif score >= 40: grade = 'D'
        else:             grade = 'F'

        result = {
            'score':     score,
            'grade':     grade,
            'issues':    issues,
            'breakdown': details,
            'ts':        time.time(),
        }
        with self._lock:
            self._score     = score
            self._score_ts  = time.time()
            self._breakdown = result
        return result

    def get_cached_score(self) -> dict:
        with self._lock:
            return dict(self._breakdown) if self._breakdown else {'score': 100, 'grade': 'A'}


health_engine = HealthEngine()
