"""
NetWatch Pro — Settings Manager
Live-editable settings with JSON persistence.
"""

import os, json, threading, logging

log = logging.getLogger(__name__)
SETTINGS_PATH = '/app/data/settings.json'

DEFAULTS = {
    # Scanning
    'scan_interval':       60,       # seconds
    'network_range':       'auto',
    'passive_only':        False,    # if True, skip active nmap scan

    # Alert thresholds
    'bw_spike_multiplier': 8.0,      # x above baseline
    'bw_spike_min_mbps':   25.0,     # minimum Mbps to trigger
    'brute_syn_threshold': 20,       # SYNs per 10s
    'dns_flood_threshold': 200,      # queries per 10s
    'beacon_threshold':    30,       # same domain queries per 60s
    'portscan_threshold':  30,       # unique ports per 5s
    'device_rejoin_mins':  10,       # minutes offline before toast

    # Display
    'max_packet_rows':     300,
    'max_flow_rows':       300,
    'max_alert_rows':      2000,

    # Notifications
    'browser_notifications': True,
    'toast_new_device':      True,
    'toast_security':        True,

    # Suricata
    'suricata_eve_path':   '/var/log/suricata/eve.json',

    # Authentication
    'netwatch_password': '',   # leave blank to use Pi-hole password

    # Pi-hole
    'pihole_url':          'http://127.0.0.1:8888',    # backend API URL (loopback — always local)
    'pihole_public_url':   'http://10.10.32.12:8888',  # browser URL (real IP for UI links)
    'pihole_password':     '',   # Pi-hole v6 web password
    'pihole_token':        '',
    'suricata_enabled':    True,
}


class SettingsManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._data = dict(DEFAULTS)
        self._load()

    def _load(self):
        try:
            if os.path.exists(SETTINGS_PATH):
                with open(SETTINGS_PATH) as f:
                    saved = json.load(f)
                    self._data.update({k: v for k, v in saved.items() if k in DEFAULTS})
                log.info(f"Settings loaded from {SETTINGS_PATH}")
        except Exception as e:
            log.warning(f"Settings load error: {e}")

    def _save(self):
        try:
            os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
            with open(SETTINGS_PATH, 'w') as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            log.warning(f"Settings save error: {e}")

    def get(self, key, default=None):
        with self._lock:
            return self._data.get(key, DEFAULTS.get(key, default))

    def get_all(self) -> dict:
        with self._lock:
            return {**DEFAULTS, **self._data}

    def update(self, updates: dict) -> dict:
        """Update settings, validate types, persist. Returns final settings."""
        with self._lock:
            for k, v in updates.items():
                if k not in DEFAULTS:
                    continue
                # Type coercion
                expected = type(DEFAULTS[k])
                try:
                    if expected == bool:
                        v = bool(v)
                    elif expected == int:
                        v = int(v)
                    elif expected == float:
                        v = float(v)
                    elif expected == str:
                        v = str(v)
                    self._data[k] = v
                except (ValueError, TypeError) as e:
                    log.warning(f"Settings type error for {k}: {e}")
            self._save()
            return dict(self._data)

    def reset(self) -> dict:
        with self._lock:
            self._data = dict(DEFAULTS)
            self._save()
            return dict(self._data)


# Singleton
settings = SettingsManager()
