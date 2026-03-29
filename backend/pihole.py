"""
NetWatch Pro — Pi-hole v6 Integration
Uses http.client (matches curl exactly).
Auth: POST /api/auth {"password": "..."}
All v6 data shapes are handled defensively.
"""
import os, time, threading, logging, json, http.client
from typing import Optional

log = logging.getLogger(__name__)
POLL_INTERVAL = 20


def _to_dict(val, default=None):
    """Safely convert any value to a dict. Pi-hole v6 sometimes returns lists."""
    if isinstance(val, dict): return val
    if isinstance(val, list):
        # Convert [{name/ip/domain: x, count: y}] to {name: count}
        out = {}
        for item in val:
            if not isinstance(item, dict): continue
            key = item.get('name') or item.get('ip') or item.get('domain') or item.get('id') or ''
            cnt = item.get('count', 0)
            if key: out[str(key)] = cnt
        return out
    return default or {}


class PiholeEngine:
    def __init__(self):
        self._lock    = threading.Lock()
        self._running = False
        self._thread  = None

        self.url        = os.environ.get('PIHOLE_URL',        'http://127.0.0.1:8888').rstrip('/')
        self.public_url = os.environ.get('PIHOLE_PUBLIC_URL', 'http://10.10.32.12:8888').rstrip('/')
        self.password   = os.environ.get('PIHOLE_PASSWORD',   '')
        self.token      = os.environ.get('PIHOLE_API_TOKEN',  '')

        self._sid:          str   = ''
        self._sid_exp:      float = 0
        self._summary:      dict  = {}
        self._top_queries:  dict  = {}
        self._top_blocked:  dict  = {}
        self._top_clients:  list  = []   # list of {ip, name, count}
        self._overtime:     list  = []
        self._query_types:  list  = []
        self._blocking:     str   = 'unknown'
        self._last_update:  float = 0
        self._available:    bool  = False
        self._error:        str   = ''

    # ── HTTP ──────────────────────────────────────────────────

    def _conn(self):
        url = self.url
        https = url.startswith('https://')
        rest  = url[8:] if https else url[7:]
        if ':' in rest:
            host, port = rest.rsplit(':', 1); port = int(port)
        else:
            host = rest; port = 443 if https else 80
        if https:
            import ssl
            return http.client.HTTPSConnection(host, port, timeout=6,
                context=ssl._create_unverified_context())
        return http.client.HTTPConnection(host, port, timeout=6)

    def _req(self, method, path, body=None, sid=None):
        headers = {'Content-Type': 'application/json',
                   'Accept':       'application/json',
                   'User-Agent':   'curl/7.88.1'}
        if sid: headers['X-FTL-SID'] = sid
        payload = json.dumps(body).encode() if body is not None else None
        if payload: headers['Content-Length'] = str(len(payload))
        try:
            c = self._conn()
            c.request(method, path, body=payload, headers=headers)
            r   = c.getresponse()
            raw = r.read().decode('utf-8', errors='replace')
            c.close()
            log.debug(f"PH {method} {path} → {r.status}")
            if r.status >= 400:
                log.debug(f"PH {r.status}: {raw[:300]}")
                return None
            return json.loads(raw) if raw.strip() else {}
        except ConnectionRefusedError:
            log.debug(f"PH refused {self.url}")
        except Exception as e:
            log.debug(f"PH {method} {path}: {type(e).__name__}: {e}")
        return None

    # ── Auth ──────────────────────────────────────────────────

    def _auth(self):
        now = time.time()
        if self._sid and now < self._sid_exp - 60:
            return True
        pw = self.password or self.token
        r  = self._req('POST', '/api/auth', body={'password': pw})
        if not r:
            self._error = f'Cannot reach Pi-hole at {self.url}'
            return False
        s = r.get('session', {})
        if s.get('valid'):
            self._sid     = s.get('sid', '')
            self._sid_exp = now + int(s.get('validity', 1800))
            self._error   = ''
            log.info(f"PH auth OK sid={self._sid[:8]}...")
            return True
        self._error  = f"Wrong password: {s.get('message','unknown')}"
        self._sid    = ''
        log.warning(f"PH auth failed: {self._error}")
        return False

    def _get(self, path):
        return self._req('GET', path, sid=self._sid)

    def _post(self, path, body):
        return self._req('POST', path, body=body, sid=self._sid)

    # ── Poll ──────────────────────────────────────────────────

    def _poll(self):
        if not self._auth():
            with self._lock: self._available = False
            return False

        summary = self._get('/api/stats/summary')
        if not summary:
            with self._lock:
                self._available = False
                self._error = 'Stats endpoint failed after auth'
            return False

        br = self._get('/api/dns/blocking')
        blocking = 'unknown'
        if br is not None:
            blocking = 'enabled' if br.get('blocking') else 'disabled'

        with self._lock:
            self._summary     = summary
            self._blocking    = blocking
            self._available   = True
            self._last_update = time.time()
            self._error       = ''

        # Top domains — returns {"domains": {"domain": count}}
        r = self._get('/api/stats/top_domains?count=10')
        if r:
            raw = r.get('domains', r)
            with self._lock: self._top_queries = _to_dict(raw)

        # Top blocked — Pi-hole v6 may use different endpoint names
        r = self._get('/api/stats/top_blocked?count=10')
        if not r or not r.get('blocked'):
            r = self._get('/api/stats/top_ads?count=10')  # v5/alternate
        if r:
            raw = r.get('blocked', r.get('domains', r.get('ads', r)))
            with self._lock: self._top_blocked = _to_dict(raw)

        # Top clients — returns {"clients": [{"ip":..., "name":..., "count":...}]}
        r = self._get('/api/stats/top_clients?count=10')
        if r:
            clients_raw = r.get('clients', [])
            if isinstance(clients_raw, list):
                clients = [{'ip':    c.get('ip', c.get('name', '')),
                            'name':  c.get('name', c.get('ip', '')),
                            'count': c.get('count', 0)}
                           for c in clients_raw if isinstance(c, dict)]
            else:
                clients = [{'ip': k, 'name': k, 'count': v}
                           for k, v in _to_dict(clients_raw).items()]
            with self._lock: self._top_clients = clients

        # History
        r = self._get('/api/history')
        if r:
            with self._lock: self._overtime = r.get('history', [])

        # Query types — try multiple response shapes
        r = self._get('/api/queries/types')
        if r:
            # v6 may return {"A": 123, "AAAA": 45} directly or {"types": [...]}
            types_raw = r.get('types', None)
            if types_raw is None:
                # Direct dict format: convert to list
                types_list = [{'name': k, 'count': v} for k, v in r.items()
                               if isinstance(v, (int, float)) and k not in ('took',)]
                with self._lock: self._query_types = types_list
            else:
                with self._lock: self._query_types = types_raw

        log.info(f"PH poll OK blocking={blocking}")
        return True

    def _safe_poll(self):
        try: self._poll()
        except Exception as e: log.debug(f"PH safe poll: {e}")

    # ── Lifecycle ─────────────────────────────────────────────

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True, name='pihole')
        self._thread.start()
        log.info(f"PH started backend={self.url} public={self.public_url}")

    def stop(self): self._running = False

    def _loop(self):
        fails = 0; time.sleep(3)
        try: self._poll(); fails = 0
        except Exception as e: log.warning(f"PH first: {e}"); fails = 1
        while self._running:
            time.sleep(min(POLL_INTERVAL * (2 ** min(fails, 2)), 120))
            try:
                fails = 0 if self._poll() else fails + 1
            except Exception as e:
                fails += 1; log.debug(f"PH loop #{fails}: {e}")

    def set_credentials(self, url, password='', token='', public_url=''):
        with self._lock:
            self.url        = url.rstrip('/')
            self.public_url = (public_url or url).rstrip('/')
            self.password   = password
            self.token      = token
            self._sid       = ''
            self._sid_exp   = 0
            self._available = False
            self._error     = ''
        threading.Thread(target=self._safe_poll, daemon=True).start()

    # ── Public API ────────────────────────────────────────────

    @property
    def is_available(self): return self._available

    def get_summary(self):
        with self._lock:
            s, av, bl = dict(self._summary), self._available, self._blocking
            rt  = round(time.time() - self._last_update) if self._last_update else None
            err = self._error
        if not av:
            return {'available': False, 'url': self.public_url,
                    'backend_url': self.url, 'error': err or 'Not connected',
                    'has_auth': bool(self.password or self.token)}
        q = s.get('queries', {})
        def _int(v, fallback=0):
            try: return int(v or fallback)
            except: return fallback
        total   = _int(q.get('total',   s.get('dns_queries_today')))
        blocked = _int(q.get('blocked', s.get('ads_blocked_today')))
        pct     = round(blocked / max(total, 1) * 100, 1)
        return {
            'available':         True,
            'url':               self.public_url,
            'backend_url':       self.url,
            'has_auth':          bool(self.password or self.token),
            'status':            bl,
            'total_queries':     total,
            'queries_blocked':   blocked,
            'pct_blocked':       pct,
            'domains_blocked':   _int(s.get('gravity', {}).get('domains_being_blocked',
                                      s.get('domains_being_blocked'))),
            'unique_clients':    _int(s.get('clients', {}).get('active',
                                      s.get('unique_clients'))),
            'unique_domains':    _int(q.get('unique_domains', s.get('unique_domains'))),
            'queries_forwarded': _int(q.get('forwarded',  s.get('queries_forwarded'))),
            'queries_cached':    _int(q.get('cached',     s.get('queries_cached'))),
            'last_updated_secs': rt,
            'gravity_last_updated': '',
        }

    def get_top_data(self):
        with self._lock:
            # Everything is already normalized — safe to return directly
            return {
                'top_queries':    dict(self._top_queries),
                'top_blocked':    dict(self._top_blocked),
                'top_clients':    list(self._top_clients),   # list of {ip,name,count}
                'recent_blocked': [],
            }

    def get_overtime(self):
        with self._lock: ot = list(self._overtime)
        series = []
        for item in ot[-144:]:
            if isinstance(item, dict):
                series.append({'ts':      int(item.get('timestamp', 0)),
                               'queries': item.get('queries', 0),
                               'blocked': item.get('blocked', 0)})
        return {'series': series}

    def get_query_types(self):
        with self._lock: qt = list(self._query_types)
        if not qt: return []
        items = [(q.get('name',''), q.get('count',0))
                 for q in qt if isinstance(q, dict)]
        total = sum(c for _, c in items) or 1
        return sorted([{'type': n, 'count': c,
                        'pct': round(c / total * 100, 1)}
                       for n, c in items if n],
                      key=lambda x: -x['count'])

    def get_full(self):
        return {'summary':     self.get_summary(),
                'top':         self.get_top_data(),
                'overtime':    self.get_overtime(),
                'query_types': self.get_query_types()}

    def action(self, cmd):
        if not self._auth():
            return {'ok': False, 'error': self._error or 'Auth failed'}
        enable = (cmd == 'enable')
        r = self._post('/api/dns/blocking', {'blocking': enable, 'timer': None})
        if r is not None:
            with self._lock:
                self._blocking = 'enabled' if enable else 'disabled'
            return {'ok': True, 'blocking': enable}
        return {'ok': False, 'error': 'Request failed'}

    def debug_info(self):
        with self._lock:
            return {
                'available':    self._available,
                'url':          self.public_url,
                'backend_url':  self.url,
                'has_password': bool(self.password or self.token),
                'session_active': bool(self._sid),
                'session_ttl':  max(0, round(self._sid_exp - time.time()))
                                  if self._sid_exp else 0,
                'last_update':  self._last_update,
                'error':        self._error,
            }


pihole_engine = PiholeEngine()
