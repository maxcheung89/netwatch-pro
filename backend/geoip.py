"""
NetWatch Pro — GeoIP + WhoIs Lookup
Uses ip-api.com (free, no API key, 45 req/min limit).
All results cached in SQLite — external API only called once per IP.
"""

import sqlite3, time, threading, logging, json, urllib.request, urllib.error, ipaddress
from typing import Optional

log = logging.getLogger(__name__)

DB_PATH     = '/app/data/geoip.db'
CACHE_TTL   = 7 * 86_400     # 7 days
RATE_LIMIT  = 1.5            # seconds between API calls (45/min limit)
BATCH_URL   = 'http://ip-api.com/batch'
SINGLE_URL  = 'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,org,as,query'

PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return True


class GeoIPEngine:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path   = db_path
        self._lock     = threading.Lock()
        self._api_lock = threading.Lock()   # serialises API calls
        self._last_api = 0.0
        self._pending:  set = set()         # IPs currently being looked up
        self._init_db()

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=5, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        c = self._conn()
        c.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS geoip (
                ip          TEXT PRIMARY KEY,
                country     TEXT DEFAULT '',
                country_code TEXT DEFAULT '',
                region      TEXT DEFAULT '',
                city        TEXT DEFAULT '',
                org         TEXT DEFAULT '',
                asn         TEXT DEFAULT '',
                flag        TEXT DEFAULT '',
                ts          REAL
            );
        """)
        c.commit(); c.close()

    def _cache_get(self, ip: str) -> Optional[dict]:
        try:
            c   = self._conn()
            row = c.execute("SELECT * FROM geoip WHERE ip=?", (ip,)).fetchone()
            c.close()
            if row and (time.time() - row['ts']) < CACHE_TTL:
                return dict(row)
        except Exception as e:
            log.debug(f"GeoIP cache get: {e}")
        return None

    def _cache_set(self, ip: str, data: dict):
        try:
            with self._lock:
                c = self._conn()
                c.execute("""INSERT OR REPLACE INTO geoip
                    (ip,country,country_code,region,city,org,asn,flag,ts)
                    VALUES (?,?,?,?,?,?,?,?,?)""", (
                    ip,
                    data.get('country',''),
                    data.get('countryCode',''),
                    data.get('regionName',''),
                    data.get('city',''),
                    data.get('org',''),
                    data.get('as',''),
                    self._flag(data.get('countryCode','')),
                    time.time(),
                ))
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"GeoIP cache set: {e}")

    @staticmethod
    def _flag(cc: str) -> str:
        """Convert country code to flag emoji."""
        if not cc or len(cc) != 2:
            return '🌐'
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)

    def _fmt(self, row: dict) -> dict:
        """Format a DB row or API response into a clean display dict."""
        cc   = row.get('country_code') or row.get('countryCode', '')
        flag = row.get('flag') or self._flag(cc)
        org  = row.get('org', '')
        asn  = row.get('asn') or row.get('as', '')
        city = row.get('city', '')
        country = row.get('country', '')

        # Build short label: "GitHub Inc · US"
        org_short = org.split(' AS')[0][:28] if org else ''
        label = ''
        if org_short:
            label = org_short
            if country:
                label += f' · {cc or country[:2]}'
        elif city and country:
            label = f'{city}, {country}'
        elif country:
            label = country

        return {
            'ip':          row.get('ip',''),
            'country':     country,
            'country_code':cc,
            'city':        city,
            'org':         org,
            'asn':         asn,
            'flag':        flag,
            'label':       label or '🌐 Unknown',
        }

    def _api_lookup(self, ip: str) -> Optional[dict]:
        """Single IP lookup via ip-api.com with rate limiting."""
        with self._api_lock:
            wait = RATE_LIMIT - (time.time() - self._last_api)
            if wait > 0:
                time.sleep(wait)
            try:
                url = SINGLE_URL.format(ip=ip)
                req = urllib.request.Request(url, headers={'User-Agent': 'NetWatch-Pro/1.0'})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                self._last_api = time.time()
                if data.get('status') == 'success':
                    data['ip'] = ip
                    return data
            except Exception as e:
                log.debug(f"GeoIP API {ip}: {e}")
            self._last_api = time.time()
        return None

    def lookup(self, ip: str, async_ok: bool = True) -> Optional[dict]:
        """
        Look up an IP. Returns cached result immediately if available.
        If async_ok=True and not cached, starts background lookup and returns None.
        If async_ok=False, blocks until lookup completes.
        """
        if _is_private(ip):
            return None   # Never look up private IPs

        cached = self._cache_get(ip)
        if cached:
            return self._fmt(cached)

        if ip in self._pending:
            return None   # Already being looked up

        if async_ok:
            self._pending.add(ip)
            threading.Thread(target=self._bg_lookup, args=(ip,),
                             daemon=True, name=f'geoip-{ip}').start()
            return None
        else:
            result = self._api_lookup(ip)
            if result:
                self._cache_set(ip, result)
                return self._fmt(result)
            return None

    def _bg_lookup(self, ip: str):
        try:
            result = self._api_lookup(ip)
            if result:
                self._cache_set(ip, result)
        finally:
            self._pending.discard(ip)

    def bulk_lookup(self, ips: list) -> dict:
        """
        Look up multiple IPs. Returns dict of ip → geo_info.
        Hits cache first, then batches uncached to API.
        """
        result   = {}
        to_fetch = []

        for ip in ips:
            if _is_private(ip):
                continue
            cached = self._cache_get(ip)
            if cached:
                result[ip] = self._fmt(cached)
            else:
                to_fetch.append(ip)

        # Fetch uncached in background (fire and forget)
        for ip in to_fetch[:20]:   # cap at 20 background lookups
            if ip not in self._pending:
                self._pending.add(ip)
                threading.Thread(target=self._bg_lookup, args=(ip,),
                                daemon=True).start()

        return result

    def get_cached(self, ip: str) -> Optional[dict]:
        """Return cached result only — never triggers API call."""
        if _is_private(ip):
            return None
        cached = self._cache_get(ip)
        return self._fmt(cached) if cached else None

    def stats(self) -> dict:
        try:
            c     = self._conn()
            total = c.execute("SELECT COUNT(*) FROM geoip").fetchone()[0]
            c.close()
            return {'cached': total, 'pending': len(self._pending)}
        except Exception:
            return {'cached': 0, 'pending': 0}


geoip_engine = GeoIPEngine()
