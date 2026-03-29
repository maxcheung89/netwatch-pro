"""
NetWatch Pro — Data Store
Persistent history for L2 (DNS/TLS/HTTP) and L4 (Flows) data.

Retention model:
  - Hot (SQLite):  last 30 days, queryable with time-range filters
  - Archive (CSV): older data exported to /app/data/archive/YYYY-MM/
                   one CSV per table per month, auto-generated at rollover
  - Archive index: /app/data/archive/index.json — lists available files

Archiving runs nightly. Data beyond 30 days is exported then deleted from SQLite.
"""

import sqlite3, time, threading, logging, os, json, csv, io
from datetime import datetime, timezone
from typing   import Optional

log = logging.getLogger(__name__)

DB_PATH      = '/app/data/datastore.db'
ARCHIVE_ROOT = '/app/data/archive'
HOT_DAYS     = 30          # days to keep in SQLite
ARCHIVE_DAYS = HOT_DAYS    # anything older goes to CSV archive

TIME_RANGES = {
    '1d':  86_400,
    '3d':  3 * 86_400,
    '1w':  7 * 86_400,
    '1m':  30 * 86_400,
}


class DataStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock   = threading.Lock()
        os.makedirs(ARCHIVE_ROOT, exist_ok=True)
        self._init_db()
        # Archive + prune runs nightly
        threading.Thread(target=self._nightly_loop, daemon=True,
                         name='datastore-archive').start()
        log.info(f"DataStore ready: {db_path}")

    # ── Schema ──────────────────────────────────────────────────

    def _init_db(self):
        c = self._conn()
        c.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA temp_store=MEMORY;
            PRAGMA cache_size=-8000;

            -- L2: DNS queries
            CREATE TABLE IF NOT EXISTS dns_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                src_ip   TEXT    NOT NULL,
                query    TEXT    NOT NULL,
                qtype    TEXT    DEFAULT 'A',
                is_resp  INTEGER DEFAULT 0,
                answer   TEXT    DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS dns_ts     ON dns_log(ts DESC);
            CREATE INDEX IF NOT EXISTS dns_src    ON dns_log(src_ip);
            CREATE INDEX IF NOT EXISTS dns_query  ON dns_log(query);

            -- L2: TLS sessions
            CREATE TABLE IF NOT EXISTS tls_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                src_ip   TEXT    NOT NULL,
                dst_ip   TEXT    DEFAULT '',
                sni      TEXT    DEFAULT '',
                ja3      TEXT    DEFAULT '',
                port     INTEGER DEFAULT 443
            );
            CREATE INDEX IF NOT EXISTS tls_ts     ON tls_log(ts DESC);
            CREATE INDEX IF NOT EXISTS tls_src    ON tls_log(src_ip);
            CREATE INDEX IF NOT EXISTS tls_sni    ON tls_log(sni);

            -- L2: HTTP requests
            CREATE TABLE IF NOT EXISTS http_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                src_ip   TEXT    NOT NULL,
                method   TEXT    DEFAULT 'GET',
                host     TEXT    DEFAULT '',
                path     TEXT    DEFAULT '/',
                status   INTEGER DEFAULT 0,
                ua       TEXT    DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS http_ts    ON http_log(ts DESC);
            CREATE INDEX IF NOT EXISTS http_src   ON http_log(src_ip);
            CREATE INDEX IF NOT EXISTS http_host  ON http_log(host);

            -- L4: Flow records (snapshots, not live)
            CREATE TABLE IF NOT EXISTS flow_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL    NOT NULL,
                src_ip   TEXT    NOT NULL,
                src_port INTEGER DEFAULT 0,
                dst_ip   TEXT    NOT NULL,
                dst_port INTEGER DEFAULT 0,
                proto    TEXT    DEFAULT '',
                app      TEXT    DEFAULT '',
                bytes    INTEGER DEFAULT 0,
                pkts     INTEGER DEFAULT 0,
                rtt_ms   REAL    DEFAULT 0,
                duration REAL    DEFAULT 0,
                state    TEXT    DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS flow_ts    ON flow_log(ts DESC);
            CREATE INDEX IF NOT EXISTS flow_src   ON flow_log(src_ip);
            CREATE INDEX IF NOT EXISTS flow_dst   ON flow_log(dst_ip);
        """)
        c.commit(); c.close()

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=5, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    # ── Write helpers ───────────────────────────────────────────

    def log_dns(self, ts, src_ip, query, qtype='A', is_resp=False, answer=''):
        try:
            with self._lock:
                c = self._conn()
                c.execute(
                    "INSERT INTO dns_log (ts,src_ip,query,qtype,is_resp,answer) VALUES (?,?,?,?,?,?)",
                    (ts, src_ip, query, qtype, 1 if is_resp else 0, answer)
                )
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"log_dns: {e}")

    def log_tls(self, ts, src_ip, dst_ip='', sni='', ja3='', port=443):
        if not sni: return   # skip sessions with no SNI — not useful
        try:
            with self._lock:
                c = self._conn()
                c.execute(
                    "INSERT INTO tls_log (ts,src_ip,dst_ip,sni,ja3,port) VALUES (?,?,?,?,?,?)",
                    (ts, src_ip, dst_ip, sni, ja3, port)
                )
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"log_tls: {e}")

    def log_http(self, ts, src_ip, method='GET', host='', path='/', status=0, ua=''):
        if not host: return
        try:
            with self._lock:
                c = self._conn()
                c.execute(
                    "INSERT INTO http_log (ts,src_ip,method,host,path,status,ua) VALUES (?,?,?,?,?,?,?)",
                    (ts, src_ip, method, host, path, status, ua)
                )
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"log_http: {e}")

    def log_flow(self, ts, src_ip, src_port, dst_ip, dst_port,
                 proto='', app='', bytes_=0, pkts=0, rtt_ms=0, duration=0, state=''):
        try:
            with self._lock:
                c = self._conn()
                c.execute(
                    """INSERT INTO flow_log
                       (ts,src_ip,src_port,dst_ip,dst_port,proto,app,bytes,pkts,rtt_ms,duration,state)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (ts, src_ip, src_port, dst_ip, dst_port,
                     proto, app, bytes_, pkts, rtt_ms, duration, state)
                )
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"log_flow: {e}")

    # ── Batch flow snapshot (called on scan / periodic) ─────────

    def snapshot_flows(self, flows: list):
        """Write a snapshot of current live flows to history."""
        if not flows: return
        now = time.time()
        rows = []
        for f in flows:
            rows.append((
                f.get('ts') or now,
                f.get('src_ip',''), f.get('src_port',0),
                f.get('dst_ip',''), f.get('dst_port',0),
                f.get('proto',''), f.get('app',''),
                f.get('bytes',0), f.get('pkts',0),
                f.get('rtt_ms',0), f.get('duration',0),
                f.get('state',''),
            ))
        try:
            with self._lock:
                c = self._conn()
                c.executemany(
                    """INSERT INTO flow_log
                       (ts,src_ip,src_port,dst_ip,dst_port,proto,app,bytes,pkts,rtt_ms,duration,state)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", rows
                )
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"snapshot_flows: {e}")

    # ── Query helpers ───────────────────────────────────────────

    def _time_window(self, range_str: str):
        secs = TIME_RANGES.get(range_str, TIME_RANGES['1d'])
        return time.time() - secs

    def query_dns(self, range_str='1d', ip='', q='', limit=500, offset=0):
        since = self._time_window(range_str)
        try:
            c = self._conn()
            filters = "WHERE ts >= ?"
            params  = [since]
            if ip:
                pat = ip.strip()
                filters += " AND (src_ip = ? OR src_ip LIKE ?)"
                params  += [pat, f'{pat}.%']
            if q:  filters += " AND query LIKE ?";  params.append(f'%{q}%')
            total = c.execute(f"SELECT COUNT(*) FROM dns_log {filters}", params).fetchone()[0]
            rows  = c.execute(
                f"SELECT * FROM dns_log {filters} ORDER BY ts DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()
            c.close()
            return {'rows': [dict(r) for r in rows], 'total': total,
                    'has_more': (offset + limit) < total}
        except Exception as e:
            log.debug(f"query_dns: {e}")
            return {'rows': [], 'total': 0, 'has_more': False}

    def query_tls(self, range_str='1d', ip='', sni='', limit=500, offset=0):
        since = self._time_window(range_str)
        try:
            c = self._conn()
            filters = "WHERE ts >= ?"
            params  = [since]
            if ip:  filters += " AND src_ip LIKE ?"; params.append(f'%{ip}%')
            if sni: filters += " AND sni LIKE ?";    params.append(f'%{sni}%')
            total = c.execute(f"SELECT COUNT(*) FROM tls_log {filters}", params).fetchone()[0]
            rows  = c.execute(
                f"SELECT * FROM tls_log {filters} ORDER BY ts DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()
            c.close()
            return {'rows': [dict(r) for r in rows], 'total': total,
                    'has_more': (offset + limit) < total}
        except Exception as e:
            log.debug(f"query_tls: {e}")
            return {'rows': [], 'total': 0, 'has_more': False}

    def query_flows(self, range_str='1d', ip='', port='',
                    proto='', limit=500, offset=0):
        since = self._time_window(range_str)
        try:
            c = self._conn()
            filters = "WHERE ts >= ?"
            params  = [since]
            if ip:
                pat = ip.strip()
                filters += " AND (src_ip = ? OR src_ip LIKE ? OR dst_ip = ? OR dst_ip LIKE ?)"
                params  += [pat, f'{pat}.%', pat, f'{pat}.%']
            if port:
                filters += " AND (src_port=? OR dst_port=?)"
                params  += [int(port), int(port)]
            if proto:
                filters += " AND proto=?"
                params.append(proto.upper())
            total = c.execute(f"SELECT COUNT(*) FROM flow_log {filters}", params).fetchone()[0]
            rows  = c.execute(
                f"SELECT * FROM flow_log {filters} ORDER BY ts DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()
            c.close()
            return {'rows': [dict(r) for r in rows], 'total': total,
                    'has_more': (offset + limit) < total}
        except Exception as e:
            log.debug(f"query_flows: {e}")
            return {'rows': [], 'total': 0, 'has_more': False}

    def get_db_stats(self):
        """Row counts and time range for each table."""
        try:
            c = self._conn()
            stats = {}
            for tbl in ('dns_log', 'tls_log', 'http_log', 'flow_log'):
                row = c.execute(
                    f"SELECT COUNT(*) as n, MIN(ts) as oldest, MAX(ts) as newest FROM {tbl}"
                ).fetchone()
                stats[tbl] = dict(row) if row else {}
            c.close()
            return stats
        except Exception as e:
            log.debug(f"db_stats: {e}")
            return {}

    # ── Monthly Archive ─────────────────────────────────────────

    def _archive_month(self, year: int, month: int):
        """
        Export all rows from a given month to CSV files, then delete them.
        Files go to /app/data/archive/YYYY-MM/tablename.csv
        """
        # Month start/end as Unix timestamps
        import calendar
        month_start = datetime(year, month, 1, tzinfo=timezone.utc).timestamp()
        last_day    = calendar.monthrange(year, month)[1]
        month_end   = datetime(year, month, last_day, 23, 59, 59,
                                tzinfo=timezone.utc).timestamp()

        month_label = f"{year}-{month:02d}"
        out_dir     = os.path.join(ARCHIVE_ROOT, month_label)
        os.makedirs(out_dir, exist_ok=True)

        tables = {
            'dns_log':  ['id','ts','src_ip','query','qtype','is_resp','answer'],
            'tls_log':  ['id','ts','src_ip','dst_ip','sni','ja3','port'],
            'http_log': ['id','ts','src_ip','method','host','path','status','ua'],
            'flow_log': ['id','ts','src_ip','src_port','dst_ip','dst_port',
                         'proto','app','bytes','pkts','rtt_ms','duration','state'],
        }

        archived = {}
        for tbl, cols in tables.items():
            out_path = os.path.join(out_dir, f"{tbl}.csv")
            # Skip if already archived this month (idempotent)
            try:
                c = self._conn()
                rows = c.execute(
                    f"SELECT * FROM {tbl} WHERE ts >= ? AND ts <= ?",
                    (month_start, month_end)
                ).fetchall()
                if rows:
                    with open(out_path, 'w', newline='') as f:
                        w = csv.DictWriter(f, fieldnames=cols)
                        w.writeheader()
                        w.writerows([dict(r) for r in rows])
                    # Delete from hot DB
                    with self._lock:
                        c.execute(f"DELETE FROM {tbl} WHERE ts >= ? AND ts <= ?",
                                  (month_start, month_end))
                        c.commit()
                    archived[tbl] = len(rows)
                    log.info(f"Archive {month_label}/{tbl}.csv: {len(rows)} rows")
                c.close()
            except Exception as e:
                log.warning(f"Archive {tbl} {month_label}: {e}")

        if archived:
            self._update_archive_index()

        return archived

    def _update_archive_index(self):
        """Rebuild the archive index JSON file."""
        index = []
        if not os.path.isdir(ARCHIVE_ROOT):
            return
        for month_dir in sorted(os.listdir(ARCHIVE_ROOT), reverse=True):
            full = os.path.join(ARCHIVE_ROOT, month_dir)
            if not os.path.isdir(full): continue
            files = []
            for fname in sorted(os.listdir(full)):
                fpath = os.path.join(full, fname)
                if fname.endswith('.csv'):
                    files.append({
                        'name':  fname,
                        'size':  os.path.getsize(fpath),
                        'rows':  sum(1 for _ in open(fpath)) - 1,  # minus header
                        'url':   f"/api/archive/{month_dir}/{fname}",
                    })
            if files:
                index.append({'month': month_dir, 'files': files})
        with open(os.path.join(ARCHIVE_ROOT, 'index.json'), 'w') as f:
            json.dump(index, f, indent=2)

    def get_archive_index(self):
        idx_path = os.path.join(ARCHIVE_ROOT, 'index.json')
        if not os.path.exists(idx_path):
            self._update_archive_index()
        try:
            with open(idx_path) as f:
                return json.load(f)
        except Exception:
            return []

    def get_archive_file(self, month: str, filename: str):
        """Return raw bytes of a specific archive CSV, or None."""
        # Sanitize path components
        if '/' in month or '\\' in month or '/' in filename or '\\' in filename:
            return None
        path = os.path.join(ARCHIVE_ROOT, month, filename)
        if not os.path.isfile(path):
            return None
        with open(path, 'rb') as f:
            return f.read()

    # ── Nightly job ─────────────────────────────────────────────

    def _nightly_loop(self):
        time.sleep(120)   # wait for startup
        while True:
            try:
                self._run_nightly()
            except Exception as e:
                log.warning(f"Nightly job: {e}")
            # Sleep until next midnight UTC
            now  = datetime.now(timezone.utc)
            next_midnight = now.replace(hour=0, minute=0, second=0,
                                        microsecond=0)
            from datetime import timedelta
            next_midnight += timedelta(days=1)
            sleep_secs = (next_midnight - now).total_seconds()
            log.info(f"DataStore: next archive in {sleep_secs/3600:.1f}h")
            time.sleep(max(sleep_secs, 3600))

    def _run_nightly(self):
        """Archive any month that has ended and prune hot DB."""
        now   = datetime.now(timezone.utc)
        cutoff = time.time() - (HOT_DAYS * 86_400)

        # Find which months need archiving (have data older than HOT_DAYS)
        try:
            c = self._conn()
            for tbl in ('dns_log', 'tls_log', 'http_log', 'flow_log'):
                oldest_ts = c.execute(
                    f"SELECT MIN(ts) FROM {tbl} WHERE ts < ?", (cutoff,)
                ).fetchone()[0]
                if oldest_ts:
                    dt = datetime.fromtimestamp(oldest_ts, tz=timezone.utc)
                    # Archive all complete months up to last month
                    while (dt.year, dt.month) < (now.year, now.month):
                        self._archive_month(dt.year, dt.month)
                        if dt.month == 12:
                            dt = dt.replace(year=dt.year+1, month=1)
                        else:
                            dt = dt.replace(month=dt.month+1)
            c.close()
        except Exception as e:
            log.warning(f"Nightly archive: {e}")

        # Hard prune anything still over HOT_DAYS (shouldn't happen after archive)
        try:
            with self._lock:
                c = self._conn()
                for tbl in ('dns_log', 'tls_log', 'http_log', 'flow_log'):
                    c.execute(f"DELETE FROM {tbl} WHERE ts < ?", (cutoff,))
                c.commit(); c.close()
        except Exception as e:
            log.debug(f"Prune: {e}")


# Singleton
datastore = DataStore()
