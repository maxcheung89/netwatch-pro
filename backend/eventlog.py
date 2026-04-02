"""
NetWatch Pro — Persistent Event Log
Stores ALL events in SQLite with full-text search and pagination.
Lightweight: uses WAL mode, indexes on timestamp+type, auto-prunes old rows.
"""

import sqlite3, time, threading, logging
from typing import List, Optional

log = logging.getLogger(__name__)

# Keep last 30 days or 50,000 rows — whichever comes first
MAX_ROWS    = 500_000
MAX_AGE_SEC = 30 * 86_400   # 30 days
PRUNE_EVERY = 3600           # prune check every hour

# Event types
EV_JOINED    = 'joined'
EV_LEFT      = 'left'
EV_SCAN      = 'scan'
EV_ALERT     = 'alert'
EV_DNS       = 'dns'
EV_PIHOLE    = 'pihole'
EV_SURICATA  = 'suricata'
EV_AUTH      = 'auth'
EV_SYSTEM    = 'system'

TYPE_ICON = {
    EV_JOINED:   '📡',
    EV_LEFT:     '🔴',
    EV_SCAN:     '🔍',
    EV_ALERT:    '🚨',
    EV_DNS:      '🌐',
    EV_PIHOLE:   '🔵',
    EV_SURICATA: '⚡',
    EV_AUTH:     '🔒',
    EV_SYSTEM:   'ℹ',
}


class EventLog:
    def __init__(self, db_path: str = '/app/data/events.db'):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._init_db()
        threading.Thread(target=self._prune_loop, daemon=True,
                         name='eventlog-prune').start()
        log.info(f"EventLog ready: {db_path}")

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=5, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        conn = self._conn()
        conn.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA temp_store=MEMORY;

            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         REAL    NOT NULL,
                ev_type    TEXT    NOT NULL,
                ip         TEXT    DEFAULT '',
                mac        TEXT    DEFAULT '',
                hostname   TEXT    DEFAULT '',
                vendor     TEXT    DEFAULT '',
                device_type TEXT   DEFAULT '',
                message    TEXT    NOT NULL,
                detail     TEXT    DEFAULT '',
                severity   TEXT    DEFAULT 'info'
            );

            CREATE INDEX IF NOT EXISTS idx_ts     ON events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_type   ON events(ev_type);
            CREATE INDEX IF NOT EXISTS idx_ip     ON events(ip);
            CREATE INDEX IF NOT EXISTS idx_mac    ON events(mac);

            -- FTS for search across message + detail + ip + hostname
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                message, detail, ip, hostname, vendor,
                content=events,
                content_rowid=id
            );

            -- Keep FTS in sync
            CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid, message, detail, ip, hostname, vendor)
                VALUES (new.id, new.message, new.detail, new.ip, new.hostname, new.vendor);
            END;
        """)
        conn.commit()
        conn.close()

    # ── Write ───────────────────────────────────────────────────

    def add(self, ev_type: str, message: str, *,
            ip: str = '', mac: str = '', hostname: str = '',
            vendor: str = '', device_type: str = '',
            detail: str = '', severity: str = 'info',
            ts: float = None) -> int:
        """Add an event. Returns the new row id."""
        now = ts or time.time()
        try:
            with self._lock:
                conn = self._conn()
                cur = conn.execute(
                    """INSERT INTO events
                       (ts,ev_type,ip,mac,hostname,vendor,device_type,message,detail,severity)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (now, ev_type, ip, mac, hostname, vendor,
                     device_type, message, detail, severity)
                )
                conn.commit()
                row_id = cur.lastrowid
                conn.close()
                return row_id
        except Exception as e:
            log.debug(f"EventLog add: {e}")
            return -1

    def add_device_event(self, ev_type: str, fp, detail: str = ''):
        """Convenience wrapper for device fingerprint objects."""
        label = getattr(fp, 'label', '') or getattr(fp, 'hostname', '') or \
                getattr(fp, 'dhcp_hostname', '') or fp.ip or fp.mac
        msg = f"{label} {ev_type}"
        self.add(ev_type, msg,
                 ip=fp.ip, mac=fp.mac,
                 hostname=label,
                 vendor=getattr(fp, 'vendor', ''),
                 device_type=getattr(fp, 'device_type', ''),
                 detail=detail,
                 severity='info' if ev_type == EV_LEFT else 'info')

    # ── Read ────────────────────────────────────────────────────

    def query(self,
              limit: int = 100,
              offset: int = 0,
              ev_type: str = None,
              ip: str = None,
              mac: str = None,
              search: str = None,
              since_ts: float = None,
              until_ts: float = None,
              severity: str = None) -> dict:
        """
        Paginated, filterable query.
        Returns {'events': [...], 'total': N, 'has_more': bool}
        """
        try:
            conn = self._conn()

            # FTS search path
            if search and search.strip():
                q = f'"{search.strip()}"' if ' ' in search else search.strip() + '*'
                base = """
                    SELECT e.* FROM events e
                    JOIN events_fts f ON f.rowid = e.id
                    WHERE events_fts MATCH ?
                """
                params = [q]
                count_base = """
                    SELECT COUNT(*) FROM events e
                    JOIN events_fts f ON f.rowid = e.id
                    WHERE events_fts MATCH ?
                """
                count_params = [q]
            else:
                base = "SELECT * FROM events WHERE 1=1"
                params = []
                count_base = "SELECT COUNT(*) FROM events WHERE 1=1"
                count_params = []

            # Filters
            if ev_type:
                base += " AND ev_type=?"; params.append(ev_type)
                count_base += " AND ev_type=?"; count_params.append(ev_type)
            if ip:
                pat = ip.strip()
                base += " AND (ip = ? OR ip LIKE ?)"
                params += [pat, f'{pat}.%']
                count_base += " AND ip LIKE ?"; count_params.append(f'%{ip}%')
            if mac:
                base += " AND mac LIKE ?"; params.append(f'%{mac}%')
                count_base += " AND mac LIKE ?"; count_params.append(f'%{mac}%')
            if severity:
                base += " AND severity=?"; params.append(severity)
                count_base += " AND severity=?"; count_params.append(severity)
            if since_ts:
                base += " AND ts>=?"; params.append(since_ts)
                count_base += " AND ts>=?"; count_params.append(since_ts)
            if until_ts:
                base += " AND ts<=?"; params.append(until_ts)
                count_base += " AND ts<=?"; count_params.append(until_ts)

            total = conn.execute(count_base, count_params).fetchone()[0]
            rows  = conn.execute(
                f"{base} ORDER BY ts DESC LIMIT ? OFFSET ?",
                params + [limit, offset]
            ).fetchall()
            conn.close()

            events = [dict(r) for r in rows]
            for e in events:
                e['icon'] = TYPE_ICON.get(e['ev_type'], '•')

            return {
                'events':   events,
                'total':    total,
                'offset':   offset,
                'limit':    limit,
                'has_more': (offset + limit) < total,
            }
        except Exception as e:
            log.debug(f"EventLog query: {e}")
            return {'events': [], 'total': 0, 'offset': offset,
                    'limit': limit, 'has_more': False}

    def get_stats(self) -> dict:
        """Row counts by type for the stats display."""
        try:
            conn = self._conn()
            rows = conn.execute(
                "SELECT ev_type, COUNT(*) as cnt FROM events GROUP BY ev_type"
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            oldest= conn.execute("SELECT MIN(ts) FROM events").fetchone()[0]
            conn.close()
            by_type = {r['ev_type']: r['cnt'] for r in rows}
            return {'total': total, 'by_type': by_type, 'oldest_ts': oldest}
        except Exception as e:
            log.debug(f"EventLog stats: {e}")
            return {'total': 0, 'by_type': {}, 'oldest_ts': None}

    def clear(self):
        try:
            with self._lock:
                conn = self._conn()
                conn.execute("DELETE FROM events")
                conn.execute("DELETE FROM events_fts")
                conn.commit()
                conn.close()
        except Exception as e:
            log.debug(f"EventLog clear: {e}")

    # ── Prune ───────────────────────────────────────────────────

    def _prune(self):
        try:
            cutoff = time.time() - MAX_AGE_SEC
            with self._lock:
                conn = self._conn()
                # Remove old rows
                conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                # Cap total rows
                count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if count > MAX_ROWS:
                    excess = count - MAX_ROWS
                    conn.execute(
                        "DELETE FROM events WHERE id IN "
                        "(SELECT id FROM events ORDER BY ts ASC LIMIT ?)", (excess,)
                    )
                conn.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
                conn.commit()
                conn.close()
        except Exception as e:
            log.debug(f"EventLog prune: {e}")

    def _prune_loop(self):
        time.sleep(60)   # Wait for startup
        while True:
            self._prune()
            time.sleep(PRUNE_EVERY)


# Singleton
event_log = EventLog()
