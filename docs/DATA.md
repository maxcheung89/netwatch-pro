# NetWatch Pro — Data Reference

All persistent data lives in the `netwatch_data` Docker volume, mounted at `/app/data/` inside the container.

```
/app/data/
├── devices.db       ← device inventory + alerts (SQLite)
├── datastore.db     ← L2/L4 protocol history (SQLite)
├── events.db        ← event log with full-text search (SQLite)
├── geoip.db         ← GeoIP cache (SQLite)
├── settings.json    ← live settings (JSON)
└── archive/
    ├── 2025-01/
    │   ├── dns_log.csv
    │   ├── tls_log.csv
    │   ├── http_log.csv
    │   └── flow_log.csv
    └── 2025-02/
        └── ...
```

---

## How to access the data

### Via the dashboard

All data is queryable through the NetWatch Pro UI:
- **L2 Protocol → HISTORY** — DNS, TLS, HTTP history with time-range filters
- **L4 Flows → HISTORY** — connection history
- **Dashboard → Event Log → HISTORY** — all system events
- **L3 Discovery** — device inventory with export to CSV
- **Settings → Export** — full JSON snapshot or per-table CSV downloads

### Via SQLite directly

```bash
# Open a shell in the container
docker exec -it netwatch-pro bash

# Or query directly from the host
docker exec netwatch-pro sqlite3 /app/data/devices.db ".tables"
```

### Via the API

All data is accessible through the REST API (requires a valid session cookie):

```bash
# Get your session cookie from the browser DevTools → Application → Cookies → nw_session
SESSION=your_session_cookie_value

curl -b "nw_session=$SESSION" http://localhost:5000/api/devices
curl -b "nw_session=$SESSION" http://localhost:5000/api/alerts
curl -b "nw_session=$SESSION" http://localhost:5000/api/history/dns?range=1d
curl -b "nw_session=$SESSION" http://localhost:5000/api/export/full.json
```

---

## Database: `devices.db`

Shared by the device inventory and alert engine.

### Table: `devices`

One row per discovered device (keyed by MAC address).

| Column | Type | Description |
|--------|------|-------------|
| `mac` | TEXT PK | MAC address (lowercase, colon-separated) |
| `ip` | TEXT | Most recent IP address |
| `hostname` | TEXT | Reverse DNS hostname |
| `dhcp_hostname` | TEXT | Hostname from DHCP DISCOVER packet |
| `vendor` | TEXT | OUI vendor name (from nmap/arp-scan database) |
| `device_type` | TEXT | Guessed device category (e.g. "Raspberry Pi", "iPhone") |
| `os_guess` | TEXT | OS hint (e.g. "Linux", "Windows", "iOS") |
| `confidence` | REAL | 0.0–1.0 confidence of device_type guess |
| `is_online` | INTEGER | 1 = online right now, 0 = offline |
| `first_seen` | REAL | Unix timestamp of first packet |
| `last_seen` | REAL | Unix timestamp of most recent packet |
| `label` | TEXT | Your custom name (editable in UI) |
| `alert_on_join` | INTEGER | 1 = show join toast for this device |
| `open_ports` | TEXT | Comma-separated port list from last nmap scan |

**Useful queries:**

```sql
-- All online devices with vendor info
SELECT ip, mac, label, vendor, device_type, last_seen
FROM devices WHERE is_online=1 ORDER BY last_seen DESC;

-- Unknown/unidentified devices
SELECT ip, mac, first_seen FROM devices
WHERE (vendor IS NULL OR vendor='Unknown') AND is_online=1;

-- Devices not seen in 7 days
SELECT ip, mac, label, last_seen FROM devices
WHERE last_seen < strftime('%s','now','-7 days');
```

### Table: `alerts`

Every security alert ever fired.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PK | Hash-based unique ID for deduplication |
| `ts` | REAL | Unix timestamp |
| `sev` | TEXT | `info` / `warning` / `high` / `critical` |
| `cat` | TEXT | `network` / `security` / `traffic` |
| `title` | TEXT | Short alert name |
| `detail` | TEXT | Full description with IPs and context |
| `src_ip` | TEXT | Source IP that triggered the alert |
| `dst_ip` | TEXT | Destination IP (if applicable) |
| `mac` | TEXT | MAC address (if known) |
| `dismissed` | INTEGER | 1 = user dismissed/resolved this alert |

**Useful queries:**

```sql
-- Recent undismissed security alerts
SELECT datetime(ts,'unixepoch','localtime') as time, sev, title, src_ip
FROM alerts WHERE dismissed=0 AND cat='security'
ORDER BY ts DESC LIMIT 50;

-- Most frequent alert types
SELECT title, COUNT(*) as count FROM alerts
GROUP BY title ORDER BY count DESC LIMIT 10;

-- All alerts for a specific device
SELECT datetime(ts,'unixepoch','localtime'), sev, title, detail
FROM alerts WHERE src_ip='10.10.32.16' OR mac='aa:bb:cc:dd:ee:ff'
ORDER BY ts DESC;
```

---

## Database: `datastore.db`

L2 and L4 protocol history. Data older than 30 days is automatically archived to CSV.

### Table: `dns_log`

Every DNS query captured by the packet sniffer.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `ts` | REAL | Unix timestamp |
| `src_ip` | TEXT | IP that made the query |
| `query` | TEXT | Domain queried (e.g. `api.github.com`) |
| `qtype` | TEXT | Query type (`A`, `AAAA`, `PTR`, etc.) |
| `is_resp` | INTEGER | 1 = this is a response, 0 = query |
| `answer` | TEXT | Comma-separated resolved IPs |

**Useful queries:**

```sql
-- Top queried domains in last 24 hours
SELECT query, COUNT(*) as hits FROM dns_log
WHERE ts > strftime('%s','now','-1 day') AND is_resp=0
GROUP BY query ORDER BY hits DESC LIMIT 20;

-- All DNS queries from a specific device today
SELECT datetime(ts,'unixepoch','localtime'), query, answer
FROM dns_log WHERE src_ip='10.10.32.10' AND ts > strftime('%s','now','-1 day')
AND is_resp=0 ORDER BY ts DESC;

-- Unusual long queries (possible DNS tunneling)
SELECT datetime(ts,'unixepoch','localtime'), src_ip, query, length(query) as len
FROM dns_log WHERE length(query) > 80 ORDER BY ts DESC LIMIT 20;
```

### Table: `tls_log`

Every TLS session where the SNI (Server Name Indication) was captured.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | |
| `ts` | REAL | Unix timestamp |
| `src_ip` | TEXT | Client IP |
| `dst_ip` | TEXT | Server IP |
| `sni` | TEXT | Server name from ClientHello (e.g. `google.com`) |
| `ja3` | TEXT | JA3 fingerprint of the TLS client |
| `port` | INTEGER | Destination port (usually 443) |

**Useful queries:**

```sql
-- Top TLS destinations in last week
SELECT sni, COUNT(*) as sessions FROM tls_log
WHERE ts > strftime('%s','now','-7 days')
GROUP BY sni ORDER BY sessions DESC LIMIT 20;

-- Unique JA3 fingerprints (detect unusual TLS clients)
SELECT ja3, COUNT(*) as count, GROUP_CONCAT(DISTINCT src_ip) as clients
FROM tls_log WHERE ja3 != '' GROUP BY ja3 ORDER BY count DESC;
```

### Table: `flow_log`

Snapshots of network flows (taken on each network scan, ~every 60 seconds).

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | |
| `ts` | REAL | Snapshot timestamp |
| `src_ip` | TEXT | Source IP |
| `src_port` | INTEGER | Source port |
| `dst_ip` | TEXT | Destination IP |
| `dst_port` | INTEGER | Destination port |
| `proto` | TEXT | `TCP` / `UDP` / `ICMP` |
| `app` | TEXT | Application protocol (`DNS`, `TLS`, `HTTP`) |
| `bytes` | INTEGER | Total bytes transferred |
| `pkts` | INTEGER | Total packets |
| `rtt_ms` | REAL | Round-trip time in milliseconds |
| `duration` | REAL | Flow duration in seconds |
| `state` | TEXT | TCP state (`ESTABLISHED`, `SYN_SENT`, etc.) |

**Useful queries:**

```sql
-- Top bandwidth consumers today
SELECT src_ip, SUM(bytes) as total_bytes,
       CAST(SUM(bytes)/1000000.0 AS INTEGER) as MB
FROM flow_log WHERE ts > strftime('%s','now','-1 day')
GROUP BY src_ip ORDER BY total_bytes DESC LIMIT 10;

-- Connections to unusual ports
SELECT src_ip, dst_ip, dst_port, COUNT(*) as connections
FROM flow_log WHERE dst_port NOT IN (80,443,53,22,8888,5000)
AND ts > strftime('%s','now','-1 day')
GROUP BY src_ip, dst_ip, dst_port ORDER BY connections DESC;
```

---

## Database: `events.db`

System event log with full-text search (SQLite FTS5).

### Table: `events`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | |
| `ts` | REAL | Unix timestamp |
| `ev_type` | TEXT | `joined` / `left` / `scan` / `alert` / `system` |
| `message` | TEXT | Human-readable event summary |
| `ip` | TEXT | Associated IP (if applicable) |
| `mac` | TEXT | Associated MAC (if applicable) |
| `hostname` | TEXT | Device hostname at time of event |
| `vendor` | TEXT | Device vendor at time of event |
| `device_type` | TEXT | Device type at time of event |
| `detail` | TEXT | Extended detail |
| `severity` | TEXT | `info` / `warning` / `critical` |

**Useful queries:**

```sql
-- Recent device joins
SELECT datetime(ts,'unixepoch','localtime'), ip, mac, hostname, vendor
FROM events WHERE ev_type='joined' ORDER BY ts DESC LIMIT 20;

-- Full-text search (FTS5)
SELECT datetime(ts,'unixepoch','localtime'), message, detail
FROM events_fts WHERE events_fts MATCH 'dns tunneling'
ORDER BY ts DESC;
```

---

## Database: `geoip.db`

GeoIP cache from ip-api.com. Results are cached for 7 days.

### Table: `geoip`

| Column | Type | Description |
|--------|------|-------------|
| `ip` | TEXT PK | IP address |
| `country` | TEXT | Country name |
| `country_code` | TEXT | Two-letter code (e.g. `US`) |
| `region` | TEXT | Region/state name |
| `city` | TEXT | City |
| `org` | TEXT | Organization (e.g. `AS13335 Cloudflare`) |
| `asn` | TEXT | ASN string |
| `flag` | TEXT | Flag emoji |
| `ts` | REAL | Cache timestamp |

---

## Monthly CSV Archives

Data older than 30 days is exported to CSV and removed from SQLite. Files are stored at:

```
/app/data/archive/YYYY-MM/dns_log.csv
/app/data/archive/YYYY-MM/tls_log.csv
/app/data/archive/YYYY-MM/http_log.csv
/app/data/archive/YYYY-MM/flow_log.csv
```

Download them from the dashboard:
- **L2 Protocol → HISTORY → Monthly Archive (CSV)**
- **L4 Flows → HISTORY → Monthly Archive (CSV)**

Or via the API:
```bash
# List available archives
curl -b "nw_session=$SESSION" http://localhost:5000/api/archive

# Download a specific file
curl -b "nw_session=$SESSION" \
  http://localhost:5000/api/archive/2025-01/dns_log.csv \
  -o dns_log_2025_01.csv
```

---

## API Quick Reference

All endpoints require a session cookie (`nw_session`).

| Endpoint | Description |
|----------|-------------|
| `GET /api/devices` | All devices |
| `GET /api/alerts` | Alert list (`?sev=high&unread=1`) |
| `GET /api/flows` | Live flows |
| `GET /api/talkers` | Top bandwidth users |
| `GET /api/protocols` | Protocol distribution |
| `GET /api/history/dns` | DNS history (`?range=1d&ip=10.0.0.1`) |
| `GET /api/history/tls` | TLS history |
| `GET /api/history/flows` | Flow history |
| `GET /api/incidents` | Active incidents |
| `GET /api/health` | Network health score |
| `GET /api/geoip/<ip>` | GeoIP lookup |
| `GET /api/events/history` | Event log (`?q=dns+tunnel`) |
| `POST /api/action/block_ip` | Block IP via Pi-hole |
| `GET /api/export/devices.csv` | Export device inventory |
| `GET /api/export/full.json` | Full data snapshot |
| `GET /api/archive` | List monthly archives |
