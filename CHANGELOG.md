# NetWatch Pro — Changelog

All notable changes to this project are documented here.

---

## [v32] — Record Limits Removed + Data Analysis + Logo
- **Alert cap raised** — in-memory and DB limits raised from 1,000 → 10,000; no more truncated alert history
- **Suricata cap raised** — from 2,000 → 10,000 stored alerts
- **Event log cap raised** — from 50,000 → 500,000 rows (SQLite handles this fine with WAL mode)
- **API response limits raised** — history endpoints: 500 → 5,000 per page; alerts API: 200 → 1,000 default
- **Logo** — replaced text/hex logo with PNG image on both topbar and login page (`frontend/logo.png`)
- **Discord bot alert dedup fix** — alerts were going silent because NetWatch IDs are deterministic hashes; fixed with 10-minute timestamp bucket so re-fired alerts notify again
- **Discord bot channel fix** — `get_channel()` (cache-only) replaced with `fetch_channel()` (real API call) — resolves "channel not found" on startup
- **`.env` file** — all passwords and settings moved out of `docker-compose.yml` into `.env`
- **Pi-hole v6 password** — `install.sh` now calls `pihole setpassword` after startup (env vars are ignored by Pi-hole v6)
- **DNS check non-destructive** — `install.sh` detects existing DNS setup (`DNSStubListener=no`, direct nameservers) and never overwrites a working config
- **Hagezi blocklist docs** — `README.md` and `docs/SETUP.md` include instructions for adding Hagezi Pro+ and other blocklists

## [v31] — Mobile & Live Indicator Fixes
- **Topbar LIVE dot** — ws-pill now shows blinking red dot when WebSocket is connected; turns grey when offline
- **Mobile menu fixed** — `toggleMobileNav()` logic bug caused menu to open and immediately close; fixed to clean if/else
- **Logo → dashboard** — clicking the NetWatch logo from any tab returns to the dashboard
- **Hamburger moved to topbar left** — consistent top-left position on all mobile browsers

## [v30] — Mobile Overhaul + UI Fixes
- **LIVE buttons** — Event Log LIVE button gets blinking dot (was missing); all three LIVE tab buttons now match
- **Active Incidents resizable** — drag the bottom edge to see more incidents
- **Mobile hamburger** — moved to DOM-first position so it always renders far-left
- **Mobile content scrollable** — `.content` was `overflow:hidden` which clipped all panels; fixed to `overflow-y:auto`
- **Mobile panels** — removed `flex:1` that caused panels to collapse; natural `height:auto` layout
- **Touch targets** — 48px minimum height on drawer items per Apple/Material guidelines
- **Tap delay** — `touch-action:manipulation` eliminates 300ms tap delay on iOS

## [v29] — FOUC Fix + Mobile Navigation
- **Tab flash on load** — non-active panels now hidden via CSS `:not(.active)` in `<head>` (faster than JS)
- **Dashboard `active` in HTML** — dashboard panel has class in markup so first paint is correct before JS loads
- **`tab()` sets `style.display`** — explicit inline style beats all CSS specificity; no more tabs ever getting stuck
- **Notification permission** — removed auto-request on page load; browser prompt no longer appears behind the app
- **Mobile drawer** — full-height overlay, tap-backdrop to close, body scroll lock while open

## [v28] — Animated Health Donut + Protocol Fixes
- **Health Score donut** — SVG ring animation replacing static progress bar; grade letter centered
- **Online cell** — click to jump to L3 Discovery
- **Top Talkers layout** — CSS Grid replaces broken flex row; rank/IP/bar/bytes always aligned
- **Protocol "0" / "2"** — `capture.py proto_name` expanded to 12 protocols (HOPOPT, IGMP, GRE, ESP, etc.)
- **Duplicate Top Talker** — removed redundant insight card; replaced with Network Speed (In/Out/Pkt/s)
- **`loadPD` async bug** — `await` in non-async function silently returned undefined; fixed
- **Colorful packet rows** — each L1 packet row gets protocol color glow
- **L2 Protocol spacing** — `gap:8px` between DNS/TLS/HTTP cards

## [v27] — Actionability + Intelligence
- **Network Health Score** — 0–100% with letter grade; deductions for incidents, anomalies, Pi-hole status
- **Alert → Incidents engine** — 1,000+ raw alerts collapse to meaningful grouped incidents with count/duration
- **Block IP** — 🚫 BLOCK button on every alert; Pi-hole blacklist + iptables commands shown
- **GeoIP + WhoIs** — external IPs show `🇺🇸 GitHub Inc · US` in Top Talkers and alert cards
- **7-day bandwidth anomaly** — per-device rolling baseline; fires when usage exceeds 3× average
- **Mobile responsive** — two CSS breakpoints (768px, 480px)
- New backend: `incidents.py`, `health.py`, `geoip.py`

## [v26] — Full Code Audit
- Removed duplicate DNS whitelist entries in `alerts.py`
- Fixed all bare `except:` clauses across all Python files
- Fixed `onclick="if(confirm...)"` anti-pattern → `confirmReset()` function
- Added missing CSS classes: `.live`, `.out`, `.scanning`, `.ws-pill`
- Fixed `renderSurAlerts()` IP filter from substring to exact prefix match
- All settings keys verified present in `settings.py`

## [v25] — Global IP Filter
- **`🔍 FILTER:` input in topbar** — type once, all tabs filter simultaneously
- **Bidirectional sync** — typing in a tab's own filter pushes to global
- **Tab switch sync** — switching tabs applies existing global filter to new tab
- Fixed `tab()` override pattern (caused all tabs to disappear) — inlined into original
- Fixed `renderPkts` duplicate pattern — inlined global filter

## [v24] — Cyberpunk UI Redesign
- Complete CSS rewrite with cyberpunk glassmorphism
- Animated background: grid tiles, light streaks, floating particles
- Glass cards with `backdrop-filter: blur(14px)`
- Per-tab accent colors, tab fade-in animation
- Neon chip hover effects, cyberpunk scrollbar
- Fixed IP partial match: `10.10.32.3` no longer shows `10.10.32.30`
  - Frontend: `ipMatch()` function with boundary checking
  - Backend: SQL `= ?` OR `LIKE 'prefix.%'` instead of `LIKE '%ip%'`

## [v23] — Login Page Redesign + Auth Fix
- **Login cookie bug** — `secure=True` globally blocked cookies over plain HTTP (LAN access broken)
  - Fixed: `secure` flag set per-request based on `CF-Connecting-IP` header
- New login page: cyberpunk matrix grid canvas animation
- Caps lock warning, show/hide password, rate limit countdown

## [v22] — CSV Import for Device Labels
- **⬆ Import CSV** button in L3 Discovery
- Upload exported CSV to restore labels after redeployment
- MAC-primary matching with IP fallback
- Drag-and-drop with preview, result summary
- Supports labels + hostnames + device_type

## [v21] — L2/L4 Persistent History
- New `datastore.py` — SQLite WAL database for DNS, TLS, HTTP, Flow history
- Time-range filters: 1D / 3D / 1W / 1M
- Monthly CSV archiving — data older than 30 days exported to `/app/data/archive/YYYY-MM/`
- Archive browser in L2 Protocol and L4 Flows history panels
- Pagination for all history tables (200 rows/page)

## [v20] — Incident Grouping (first version)
- Alert engine feeds into incident grouper
- Dashboard shows active incident count
- BLOCK + RESOLVE buttons per incident

## [v19] — Event Log Persistence
- `eventlog.py` — SQLite FTS5 database for all events
- History tab in dashboard Event Log
- Full-text search, pagination, 30-day retention
- Severity filters and IP/MAC filtering

## [v18] — Pi-hole v6 Integration
- Rewrote `pihole.py` for Pi-hole v6 REST API (breaking change from v5)
- Session auth with SID token
- Top blocked/clients/query types
- Block rate donut chart
- Timeline chart (queries over time)
- Enable/Disable toggle

## [v17] — Suricata IDS Integration
- `suricata.py` — tails EVE JSON log in real-time
- Alert severity mapping (1-3 → critical/high/warning)
- DNS, TLS, HTTP, Flow tables from Suricata
- Traffic series chart
- Top sources/destinations

## [v16] — Topology Visualization
- Force-directed graph of device connections
- Node sizing by traffic volume
- Click node to see connection detail
- ResizeObserver for canvas resize

## [v15] — Flow History + Stats
- L4 Flows tab with live connection table
- Sort by bytes or time
- Per-IP flow detail
- Hide :5000 filter (suppress own traffic)

## [v14] — Settings + Export
- Settings panel with all tunable parameters
- Live settings persistence (JSON file)
- Export: devices/alerts/flows/suricata/events CSV + full JSON

## [v13] — Security Detection Engine
- ARP spoofing / MITM detection
- Brute-force detection (SSH/RDP/FTP/VNC)
- Port scan detection
- DNS tunneling / DGA detection
- Beaconing / C2 pattern detection
- Bandwidth spike alerts
- Extensive whitelist (CDNs, OS telemetry, NTP, OCSP)

## [v12] — Asset Inventory
- L3 Discovery tab with full device inventory
- OUI vendor lookup from nmap/arp-scan
- Device type fingerprinting (OS heuristics)
- Inline click-to-edit labels
- Online/offline status with last-seen timestamp

## [v11] — Protocol DPI
- L2 Protocol tab: DNS queries, TLS sessions, HTTP requests
- JA3 fingerprinting for TLS
- DNS response tracking

## [v10] — Auth System
- Session-based login (`auth.py`)
- 256-bit tokens, httpOnly cookies
- Rate limiting (5 attempts / 60 sec)
- 8-hour session lifetime
- Cloudflare Tunnel support

## [v1–v9] — Foundation
- Raw packet capture via AF_PACKET socket (promiscuous mode)
- Flow tracking with RTT measurement
- Basic dashboard with bandwidth chart
- Docker + Pi-hole integration
- Initial Flask + SocketIO architecture
