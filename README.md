# NetWatch Pro

**A self-hosted network intelligence platform for your home lab.**

NetWatch Pro monitors everything on your LAN in real time — who's on the network, what they're connecting to, security threats, DNS queries, and more — all from a single cyberpunk-themed dashboard.

```
http://your-server-ip:5000
```

---

## What it does

| Layer | Feature |
|-------|---------|
| **L1 Capture** | Raw packet capture from your NIC in promiscuous mode — every frame, colored by protocol |
| **L2 Protocol** | DNS query log, TLS sessions with JA3 fingerprints, HTTP traffic, persistent history (1D/3D/1W/1M) |
| **L3 Discovery** | Full asset inventory: vendor, OS guess, hostname, device type — auto-updated on every scan |
| **L4 Flows** | Active connections with RTT, bandwidth, state; persistent flow history |
| **Topology** | Force-directed graph of who's talking to whom |
| **Alerts** | Security detection: ARP spoofing, brute-force, port scans, DNS tunneling, beaconing |
| **Incidents** | Alert grouping engine — 1,000 alerts → "5 active incidents" |
| **Pi-hole** | Full Pi-hole v6 dashboard: block rates, top clients, query types, enable/disable |
| **Suricata** | Real-time IDS alert feed from Suricata EVE JSON |
| **Health Score** | Single 0–100% network health metric, updated every 30 seconds |
| **GeoIP** | External IPs resolved to country + org (hover in Top Talkers / alerts) |
| **Block IP** | One-click Pi-hole blacklist + iptables commands for any suspicious IP |

---

## Screenshots

> Dashboard with animated health score, top talkers with GeoIP, live event log

> Alerts tab with grouped incidents, severity pills, Block IP button

> L1 Capture with colorful protocol-coded packet stream

> L3 Discovery asset inventory with inline label editing

> Pi-hole dashboard integrated directly in the app

---

## Requirements

| Requirement | Notes |
|------------|-------|
| Ubuntu 22.04+ / Debian 12+ | Other Linux distros work; tested on Ubuntu |
| Docker + Docker Compose v2 | `docker compose` (not `docker-compose`) |
| Network interface with promiscuous mode support | Usually `eth0` — not WiFi |
| Root / sudo access | Needed for raw socket capture |
| 1 GB RAM minimum | 2 GB recommended |
| Suricata (optional) | Install on host for IDS integration |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/yourusername/netwatch-pro.git
cd netwatch-pro

# 2. Configure
cp .env.example .env
nano .env        # set PIHOLE_PASSWORD and your server IP

# 3. Install
sudo ./install.sh
```

The installer:
- Configures DNS so Docker can resolve during build
- Wipes any old containers/volumes for a clean state
- Verifies your network interface is UP
- Builds the image and starts both services
- Prints the URL and password when done

**Access:** `http://your-server-ip:5000`  
**Default login:** your Pi-hole password (set in `.env`)

---

## Configuration

All settings live in `.env`. Copy `.env.example` to get started:

```bash
cp .env.example .env
```

Key settings:

```env
# Your Pi-hole + NetWatch login password
PIHOLE_PASSWORD=your-strong-password

# Your server's LAN IP (for the Pi-hole admin link)
PIHOLE_PUBLIC_URL=http://192.168.1.100:8888

# Network interface to capture on (find with: ip link show)
CAPTURE_INTERFACE=eth0

# Set to 1 if accessing via Cloudflare Tunnel
BEHIND_CLOUDFLARE=0

# Timezone
TZ=America/Chicago
```

> `.env` is listed in `.gitignore` — your passwords are never committed to git.

---

## After Installation

### Point your devices at Pi-hole DNS

Set your router's DNS server to your server's IP. This routes all DNS queries through Pi-hole and makes them visible in NetWatch.

Most routers: **Settings → DHCP → DNS Server → set to your server IP**

### Configure Pi-hole in NetWatch

1. Open NetWatch → click the **Pi-hole** tab
2. Click **Configure**
3. Enter your server's LAN IP and the password from `.env`

### Set device labels

1. Open the **L3 Discovery** tab
2. Click any device name to edit it inline
3. Export as CSV when done: **⬇ Export CSV**
4. After a reinstall, reimport: **⬆ Import CSV** — all your labels restore instantly

---

## Updating

```bash
cd netwatch-pro
git pull
sudo ./install.sh      # rebuilds image, wipes old volumes, restarts
```

> **Note:** `install.sh` wipes Docker volumes on every run for a clean build. Export your device labels CSV before updating if you want to preserve them.

---

## Data and Databases

NetWatch stores data in a Docker volume (`netwatch_data`) mounted at `/app/data` inside the container.

See **[docs/DATA.md](docs/DATA.md)** for a full explanation of every database, table, and what the data means.

---

## Accessing Data Directly

```bash
# Open a shell inside the container
docker exec -it netwatch-pro bash

# Browse the data directory
ls /app/data/

# Query the device inventory
sqlite3 /app/data/devices.db "SELECT ip, mac, hostname, vendor FROM devices ORDER BY last_seen DESC"

# Query DNS history
sqlite3 /app/data/datastore.db "SELECT datetime(ts,'unixepoch','localtime'), src_ip, query FROM dns_log ORDER BY ts DESC LIMIT 20"

# View recent alerts
sqlite3 /app/data/devices.db "SELECT datetime(ts,'unixepoch','localtime'), sev, title, detail FROM alerts ORDER BY ts DESC LIMIT 20"

# Export a full JSON snapshot
curl -b "nw_session=YOUR_SESSION" http://localhost:5000/api/export/full.json > netwatch_snapshot.json
```

---

## Cloudflare Tunnel (remote access)

To access NetWatch securely from outside your LAN:

1. Install `cloudflared` on your server
2. Create a tunnel pointing to `http://localhost:5000`
3. In `.env` set `BEHIND_CLOUDFLARE=1`
4. Enable **True-Client-IP Header** in the Cloudflare dashboard
5. Reinstall: `sudo ./install.sh`

With `BEHIND_CLOUDFLARE=1`, session cookies are set with `Secure=True` (HTTPS only), and real client IPs come from the `CF-Connecting-IP` header instead of the proxy IP.

---

## Suricata IDS Integration

Suricata provides deep packet inspection and signature-based threat detection that complements NetWatch's own heuristics.

```bash
# Install Suricata on host
sudo apt install suricata

# Update rules
sudo suricata-update

# Start Suricata on your interface
sudo suricata -D -i eth0 -c /etc/suricata/suricata.yaml

# NetWatch reads /var/log/suricata/eve.json automatically
```

See **[docs/SETUP.md](docs/SETUP.md)** for detailed Suricata configuration.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Host (Ubuntu)                  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              netwatch-pro container              │   │
│  │                                                  │   │
│  │  AF_PACKET ──► capture.py                       │   │
│  │                    │                             │   │
│  │          ┌─────────┼─────────┐                  │   │
│  │      protocol.py  flows.py  discovery.py         │   │
│  │          │          │          │                 │   │
│  │      alerts.py  incidents.py  health.py          │   │
│  │          │          │          │                 │   │
│  │          └─────────►app.py◄───┘                  │   │
│  │                     │                            │   │
│  │              Flask + SocketIO                    │   │
│  │                     │                            │   │
│  │    ┌────────────────┴──────────────────┐         │   │
│  │ devices.db  datastore.db  events.db  geoip.db    │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │                pihole container                  │   │
│  │            Pi-hole v6 DNS + Admin UI             │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Suricata (optional, runs on host)                      │
│  eve.json ──► mounted read-only into netwatch           │
└─────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

**Tabs not loading / blank page after login**
```bash
docker compose logs netwatch --tail 50
```

**Pi-hole not connecting**
```bash
# Check Pi-hole is running
curl http://localhost:8888/admin/

# Check NetWatch can reach it
docker exec netwatch-pro curl http://127.0.0.1:8888/api/auth
```

**No packets captured**
```bash
# Verify your interface is UP
ip link show eth0

# Check the container has raw socket access
docker exec netwatch-pro tcpdump -i eth0 -c 5
```

**Login cookie not sticking (LAN access)**  
Make sure `BEHIND_CLOUDFLARE=0` in `.env`. The `=1` setting forces `Secure` cookies which don't work over plain HTTP.

**Out of disk space**  
```bash
# Check volume size
docker system df
# Archive old data (runs automatically nightly, or trigger manually)
curl -X POST http://localhost:5000/api/archive/trigger
```

---

## Contributing

Pull requests welcome. Please:
1. Run the project and verify your change works end-to-end
2. Keep backend Python files passing `ast.parse()` with no bare `except:` clauses
3. Keep frontend JS passing `node --check` with no duplicate function definitions
4. Update `CHANGELOG.md` with a one-line summary

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Credits

Built with:
- [Flask](https://flask.palletsprojects.com/) + [Flask-SocketIO](https://flask-socketio.readthedocs.io/)
- [Pi-hole](https://pi-hole.net/) for DNS filtering
- [Suricata](https://suricata.io/) for IDS
- [ip-api.com](https://ip-api.com/) for GeoIP (free tier, no key needed)
- [Chart.js](https://www.chartjs.org/) for bandwidth charts
- IBM Plex Mono for the cyberpunk monospace aesthetic
