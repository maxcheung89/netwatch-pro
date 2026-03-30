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
| **Health Score** | Single 0–100% network health metric with animated donut, updated every 30 seconds |
| **GeoIP** | External IPs resolved to country + org in Top Talkers and alert cards |
| **Block IP** | One-click Pi-hole blacklist + iptables commands for any suspicious IP |

---

## Requirements

| Requirement | Notes |
|------------|-------|
| Ubuntu 22.04+ / Debian 12+ | Other Linux distros work; tested on Ubuntu |
| Docker + Docker Compose v2 | `docker compose` (not `docker-compose`) |
| Ethernet interface | WiFi does not support promiscuous mode capture |
| Root / sudo access | Required for raw socket capture |
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
nano .env        # set PIHOLE_PASSWORD and your server's LAN IP

# 3. Install
sudo ./install.sh
```

The installer:
- Reads config from `.env` — no hardcoded passwords anywhere
- Detects your existing DNS setup and does **not** overwrite a working config
- Builds the image, starts both containers
- Automatically sets the Pi-hole password via `pihole setpassword`
- Prints the URL, DNS server, and password when done

**Access:** `http://your-server-ip:5000`  
**Default login:** your Pi-hole password (set in `.env`)

---

## Configuration

All settings live in `.env`. Copy `.env.example` to get started:

```bash
cp .env.example .env
nano .env
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

> `.env` is in `.gitignore` — your passwords are never committed to git.

---

## DNS Port 53 Setup

Pi-hole needs port 53. On Ubuntu 22.04+, `systemd-resolved` typically holds that port. You do **not** need to disable it — just tell it to stop using port 53:

```bash
# Add to /etc/systemd/resolved.conf
sudo nano /etc/systemd/resolved.conf
```

```ini
[Resolve]
DNSStubListener=no
```

```bash
sudo systemctl restart systemd-resolved
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

`install.sh` detects this configuration and skips the DNS setup step entirely.

---

## Pi-hole Password — Important Note

**Pi-hole v6 changed how passwords work.** The `WEBPASSWORD` environment variable (v5) is silently ignored in v6. `install.sh` handles this by calling `pihole setpassword` automatically after startup — no manual steps needed.

If you ever need to reset it manually:
```bash
docker exec -it pihole pihole setpassword your-new-password
```

---

## Adding DNS Blocklists to Pi-hole

Pi-hole blocks millions of ad, tracking, and malware domains using community-maintained blocklists. Adding more lists increases coverage significantly.

### Recommended: Hagezi Pro+ Blocklist

The [Hagezi DNS Blocklists](https://github.com/hagezi/dns-blocklists) are among the best maintained lists available. The **Pro Plus** list blocks ads, tracking, malware, phishing, and coin mining with minimal false positives.

**Via Pi-hole Admin UI:**

1. Open Pi-hole Admin → `http://your-server-ip:8888/admin`
2. Go to **Lists** in the left sidebar
3. Click **Add Blocklist**
4. Paste this URL:
   ```
   https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.plus-compressed.txt
   ```
5. Add a comment: `Hagezi Pro Plus`
6. Click **Save**
7. Run **Tools → Update Gravity** (or see command below)

**Via command line:**

```bash
# Add the list to Pi-hole's database
docker exec pihole pihole-FTL sqlite3 /etc/pihole/gravity.db \
  "INSERT OR IGNORE INTO adlist (address, enabled, comment) \
   VALUES ('https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.plus-compressed.txt', 1, 'Hagezi Pro Plus');"

# Download and apply all enabled blocklists
docker exec pihole pihole -g
```

> Gravity update takes 1–3 minutes depending on your internet speed and how many lists you have. Pi-hole continues blocking during the update.

### Other recommended lists

| List | URL | What it blocks |
|------|-----|---------------|
| **Hagezi Pro+** | `https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/pro.plus-compressed.txt` | Ads, tracking, malware, phishing, coin mining |
| **Hagezi Threat Intelligence** | `https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/hosts/tif.txt` | Known C2 / malware domains |
| **OISD Big** | `https://big.oisd.nl` | Large general-purpose list |
| **StevenBlack Unified** | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | Classic ads + malware |

### Keeping lists updated

Pi-hole updates gravity automatically once per week. To update manually:

```bash
docker exec pihole pihole -g
```

---

## After Installation

### 1. Point your router at Pi-hole DNS

Set your router's DNS server to your server's IP. Most routers: **Settings → DHCP → Primary DNS → your server IP**

After changing, devices will use Pi-hole for DNS on their next DHCP renewal. You can force it by reconnecting to WiFi or running `sudo dhclient -r && sudo dhclient` on Linux.

### 2. Configure Pi-hole in NetWatch

1. Open NetWatch → click the **Pi-hole** tab
2. Click **Configure**
3. Enter your server's LAN IP and the password from `.env`
4. Click **Save & Connect**

### 3. Label your devices

1. Open **L3 Discovery**
2. Click any device name to edit it inline
3. Click **⬇ Export CSV** to save your labels
4. After any reinstall, click **⬆ Import CSV** to restore them instantly

---

## Updating

```bash
cd netwatch-pro
git pull

# Export device labels before wiping (install.sh wipes volumes)
# NetWatch → L3 Discovery → ⬇ Export CSV

sudo ./install.sh

# Re-import labels after install
# NetWatch → L3 Discovery → ⬆ Import CSV
```

---

## Data and Databases

See **[docs/DATA.md](docs/DATA.md)** for every database, table, and useful queries.

```bash
# Quick examples
docker exec netwatch-pro sqlite3 /app/data/devices.db \
  "SELECT ip, label, vendor FROM devices WHERE is_online=1"

docker exec netwatch-pro sqlite3 /app/data/datastore.db \
  "SELECT datetime(ts,'unixepoch','localtime'), src_ip, query FROM dns_log ORDER BY ts DESC LIMIT 20"
```

---

## Cloudflare Tunnel (remote access)

1. Install `cloudflared`, create a tunnel to `http://localhost:5000`
2. Enable **True-Client-IP Header** in Cloudflare dashboard
3. Set `BEHIND_CLOUDFLARE=1` in `.env`
4. Run `sudo ./install.sh`

See **[docs/SETUP.md](docs/SETUP.md)** for the full guide.

---

## Suricata IDS Integration

```bash
sudo apt install suricata suricata-update
sudo suricata-update
sudo systemctl enable --now suricata
```

NetWatch reads `/var/log/suricata/eve.json` automatically. See **[docs/SETUP.md](docs/SETUP.md)** for configuration details.

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
│  │     │                                            │   │
│  │  protocol.py  flows.py  discovery.py             │   │
│  │  alerts.py  incidents.py  health.py  geoip.py    │   │
│  │     └──────────► app.py (Flask + SocketIO)       │   │
│  │                    │                             │   │
│  │   devices.db  datastore.db  events.db  geoip.db  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │    pihole container  ─  Pi-hole v6 DNS + Web UI  │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Suricata ──► /var/log/suricata/eve.json (read-only)    │
└─────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

**All tabs blank / only dashboard shows**  
Hard-reload the page (`Ctrl+Shift+R`). Check browser console for JavaScript errors.

**Pi-hole not connecting / wrong password**
```bash
# Pi-hole v6 requires setpassword — env vars are unreliable in v6:
docker exec -it pihole pihole setpassword your-password

# Verify Pi-hole is responding
curl http://localhost:8888/admin/
docker compose logs pihole --tail 30
```

**Login cookie not sticking (LAN access)**  
Ensure `BEHIND_CLOUDFLARE=0` in `.env`. The `=1` setting requires HTTPS.

**No packets captured**
```bash
ip link show eth0
grep CAPTURE_INTERFACE .env
docker exec netwatch-pro tcpdump -i eth0 -c 5
```

**Port 53 already in use**
```bash
echo -e "[Resolve]\nDNSStubListener=no" | sudo tee -a /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" | sudo tee /etc/resolv.conf
sudo ./install.sh
```

**Suricata alerts not showing**
```bash
sudo tail -f /var/log/suricata/eve.json
docker exec netwatch-pro ls /var/log/suricata/
```

---

## Contributing

1. Verify your change works end-to-end on a real deployment
2. Python: no bare `except:` clauses, passes `ast.parse()`
3. JavaScript: passes `node --check`, no duplicate function definitions
4. Update `CHANGELOG.md`

---

## License

MIT — see [LICENSE](LICENSE)

---

## Credits

Built with: Flask · Flask-SocketIO · Pi-hole · Suricata · ip-api.com · Chart.js · IBM Plex Mono  
Blocklists: [Hagezi DNS Blocklists](https://github.com/hagezi/dns-blocklists)
