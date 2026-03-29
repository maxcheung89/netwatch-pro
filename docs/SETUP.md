# NetWatch Pro — Setup Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Initial Configuration](#initial-configuration)
4. [Network Setup (Router DNS)](#network-setup)
5. [Suricata IDS (optional)](#suricata-ids)
6. [Cloudflare Tunnel (optional)](#cloudflare-tunnel)
7. [Updating](#updating)
8. [Uninstalling](#uninstalling)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware

- Any Linux server, NAS, Raspberry Pi 4, or mini PC on your LAN
- The server must be connected via **ethernet** (not WiFi) for packet capture to work
- 1 GB RAM minimum, 2 GB recommended
- 8 GB disk minimum (databases grow ~50 MB/month on a typical home network)

### Software

```bash
# Docker (install if not already present)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Verify Docker Compose v2 is available
docker compose version   # should show v2.x.x
```

### Check your network interface

```bash
ip link show
# Look for your ethernet interface — usually eth0, ens3, enp2s0, etc.
# It should show "state UP"

# If it's not eth0, update your .env:
# CAPTURE_INTERFACE=ens3
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netwatch-pro.git
cd netwatch-pro

# Create your environment file
cp .env.example .env

# Edit it — at minimum set these:
nano .env
```

Minimum required settings in `.env`:

```env
PIHOLE_PASSWORD=your-strong-password-here
PIHOLE_PUBLIC_URL=http://192.168.1.100:8888   # your server's LAN IP
CAPTURE_INTERFACE=eth0                         # your ethernet interface
TZ=America/New_York                            # your timezone
```

Then install:

```bash
sudo ./install.sh
```

The install takes 2–5 minutes on first run (downloads Pi-hole image, builds NetWatch image).

When it finishes, you'll see:

```
════════════════════════════════════════════════════
  ✓ Installation complete!

  NetWatch Pro:   http://192.168.1.100:5000
  Pi-hole Admin:  http://192.168.1.100:8888/admin
  DNS Server:     192.168.1.100  (port 53)

  Pi-hole password: your-strong-password-here
════════════════════════════════════════════════════
```

---

## Initial Configuration

### 1. Log in to NetWatch

Open `http://your-server-ip:5000` in your browser.  
Log in with the password from your `.env` file.

### 2. Connect Pi-hole

1. Click the **Pi-hole** tab
2. Click **Configure**
3. URL: `http://your-server-ip:8888`
4. Password: same as your `PIHOLE_PASSWORD` in `.env`
5. Click **Save & Connect**

The Pi-hole tab should show stats within a few seconds.

### 3. Label your devices

NetWatch will start discovering devices immediately. Once they appear in **L3 Discovery**:

1. Click any device's name/IP to edit it inline
2. Give it a descriptive label: `Living Room TV`, `Work Laptop`, etc.
3. When you're done, click **⬇ Export CSV** to save your labels
4. After any future reinstall, click **⬆ Import CSV** to restore them

### 4. Wait for data to accumulate

- **Flows and DNS history** start populating immediately
- **Device inventory** fills in within 1–2 minutes (first scan)
- **Protocol distribution** needs 5–10 minutes of traffic
- **Bandwidth anomaly detection** needs 30+ minutes of baseline data
- **Health Score** will be meaningful after ~15 minutes

---

## Network Setup

For NetWatch to see your entire network's DNS traffic, set your router to use your server as its DNS server.

### On your router (most common)

1. Log in to your router admin panel (usually `192.168.1.1`)
2. Find **DHCP Settings** or **LAN Settings**
3. Set **Primary DNS** to your server's IP (e.g. `192.168.1.100`)
4. Save and let devices renew their DHCP leases

After this, all DNS queries from all devices will go through Pi-hole and appear in NetWatch.

### Verify it's working

```bash
# From any device on your network, check which DNS server it's using:
# macOS / Linux:
nslookup google.com

# The response should show "Server: 192.168.1.100" (your server)
```

---

## Suricata IDS

Suricata provides signature-based intrusion detection that shows up in NetWatch's **Suricata** tab.

### Install Suricata on the host

```bash
sudo apt install suricata suricata-update

# Download latest rules
sudo suricata-update

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### Configure Suricata for your interface

Edit `/etc/suricata/suricata.yaml`:

```yaml
# Find the af-packet section and set your interface
af-packet:
  - interface: eth0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### Start Suricata

```bash
# Start as a service
sudo systemctl start suricata
sudo systemctl enable suricata

# Verify it's running and creating the EVE log
sudo tail -f /var/log/suricata/eve.json
```

NetWatch reads `/var/log/suricata/eve.json` automatically — it's mounted read-only into the container.

### Verify integration

Open NetWatch → **Suricata** tab. You should see the status dot go green and alerts start appearing within a minute.

---

## Cloudflare Tunnel

Cloudflare Tunnel lets you access NetWatch securely from anywhere without opening ports on your router.

### Prerequisites

- A Cloudflare account (free)
- A domain name managed by Cloudflare

### Setup

```bash
# Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb

# Authenticate with Cloudflare
cloudflared tunnel login

# Create a tunnel
cloudflared tunnel create netwatch

# Configure the tunnel
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: YOUR_TUNNEL_ID
credentials-file: /home/youruser/.cloudflared/YOUR_TUNNEL_ID.json

ingress:
  - hostname: netwatch.yourdomain.com
    service: http://localhost:5000
  - service: http_status:404
EOF

# Route DNS
cloudflared tunnel route dns netwatch netwatch.yourdomain.com

# Start the tunnel
cloudflared tunnel run netwatch

# Install as a service
sudo cloudflared service install
sudo systemctl start cloudflared
```

### Enable Cloudflare secure headers

In the Cloudflare dashboard:
1. Go to your domain → **Network**
2. Enable **True-Client-IP Header** (sends real client IP to NetWatch)

### Update NetWatch config

In your `.env`:
```env
BEHIND_CLOUDFLARE=1
```

Then reinstall:
```bash
sudo ./install.sh
```

With `BEHIND_CLOUDFLARE=1`:
- Session cookies use `Secure=True` (HTTPS only)
- Rate limiting uses the real client IP from `CF-Connecting-IP`
- Both LAN (`http://ip:5000`) and tunnel access work simultaneously

---

## Updating

```bash
cd netwatch-pro

# Pull latest code
git pull

# Export device labels first (install.sh wipes volumes)
# In NetWatch UI: L3 Discovery → ⬇ Export CSV → save the file

# Reinstall (builds new image, wipes old data)
sudo ./install.sh

# After install: re-import labels
# In NetWatch UI: L3 Discovery → ⬆ Import CSV → upload your saved file
```

### Updating Pi-hole only

```bash
docker compose pull pihole
docker compose up -d pihole
```

---

## Uninstalling

```bash
cd netwatch-pro

# Stop and remove containers + volumes
docker compose down -v

# Remove the built image
docker rmi netwatch-pro:latest

# Remove cloudflared if installed
sudo systemctl stop cloudflared
sudo cloudflared service uninstall
```

---

## Troubleshooting

### Nothing showing in packet capture

```bash
# Check your interface is UP
ip link show eth0

# Verify the interface in your .env matches
grep CAPTURE_INTERFACE .env

# Test raw packet access directly
docker exec netwatch-pro tcpdump -i eth0 -c 10
```

### Pi-hole shows "not connected"

```bash
# Is Pi-hole actually running?
docker ps | grep pihole
curl http://localhost:8888/admin/

# Check Pi-hole logs for auth errors
docker compose logs pihole --tail 30

# Verify the password in .env matches what Pi-hole has
grep PIHOLE_PASSWORD .env
```

### Login page keeps reappearing (cookie not sticking)

This is the `BEHIND_CLOUDFLARE` setting:
- If accessing via LAN (`http://ip:5000`): set `BEHIND_CLOUDFLARE=0`
- If accessing via Cloudflare Tunnel only: set `BEHIND_CLOUDFLARE=1`

After changing `.env`, run `sudo ./install.sh` to apply.

### Container keeps restarting

```bash
docker compose logs netwatch --tail 100
# Look for Python exceptions or import errors
```

### High CPU usage

Packet capture is CPU-intensive on busy networks. Tune in Settings:
- **Scan interval** — increase from 60s to 120s
- **Max packet rows** — reduce from 500 to 200
- **Passive only** — enable to skip nmap/arp-scan active scanning

### Port 53 already in use

```bash
# Ubuntu 22.04+ runs systemd-resolved on port 53
sudo systemctl disable systemd-resolved
sudo systemctl stop systemd-resolved
# Then reinstall
sudo ./install.sh
```

### Suricata alerts not appearing

```bash
# Check the EVE log is being written
sudo tail -f /var/log/suricata/eve.json

# Verify the file is mounted in the container
docker exec netwatch-pro ls -la /var/log/suricata/

# Check NetWatch can read it
docker exec netwatch-pro tail -n 5 /var/log/suricata/eve.json
```
