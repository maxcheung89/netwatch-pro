#!/bin/bash
set -e
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║      NetWatch Pro — Install          ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${NC}"

[ "$EUID" -ne 0 ] && echo -e "${RED}Run as root: sudo ./install.sh${NC}" && exit 1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── 0. Check .env ────────────────────────────────────────────
if [ ! -f .env ]; then
    echo -e "${YELLOW}[!] No .env file found — creating from .env.example${NC}"
    cp .env.example .env
    echo -e "${YELLOW}    Set your password in .env then re-run:${NC}"
    echo -e "    ${CYAN}nano .env && sudo ./install.sh${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ .env found${NC}"
source .env
PIHOLE_PASS="${PIHOLE_PASSWORD:-changeme123}"

# ── 1. DNS check (non-destructive) ───────────────────────────
echo -e "${YELLOW}[1/6] Checking DNS...${NC}"

# Detect which DNS approach is in use — do NOT clobber existing configs
DNS_OK=false

# Method A: resolv.conf has a real nameserver (not 127.0.0.53 stub)
if grep -qE "^nameserver (1\.1\.1\.1|8\.8\.8\.8|[^1])" /etc/resolv.conf 2>/dev/null; then
    echo -e "${GREEN}  ✓ /etc/resolv.conf already has working nameservers${NC}"
    DNS_OK=true
fi

# Method B: systemd-resolved with DNSStubListener=no
if grep -q "DNSStubListener=no" /etc/systemd/resolved.conf 2>/dev/null; then
    echo -e "${GREEN}  ✓ systemd-resolved: DNSStubListener=no (port 53 is free)${NC}"
    DNS_OK=true
fi

# Method C: systemd-resolved is disabled entirely
if ! systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo -e "${GREEN}  ✓ systemd-resolved is not running (port 53 is free)${NC}"
    DNS_OK=true
fi

if [ "$DNS_OK" = false ]; then
    echo -e "${YELLOW}  ⚠ systemd-resolved may be using port 53.${NC}"
    echo -e "${YELLOW}    Recommended fix — add to /etc/systemd/resolved.conf:${NC}"
    echo -e "    ${CYAN}[Resolve]"
    echo -e "    DNSStubListener=no${NC}"
    echo -e "${YELLOW}    Then run: sudo systemctl restart systemd-resolved${NC}"
    echo -e "${YELLOW}    Continuing anyway — Pi-hole port binding may fail.${NC}"
fi

# Ensure Docker can resolve DNS during build
mkdir -p /etc/docker
if ! grep -q '"dns"' /etc/docker/daemon.json 2>/dev/null; then
    printf '{\n  "dns": ["1.1.1.1", "8.8.8.8"]\n}\n' > /etc/docker/daemon.json
    systemctl restart docker 2>/dev/null || true
    sleep 3
    echo -e "${GREEN}  ✓ Docker DNS configured${NC}"
fi

# ── 2. Full wipe ──────────────────────────────────────────────
echo -e "${YELLOW}[2/6] Full wipe (containers + volumes)...${NC}"
docker compose down -v --remove-orphans 2>/dev/null || true
docker rm -f netwatch-pro pihole 2>/dev/null || true
docker rmi -f netwatch-pro:latest 2>/dev/null || true
COMPOSE_DIR="$(basename "$SCRIPT_DIR")"
for vol in "${COMPOSE_DIR}_netwatch_data" "${COMPOSE_DIR}_pihole_data" "${COMPOSE_DIR}_pihole_dnsmasq"; do
    docker volume rm "$vol" 2>/dev/null && echo -e "${GREEN}  ✓ Wiped: $vol${NC}" || true
done
docker builder prune -f 2>/dev/null || true
echo -e "${GREEN}  ✓ Clean slate${NC}"

# ── 3. Check interface ────────────────────────────────────────
echo -e "${YELLOW}[3/6] Checking network interface...${NC}"
IFACE="${CAPTURE_INTERFACE:-eth0}"
if ip link show "$IFACE" 2>/dev/null | grep -q "state UP"; then
    echo -e "${GREEN}  ✓ $IFACE is UP${NC}"
else
    echo -e "${RED}  ✗ $IFACE is not UP. Available interfaces:${NC}"
    ip link show | grep -E "state UP" | awk '{print "    "$2}' | tr -d ':'
    echo -e "${YELLOW}  Update CAPTURE_INTERFACE in .env and re-run${NC}"
fi

# ── 4. Verify files ───────────────────────────────────────────
echo -e "${YELLOW}[4/6] Verifying files...${NC}"
OK=true
for f in Dockerfile docker-compose.yml .env backend/app.py frontend/index.html; do
    if [ -f "$f" ]; then echo -e "${GREEN}  ✓ $f${NC}"; else echo -e "${RED}  ✗ MISSING: $f${NC}"; OK=false; fi
done
[ "$OK" = false ] && echo -e "${RED}Missing files — re-clone the repository${NC}" && exit 1

# ── 5. Build ──────────────────────────────────────────────────
echo -e "${YELLOW}[5/6] Building image (no cache)...${NC}"
docker compose build --no-cache
echo -e "${GREEN}  ✓ Image built${NC}"

# ── 6. Start services ─────────────────────────────────────────
echo -e "${YELLOW}[6/6] Starting services...${NC}"
docker compose up -d
echo ""

# Wait for Pi-hole to be ready before setting password
echo -n "  Waiting for Pi-hole     "
PIHOLE_UP=false
for i in $(seq 1 40); do
    if curl -sf --max-time 2 http://localhost:8888/admin/ >/dev/null 2>&1; then
        echo -e " ${GREEN}✓ UP${NC}"
        PIHOLE_UP=true
        break
    fi
    echo -n "."; sleep 2
done
if [ "$PIHOLE_UP" = false ]; then
    echo -e " ${RED}✗ timeout${NC}"
    echo "  → sudo docker compose logs pihole"
fi

# ── Pi-hole password (Pi-hole v6 requires pihole setpassword) ─
# WEBPASSWORD env var is Pi-hole v5 only.
# FTLCONF_webserver_api_password works in v6 but only on first boot.
# `pihole setpassword` is the guaranteed method for all versions.
if [ "$PIHOLE_UP" = true ]; then
    echo -n "  Setting Pi-hole password"
    # Give FTL a moment to fully initialize after HTTP is up
    sleep 3
    if docker exec pihole pihole setpassword "$PIHOLE_PASS" >/dev/null 2>&1; then
        echo -e " ${GREEN}✓ Password set: ${PIHOLE_PASS}${NC}"
    else
        echo -e " ${YELLOW}⚠ setpassword failed — run manually:${NC}"
        echo -e "    ${CYAN}docker exec -it pihole pihole setpassword ${PIHOLE_PASS}${NC}"
    fi
fi

# Wait for NetWatch
echo -n "  Waiting for NetWatch Pro"
for i in $(seq 1 30); do
    if curl -sf --max-time 2 http://localhost:5000/health >/dev/null 2>&1; then
        echo -e " ${GREEN}✓ UP${NC}"
        break
    fi
    echo -n "."; sleep 2
    [ $i -eq 30 ] && echo -e " ${RED}✗ timeout${NC}" && echo "  → sudo docker compose logs netwatch"
done

IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ Installation complete!${NC}"
echo ""
echo -e "  NetWatch Pro:   ${CYAN}http://${IP}:5000${NC}"
echo -e "  Pi-hole Admin:  ${CYAN}http://${IP}:8888/admin${NC}"
echo -e "  DNS Server:     ${CYAN}${IP}  (port 53)${NC}"
echo ""
echo -e "  Password:    ${YELLOW}${PIHOLE_PASS}${NC}"
echo -e "  Interface:   ${YELLOW}${IFACE}${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Next steps:"
echo "  1. Set your router DNS to: ${IP}"
echo "  2. In NetWatch → Pi-hole tab → Configure"
echo "     URL: http://${IP}:8888   Password: ${PIHOLE_PASS}"
echo ""
echo "  If Pi-hole login fails, reset password manually:"
echo -e "    ${CYAN}docker exec -it pihole pihole setpassword ${PIHOLE_PASS}${NC}"
echo ""
