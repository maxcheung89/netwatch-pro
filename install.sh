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
    echo -e "${YELLOW}[!] No .env file found. Creating from .env.example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}    Edit .env and set your passwords, then re-run this script.${NC}"
    echo -e "    ${CYAN}nano .env${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ .env found${NC}"

# Load .env for password display at end
source .env

# ── 1. Verify DNS ─────────────────────────────────────────────
echo -e "${YELLOW}[1/6] Checking DNS...${NC}"
[ ! -f /etc/resolv.conf ] && printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf
if ! grep -q "1.1.1.1\|8.8.8.8" /etc/resolv.conf 2>/dev/null; then
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf
fi
mkdir -p /etc/docker
if ! grep -q "dns" /etc/docker/daemon.json 2>/dev/null; then
    printf '{\n  "dns": ["1.1.1.1", "8.8.8.8"]\n}\n' > /etc/docker/daemon.json
    systemctl restart docker 2>/dev/null || true
    sleep 3
fi
echo -e "${GREEN}  ✓ DNS configured${NC}"

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

# ── 6. Start + health checks ──────────────────────────────────
echo -e "${YELLOW}[6/6] Starting services...${NC}"
docker compose up -d
echo ""

echo -n "  Waiting for NetWatch Pro"
for i in $(seq 1 30); do
    curl -sf --max-time 2 http://localhost:5000/health >/dev/null 2>&1 && echo -e " ${GREEN}✓ UP${NC}" && break
    echo -n "."; sleep 2
    [ $i -eq 30 ] && echo -e " ${RED}✗ timeout${NC}" && echo "  → sudo docker compose logs netwatch"
done

echo -n "  Waiting for Pi-hole     "
for i in $(seq 1 30); do
    curl -sf --max-time 2 http://localhost:8888/admin/ >/dev/null 2>&1 && echo -e " ${GREEN}✓ UP${NC}" && break
    echo -n "."; sleep 2
    [ $i -eq 30 ] && echo -e " ${RED}✗ timeout${NC}" && echo "  → sudo docker compose logs pihole"
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
echo -e "  Password:    ${YELLOW}${PIHOLE_PASSWORD:-changeme123}${NC}"
echo -e "  Interface:   ${YELLOW}${CAPTURE_INTERFACE:-eth0}${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Next steps:"
echo "  1. Set your router DNS to: ${IP}"
echo "  2. In NetWatch → Pi-hole tab → Configure"
echo "     URL: http://${IP}:8888   Password: ${PIHOLE_PASSWORD:-changeme123}"
echo ""
