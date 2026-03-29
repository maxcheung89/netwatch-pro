FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap arp-scan tcpdump iproute2 net-tools iputils-ping dnsutils curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir \
    "flask==3.0.3"            \
    "flask-socketio==5.3.6"   \
    "flask-cors==4.0.1"       \
    "python-socketio==5.11.1" \
    "python-engineio==4.9.1"  \
    "werkzeug==3.0.3"         \
    "eventlet==0.35.2"        \
    "dnspython==2.6.1"        \
    "gunicorn==22.0.0"

# Copy ALL backend + frontend files
COPY backend/ /app/
COPY frontend/ /app/frontend/

RUN mkdir -p /app/data /var/log/suricata

# Verify OUI files
RUN ls /usr/share/nmap/nmap-mac-prefixes 2>/dev/null && echo "nmap OUI: OK" || echo "nmap OUI: missing"
RUN ls /usr/share/arp-scan/ 2>/dev/null && echo "arp-scan OUI: OK" || echo "arp-scan OUI: missing"

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "-u", "app.py"]
