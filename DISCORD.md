# NetWatch Pro — Discord Bot

Get real-time network alerts in Discord and control NetWatch from slash commands.

---

## What the bot does

**Automatic notifications** — sent to your Discord channel whenever:
- A new security alert fires (ARP spoofing, brute force, DNS tunneling, etc.)
- A new incident is grouped (e.g. "Device 10.10.32.16 triggering 50+ alerts")
- The network health score drops significantly or crosses a threshold

**Slash commands** from Discord:

| Command | What it does |
|---------|-------------|
| `/status` | Health score, grade, active issues, device/flow/alert counts |
| `/devices` | All currently online devices with IP, label, and type |
| `/alerts [count]` | Recent unresolved alerts |
| `/incidents` | Active grouped incidents with resolve/block hints |
| `/talkers` | Top bandwidth users right now with bar chart |
| `/dns <ip>` | Last 24h of DNS queries from a device |
| `/whois <ip>` | GeoIP country, city, organisation, ASN |
| `/block <ip> [reason]` | Add IP to Pi-hole blocklist + show iptables commands |
| `/unblock <ip>` | Remove IP from Pi-hole blocklist |
| `/resolve <id>` | Dismiss an incident (ID shown in alerts/incidents) |
| `/resolve_all` | Dismiss all active incidents at once |
| `/scan` | Trigger an active nmap + arp-scan right now |
| `/help` | Show all commands with configuration summary |

---

## Setup — Step by step

### Step 1 — Create a Discord Application

1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. Click **New Application** → give it a name: `NetWatch Pro`
3. Go to the **Bot** tab on the left
4. Click **Add Bot** → **Yes, do it!**
5. Under **Token**, click **Reset Token** → copy it → save it somewhere safe  
   *(You only see it once — treat it like a password)*
6. Scroll down to **Privileged Gateway Intents** — you do **not** need any privileged intents
7. Click **Save Changes**

### Step 2 — Invite the bot to your server

1. Go to the **OAuth2 → URL Generator** tab
2. Under **Scopes**, check:
   - `bot`
   - `applications.commands`
3. Under **Bot Permissions**, check:
   - `Send Messages`
   - `Embed Links`
   - `Read Message History`
4. Copy the generated URL at the bottom
5. Open it in your browser → select your server → **Authorise**

### Step 3 — Get your channel ID

1. In Discord, go to **Settings → Advanced → Enable Developer Mode**
2. Right-click the channel you want alerts in → **Copy Channel ID**
3. Save the ID (it's a long number like `1234567890123456789`)

### Step 4 — Add to your `.env`

```env
DISCORD_BOT_TOKEN=your_bot_token_here
DISCORD_CHANNEL_ID=1234567890123456789
NETWATCH_URL=http://localhost:5000
POLL_INTERVAL=30
MIN_NOTIFY_SEV=high
```

**`MIN_NOTIFY_SEV`** controls which alerts trigger notifications:
- `info` — everything (very noisy)
- `warning` — warnings + high + critical
- `high` — only high and critical (recommended)
- `critical` — only critical alerts

### Step 5 — Start the bot

The Discord bot runs as a separate Docker service using a [Compose profile](https://docs.docker.com/compose/profiles/):

```bash
cd netwatch-pro

# Start NetWatch + Pi-hole + Discord bot
docker compose --profile discord up -d

# Or start just the Discord bot (if NetWatch is already running)
docker compose --profile discord up -d discord-bot

# View bot logs
docker compose logs discord-bot -f

# Stop just the bot
docker compose stop discord-bot
```

The bot will send a startup message to your channel when it connects:

> 🟢 **NetWatch Pro Bot Online**  
> Connected to **http://localhost:5000**  
> Polling every **30s** | Min severity: **HIGH**

### Updating install.sh (optional)

If you want `sudo ./install.sh` to start the bot automatically, add `--profile discord` to the compose commands in `install.sh`. Or just start it manually when needed.

---

## Alert examples

**High severity alert:**
```
🔴 [HIGH] Brute-Force Attempt — SSH

10.10.32.99 → 10.10.32.12:22 (SSH) | 35 SYNs in 10s

Severity: HIGH   Category: security
Source IP: 10.10.32.99
Action: /block 10.10.32.99 to block this IP
```

**Incident notification:**
```
🔥 INCIDENT: ARP Spoofing / MITM

×42 events over 3h 12m

Device IP: 10.10.32.16
Actions: /block 10.10.32.16 — block this IP
         /resolve inc_a1b2c3d4 — mark resolved
```

**Health score drop:**
```
🚨 Health Score Dropped: 85% → 62%

Issues:
• 2 active high-severity incidents
• Device 10.10.32.16 with abnormal bandwidth

Grade: C
```

---

## Slash command examples

**`/block 10.10.32.99 Brute force on SSH`**
```
🚫 IP Blocked: 10.10.32.99
🇷🇺 Unknown AS · RU — AS12345 Some ISP

Pi-hole: ✅ Added to blocklist

Router / Firewall Commands:
  # Drop all traffic from 10.10.32.99:
  iptables -I FORWARD -s 10.10.32.99 -j DROP

  # Undo:
  iptables -D FORWARD -s 10.10.32.99 -j DROP

  # nftables:
  nft add rule inet filter forward ip saddr 10.10.32.99 drop

Reason: Brute force on SSH
Blocked by: Maverick#1234
```

**`/status`**
```
✅ Network Health: 94% — Grade A
██████████ 94%

Status: All systems normal ✅

🖥️ Devices: Online: 18 / 31
🔀 Flows: 142
🚨 Alerts: Unread: 3
🔥 Incidents: 0
```

**`/whois 8.8.8.8`**
```
🌍 WhoIs: 8.8.8.8
🇺🇸 United States

City: Mountain View
Organisation: AS15169 Google LLC
ASN: AS15169 Google LLC
Country Code: US

Actions:
/block 8.8.8.8 — add to Pi-hole blocklist
/dns 8.8.8.8 — view DNS queries
```

---

## Troubleshooting

**Bot online but no slash commands appearing**  
Commands can take up to 1 hour to propagate globally. For instant registration, run:
```bash
docker compose logs discord-bot | grep "Synced"
# Should show: Synced N slash commands
```
If you see errors, the bot token or channel ID may be wrong.

**Bot not connecting to NetWatch**
```bash
docker compose logs discord-bot --tail 20
# Look for: "NetWatch login OK" or connection errors
```
Verify `NETWATCH_URL` in `.env` — if running on the same machine, use `http://localhost:5000`.

**Too many/few notifications**  
Adjust `MIN_NOTIFY_SEV` in `.env`:
```env
MIN_NOTIFY_SEV=high      # default — high + critical only
MIN_NOTIFY_SEV=warning   # also get warnings
MIN_NOTIFY_SEV=critical  # only the most severe
```
Restart the bot: `docker compose restart discord-bot`

**Bot spamming old alerts on restart**  
The bot tracks seen alerts in memory. On restart it re-polls and marks all current alerts as "seen" before starting to notify — it should not replay old alerts. If it does, check the `POLL_INTERVAL` isn't very short.

**"Missing Access" error in logs**  
The bot doesn't have permission to post in that channel. Go to Discord → channel settings → Permissions → add the bot role with **Send Messages** and **Embed Links**.
