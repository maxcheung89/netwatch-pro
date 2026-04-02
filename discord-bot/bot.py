"""
NetWatch Pro — Discord Bot
Sends real-time network alerts to Discord and accepts slash commands
for blocking IPs, resolving incidents, and querying dashboard data.

Commands:
  /status          — Network health score + summary
  /devices         — Online devices
  /alerts          — Recent unresolved alerts
  /incidents       — Active grouped incidents
  /block <ip>      — Block an IP via Pi-hole + show iptables commands
  /unblock <ip>    — Unblock an IP
  /resolve <id>    — Dismiss/resolve an incident by ID
  /resolve_all     — Dismiss all active incidents
  /talkers         — Top bandwidth users right now
  /scan            — Trigger a network scan
  /dns <ip>        — Recent DNS queries from an IP
  /whois <ip>      — GeoIP lookup for an IP
"""

import os, asyncio, logging, time, json, aiohttp, discord
from discord.ext import commands, tasks
from discord import app_commands
from datetime import datetime, timezone
from collections import defaultdict

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level    = logging.INFO,
    format   = '%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    datefmt  = '%H:%M:%S',
)
log = logging.getLogger('netwatch-bot')

# ── Config from env ───────────────────────────────────────────────────────────
DISCORD_TOKEN      = os.environ['DISCORD_BOT_TOKEN']
DISCORD_CHANNEL_ID = int(os.environ['DISCORD_CHANNEL_ID'])
NETWATCH_URL       = os.environ.get('NETWATCH_URL',      'http://localhost:5000').rstrip('/')
NETWATCH_PASSWORD  = os.environ.get('NETWATCH_PASSWORD', os.environ.get('PIHOLE_PASSWORD', 'changeme123'))

# How often to poll for new alerts / health changes (seconds)
POLL_INTERVAL      = int(os.environ.get('POLL_INTERVAL', '30'))

# Minimum severity to notify: info | warning | high | critical
MIN_NOTIFY_SEV     = os.environ.get('MIN_NOTIFY_SEV', 'high')
SEV_ORDER          = {'info': 0, 'warning': 1, 'high': 2, 'critical': 3}

# ── Colours ────────────────────────────────────────────────────────────────────
C_GREEN   = 0x00ff88
C_CYAN    = 0x00f0ff
C_AMBER   = 0xffaa00
C_RED     = 0xff2855
C_PURPLE  = 0x9945ff
C_GREY    = 0x3a5568

SEV_COLOUR = {'info': C_CYAN, 'warning': C_AMBER, 'high': C_RED, 'critical': C_RED}
SEV_EMOJI  = {'info': 'ℹ️', 'warning': '⚠️', 'high': '🔴', 'critical': '🚨'}


# ─────────────────────────────────────────────────────────────────────────────
# NetWatch API client
# ─────────────────────────────────────────────────────────────────────────────
class NetWatchClient:
    def __init__(self, base_url: str, password: str):
        self.base    = base_url
        self.password = password
        self._session: aiohttp.ClientSession | None = None
        self._cookie: str = ''

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def login(self) -> bool:
        sess = await self._get_session()
        try:
            async with sess.post(
                f'{self.base}/auth/login',
                json={'password': self.password},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get('ok'):
                        # Extract session cookie
                        cookies = r.cookies
                        if 'nw_session' in cookies:
                            self._cookie = cookies['nw_session'].value
                            log.info("NetWatch login OK")
                            return True
                log.warning(f"NetWatch login failed: {r.status}")
                return False
        except Exception as e:
            log.error(f"NetWatch login error: {e}")
            return False

    async def _get(self, path: str, **params) -> dict | list | None:
        sess = await self._get_session()
        headers = {'Cookie': f'nw_session={self._cookie}'} if self._cookie else {}
        try:
            async with sess.get(
                f'{self.base}{path}',
                params=params or None,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                if r.status == 401:
                    if await self.login():
                        return await self._get(path, **params)
                    return None
                return await r.json() if r.status == 200 else None
        except Exception as e:
            log.debug(f"GET {path}: {e}")
            return None

    async def _post(self, path: str, body: dict = None) -> dict | None:
        sess = await self._get_session()
        headers = {'Cookie': f'nw_session={self._cookie}'} if self._cookie else {}
        try:
            async with sess.post(
                f'{self.base}{path}',
                json=body or {},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                if r.status == 401:
                    if await self.login():
                        return await self._post(path, body)
                    return None
                return await r.json() if r.status in (200, 201) else None
        except Exception as e:
            log.debug(f"POST {path}: {e}")
            return None

    # ── API convenience methods ────────────────────────────────────────────
    async def health(self):           return await self._get('/api/health')
    async def stats(self):            return await self._get('/api/stats')
    async def alerts(self, limit=50): return await self._get('/api/alerts', limit=limit)
    async def incidents(self):        return await self._get('/api/incidents')
    async def devices(self):          return await self._get('/api/devices')
    async def talkers(self):          return await self._get('/api/talkers')
    async def geoip(self, ip):        return await self._get(f'/api/geoip/{ip}')
    async def dns_history(self, ip):  return await self._get('/api/history/dns', ip=ip, range='1d', limit=10)

    async def block_ip(self, ip, note='Blocked via Discord'):
        return await self._post('/api/action/block_ip', {'ip': ip, 'note': note})

    async def unblock_ip(self, ip):
        return await self._post('/api/action/unblock_ip', {'ip': ip})

    async def dismiss_incident(self, inc_id):
        return await self._post(f'/api/incidents/{inc_id}/dismiss')

    async def dismiss_all_incidents(self):
        return await self._post('/api/incidents/dismiss_all')

    async def dismiss_alert(self, alert_id):
        return await self._post(f'/api/alerts/{alert_id}/dismiss')

    async def scan(self):
        return await self._post('/api/scan')

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# ─────────────────────────────────────────────────────────────────────────────
# Discord Bot
# ─────────────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
bot     = commands.Bot(command_prefix='!', intents=intents)
nw      = NetWatchClient(NETWATCH_URL, NETWATCH_PASSWORD)

# State for dedup
# Alert key = (alert_id + 10-min bucket) so the same alert re-notifies
# after cooldown expires (NetWatch IDs are deterministic hashes, not unique)
_seen_alerts:    set = set()
_seen_incidents: set = set()
_last_health:    int = -1
_notify_channel: discord.TextChannel | None = None

def _alert_key(a: dict) -> str:
    """alert_id + 10-minute timestamp bucket — allows re-notification after cooldown."""
    bucket = int(a.get('ts', 0)) // 600
    return f"{a.get('id','')}:{bucket}"

MAX_SEEN = 2000   # cap set size to avoid unbounded memory growth

def _prune_seen(s: set, cap: int = MAX_SEEN):
    """Keep only the newest entries when the set gets too large."""
    if len(s) > cap:
        s.clear()   # simplest: clear and let it re-learn (brief dupe risk)



def _ts(unix: float) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def _fmt_bytes(b: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if b < 1024: return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} TB'


def _health_colour(score: int) -> int:
    if score >= 90: return C_GREEN
    if score >= 70: return C_AMBER
    return C_RED


def _health_emoji(score: int) -> str:
    if score >= 90: return '✅'
    if score >= 70: return '⚠️'
    return '🚨'


# ─────────────────────────────────────────────────────────────────────────────
# Polling task
# ─────────────────────────────────────────────────────────────────────────────
@tasks.loop(seconds=POLL_INTERVAL)
async def poll_netwatch():
    global _last_health, _notify_channel
    if _notify_channel is None:
        return

    try:
        # ── New alerts ─────────────────────────────────────────────
        alerts = await nw.alerts(limit=100)
        if alerts:
            for a in alerts:
                if a.get('dismissed'):
                    continue
                key = _alert_key(a)
                if key in _seen_alerts:
                    continue
                _seen_alerts.add(key)
                _prune_seen(_seen_alerts)

                # Filter by minimum severity
                if SEV_ORDER.get(a.get('sev','info'), 0) < SEV_ORDER.get(MIN_NOTIFY_SEV, 2):
                    continue

                sev   = a.get('sev', 'info')
                embed = discord.Embed(
                    title       = f"{SEV_EMOJI.get(sev,'🔔')} {a.get('title','Alert')}",
                    description = a.get('detail', ''),
                    color       = SEV_COLOUR.get(sev, C_GREY),
                    timestamp   = datetime.fromtimestamp(a.get('ts', time.time()), tz=timezone.utc),
                )
                embed.add_field(name='Severity', value=sev.upper(), inline=True)
                embed.add_field(name='Category', value=a.get('cat','—'), inline=True)

                src = a.get('src_ip','')
                if src:
                    embed.add_field(name='Source IP', value=f'`{src}`', inline=True)
                    # Add block button hint
                    embed.add_field(
                        name  = 'Action',
                        value = f'`/block {src}` to block this IP',
                        inline=False
                    )

                mac = a.get('mac','')
                if mac:
                    embed.add_field(name='MAC', value=f'`{mac}`', inline=True)

                embed.set_footer(text=f'NetWatch Pro • Alert ID: {aid[:12]}')
                await _notify_channel.send(embed=embed)

        # ── New active incidents ────────────────────────────────────
        incidents = await nw.incidents()
        if incidents:
            for inc in incidents:
                if inc.get('dismissed') or not inc.get('active'):
                    continue
                iid = inc.get('id','')
                if iid in _seen_incidents:
                    continue
                _seen_incidents.add(iid)

                sev   = inc.get('severity', 'info')
                dur   = inc.get('duration_s', 0)
                dur_s = f"{dur//3600}h {(dur%3600)//60}m" if dur > 3600 else f"{dur//60}m {dur%60}s"

                embed = discord.Embed(
                    title       = f"🔥 INCIDENT: {inc.get('title','Incident')}",
                    description = inc.get('detail',''),
                    color       = SEV_COLOUR.get(sev, C_GREY),
                    timestamp   = datetime.fromtimestamp(inc.get('first_seen', time.time()), tz=timezone.utc),
                )
                embed.add_field(name='Severity',   value=sev.upper(),                  inline=True)
                embed.add_field(name='Events',     value=str(inc.get('count','?')),    inline=True)
                embed.add_field(name='Duration',   value=dur_s,                        inline=True)
                ip = inc.get('device_ip','')
                if ip:
                    embed.add_field(name='Device IP', value=f'`{ip}`', inline=True)
                embed.add_field(
                    name  = 'Actions',
                    value = (f'`/block {ip}` — block this IP\n' if ip else '') +
                            f'`/resolve {iid}` — mark resolved',
                    inline=False
                )
                embed.set_footer(text=f'NetWatch Pro • Incident ID: {iid}')
                await _notify_channel.send(embed=embed)

        # ── Health score change ─────────────────────────────────────
        health = await nw.health()
        if health:
            score = health.get('score', -1)
            # Notify on significant drops (>10 points) or crossing thresholds
            if _last_health >= 0:
                dropped = _last_health - score
                crossed_bad = (_last_health >= 90 and score < 90) or \
                              (_last_health >= 70 and score < 70) or \
                              (_last_health >= 40 and score < 40)
                if dropped >= 15 or crossed_bad:
                    embed = discord.Embed(
                        title       = f"{_health_emoji(score)} Health Score Dropped: {_last_health}% → {score}%",
                        color       = _health_colour(score),
                        timestamp   = datetime.now(tz=timezone.utc),
                    )
                    issues = health.get('issues', [])
                    if issues:
                        embed.add_field(
                            name  = 'Issues',
                            value = '\n'.join(f'• {i}' for i in issues[:5]),
                            inline=False,
                        )
                    embed.add_field(name='Grade', value=health.get('grade','?'), inline=True)
                    embed.set_footer(text='NetWatch Pro • Use /status for details')
                    await _notify_channel.send(embed=embed)
            _last_health = score

    except Exception as e:
        log.error(f"Poll error: {e}")


@poll_netwatch.before_loop
async def before_poll():
    # wait_until_ready ensures gateway is connected but guild cache may still
    # be empty — use fetch_channel() which makes a real HTTP call instead.
    await bot.wait_until_ready()
    await nw.login()
    global _notify_channel

    # Seed seen-alerts with all currently existing alerts so we don't
    # flood the channel on bot restart, but use keyed buckets so future
    # re-fires after cooldown still get notified.
    try:
        existing = await nw.alerts(limit=500)
        if existing:
            for a in existing:
                _seen_alerts.add(_alert_key(a))
            log.info(f"Seeded {len(_seen_alerts)} existing alert keys")
    except Exception as e:
        log.debug(f"Seed alerts: {e}")
    try:
        _notify_channel = await bot.fetch_channel(DISCORD_CHANNEL_ID)
        log.info(f"Notifying in #{_notify_channel.name}")
    except discord.NotFound:
        log.error(f"Channel {DISCORD_CHANNEL_ID} not found — check DISCORD_CHANNEL_ID in .env")
    except discord.Forbidden:
        log.error(f"No permission to access channel {DISCORD_CHANNEL_ID} — check bot permissions")
    except Exception as e:
        log.error(f"Could not fetch channel {DISCORD_CHANNEL_ID}: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Events
# ─────────────────────────────────────────────────────────────────────────────
@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} ({bot.user.id})")

    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        log.info(f"Synced {len(synced)} slash commands")
    except Exception as e:
        log.error(f"Command sync failed: {e}")

    # Start poll loop (before_poll handles login + channel fetch)
    if not poll_netwatch.is_running():
        poll_netwatch.start()

    # Send startup message — use fetch_channel, not get_channel
    try:
        ch = await bot.fetch_channel(DISCORD_CHANNEL_ID)
        embed = discord.Embed(
            title       = '🟢 NetWatch Pro Bot Online',
            description = f'Connected to **{NETWATCH_URL}**\n'
                          f'Polling every **{POLL_INTERVAL}s**\n'
                          f'Minimum alert severity: **{MIN_NOTIFY_SEV.upper()}**',
            color       = C_GREEN,
            timestamp   = datetime.now(tz=timezone.utc),
        )
        embed.set_footer(text='Type /help for commands')
        await ch.send(embed=embed)
    except Exception as e:
        log.error(f"Could not send startup message: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Slash commands
# ─────────────────────────────────────────────────────────────────────────────

@bot.tree.command(name='status', description='Network health score and summary')
async def cmd_status(interaction: discord.Interaction):
    await interaction.response.defer()
    health = await nw.health()
    stats  = await nw.stats()
    if not health:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    score = health.get('score', 0)
    embed = discord.Embed(
        title     = f"{_health_emoji(score)} Network Health: {score}% — Grade {health.get('grade','?')}",
        color     = _health_colour(score),
        timestamp = datetime.now(tz=timezone.utc),
    )

    # Bar visualisation
    filled = round(score / 10)
    bar    = '█' * filled + '░' * (10 - filled)
    embed.description = f'`{bar}` {score}%'

    issues = health.get('issues', [])
    if issues:
        embed.add_field(name='⚠️ Issues', value='\n'.join(f'• {i}' for i in issues[:5]), inline=False)
    else:
        embed.add_field(name='Status', value='All systems normal ✅', inline=False)

    if stats:
        d = stats.get('devices', {})
        f = stats.get('flows', {})
        a = stats.get('alerts', {})
        embed.add_field(name='🖥️ Devices',      value=f"Online: **{d.get('online',0)}** / {d.get('total',0)}", inline=True)
        embed.add_field(name='🔀 Flows',         value=str(f.get('active_flows',0)),                            inline=True)
        embed.add_field(name='🚨 Alerts',        value=f"Unread: **{a.get('unread',0)}**",                      inline=True)

    inc = await nw.incidents()
    active_inc = [i for i in (inc or []) if i.get('active') and not i.get('dismissed')]
    embed.add_field(name='🔥 Incidents', value=str(len(active_inc)), inline=True)
    embed.set_footer(text='NetWatch Pro')
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='devices', description='Show online devices')
async def cmd_devices(interaction: discord.Interaction):
    await interaction.response.defer()
    devices = await nw.devices()
    if not devices:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    online = [d for d in devices if d.get('is_online')]
    online.sort(key=lambda d: d.get('last_seen', 0), reverse=True)

    embed = discord.Embed(
        title     = f'🖥️ Online Devices ({len(online)})',
        color     = C_CYAN,
        timestamp = datetime.now(tz=timezone.utc),
    )

    rows = []
    for d in online[:20]:
        label  = d.get('label') or d.get('hostname') or d.get('vendor') or '?'
        ip     = d.get('ip', '?')
        vendor = d.get('vendor', '')
        dtype  = d.get('device_type', '')
        rows.append(f'`{ip:<16}` **{label[:20]}**  `{dtype or vendor or "—"}`')

    embed.description = '\n'.join(rows) or 'No online devices'
    if len(online) > 20:
        embed.set_footer(text=f'Showing 20 of {len(online)} — use NetWatch UI for full list')
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='alerts', description='Recent unresolved alerts')
@app_commands.describe(count='Number of alerts to show (default 10)')
async def cmd_alerts(interaction: discord.Interaction, count: int = 10):
    await interaction.response.defer()
    count   = min(max(count, 1), 25)
    alerts  = await nw.alerts(limit=50)
    if alerts is None:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    unread = [a for a in alerts if not a.get('dismissed')][:count]
    embed  = discord.Embed(
        title     = f'🚨 Recent Alerts ({len(unread)} shown)',
        color     = C_RED if unread else C_GREEN,
        timestamp = datetime.now(tz=timezone.utc),
    )

    if not unread:
        embed.description = '✅ No unresolved alerts'
    else:
        for a in unread:
            sev   = a.get('sev', 'info')
            emoji = SEV_EMOJI.get(sev, '•')
            src   = a.get('src_ip', '')
            name  = f"{emoji} [{sev.upper()}] {a.get('title','?')[:40]}"
            val   = a.get('detail', '')[:80]
            if src: val += f'\n`{src}`'
            embed.add_field(name=name, value=val or '—', inline=False)

    await interaction.followup.send(embed=embed)


@bot.tree.command(name='incidents', description='Active grouped incidents')
async def cmd_incidents(interaction: discord.Interaction):
    await interaction.response.defer()
    incidents = await nw.incidents()
    if incidents is None:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    active = [i for i in incidents if i.get('active') and not i.get('dismissed')]
    embed  = discord.Embed(
        title     = f'🔥 Active Incidents ({len(active)})',
        color     = C_RED if active else C_GREEN,
        timestamp = datetime.now(tz=timezone.utc),
    )

    if not active:
        embed.description = '✅ No active incidents'
    else:
        for inc in active[:10]:
            sev    = inc.get('severity','info')
            dur    = inc.get('duration_s', 0)
            dur_s  = f"{dur//3600}h {(dur%3600)//60}m" if dur > 3600 else f"{dur//60}m"
            iid    = inc.get('id','')[:8]
            ip     = inc.get('device_ip','')
            name   = f"{SEV_EMOJI.get(sev,'•')} {inc.get('title','?')[:40]}"
            val    = (f"`{ip}` • " if ip else '') + \
                     f"×{inc.get('count','?')} events • {dur_s}\n" + \
                     f"`/resolve {inc.get('id','')}` | `/block {ip}`" if ip else \
                     f"×{inc.get('count','?')} events • {dur_s}\n`/resolve {inc.get('id','')}`"
            embed.add_field(name=name, value=val, inline=False)

    await interaction.followup.send(embed=embed)


@bot.tree.command(name='block', description='Block an IP address via Pi-hole + show firewall commands')
@app_commands.describe(ip='IP address to block', reason='Reason for blocking (optional)')
async def cmd_block(interaction: discord.Interaction, ip: str, reason: str = 'Blocked via Discord'):
    await interaction.response.defer()

    # Basic IP validation
    parts = ip.strip().split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        await interaction.followup.send(f'❌ `{ip}` is not a valid IPv4 address', ephemeral=True)
        return

    result = await nw.block_ip(ip.strip(), reason)
    if not result:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    # GeoIP for context
    geo = await nw.geoip(ip)
    geo_str = ''
    if geo and geo.get('ok') and geo.get('data'):
        d = geo['data']
        geo_str = f"{d.get('flag','🌐')} {d.get('label','')} — {d.get('org','')}"

    embed = discord.Embed(
        title     = f'🚫 IP Blocked: `{ip}`',
        color     = C_RED,
        timestamp = datetime.now(tz=timezone.utc),
    )
    if geo_str:
        embed.description = geo_str

    ph = result.get('pihole', {})
    embed.add_field(
        name  = 'Pi-hole',
        value = '✅ Added to blocklist' if ph.get('ok') else f'⚠️ {ph.get("error","Failed")}',
        inline=False,
    )

    cmds = result.get('commands', {})
    if cmds:
        embed.add_field(
            name  = '🔧 Router / Firewall Commands',
            value = f"```bash\n"
                    f"# Drop all traffic from {ip}:\n"
                    f"{cmds.get('iptables_drop','')}\n\n"
                    f"# Undo:\n"
                    f"{cmds.get('iptables_undo','')}\n\n"
                    f"# nftables:\n"
                    f"{cmds.get('nftables_drop','')}\n```",
            inline=False,
        )

    embed.add_field(name='Reason',    value=reason, inline=True)
    embed.add_field(name='Blocked by', value=str(interaction.user), inline=True)
    embed.set_footer(text='Use /unblock to reverse')
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='unblock', description='Unblock an IP address')
@app_commands.describe(ip='IP address to unblock')
async def cmd_unblock(interaction: discord.Interaction, ip: str):
    await interaction.response.defer()
    result = await nw.unblock_ip(ip.strip())
    if not result:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    ph = result.get('pihole', {})
    embed = discord.Embed(
        title = f'✅ IP Unblocked: `{ip}`',
        color = C_GREEN,
        timestamp = datetime.now(tz=timezone.utc),
    )
    embed.add_field(
        name  = 'Pi-hole',
        value = '✅ Removed from blocklist' if ph.get('ok') else f'⚠️ {ph.get("error","Not found")}',
        inline=False,
    )
    embed.add_field(name='Unblocked by', value=str(interaction.user), inline=True)
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='resolve', description='Dismiss/resolve an incident by ID')
@app_commands.describe(incident_id='Incident ID (shown in /incidents or alert messages)')
async def cmd_resolve(interaction: discord.Interaction, incident_id: str):
    await interaction.response.defer()
    result = await nw.dismiss_incident(incident_id.strip())
    if result is None:
        await interaction.followup.send(f'❌ Could not resolve incident `{incident_id[:20]}`', ephemeral=True)
        return

    embed = discord.Embed(
        title     = f'✅ Incident Resolved',
        description = f'Incident `{incident_id[:20]}` has been marked as resolved.',
        color     = C_GREEN,
        timestamp = datetime.now(tz=timezone.utc),
    )
    embed.add_field(name='Resolved by', value=str(interaction.user), inline=True)
    # Remove from seen set so we'll get future recurrences
    _seen_incidents.discard(incident_id)
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='resolve_all', description='Dismiss all active incidents')
async def cmd_resolve_all(interaction: discord.Interaction):
    await interaction.response.defer()

    # Count active first
    incidents = await nw.incidents()
    active = [i for i in (incidents or []) if i.get('active') and not i.get('dismissed')]

    result = await nw.dismiss_all_incidents()
    if result is None:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    _seen_incidents.clear()
    embed = discord.Embed(
        title       = f'✅ All Incidents Resolved ({len(active)})',
        color       = C_GREEN,
        timestamp   = datetime.now(tz=timezone.utc),
    )
    embed.add_field(name='Resolved by', value=str(interaction.user), inline=True)
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='talkers', description='Top bandwidth users right now')
async def cmd_talkers(interaction: discord.Interaction):
    await interaction.response.defer()
    talkers = await nw.talkers()
    if talkers is None:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    embed = discord.Embed(
        title     = '📊 Top Bandwidth Users',
        color     = C_PURPLE,
        timestamp = datetime.now(tz=timezone.utc),
    )

    if not talkers:
        embed.description = 'No traffic data yet — wait a minute and try again'
    else:
        mx   = talkers[0].get('bytes', 1) or 1
        rows = []
        for i, t in enumerate(talkers[:10], 1):
            ip    = t.get('ip','?')
            label = t.get('label') or t.get('hostname') or ''
            bps   = t.get('bps', 0)
            b     = t.get('bytes', 0)
            bar   = '█' * round(b / mx * 8) + '░' * (8 - round(b / mx * 8))
            rows.append(f'`{i:>2}` `{ip:<16}` `{bar}` {_fmt_bytes(b)}'
                        + (f'  _{label[:18]}_' if label else ''))
        embed.description = '\n'.join(rows)

    await interaction.followup.send(embed=embed)


@bot.tree.command(name='scan', description='Trigger an active network scan')
async def cmd_scan(interaction: discord.Interaction):
    await interaction.response.defer()
    result = await nw.scan()
    if result is None:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    embed = discord.Embed(
        title       = '🔍 Network Scan Triggered',
        description = 'Active nmap + arp-scan running. Results will appear in NetWatch in ~30 seconds.',
        color       = C_CYAN,
        timestamp   = datetime.now(tz=timezone.utc),
    )
    embed.add_field(name='Triggered by', value=str(interaction.user), inline=True)
    await interaction.followup.send(embed=embed)


@bot.tree.command(name='dns', description='Recent DNS queries from an IP address')
@app_commands.describe(ip='IP address to look up')
async def cmd_dns(interaction: discord.Interaction, ip: str):
    await interaction.response.defer()
    result = await nw.dns_history(ip.strip())
    if result is None:
        await interaction.followup.send('❌ Cannot reach NetWatch Pro', ephemeral=True)
        return

    rows = result.get('rows', [])
    embed = discord.Embed(
        title     = f'🔎 DNS Queries from `{ip}` (last 24h)',
        color     = C_CYAN,
        timestamp = datetime.now(tz=timezone.utc),
    )

    if not rows:
        embed.description = 'No DNS queries found for this IP in the last 24 hours'
    else:
        lines = []
        for r in rows[:15]:
            ts    = datetime.fromtimestamp(r.get('ts', 0), tz=timezone.utc).strftime('%H:%M')
            query = r.get('query', '?')[:50]
            lines.append(f'`{ts}` {query}')
        embed.description = '\n'.join(lines)
        embed.set_footer(text=f'{result.get("total",0)} total queries')

    await interaction.followup.send(embed=embed)


@bot.tree.command(name='whois', description='GeoIP + WhoIs lookup for an IP address')
@app_commands.describe(ip='IP address to look up')
async def cmd_whois(interaction: discord.Interaction, ip: str):
    await interaction.response.defer()
    result = await nw.geoip(ip.strip())

    embed = discord.Embed(
        title     = f'🌍 WhoIs: `{ip}`',
        color     = C_CYAN,
        timestamp = datetime.now(tz=timezone.utc),
    )

    if result and result.get('ok') and result.get('data'):
        d = result['data']
        embed.description = f"{d.get('flag','🌐')} **{d.get('country','?')}**"
        if d.get('city'):       embed.add_field(name='City',         value=d['city'],         inline=True)
        if d.get('org'):        embed.add_field(name='Organisation', value=d['org'][:50],     inline=True)
        if d.get('asn'):        embed.add_field(name='ASN',          value=d['asn'][:50],     inline=True)
        if d.get('country_code'): embed.add_field(name='Country Code', value=d['country_code'], inline=True)
        embed.add_field(
            name  = 'Actions',
            value = f'`/block {ip}` — add to Pi-hole blocklist\n`/dns {ip}` — view DNS queries',
            inline=False,
        )
    elif result and result.get('pending'):
        embed.description = '⏳ GeoIP lookup started — try again in a few seconds'
        embed.color = C_AMBER
    else:
        embed.description = '🏠 Private/local IP — no GeoIP data available'

    await interaction.followup.send(embed=embed)


@bot.tree.command(name='help', description='Show all available commands')
async def cmd_help(interaction: discord.Interaction):
    embed = discord.Embed(
        title       = '📡 NetWatch Pro Bot — Commands',
        description = 'Monitor your network and respond to threats from Discord.',
        color       = C_CYAN,
    )
    commands_list = [
        ('/status',              'Network health score and summary'),
        ('/devices',             'Show all online devices'),
        ('/alerts [count]',      'Recent unresolved alerts'),
        ('/incidents',           'Active grouped incidents'),
        ('/talkers',             'Top bandwidth users right now'),
        ('/dns <ip>',            'Recent DNS queries from an IP'),
        ('/whois <ip>',          'GeoIP + WhoIs lookup'),
        ('/block <ip> [reason]', 'Block IP via Pi-hole + show firewall commands'),
        ('/unblock <ip>',        'Remove IP from Pi-hole blocklist'),
        ('/resolve <id>',        'Dismiss an incident by ID'),
        ('/resolve_all',         'Dismiss all active incidents'),
        ('/scan',                'Trigger active network scan'),
    ]
    for name, desc in commands_list:
        embed.add_field(name=f'`{name}`', value=desc, inline=False)

    embed.add_field(
        name  = '⚙️ Configuration',
        value = f'Connected to: `{NETWATCH_URL}`\n'
                f'Notifying in: <#{DISCORD_CHANNEL_ID}>\n'
                f'Poll interval: `{POLL_INTERVAL}s`\n'
                f'Min severity: `{MIN_NOTIFY_SEV.upper()}`',
        inline=False,
    )
    embed.set_footer(text='NetWatch Pro • github.com/yourusername/netwatch-pro')
    await interaction.response.send_message(embed=embed, ephemeral=True)


# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────
async def main():
    async with bot:
        await bot.start(DISCORD_TOKEN)

if __name__ == '__main__':
    asyncio.run(main())
