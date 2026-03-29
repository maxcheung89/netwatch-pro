"""
Fetch IEEE OUI database at container startup and cache it.
Used as fallback when a MAC isn't in our static DB.
"""
import os, re, logging, urllib.request, sqlite3

log = logging.getLogger(__name__)
OUI_CACHE: dict = {}
OUI_CACHE_LOADED = False

def _load_from_nmap():
    """nmap ships an OUI file at /usr/share/nmap/nmap-mac-prefixes"""
    path = '/usr/share/nmap/nmap-mac-prefixes'
    if not os.path.exists(path):
        return 0
    count = 0
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    prefix = parts[0].upper().replace('-','').replace(':','')[:6]
                    vendor = parts[1].strip()
                    if prefix and vendor:
                        OUI_CACHE[prefix] = vendor
                        count += 1
    except Exception as e:
        log.warning(f"nmap OUI load: {e}")
    return count

def _load_from_arp_scan():
    """arp-scan ships an OUI file at /usr/share/arp-scan/ieee-oui.txt"""
    for path in ['/usr/share/arp-scan/ieee-oui.txt', '/usr/share/arp-scan/mac-vendor.txt']:
        if not os.path.exists(path): continue
        count = 0
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        prefix = parts[0].upper().replace('-','').replace(':','')[:6]
                        vendor = parts[1].strip()
                        if prefix and vendor:
                            OUI_CACHE[prefix] = vendor
                            count += 1
        except Exception as e:
            log.warning(f"arp-scan OUI load ({path}): {e}")
        if count > 0:
            return count
    return 0

def init_oui_cache():
    global OUI_CACHE_LOADED
    if OUI_CACHE_LOADED:
        return len(OUI_CACHE)
    n = _load_from_nmap()
    a = _load_from_arp_scan()
    total = len(OUI_CACHE)
    log.info(f"OUI cache: {total} entries (nmap={n}, arp-scan={a})")
    OUI_CACHE_LOADED = True
    return total

def lookup_vendor_dynamic(mac: str) -> str:
    """Look up vendor from the dynamic OUI cache."""
    prefix = mac.upper().replace(':','').replace('-','')[:6]
    return OUI_CACHE.get(prefix, '')
