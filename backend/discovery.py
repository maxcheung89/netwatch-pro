"""
NetWatch Pro — Layer 3: Network Discovery & Asset Identification
Expanded OUI DB (~300 entries), improved device fingerprinting,
DHCP monitoring, SQLite persistence
"""

import re, time, socket, threading, sqlite3, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict

log = logging.getLogger(__name__)

# ── OUI → Vendor (expanded ~300 prefixes) ─────────────────────
OUI_DB: Dict[str, str] = {
    # Apple
    '001124':'Apple','001451':'Apple','001636':'Apple','0017F2':'Apple',
    '0019E3':'Apple','001B63':'Apple','001CB3':'Apple','001D4F':'Apple',
    '001E52':'Apple','001EC2':'Apple','001F3A':'Apple','001F5B':'Apple',
    '002312':'Apple','0023DF':'Apple','002500':'Apple','002608':'Apple',
    '003065':'Apple','0050E4':'Apple','006171':'Apple','007040':'Apple',
    '0C3E9F':'Apple','0C4DE9':'Apple','0C74C2':'Apple','0CB31F':'Apple',
    '100D7F':'Apple','1058BF':'Apple','109A DD':'Apple','10DDB1':'Apple',
    '143755':'Apple','14BD61':'Apple','18AF61':'Apple','1C1AC0':'Apple',
    '1C5CF2':'Apple','1C9193':'Apple','200AB0':'Apple','20A2E4':'Apple',
    '20C9D0':'Apple','241EEB':'Apple','244B03':'Apple','248A07':'Apple',
    '28CFE9':'Apple','28E02C':'Apple','2C1F23':'Apple','2C200B':'Apple',
    '2CAE2B':'Apple','300AE4':'Apple','303193':'Apple','30F7C5':'Apple',
    '340285':'Apple','347C25':'Apple','38484C':'Apple','38B54D':'Apple',
    '3C0754':'Apple','3C15C2':'Apple','3CA832':'Apple','3CB815':'Apple',
    '40335B':'Apple','403CFC':'Apple','40A6D9':'Apple','40D81F':'Apple',
    '44D884':'Apple','44FB42':'Apple','48437C':'Apple','48A91C':'Apple',
    '4C3275':'Apple','4C74BF':'Apple','4C8D79':'Apple','50EAD6':'Apple',
    '54726F':'Apple','546782':'Apple','58B035':'Apple','58E2C2':'Apple',
    '5C5948':'Apple','5C8D4E':'Apple','5CF938':'Apple','60334B':'Apple',
    '60F4EB':'Apple','6470BC':'Apple','6C4008':'Apple','6C709F':'Apple',
    '6CAB31':'Apple','6CF049':'Apple','700514':'Apple','703C69':'Apple',
    '709C82':'Apple','70A2B3':'Apple','70DEE2':'Apple','74E1B6':'Apple',
    '745FB4':'Apple','7486E2':'Apple','74E2CB':'Apple','74E7C6':'Apple',
    '784F43':'Apple','788789':'Apple','78CA39':'Apple','78D75F':'Apple',
    '78FA6A':'Apple','7C5049':'Apple','7CF05F':'Apple','7CF11F':'Apple',
    '80006E':'Apple','80929F':'Apple','80B8AB':'Apple','80EA96':'Apple',
    '80ED2C':'Apple','840D8E':'Apple','845B12':'Apple','84788D':'Apple',
    '848506':'Apple','88C663':'Apple','88CB87':'Apple','8C2DAA':'Apple',
    '8C58BB':'Apple','8C7B9D':'Apple','8C7C92':'Apple','90272E':'Apple',
    '902347':'Apple','9027E4':'Apple','9038DF':'Apple','903C92':'Apple',
    '905C44':'Apple','90840D':'Apple','90B21F':'Apple','94E96A':'Apple',
    '98014A':'Apple','98B8E3':'Apple','98D6BB':'Apple','9C04EB':'Apple',
    '9C293F':'Apple','9C35EB':'Apple','9CF387':'Apple','A01826':'Apple',
    'A01C9B':'Apple','A02568':'Apple','A0278B':'Apple','A0D795':'Apple',
    'A4B197':'Apple','A4C361':'Apple','A4D18C':'Apple','A8667F':'Apple',
    'A88195':'Apple','A8BAE9':'Apple','A8BB50':'Apple','A8BEED':'Apple',
    'AC3C0B':'Apple','AC61EA':'Apple','ACE433':'Apple','ACF7F3':'Apple',
    'B065BD':'Apple','B418D1':'Apple','B48B19':'Apple','B4F0AB':'Apple',
    'B8098A':'Apple','B80986':'Apple','B8782E':'Apple','B88D12':'Apple',
    'B8C111':'Apple','BC3BAF':'Apple','BC4CC4':'Apple','BC52B7':'Apple',
    'BC6778':'Apple','BC9FEF':'Apple','BCA9A5':'Apple','C06392':'Apple',
    'C08997':'Apple','C09436':'Apple','C0CCF8':'Apple','C0F2FB':'Apple',
    'C41F86':'Apple','C82A14':'Apple','C8699F':'Apple','C86F1D':'Apple',
    'C8BFAC':'Apple','CC08E0':'Apple','CCA223':'Apple','CCCCCC':'Apple',
    'D003DF':'Apple','D04FB3':'Apple','D0A637':'Apple','D0C5F3':'Apple',
    'D4619D':'Apple','D4F46F':'Apple','D81D77':'Apple','D83062':'Apple',
    'D8A25E':'Apple','D8BB2C':'Apple','DC0C5C':'Apple','DC2B2A':'Apple',
    'DC37140':'Apple','DC9B9C':'Apple','DCA904':'Apple','DCFB02':'Apple',
    'E02759':'Apple','E0AC84':'Apple','E0B52D':'Apple','E0F5C6':'Apple',
    'E45BAB':'Apple','E49315':'Apple','E4C63D':'Apple','E4E0A6':'Apple',
    'E89E34':'Apple','E8802E':'Apple','E88D28':'Apple','E89235':'Apple',
    'EC2C73':'Apple','ECB29B':'Apple','ECC40D':'Apple','F01D4F':'Apple',
    'F02475':'Apple','F045DA':'Apple','F0768F':'Apple','F0B479':'Apple',
    'F0CB8B':'Apple','F0CEB4':'Apple','F0D1A9':'Apple','F0DCE2':'Apple',
    'F0DBE2':'Apple','F40B6B':'Apple','F41BB0':'Apple','F43E61':'Apple',
    'F45C89':'Apple','F4F15A':'Apple','F81EDF':'Apple','F82793':'Apple',
    'F8DFB2':'Apple','FC253F':'Apple','FC3274':'Apple','FCA13E':'Apple',
    'FCE998':'Apple',
    # Samsung
    '002339':'Samsung','00E064':'Samsung','08FC88':'Samsung',
    '10D542':'Samsung','1477A9':'Samsung','1C62B8':'Samsung',
    '1C66AA':'Samsung','20D390':'Samsung','28987B':'Samsung',
    '2C0E3D':'Samsung','2CAE2B':'Samsung','34145F':'Samsung',
    '3471C8':'Samsung','38AA3C':'Samsung','3C5A37':'Samsung',
    '40D3AE':'Samsung','4C3C16':'Samsung','50B7C3':'Samsung',
    '5C3C27':'Samsung','5CF6DC':'Samsung','60A10A':'Samsung',
    '64B310':'Samsung','6C8336':'Samsung','6CB7F4':'Samsung',
    '74E5F9':'Samsung','788C54':'Samsung','78408C':'Samsung',
    '7C1951':'Samsung','7CB9B5':'Samsung','84C9B2':'Samsung',
    '8803A8':'Samsung','88329B':'Samsung','90F1AA':'Samsung',
    '94351A':'Samsung','94D7B5':'Samsung','9883E7':'Samsung',
    '9C02D8':'Samsung','A0219B':'Samsung','A4EB76':'Samsung',
    'A8D1B8':'Samsung','AC5F3E':'Samsung','B047BF':'Samsung',
    'B44BD2':'Samsung','B47443':'Samsung','B4EF39':'Samsung',
    'B8F009':'Samsung','BC4486':'Samsung','BC8CCD':'Samsung',
    'C01173':'Samsung','C4576D':'Samsung','C44607':'Samsung',
    'C8BA94':'Samsung','CC07AB':'Samsung','CC2504':'Samsung',
    'D0176A':'Samsung','D0DFCA':'Samsung','D022BE':'Samsung',
    'D4E8B2':'Samsung','DC7144':'Samsung','E4402E':'Samsung',
    'E892A4':'Samsung','ECADCA':'Samsung','F025B7':'Samsung',
    'F0BF97':'Samsung','F0E77E':'Samsung','F47B5E':'Samsung',
    'F4F5DB':'Samsung','F4F5E8':'Samsung','F80CF3':'Samsung',
    'FC0FE6':'Samsung',
    # Raspberry Pi
    'B827EB':'Raspberry Pi','DC2B2A':'Raspberry Pi',
    'E45F01':'Raspberry Pi','DCA632':'Raspberry Pi',
    '2CCF67':'Raspberry Pi','D8E454':'Raspberry Pi',
    # Google / Nest / Chromecast
    '001A11':'Google','18B4D7':'Google','20DF3B':'Google',
    '2CBE08':'Google','48D705':'Google','4C1754':'Google',
    '54607E':'Google','58B03F':'Google','606077':'Google',
    '6805CA':'Google','6C5350':'Google','804F58':'Google',
    '86D6C8':'Google','948A6A':'Google','94EB2C':'Google',
    'A47733':'Google','A4DA22':'Google','AC1D19':'Google',
    'C03AAE':'Google','D446AB':'Google','DA86A4':'Google',
    'E4F0A2':'Google','F88FCA':'Google','FA00F1':'Google',
    # Amazon / Echo / Fire TV
    '0C4728':'Amazon','10AE60':'Amazon','18742E':'Amazon',
    '1C12B0':'Amazon','28EF01':'Amazon','34D270':'Amazon',
    '400293':'Amazon','40B4CD':'Amazon','440066':'Amazon',
    '44650D':'Amazon','484DCE':'Amazon','4CEFF7':'Amazon',
    '5057FB':'Amazon','506814':'Amazon','680571':'Amazon',
    '6C5669':'Amazon','747548':'Amazon','74C246':'Amazon',
    '788899':'Amazon','84D6D0':'Amazon','8871E5':'Amazon',
    '8C29FF':'Amazon','944A0C':'Amazon','A002DC':'Amazon',
    'A019E7':'Amazon','A44E31':'Amazon','A47733':'Amazon',
    'AC63BE':'Amazon','B003AF':'Amazon','B43A28':'Amazon',
    'B47C9C':'Amazon','BCF5AC':'Amazon','C0EE40':'Amazon',
    'C4A35D':'Amazon','C81F66':'Amazon','D4F16B':'Amazon',
    'D8D43C':'Amazon','F0272D':'Amazon','F0D2F1':'Amazon',
    'F40BFC':'Amazon','F4528B':'Amazon','F45B9D':'Amazon',
    'F81A67':'Amazon','FC65DE':'Amazon',
    # Cisco / Linksys
    '000142':'Cisco','000E84':'Cisco','0012DA':'Cisco',
    '001601':'Cisco','001BB1':'Cisco','001D45':'Cisco',
    '002155':'Cisco','0021A0':'Cisco','0025B5':'Cisco',
    '0026CB':'Cisco','003A9A':'Cisco','00407D':'Cisco',
    '005049':'Cisco','005079':'Cisco','00503E':'Cisco',
    '0050E2':'Cisco','00501D':'Cisco','006076':'Cisco',
    '0060B0':'Cisco','0060BF':'Cisco','206036':'Cisco',
    '2CFD55':'Cisco','44AD88':'Cisco','48F8B3':'Cisco',
    '5005AF':'Cisco','5475D0':'Cisco','58971C':'Cisco',
    '70EA1A':'Cisco','78DA6E':'Cisco','8C4016':'Cisco',
    '946A77':'Cisco','9849CB':'Cisco','A04CB9':'Cisco',
    'A89D21':'Cisco','ACF23C':'Cisco','B0AA77':'Cisco',
    'B4D06B':'Cisco','B8B900':'Cisco','CC46D6':'Cisco',
    'D4E880':'Cisco','DCF64C':'Cisco','E0D1EB':'Cisco',
    'E4AA5D':'Cisco','F01C2D':'Cisco','F43E61':'Cisco',
    # TP-Link
    '10BEF5':'TP-Link','14CC20':'TP-Link','1C3BF3':'TP-Link',
    '2008ED':'TP-Link','28285D':'TP-Link','34E894':'TP-Link',
    '3C52A1':'TP-Link','40169F':'TP-Link','50C7BF':'TP-Link',
    '54AF97':'TP-Link','589927':'TP-Link','5C628B':'TP-Link',
    '602AD0':'TP-Link','6466B3':'TP-Link','64700A':'TP-Link',
    '6C5CCC':'TP-Link','74DA38':'TP-Link','7886D9':'TP-Link',
    '8CFAB1':'TP-Link','907030':'TP-Link','944452':'TP-Link',
    '98DABC':'TP-Link','A0F3C1':'TP-Link','ACC21B':'TP-Link',
    'B0487A':'TP-Link','B0BE76':'TP-Link','B4B024':'TP-Link',
    'B8D812':'TP-Link','BC4605':'TP-Link','C46E1F':'TP-Link',
    'C8D3A3':'TP-Link','D8EB97':'TP-Link','E8DE27':'TP-Link',
    'ECF834':'TP-Link','F4F26D':'TP-Link','F81A67':'TP-Link',
    'FCC897':'TP-Link',
    # Ubiquiti
    '00156D':'Ubiquiti','0418D6':'Ubiquiti','0427E8':'Ubiquiti',
    '0CB8AD':'Ubiquiti','18E829':'Ubiquiti','24A43C':'Ubiquiti',
    '246895':'Ubiquiti','40A3CC':'Ubiquiti','44D9E7':'Ubiquiti',
    '4CA5D9':'Ubiquiti','60227C':'Ubiquiti','68722D':'Ubiquiti',
    '6C3B6B':'Ubiquiti','788A20':'Ubiquiti','802AA8':'Ubiquiti',
    'ACE7E5':'Ubiquiti','B4FBE4':'Ubiquiti','DC9FDB':'Ubiquiti',
    'E063DA':'Ubiquiti','E09F2A':'Ubiquiti','F09FC2':'Ubiquiti',
    'F4E2C6':'Ubiquiti','F8D111':'Ubiquiti','FCECDA':'Ubiquiti',
    # Intel
    '001C25':'Intel','001DEB':'Intel','002586':'Intel',
    '0026C6':'Intel','0CB37E':'Intel','105ABD':'Intel',
    '1418C3':'Intel','186098':'Intel','1C69A5':'Intel',
    '24F5A2':'Intel','2C16DB':'Intel','2C2DE9':'Intel',
    '4CBB58':'Intel','5002EC':'Intel','508702':'Intel',
    '60676D':'Intel','6C8814':'Intel','748DB8':'Intel',
    '7085C2':'Intel','8086F2':'Intel','8C8D28':'Intel',
    '8C70C4':'Intel','90E2BA':'Intel','946244':'Intel',
    'A0A8CD':'Intel','A4C3F0':'Intel','B43A28':'Intel',
    'B4B67C':'Intel','C85B76':'Intel','D05048':'Intel',
    'D8FC93':'Intel','E0069B':'Intel','E0D55E':'Intel',
    'E43848':'Intel','F40304':'Intel','F8966F':'Intel',
    # Netgear
    '000FB5':'Netgear','001422':'Netgear','001B2F':'Netgear',
    '001E2A':'Netgear','002275':'Netgear','00266C':'Netgear',
    '04A151':'Netgear','0840F3':'Netgear','1C5F2B':'Netgear',
    '200DC5':'Netgear','20E52A':'Netgear','28C68E':'Netgear',
    '2C3033':'Netgear','303D17':'Netgear','40163B':'Netgear',
    '44945C':'Netgear','587E61':'Netgear','6CB0CE':'Netgear',
    '74441A':'Netgear','803718':'Netgear','84189F':'Netgear',
    '900F0E':'Netgear','9C3DCF':'Netgear','A040A0':'Netgear',
    'A41850':'Netgear','A440A2':'Netgear','C4048A':'Netgear',
    'C86000':'Netgear','D476EA':'Netgear','E091F5':'Netgear',
    'E0469A':'Netgear',
    # Synology
    '001132':'Synology','0011320':'Synology','001CF0':'Synology',
    '080058':'Synology',
    # QNAP
    '00089A':'QNAP','245EBE':'QNAP','2C5467':'QNAP',
    '4C6BC7':'QNAP','6066B3':'QNAP',
    # Microsoft / Xbox
    '00155D':'Microsoft','00125A':'Microsoft','001DD8':'Microsoft',
    '0025AE':'Microsoft','28187B':'Microsoft','3C83A2':'Microsoft',
    '485073':'Microsoft','60451D':'Microsoft','7C1E52':'Microsoft',
    '9C4EBB':'Microsoft','BC8382':'Microsoft','C45AB1':'Microsoft',
    # Dell
    '001372':'Dell','001A4B':'Dell','00212B':'Dell',
    '001E4F':'Dell','0021E9':'Dell','18A99B':'Dell',
    '1CA3F6':'Dell','24B6FD':'Dell','2892E8':'Dell',
    '34E6AD':'Dell','44A842':'Dell','5CF9DD':'Dell',
    '788389':'Dell','BCF785':'Dell','C81F66':'Dell',
    'D4AE52':'Dell','F06DA1':'Dell','F48E92':'Dell',
    # HP / HPE
    '000854':'HP','001321':'HP','0014C2':'HP',
    '001560':'HP','001A4B':'HP','001B78':'HP',
    '0024EB':'HP','0024E8':'HP','00248C':'HP',
    '14584F':'HP','1CC1DE':'HP','20474A':'HP',
    '246AAB':'HP','3494FE':'HP','3C4A92':'HP',
    '380A4A':'HP','3C52A1':'HP','484CDD':'HP',
    '501869':'HP','5CF9DD':'HP','682275':'HP',
    '6CC217':'HP','78AC44':'HP','80C16E':'HP',
    '9457A5':'HP','98E7F4':'HP','B499BA':'HP',
    'C81F66':'HP','D4853A':'HP','F4CE46':'HP',
    # Aruba Networks
    '000B86':'Aruba','001A1E':'Aruba','24DE C6':'Aruba',
    '40E3D6':'Aruba','6CB311':'Aruba','84D47E':'Aruba',
    '94B40A':'Aruba','D8C7C8':'Aruba',
    # Xiaomi
    '0CF199':'Xiaomi','1062BD':'Xiaomi','14F65A':'Xiaomi',
    '20A79E':'Xiaomi','28E31F':'Xiaomi','286C07':'Xiaomi',
    '2CF403':'Xiaomi','3481F4':'Xiaomi','38A4ED':'Xiaomi',
    '64B473':'Xiaomi','7811DC':'Xiaomi','7851C8':'Xiaomi',
    '8CBEBE':'Xiaomi','AC2350':'Xiaomi','B0E235':'Xiaomi',
    'C40BCB':'Xiaomi','D4970B':'Xiaomi','F0B429':'Xiaomi',
    'F48B32':'Xiaomi','FC64BA':'Xiaomi',
    # Huawei
    '001E10':'Huawei','007751':'Huawei','00E0FC':'Huawei',
    '0806BB':'Huawei','1002B5':'Huawei','1C8E5C':'Huawei',
    '289458':'Huawei','2C9EFC':'Huawei','30D17E':'Huawei',
    '40D885':'Huawei','48A472':'Huawei','4C1FCC':'Huawei',
    '587B56':'Huawei','5CF96A':'Huawei','60DE44':'Huawei',
    '70723C':'Huawei','741AA4':'Huawei','7C60B7':'Huawei',
    '8001E4':'Huawei','845D78':'Huawei','88A2D7':'Huawei',
    '8C0D76':'Huawei','94049C':'Huawei','9810E0':'Huawei',
    '9C37F4':'Huawei','A086C6':'Huawei','B08F38':'Huawei',
    'B80E8F':'Huawei','BC614E':'Huawei','C4F081':'Huawei',
    'CC3995':'Huawei','D0271D':'Huawei','D4614F':'Huawei',
    'D878F5':'Huawei','DCA232':'Huawei','E0247F':'Huawei',
    'E04F43':'Huawei','E8CD2D':'Huawei','F4CBE6':'Huawei',
    'F8019A':'Huawei','F84ABF':'Huawei','FC48EF':'Huawei',
    # Sony / PlayStation
    '002618':'Sony','0019C5':'Sony','001FA7':'Sony',
    '002565':'Sony','0050F1':'Sony','28FDA1':'Sony',
    '30000D':'Sony','4C2678':'Sony','5065F3':'Sony',
    '54208B':'Sony','84C669':'Sony','BC60A7':'Sony',
    'F8D0AC':'Sony',
    # Nintendo
    '00195B':'Nintendo','002709':'Nintendo','00197E':'Nintendo',
    '0009BF':'Nintendo','002659':'Nintendo','0050F1':'Nintendo',
    '4C5007':'Nintendo','78878A':'Nintendo','A438CC':'Nintendo',
    'B8AE6E':'Nintendo','E00C7F':'Nintendo',
    # Roku
    '08050F':'Roku','B0A737':'Roku','B8339E':'Roku',
    'CC6EE4':'Roku','D4E235':'Roku','D8315A':'Roku',
    'DC3A5E':'Roku','F0A0A7':'Roku',
    # LG Electronics
    '000E62':'LG','001019':'LG','001E75':'LG',
    '0021FB':'LG','0025E5':'LG','2C54CF':'LG',
    '30766F':'LG','34DF2A':'LG','40E230':'LG',
    '4C544A':'LG','58E7C2':'LG','5C4985':'LG',
    '5C8B1B':'LG','60E3AC':'LG','6CB4B8':'LG',
    '74A5CE':'LG','78990D':'LG','7C6669':'LG',
    '8411E7':'LG','88C9D0':'LG','8CC8CD':'LG',
    '900E40':'LG','98C7F8':'LG','9C3B70':'LG',
    'A0F823':'LG','B8494E':'LG','BC4160':'LG',
    'BC814A':'LG','C083C4':'LG','C4360C':'LG',
    'C40291':'LG','CC2D8C':'LG','E80862':'LG',
    'E89EC4':'LG','EC8829':'LG','F017C4':'LG',
    'F8EAB4':'LG','F8F1B4':'LG',
    # Bosch / Nest / Smart Home
    '18B4D7':'Nest Labs','641260':'Nest Labs',
    'D8EB46':'Nest Labs','18B905':'Nest Labs',
    # Ring / Amazon Doorbells
    '3497F6':'Ring','2C63A7':'Ring','BC9DBC':'Ring',
    # Philips Hue
    '001788':'Signify/Philips','ECB5FA':'Signify/Philips',
    # ASUS
    '001FC6':'Asus','00E018':'Asus','0401F5':'Asus',
    '0800278':'Asus','10BF48':'Asus','107B44':'Asus',
    '1C872C':'Asus','1CB72C':'Asus','20CF30':'Asus',
    '2C56DC':'Asus','2CAE2B':'Asus','305A3A':'Asus',
    '38D547':'Asus','40167E':'Asus','485B39':'Asus',
    '4CA163':'Asus','5404A6':'Asus','549B12':'Asus',
    '5C514F':'Asus','60D2E4':'Asus','64006A':'Asus',
    '706F81':'Asus','74D02B':'Asus','787B8A':'Asus',
    '7894B4':'Asus','90E6BA':'Asus','AC220B':'Asus',
    'AC9E17':'Asus','B06EBF':'Asus','B0CDB8':'Asus',
    'B42E99':'Asus','BC02A5':'Asus','C860007':'Asus',
    'CADB02':'Asus','D027887':'Asus','E89D87':'Asus',
    'ECA86B':'Asus','F0795978':'Asus',
    # Lenovo
    '000D3A':'Lenovo','0024AE':'Lenovo','002490':'Lenovo',
    '001A6B':'Lenovo','001EC8':'Lenovo','005056':'VMware',
    '000C29':'VMware','001C14':'VMware',
    # Qualcomm / Atheros
    '000AF7':'Qualcomm','000F3D':'Qualcomm','001374':'Qualcomm',
    '004096':'Qualcomm','002186':'Atheros',
    # Broadcom (common in phones/laptops)
    '000AF7':'Broadcom','001018':'Broadcom',
}

def mac_to_vendor(mac: str) -> str:
    prefix = mac.upper().replace(':', '').replace('-', '')[:6]
    # 1. Check our static DB first (fastest)
    v = OUI_DB.get(prefix)
    if v: return v
    # 2. Check dynamic OUI cache (from nmap/arp-scan system files)
    try:
        from oui_fetch import lookup_vendor_dynamic
        v = lookup_vendor_dynamic(mac)
        if v: return v
    except ImportError:
        pass
    return 'Unknown'


# ── OS fingerprinting ──────────────────────────────────────────

def _ttl_to_os(ttl: int) -> str:
    if ttl <= 0:   return ''
    if ttl <= 64:  return 'Linux / Android / macOS'
    if ttl <= 128: return 'Windows'
    if ttl <= 255: return 'Cisco IOS / FreeBSD'
    return ''

def _window_to_os(win: int) -> str:
    if win in {65535, 8192, 16384, 65392, 64240}:  return 'Windows'
    if win in {5840, 14600, 29200, 65535, 43690}:  return 'Linux'
    if win in {65535, 32768, 16384, 131072, 65228}: return 'macOS'
    return ''

# ── Device type patterns ───────────────────────────────────────
DEVICE_PATTERNS = [
    (re.compile(r'iphone|ipad|ipod',        re.I), 'Phone / Tablet',    'iOS',     90),
    (re.compile(r'\bandroid\b|galaxy|pixel|oneplus|moto[r]?ola|redmi|poco', re.I),
                                                    'Phone / Tablet',    'Android', 85),
    (re.compile(r'raspberrypi|raspberry.?pi', re.I),'IoT / SBC',        'Linux',   95),
    (re.compile(r'\broku\b',                re.I), 'Streaming',         '',        90),
    (re.compile(r'firetv|fire.?tv|amazon.*tv', re.I),'Streaming',       'Fire OS', 85),
    (re.compile(r'appletv|apple.?tv',       re.I), 'Streaming',         'tvOS',    90),
    (re.compile(r'chromecast',              re.I), 'Streaming',         'Cast OS', 90),
    (re.compile(r'\bnvidia.?shield\b',      re.I), 'Streaming',         'Android', 85),
    (re.compile(r'printer|jetdirect|printserver|epson|canon.*mg|brother|lexmark|ricoh|xerox', re.I),
                                                    'Printer',           '',        85),
    (re.compile(r'\bring\b|doorbell',       re.I), 'Security Camera',   '',        80),
    (re.compile(r'nest|arlo|wyze|eufy|blink|hikvision|dahua|reolink', re.I),
                                                    'Security Camera',   '',        80),
    (re.compile(r'synology|qnap|nas|diskstation|readynas|freenas|truenas', re.I),
                                                    'NAS',               '',        90),
    (re.compile(r'unifi|ubiquiti|mikrotik|openwrt|dd-wrt|meraki|pfsense|opnsense', re.I),
                                                    'Router / AP',       '',        90),
    (re.compile(r'linksys|netgear|dlink|d-link|zyxel|tplink|tp-link|asus.*rt|orbi|eero|velop', re.I),
                                                    'Router / AP',       '',        80),
    (re.compile(r'macbook|imac|mac.?mini|mac.?pro|macpro', re.I),
                                                    'PC / Mac',          'macOS',   90),
    (re.compile(r'windows.*pc|desktop|latitude|thinkpad|elitebook|spectre|inspiron|xps', re.I),
                                                    'PC',                'Windows', 80),
    (re.compile(r'ubuntu|debian|fedora|centos|arch|kali|mint|raspbian', re.I),
                                                    'PC / Server',       'Linux',   80),
    (re.compile(r'\becho\b|alexa',          re.I), 'Smart Speaker',     'Amazon',  85),
    (re.compile(r'google.?home|homepod',    re.I), 'Smart Speaker',     '',        85),
    (re.compile(r'\bxbox\b',                re.I), 'Gaming Console',    '',        90),
    (re.compile(r'playstation|ps[345]\b',   re.I), 'Gaming Console',    '',        90),
    (re.compile(r'nintendo|switch|wii',     re.I), 'Gaming Console',    '',        85),
    (re.compile(r'samsung.*tv|lg.*tv|vizio|bravia|hisense.*tv|tcl.*tv|sony.*tv', re.I),
                                                    'Smart TV',          '',        85),
    (re.compile(r'\btv\b|\bsmartTV\b',      re.I), 'Smart TV',          '',        60),
    (re.compile(r'cisco|catalyst|nexus|juniper|paloalto|fortinet', re.I),
                                                    'Network Equipment', '',        90),
    (re.compile(r'vmware|esxi|hyperv|proxmox|virtualbox', re.I),
                                                    'Hypervisor / VM',   '',        85),
    (re.compile(r'switch|managed.*switch|sgs|sg\d{3}', re.I),
                                                    'Network Switch',    '',        75),
    (re.compile(r'hp.*server|dell.*server|poweredge|proliant', re.I),
                                                    'Server',            '',        85),
    (re.compile(r'raspberry|arduino|esp32|esp8266|nodemcu|wemos', re.I),
                                                    'IoT / Embedded',    '',        85),
    (re.compile(r'philips.*hue|lifx|wled|tasmota|shelly|tuya|sonoff', re.I),
                                                    'Smart Light / IoT', '',        85),
    (re.compile(r'thermostat|ecobee|honeywell|tado', re.I),
                                                    'Smart Thermostat',  '',        85),
]

def guess_device(hostname: str, dhcp_hostname: str, dhcp_vendor: str, vendor: str):
    combined = ' '.join([hostname, dhcp_hostname, dhcp_vendor, vendor])
    for pattern, dtype, os_hint, conf in DEVICE_PATTERNS:
        if pattern.search(combined):
            return dtype, os_hint, conf
    # Vendor-based fallback
    v = vendor.lower()
    if 'apple'       in v: return 'Apple Device',       'Apple',   60
    if 'raspberry'   in v: return 'IoT / SBC',          'Linux',   90
    if 'samsung'     in v: return 'Samsung Device',     '',        55
    if 'amazon'      in v: return 'Amazon Device',      '',        60
    if 'google'      in v: return 'Google Device',      '',        60
    if 'cisco'       in v: return 'Network Equipment',  '',        70
    if 'ubiquiti'    in v: return 'Router / AP',        '',        80
    if 'tp-link'     in v: return 'Router / AP',        '',        70
    if 'netgear'     in v: return 'Router / AP',        '',        65
    if 'asus'        in v: return 'Router / PC',        '',        55
    if 'intel'       in v: return 'PC',                 '',        45
    if 'microsoft'   in v: return 'PC',                 'Windows', 55
    if 'dell'        in v: return 'PC / Server',        '',        50
    if 'hp' == v or 'hewlett' in v: return 'PC / Printer','',      45
    if 'synology'    in v: return 'NAS',                '',        90
    if 'qnap'        in v: return 'NAS',                '',        90
    if 'roku'        in v: return 'Streaming',          '',        90
    if 'sony'        in v: return 'Sony Device',        '',        50
    if 'nintendo'    in v: return 'Gaming Console',     '',        80
    if 'lg'          == v: return 'LG Device',          '',        50
    if 'vmware'      in v: return 'Hypervisor / VM',    '',        90
    if 'huawei'      in v: return 'Huawei Device',      '',        55
    if 'xiaomi'      in v: return 'Xiaomi Device',      '',        55
    if 'signify'     in v or 'philips' in v: return 'Smart Light','',75
    return 'Unknown', '', 10


# ── DeviceFingerprint ──────────────────────────────────────────

@dataclass
class DeviceFingerprint:
    mac: str
    ip: str = ''
    hostname: str = ''
    vendor: str = ''
    os_guess: str = ''
    device_type: str = ''
    confidence: int = 0
    dhcp_hostname: str = ''
    dhcp_vendor: str = ''
    ttl_seen: int = 0
    tcp_window: int = 0
    open_ports: List[int] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_online: bool = True
    label: str = ''
    alert_on_join: bool = True

    def to_dict(self) -> dict:
        return {
            'mac':          self.mac,
            'ip':           self.ip,
            'hostname':     self.label or self.hostname or self.dhcp_hostname,
            'raw_hostname': self.hostname,
            'vendor':       self.vendor,
            'os_guess':     self.os_guess,
            'device_type':  self.device_type,
            'confidence':   self.confidence,
            'dhcp_hostname':self.dhcp_hostname,
            'dhcp_vendor':  self.dhcp_vendor,
            'first_seen':   self.first_seen,
            'last_seen':    self.last_seen,
            'is_online':    self.is_online,
            'label':        self.label,
            'alert_on_join':self.alert_on_join,
            'open_ports':   self.open_ports,
            'ttl':          self.ttl_seen,
        }


# ── DB schema ──────────────────────────────────────────────────
DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, vendor TEXT,
    os_guess TEXT, device_type TEXT, dhcp_hostname TEXT, dhcp_vendor TEXT,
    first_seen REAL, last_seen REAL, is_online INTEGER DEFAULT 1,
    label TEXT DEFAULT '', alert_on_join INTEGER DEFAULT 1, open_ports TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT, ip TEXT, event_type TEXT, timestamp REAL, details TEXT
);
"""


class AssetInventory:
    def __init__(self, db_path='/app/data/devices.db'):
        self.db_path = db_path
        self._devices: Dict[str, DeviceFingerprint] = {}
        self._ip_to_mac: Dict[str, str] = {}
        self._topology: Dict[str, set] = defaultdict(set)
        self._lock = threading.RLock()
        self._init_db()
        self._load_db()

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=5)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        try:
            conn = self._conn()
            conn.executescript(DB_SCHEMA)
            conn.commit(); conn.close()
            log.info(f"Database ready: {self.db_path}")
        except Exception as e:
            log.error(f"DB init: {e}")

    def _load_db(self):
        try:
            conn = self._conn()
            rows = conn.execute('SELECT * FROM devices').fetchall()
            conn.close()
            for r in rows:
                ports = [int(x) for x in (r['open_ports'] or '').split(',') if x]
                fp = DeviceFingerprint(
                    mac=r['mac'], ip=r['ip'] or '', hostname=r['hostname'] or '',
                    vendor=r['vendor'] or '', os_guess=r['os_guess'] or '',
                    device_type=r['device_type'] or '',
                    dhcp_hostname=r['dhcp_hostname'] or '',
                    dhcp_vendor=r['dhcp_vendor'] or '',
                    first_seen=r['first_seen'] or time.time(),
                    last_seen=r['last_seen'] or time.time(),
                    is_online=bool(r['is_online']), label=r['label'] or '',
                    alert_on_join=bool(r['alert_on_join']), open_ports=ports,
                )
                self._devices[fp.mac] = fp
                if fp.ip: self._ip_to_mac[fp.ip] = fp.mac
            log.info(f"Loaded {len(self._devices)} devices from DB")
        except Exception as e:
            log.warning(f"DB load: {e}")

    def _save(self, fp: DeviceFingerprint):
        try:
            conn = self._conn()
            conn.execute('''INSERT OR REPLACE INTO devices
                (mac,ip,hostname,vendor,os_guess,device_type,dhcp_hostname,dhcp_vendor,
                 first_seen,last_seen,is_online,label,alert_on_join,open_ports)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (fp.mac,fp.ip,fp.hostname,fp.vendor,fp.os_guess,fp.device_type,
                 fp.dhcp_hostname,fp.dhcp_vendor,fp.first_seen,fp.last_seen,
                 int(fp.is_online),fp.label,int(fp.alert_on_join),
                 ','.join(map(str, fp.open_ports))))
            conn.commit(); conn.close()
        except Exception as e:
            log.debug(f"DB save: {e}")

    def _add_event(self, mac, ip, event_type, details=''):
        try:
            conn = self._conn()
            conn.execute('INSERT INTO events (mac,ip,event_type,timestamp,details) VALUES (?,?,?,?,?)',
                         (mac, ip, event_type, time.time(), details))
            conn.commit(); conn.close()
        except Exception: pass

    def process_packet(self, pkt):
        mac, ip = None, None
        if pkt.arp_sender_mac and pkt.arp_sender_mac != '00:00:00:00:00:00':
            mac = pkt.arp_sender_mac; ip = pkt.arp_sender_ip
        elif pkt.src_mac and pkt.src_ip:
            mac = pkt.src_mac; ip = pkt.src_ip
        if not mac or mac in ('ff:ff:ff:ff:ff:ff','00:00:00:00:00:00'):
            return None
        if pkt.src_ip and pkt.dst_ip:
            with self._lock:
                self._topology[pkt.src_ip].add(pkt.dst_ip)
        now = time.time()
        with self._lock:
            fp = self._devices.get(mac)
            is_new = fp is None
            was_offline = fp is not None and not fp.is_online
            if is_new:
                vendor = mac_to_vendor(mac)
                fp = DeviceFingerprint(mac=mac, ip=ip or '', vendor=vendor,
                                       first_seen=now, last_seen=now)
                self._devices[mac] = fp
            else:
                fp.last_seen = now; fp.is_online = True
                if ip and ip != fp.ip: fp.ip = ip
            if ip: self._ip_to_mac[ip] = mac
            if pkt.ttl > 0 and fp.ttl_seen == 0:
                fp.ttl_seen = pkt.ttl
                os = _ttl_to_os(pkt.ttl)
                if os and not fp.os_guess:
                    fp.os_guess = os; fp.confidence = max(fp.confidence, 40)
            if pkt.is_tcp_syn and fp.tcp_window == 0 and pkt.payload_len > 0:
                fp.tcp_window = pkt.payload_len
                os = _window_to_os(pkt.payload_len)
                if os and not fp.os_guess:
                    fp.os_guess = os; fp.confidence = max(fp.confidence, 55)
            # Re-run device type detection every time until confident
            if fp.confidence < 70 or not fp.device_type or fp.device_type == 'Unknown':
                dtype, os_hint, conf = guess_device(fp.hostname, fp.dhcp_hostname, fp.dhcp_vendor, fp.vendor)
                if conf > fp.confidence:
                    fp.device_type = dtype
                    if os_hint and not fp.os_guess: fp.os_guess = os_hint
                    fp.confidence = conf
            result = (fp, is_new, was_offline)
        if is_new or was_offline:
            self._add_event(mac, ip or '', 'joined', 'passive')
            threading.Thread(target=self._save, args=(fp,), daemon=True).start()
        return result

    def process_dhcp(self, mac, ip, hostname='', vendor_class='', source='dhcp'):
        with self._lock:
            fp = self._devices.get(mac)
            if not fp:
                fp = DeviceFingerprint(mac=mac, ip=ip, vendor=mac_to_vendor(mac))
                self._devices[mac] = fp
            if hostname:     fp.dhcp_hostname = hostname
            if vendor_class: fp.dhcp_vendor   = vendor_class
            fp.ip = ip; self._ip_to_mac[ip] = mac
            dtype, os_hint, conf = guess_device(fp.hostname, fp.dhcp_hostname, fp.dhcp_vendor, fp.vendor)
            if conf > fp.confidence:
                fp.device_type = dtype
                if os_hint: fp.os_guess = os_hint
                fp.confidence = conf
        threading.Thread(target=self._save, args=(fp,), daemon=True).start()

    def mark_offline(self, active_macs):
        now = time.time()
        with self._lock:
            for mac, fp in self._devices.items():
                if fp.is_online and mac not in active_macs:
                    fp.is_online = False; fp.last_seen = now
                    self._add_event(mac, fp.ip, 'left', 'not seen in scan')
                    threading.Thread(target=self._save, args=(fp,), daemon=True).start()

    def update_device(self, mac, **kwargs):
        with self._lock:
            fp = self._devices.get(mac)
            if not fp: return False
            if 'label'         in kwargs: fp.label         = str(kwargs['label']).strip()
            if 'hostname'      in kwargs: fp.hostname       = str(kwargs['hostname']).strip()
            if 'device_type'   in kwargs: fp.device_type    = str(kwargs['device_type']).strip()
            if 'alert_on_join' in kwargs: fp.alert_on_join  = bool(kwargs['alert_on_join'])
        threading.Thread(target=self._save, args=(fp,), daemon=True).start()
        return True

    def get_by_mac(self, mac: str):
        with self._lock:
            fp = self._devices.get(mac.lower().replace('-',':'))
            return fp.to_dict() if fp else None

    def resolve_hostnames(self, limit=30):
        with self._lock:
            targets = [(m, fp.ip) for m, fp in self._devices.items() if fp.ip and not fp.hostname][:limit]
        def _resolve(mac, ip):
            try:
                name = socket.gethostbyaddr(ip)[0]
                with self._lock:
                    fp = self._devices.get(mac)
                    if fp:
                        fp.hostname = name
                        dtype, os_hint, conf = guess_device(fp.hostname, fp.dhcp_hostname, fp.dhcp_vendor, fp.vendor)
                        if conf > fp.confidence:
                            fp.device_type = dtype
                            if os_hint: fp.os_guess = os_hint
                            fp.confidence = conf
                        threading.Thread(target=self._save, args=(fp,), daemon=True).start()
            except Exception: pass
        for mac, ip in targets:
            threading.Thread(target=_resolve, args=(mac,ip), daemon=True).start()

    def get_all(self):
        with self._lock: return [fp.to_dict() for fp in self._devices.values()]
    def get_online(self):
        with self._lock: return [fp.to_dict() for fp in self._devices.values() if fp.is_online]
    def get_topology(self):
        with self._lock: return {k: list(v)[:20] for k, v in list(self._topology.items())[:60]}
    def get_events(self, limit=100):
        try:
            conn = self._conn()
            rows = conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?',(limit,)).fetchall()
            conn.close(); return [dict(r) for r in rows]
        except: return []
    def stats(self):
        with self._lock:
            total = len(self._devices); online = sum(1 for fp in self._devices.values() if fp.is_online)
            by_type = defaultdict(int); by_vendor = defaultdict(int)
            for fp in self._devices.values():
                by_type[fp.device_type or 'Unknown'] += 1
                by_vendor[(fp.vendor or 'Unknown')[:20]] += 1
        return {'total':total,'online':online,'offline':total-online,
                'by_type':dict(by_type),'by_vendor':dict(sorted(by_vendor.items(),key=lambda x:-x[1])[:12])}
