"""MAC address -> vendor lookup.

A small built-in table covers the most common LAN vendors. For full coverage run
`netmap oui-update`, which downloads Wireshark's `manuf` database into the cache.
"""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path

MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "netmap" / "manuf"

BUILTIN = {
    "00:00:0c": "Cisco", "00:1b:54": "Cisco", "00:1e:13": "Cisco", "00:25:45": "Cisco",
    "58:97:bd": "Cisco", "70:69:5a": "Cisco", "f8:72:ea": "Cisco", "00:18:0a": "Cisco Meraki",
    "e0:55:3d": "Cisco Meraki", "88:15:44": "Cisco Meraki",
    "00:15:6d": "Ubiquiti", "04:18:d6": "Ubiquiti", "24:a4:3c": "Ubiquiti", "44:d9:e7": "Ubiquiti",
    "68:72:51": "Ubiquiti", "74:83:c2": "Ubiquiti", "78:8a:20": "Ubiquiti", "80:2a:a8": "Ubiquiti",
    "b4:fb:e4": "Ubiquiti", "dc:9f:db": "Ubiquiti", "e0:63:da": "Ubiquiti", "f0:9f:c2": "Ubiquiti",
    "fc:ec:da": "Ubiquiti", "18:e8:29": "Ubiquiti", "d0:21:f9": "Ubiquiti",
    "00:0c:42": "MikroTik", "4c:5e:0c": "MikroTik", "64:d1:54": "MikroTik", "b8:69:f4": "MikroTik",
    "d4:ca:6d": "MikroTik", "e4:8d:8c": "MikroTik", "18:fd:74": "MikroTik",
    "00:09:5b": "Netgear", "00:14:6c": "Netgear", "20:4e:7f": "Netgear", "a0:40:a0": "Netgear",
    "c4:04:15": "Netgear", "9c:3d:cf": "Netgear", "e0:91:f5": "Netgear",
    "14:cc:20": "TP-Link", "50:c7:bf": "TP-Link", "60:32:b1": "TP-Link", "98:da:c4": "TP-Link",
    "a4:2b:b0": "TP-Link", "c0:06:c3": "TP-Link", "ec:08:6b": "TP-Link", "f4:f2:6d": "TP-Link",
    "00:90:a9": "Western Digital", "00:11:32": "Synology", "90:09:d0": "Synology",
    "24:5e:be": "QNAP", "00:08:9b": "QNAP",
    "00:1a:11": "Google", "3c:5a:b4": "Google", "54:60:09": "Google", "f4:f5:d8": "Google",
    "f4:f5:e8": "Google", "d8:6c:63": "Google", "48:d6:d5": "Google",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "00:0e:58": "Sonos", "5c:aa:fd": "Sonos", "94:9f:3e": "Sonos", "b8:e9:37": "Sonos",
    "18:b4:30": "Nest", "64:16:66": "Nest",
    "44:65:0d": "Amazon", "68:54:fd": "Amazon", "74:c2:46": "Amazon", "fc:65:de": "Amazon",
    "b0:fc:0d": "Amazon", "f0:27:2d": "Amazon",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "d8:3a:dd": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    "24:0a:c4": "Espressif", "30:ae:a4": "Espressif", "84:f3:eb": "Espressif",
    "a4:cf:12": "Espressif", "bc:dd:c2": "Espressif", "c8:2b:96": "Espressif", "ec:fa:bc": "Espressif",
    "00:03:93": "Apple", "00:1b:63": "Apple", "00:25:00": "Apple", "28:cf:e9": "Apple",
    "3c:07:54": "Apple", "40:6c:8f": "Apple", "60:fb:42": "Apple", "78:31:c1": "Apple",
    "88:66:5a": "Apple", "a4:83:e7": "Apple", "ac:bc:32": "Apple", "d0:81:7a": "Apple",
    "f0:18:98": "Apple", "f4:0f:24": "Apple", "bc:d0:74": "Apple", "8c:85:90": "Apple",
    "00:12:fb": "Samsung", "5c:0a:5b": "Samsung", "8c:77:12": "Samsung", "a8:7c:01": "Samsung",
    "cc:6e:a4": "Samsung", "f8:04:2e": "Samsung",
    "00:1c:42": "Parallels", "00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:15:5d": "Microsoft Hyper-V", "02:42:ac": "Docker",
    "00:1e:0b": "HP", "3c:d9:2b": "HP", "9c:8e:99": "HP", "a0:d3:c1": "HP", "fc:15:b4": "HP",
    "00:80:77": "Brother", "30:05:5c": "Brother", "00:26:ab": "Seiko Epson", "64:eb:8c": "Seiko Epson",
    "00:00:85": "Canon", "18:0c:ac": "Canon",
    "44:19:b6": "Hikvision", "c0:56:e3": "Hikvision", "bc:ad:28": "Hikvision",
    "3c:ef:8c": "Dahua", "e0:50:8b": "Dahua", "9c:8e:cd": "Amcrest",
    "00:1a:a0": "Dell", "14:18:77": "Dell", "f8:bc:12": "Dell", "b8:ca:3a": "Dell",
    "00:21:cc": "Lenovo", "54:ee:75": "Lenovo", "8c:16:45": "Lenovo",
    "00:1f:c6": "ASUS", "2c:fd:a1": "ASUS", "04:d9:f5": "ASUS", "ac:22:0b": "ASUS",
    "00:24:d4": "FRITZ!Box (AVM)", "3c:a6:2f": "FRITZ!Box (AVM)", "c8:0e:14": "FRITZ!Box (AVM)",
    "00:1a:2b": "Ayecom", "00:0b:86": "Aruba", "24:de:c6": "Aruba", "94:b4:0f": "Aruba",
    "00:0d:b9": "PC Engines", "00:90:7f": "WatchGuard", "00:09:0f": "Fortinet", "90:6c:ac": "Fortinet",
    "00:1b:17": "Palo Alto Networks", "00:1d:aa": "DrayTek", "00:50:7f": "DrayTek",
    "00:04:4b": "Nvidia", "48:b0:2d": "Nvidia", "00:d8:61": "Micro-Star (MSI)",
    "d8:31:34": "Roku", "b0:a7:37": "Roku", "00:04:20": "Logitech", "00:05:cd": "Denon",
    "a4:77:33": "Google", "18:b9:05": "Hong Kong Bouffalo", "d4:a6:51": "Tuya", "10:d5:61": "Tuya",
    "7c:2e:bd": "Google", "00:e0:4c": "Realtek", "00:1d:c9": "GainSpan", "00:24:e4": "Withings",
}

_db: dict[str, str] | None = None


def _load() -> dict[str, str]:
    global _db
    if _db is not None:
        return _db
    db = dict(BUILTIN)
    if CACHE.exists():
        for line in CACHE.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) < 2 or "/" in cols[0]:
                continue  # skip /28 and /36 sub-allocations for simplicity
            prefix = cols[0].lower().replace("-", ":")
            if len(prefix) == 8:
                db[prefix] = cols[2].strip() if len(cols) > 2 and cols[2].strip() else cols[1].strip()
    _db = db
    return db


def is_randomized(mac: str) -> bool:
    """Locally administered MACs are used by phones/laptops for Wi-Fi privacy."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def lookup(mac: str) -> str:
    if not mac:
        return ""
    mac = mac.lower().replace("-", ":")
    vendor = _load().get(mac[:8], "")
    if not vendor and is_randomized(mac):
        return "Private (randomized MAC)"
    return vendor


def update() -> Path:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(MANUF_URL, timeout=60) as r:
        CACHE.write_bytes(r.read())
    global _db
    _db = None
    return CACHE
