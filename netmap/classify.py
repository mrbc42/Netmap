"""Guess what kind of device each host is from ports, vendor, names, TTL and web titles.

Every rule adds points to a device type; the highest score wins. The rules are
deliberately simple so they are easy to extend for your own network.
"""

from __future__ import annotations

import re
from collections import defaultdict

from .models import Host, ScanResult
from .oui import is_randomized

DEVICE_TYPES = {
    # type: (label, colour)
    "router": ("Router / Gateway", "#f97316"),
    "firewall": ("Firewall", "#ef4444"),
    "switch": ("Switch", "#0ea5e9"),
    "access_point": ("Wireless AP", "#14b8a6"),
    "server": ("Server", "#8b5cf6"),
    "nas": ("NAS / Storage", "#6366f1"),
    "hypervisor": ("Hypervisor", "#a855f7"),
    "workstation": ("Computer", "#3b82f6"),
    "phone": ("Phone / Tablet", "#22c55e"),
    "printer": ("Printer", "#eab308"),
    "camera": ("Camera", "#f43f5e"),
    "media": ("TV / Media", "#ec4899"),
    "iot": ("IoT / Smart home", "#10b981"),
    "unknown": ("Unknown", "#64748b"),
}

# (regex on hostname/vendor/title/os, type, points)
KEYWORDS = [
    (r"\b(router|gateway|gw|fritz|edgerouter|mikrotik|routeros|openwrt|dd-wrt|pfsense|opnsense|draytek|livebox|speedport|hub)\b", "router", 3),
    (r"pfsense|opnsense|fortigate|fortinet|palo alto|sophos|watchguard|sonicwall|firewall|\bfw\d*\b", "firewall", 4),
    (r"\b(sw|switch)[-_\d]|\bswitch\b|catalyst|procurve|unifi switch|usw|gs\d{3}|tl-sg|netgear prosafe", "switch", 4),
    (r"\b(ap|wap)[-_\d]|access point|unifi ap|\buap\b|aruba ap|eap\d+|deco|orbi|mesh|airport", "access_point", 4),
    (r"synology|diskstation|qnap|truenas|freenas|unraid|readynas|\bnas\b|wd ?my ?cloud", "nas", 5),
    (r"proxmox|esxi|vmware|vcenter|hyper-v|xcp-ng", "hypervisor", 5),
    (r"printer|laserjet|officejet|deskjet|envy|epson|brother|canon|kyocera|xerox|ricoh|lexmark|\bmfc\b", "printer", 4),
    (r"camera|\bcam\b|ipcam|hikvision|dahua|amcrest|reolink|axis|foscam|nvr|dvr|doorbell|ring", "camera", 4),
    (r"iphone|ipad|android|pixel|galaxy|oneplus|xiaomi|redmi|huawei|oppo|phone", "phone", 4),
    (r"\btv\b|bravia|roku|chromecast|apple ?tv|fire ?tv|shield|sonos|plex|kodi|xbox|playstation|ps[45]|nintendo|denon|yamaha|lg ?webos|samsung tv|tizen", "media", 4),
    (r"hue|nest|tuya|espressif|esp\d+|shelly|tasmota|sonoff|tplink smart|kasa|echo|alexa|home ?assistant|zigbee|smartthings|withings|ecobee|wemo|bouffalo", "iot", 4),
    (r"macbook|imac|mac-?mini|desktop|laptop|-pc\b|\bpc\b|workstation|thinkpad|latitude|surface|win(dows)?-", "workstation", 3),
    (r"\bserver\b|\bsrv\b|ubuntu|debian|centos|rhel|docker|k8s|kube|raspberry|\bpi\b|\bvm\b", "server", 2),
    (r"ubiquiti|unifi|cisco|juniper|aruba|meraki|ruckus|tp-link|netgear|mikrotik", "switch", 1),
]

PORT_RULES = [
    ({9100}, "printer", 5), ({631}, "printer", 3), ({515}, "printer", 3),
    ({554}, "camera", 4), ({8554}, "camera", 3),
    ({5000, 5001}, "nas", 2), ({548}, "nas", 2), ({2049}, "nas", 2), ({873}, "nas", 2),
    ({8006}, "hypervisor", 6), ({902}, "hypervisor", 5),
    ({62078}, "phone", 6), ({5555}, "phone", 2),
    ({8008, 8009}, "media", 4), ({7000}, "media", 2), ({32400}, "media", 2), ({3689}, "media", 2),
    ({3389}, "workstation", 3), ({135, 445}, "workstation", 3), ({5357}, "workstation", 2),
    ({1883}, "iot", 3), ({8883}, "iot", 2), ({6668}, "iot", 4), ({8123}, "iot", 3),
    ({8291}, "router", 5), ({8728}, "router", 5), ({7547}, "router", 4), ({179}, "router", 4),
    ({161}, "switch", 2), ({23}, "switch", 1),
    ({22}, "server", 1), ({3306}, "server", 3), ({5432}, "server", 3), ({6379}, "server", 3),
    ({27017}, "server", 3), ({9200}, "server", 3), ({2375}, "server", 3), ({6443}, "server", 4),
    ({25}, "server", 2), ({389}, "server", 3), ({88}, "server", 2), ({1433}, "server", 3),
    ({9090}, "server", 1), ({10000}, "server", 2),
]


def score(host: Host) -> dict[str, float]:
    s: dict[str, float] = defaultdict(float)
    ports = host.open_ports
    text = " ".join([host.hostname, *host.hostnames, host.vendor, host.http_title,
                     host.http_server, host.os_guess, *(p.banner for p in host.ports)]).lower()

    if host.is_gateway:
        s["router"] += 10
    for pattern, kind, pts in KEYWORDS:
        if re.search(pattern, text):
            s[kind] += pts
    for needed, kind, pts in PORT_RULES:
        if needed <= ports:
            s[kind] += pts

    # TTL hints: 255 = network gear / Cisco, 128 = Windows, 64 = Linux/macOS/iOS.
    if host.ttl:
        if host.ttl > 128:
            s["switch"] += 1.5
            s["router"] += 1
        elif host.ttl > 64:
            s["workstation"] += 1.5
    if "windows" in text or "microsoft" in text:
        s["workstation"] += 2
    if is_randomized(host.mac) and len(ports) <= 2:
        s["phone"] += 3
    if "apple" in host.vendor.lower() and not ports - {62078, 7000, 5000, 49152}:
        s["phone"] += 1.5
    if {80, 443} & ports and {22, 23, 161} & ports and len(ports) <= 6:
        s["switch"] += 1  # small management plane - typical of network gear
    if {53} <= ports and not host.is_gateway:
        s["server"] += 2
    if host.is_local:
        s["workstation"] += 2
    if len(ports) >= 8 and not host.is_gateway:
        s["server"] += 2
    return s


def classify(host: Host) -> str:
    s = score(host)
    if not s:
        return "unknown"
    best = max(s, key=s.get)
    return best if s[best] >= 1 else "unknown"


def classify_all(result: ScanResult) -> None:
    for h in result.hosts:
        h.device_type = classify(h)
