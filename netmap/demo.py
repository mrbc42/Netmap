"""A made-up small-office network for previewing the diagram without scanning."""

from __future__ import annotations

from .models import Hop, Host, Port, ScanResult
from .services import SERVICES


def _h(ip, name, mac, vendor, ports, ttl=64, **kw) -> Host:
    banners = kw.pop("banners", {})
    subnet = "10.10.20.0/24" if ip.startswith("10.10.20.") else "192.168.1.0/24"
    return Host(ip=ip, hostname=name, hostnames=[name] if name else [], mac=mac, vendor=vendor, ttl=ttl,
                latency_ms=round(0.4 + (int(ip.split(".")[-1]) % 7) * 0.9, 2), subnet=subnet,
                ports=[Port(p, "tcp", SERVICES.get(p, ""), banners.get(p, "")) for p in ports],
                discovered_by=["icmp", "arp"], **kw)


def demo_result() -> ScanResult:
    hosts = [
        _h("192.168.1.1", "udm-pro", "74:83:c2:1a:00:01", "Ubiquiti", [22, 53, 80, 443], is_gateway=True,
           http_title="UniFi OS", banners={22: "SSH-2.0-OpenSSH_8.4p1 Debian", 443: "UniFi OS"}),
        _h("192.168.1.2", "core-switch-24", "74:83:c2:1a:00:02", "Ubiquiti", [22, 80, 161], ttl=255,
           http_title="UniFi Switch 24 PoE"),
        _h("192.168.1.3", "ap-office", "74:83:c2:1a:00:03", "Ubiquiti", [22, 80], http_title="UniFi AP U6 Pro"),
        _h("192.168.1.4", "ap-warehouse", "74:83:c2:1a:00:04", "Ubiquiti", [22]),
        _h("192.168.1.10", "diskstation", "00:11:32:aa:bb:01", "Synology", [22, 80, 139, 443, 445, 548, 2049, 5000, 5001],
           http_title="Synology DiskStation", os_guess="Synology DS920+"),
        _h("192.168.1.11", "pve01", "00:1a:a0:cc:00:11", "Dell", [22, 111, 3128, 8006], http_title="pve01 - Proxmox Virtual Environment"),
        _h("192.168.1.12", "pihole", "dc:a6:32:00:11:12", "Raspberry Pi", [22, 53, 80], http_title="Pi-hole Admin Console"),
        _h("192.168.1.13", "homeassistant", "dc:a6:32:00:11:13", "Raspberry Pi", [22, 1883, 8123], http_title="Home Assistant"),
        _h("192.168.1.14", "git", "52:54:00:12:34:14", "QEMU/KVM", [22, 80, 443, 5432], http_title="Gitea"),
        _h("192.168.1.20", "hp-laserjet", "3c:d9:2b:00:00:20", "HP", [80, 443, 515, 631, 9100], http_title="HP LaserJet M404"),
        _h("192.168.1.30", "cam-frontdoor", "44:19:b6:00:00:30", "Hikvision", [80, 554, 8000]),
        _h("192.168.1.31", "cam-yard", "44:19:b6:00:00:31", "Hikvision", [80, 554, 8000]),
        _h("192.168.1.50", "DESKTOP-7QH2K", "00:d8:61:aa:00:50", "Micro-Star (MSI)", [135, 139, 445, 3389, 5357], ttl=128, os_guess="Windows 11"),
        _h("192.168.1.51", "LAPTOP-ANNA", "8c:16:45:aa:00:51", "Lenovo", [135, 139, 445], ttl=128),
        _h("192.168.1.52", "Macbook-Pro", "f0:18:98:aa:00:52", "Apple", [22, 5000, 7000], is_local=True),
        _h("192.168.1.60", "iPhone", "f4:0f:24:aa:00:60", "Apple", [62078]),
        _h("192.168.1.61", "Pixel-8", "2a:7b:3c:aa:00:61", "Private (randomized MAC)", []),
        _h("192.168.1.70", "Living-Room-TV", "f8:04:2e:aa:00:70", "Samsung", [8001, 8008, 8009, 9197]),
        _h("192.168.1.71", "Sonos-Kitchen", "5c:aa:fd:aa:00:71", "Sonos", [1400, 1443]),
        _h("192.168.1.80", "Philips-hue", "00:17:88:aa:00:80", "Philips Hue", [80, 443]),
        _h("192.168.1.81", "shelly-plug-office", "c8:2b:96:aa:00:81", "Espressif", [80]),
        _h("192.168.1.82", "", "d4:a6:51:aa:00:82", "Tuya", [6668]),
        _h("10.10.20.1", "lab-gw", "00:0c:42:00:20:01", "MikroTik", [22, 53, 80, 8291, 8728], ttl=64),
        _h("10.10.20.10", "k8s-master", "52:54:00:20:00:10", "QEMU/KVM", [22, 6443, 10250]),
        _h("10.10.20.11", "k8s-worker-1", "52:54:00:20:00:11", "QEMU/KVM", [22, 10250]),
        _h("10.10.20.12", "k8s-worker-2", "52:54:00:20:00:12", "QEMU/KVM", [22, 10250]),
        _h("10.10.20.20", "postgres-01", "52:54:00:20:00:20", "QEMU/KVM", [22, 5432]),
        _h("10.10.20.21", "redis-01", "52:54:00:20:00:21", "QEMU/KVM", [22, 6379]),
    ]
    return ScanResult(
        hosts=hosts, subnets=["192.168.1.0/24", "10.10.20.0/24"], gateway="192.168.1.1", local_ip="192.168.1.52",
        hops=[Hop(1, "192.168.1.1", "udm-pro", 0.6), Hop(2, "100.64.0.1", "", 7.9),
              Hop(3, "62.115.42.17", "be-1.edge1.isp.net", 9.4), Hop(4, "72.14.209.81", "", 11.2)],
        started="2026-10-23 09:30:00", duration_s=41.7, engine="demo")
