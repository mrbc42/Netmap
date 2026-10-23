"""Discover facts about the local machine's network: IP, subnet, gateway, ARP cache."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import struct
import subprocess

SYSTEM = platform.system()


def _run(cmd: list[str], timeout: float = 5) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def local_ip() -> str:
    """IP of the interface that holds the default route (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_gateway() -> str:
    if os.path.exists("/proc/net/route"):
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) > 2 and cols[1] == "00000000" and int(cols[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(cols[2], 16)))
    if SYSTEM == "Darwin":
        m = re.search(r"gateway:\s*(\S+)", _run(["route", "-n", "get", "default"]))
        if m:
            return m.group(1)
    if SYSTEM == "Windows":
        for line in _run(["route", "print", "0.0.0.0"]).splitlines():
            cols = line.split()
            if len(cols) >= 3 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                return cols[2]
    for line in _run(["netstat", "-rn"]).splitlines():
        cols = line.split()
        if len(cols) >= 2 and cols[0] in ("default", "0.0.0.0"):
            return cols[1]
    return ""


# Bridges and tunnels created by containers, VMs and VPNs - never the "real" LAN.
VIRTUAL_PREFIXES = ("lo", "podman", "docker", "cni", "veth", "virbr", "vnet", "br-", "vmnet", "vboxnet",
                    "tun", "tap", "wg", "tailscale", "zt", "flannel", "cali", "kube", "lxc", "lxd", "incus")


def is_virtual(name: str) -> bool:
    return name.lower().startswith(VIRTUAL_PREFIXES)


def interfaces() -> list[dict]:
    """IPv4 interfaces as [{'name', 'ip', 'netmask', 'network'}], loopback excluded."""
    found: list[tuple[str, str, str]] = []
    try:
        import psutil  # optional, cross-platform

        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.netmask:
                    found.append((name, a.address, a.netmask))
    except ImportError:
        if SYSTEM in ("Linux", "Darwin"):
            import fcntl

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for _, name in socket.if_nameindex():
                    ifreq = struct.pack("256s", name.encode()[:15])
                    try:
                        ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])      # SIOCGIFADDR
                        mask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, ifreq)[20:24])    # SIOCGIFNETMASK
                        found.append((name, ip, mask))
                    except OSError:
                        continue
            finally:
                s.close()
        if not found and SYSTEM == "Windows":
            out = _run(["ipconfig"])
            for m in re.finditer(r"IPv4 Address[ .]*:\s*([\d.]+).*?Subnet Mask[ .]*:\s*([\d.]+)", out, re.S):
                found.append((f"if{len(found)}", m.group(1), m.group(2)))
        if not found and SYSTEM == "Darwin":
            for m in re.finditer(r"^(\S+):.*?(?=^\S|\Z)", _run(["ifconfig"]), re.S | re.M):
                for ip, hexmask in re.findall(r"inet ([\d.]+) netmask (0x[0-9a-f]+)", m.group(0)):
                    found.append((m.group(1), ip, socket.inet_ntoa(struct.pack(">L", int(hexmask, 16)))))
    out = []
    for name, ip, mask in found:
        if ip.startswith("127."):
            continue
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        out.append({"name": name, "ip": ip, "netmask": mask, "network": str(net), "virtual": is_virtual(name)})
    return out


def default_route_interface() -> str:
    """Name of the interface carrying the default route (Linux; '' elsewhere)."""
    best, metric = "", None
    if os.path.exists("/proc/net/route"):
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) > 6 and cols[1] == "00000000" and (metric is None or int(cols[6]) < metric):
                    best, metric = cols[0], int(cols[6])
    return best


def routed_networks() -> list[str]:
    """Private networks the routing table reaches through another router (Linux)."""
    nets = []
    if os.path.exists("/proc/net/route"):
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) < 8 or cols[1] == "00000000" or cols[2] == "00000000":
                    continue
                dest = socket.inet_ntoa(struct.pack("<L", int(cols[1], 16)))
                mask = socket.inet_ntoa(struct.pack("<L", int(cols[7], 16)))
                net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
                if net.is_private and net.prefixlen >= 8:
                    nets.append(str(net))
    return nets


def primary_interface() -> dict | None:
    """The LAN interface: the one with the default route, unless that is a VPN/bridge."""
    ifaces = interfaces()
    real = [i for i in ifaces if not i["virtual"]]
    gw, route_if, lip = default_gateway(), default_route_interface(), local_ip()

    def contains(i, ip):
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(i["network"])
        except ValueError:
            return False

    for pick in (
        lambda: next(i for i in real if i["name"] == route_if),
        lambda: next(i for i in real if gw and contains(i, gw)),
        lambda: next(i for i in real if i["ip"] == lip),
        lambda: real[0],
        lambda: next(i for i in ifaces if i["ip"] == lip),
    ):
        try:
            return pick()
        except (StopIteration, IndexError):
            continue
    return None


def local_subnet(max_hosts: int = 4096) -> str:
    """CIDR of the local LAN, e.g. '192.168.1.0/24'. Huge networks shrink to the /24 around us."""
    iface = primary_interface()
    if not iface:
        return str(ipaddress.ip_network(f"{local_ip()}/24", strict=False))
    net = ipaddress.ip_network(iface["network"])
    if net.num_addresses > max_hosts:
        net = ipaddress.ip_network(f"{iface['ip']}/24", strict=False)
    return str(net)


def host_addresses() -> tuple[str, list[str]]:
    """(main LAN address, all addresses) of this machine."""
    primary = primary_interface()
    main = primary["ip"] if primary else local_ip()
    return main, list(dict.fromkeys([main] + [i["ip"] for i in interfaces()]))


def in_container() -> bool:
    return os.path.exists("/run/.containerenv") or os.path.exists("/.dockerenv")


def arp_table() -> dict[str, str]:
    """IP -> MAC from the OS neighbour cache. Populated as a side effect of scanning."""
    table: dict[str, str] = {}
    if os.path.exists("/proc/net/arp"):
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) >= 4 and cols[3] != "00:00:00:00:00:00" and cols[2] != "0x0":
                    table[cols[0]] = cols[3].lower()
        return table
    out = _run(["arp", "-a"])
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", out):
        mac = ":".join(x.zfill(2) for x in re.split("[:-]", m.group(2))).lower()
        if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            table[m.group(1)] = mac
    return table


def is_root() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
