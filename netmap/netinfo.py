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


def _linux_netmask(ip: str) -> str:
    """Find the netmask for `ip` via SIOCGIFNETMASK on each interface."""
    import fcntl  # Linux/macOS only

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _, name in socket.if_nameindex():
            ifreq = struct.pack("256s", name.encode()[:15])
            try:
                addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])
                if addr != ip:
                    continue
                return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891B, ifreq)[20:24])
            except OSError:
                continue
    finally:
        s.close()
    return ""


def local_subnet(ip: str | None = None) -> str:
    """CIDR of the local network, e.g. '192.168.1.0/24'."""
    ip = ip or local_ip()
    mask = ""
    try:
        import psutil  # optional, gives cross-platform netmasks

        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip and a.netmask:
                    mask = a.netmask
    except ImportError:
        pass
    if not mask and SYSTEM == "Linux":
        mask = _linux_netmask(ip)
    if not mask and SYSTEM == "Windows":
        out = _run(["ipconfig"])
        m = re.search(re.escape(ip) + r".*?Subnet Mask[ .]*:\s*([\d.]+)", out, re.S)
        if m:
            mask = m.group(1)
    if not mask and SYSTEM == "Darwin":
        m = re.search(r"inet " + re.escape(ip) + r" netmask (0x[0-9a-f]+)", _run(["ifconfig"]))
        if m:
            mask = socket.inet_ntoa(struct.pack(">L", int(m.group(1), 16)))
    net = ipaddress.ip_network(f"{ip}/{mask or '255.255.255.0'}", strict=False)
    return str(net)


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
