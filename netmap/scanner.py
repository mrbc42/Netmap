"""Built-in, dependency-free scanning engine.

Discovery uses whatever is available: raw ICMP (root), unprivileged ICMP
(Linux ping_group_range), the system `ping` binary, TCP connect probes
(a RST proves a host is up) and finally the OS ARP cache, which catches hosts
that firewall everything but still answer ARP.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import platform
import subprocess
import re
import select
import shutil
import socket
import ssl
import struct
import sys
import time
import urllib.request
from typing import Callable, Iterable
from xml.etree import ElementTree

from . import netinfo, oui
from .models import Hop, Host, Port, ScanResult
from .services import HTTP_PORTS, HTTPS_PORTS, PROBE_PORTS, SERVICES

Log = Callable[[str], None]


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- ICMP

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _icmp_socket() -> tuple[socket.socket, bool] | None:
    """Return (socket, is_raw) or None when ICMP is not permitted."""
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP), True
    except (PermissionError, OSError):
        pass
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP), False
    except (PermissionError, OSError):
        return None


def icmp_sweep(ips: list[str], timeout: float = 1.5, rounds: int = 2) -> dict[str, tuple[int | None, float]] | None:
    """Ping many hosts at once from a single socket. Returns ip -> (ttl, rtt_ms)."""
    sk = _icmp_socket()
    if sk is None:
        return None
    sock, raw = sk
    sock.setblocking(False)
    ident = os.getpid() & 0xFFFF
    sent: dict[str, float] = {}
    replies: dict[str, tuple[int | None, float]] = {}
    targets = set(ips)

    def drain(until: float) -> None:
        while True:
            left = until - time.monotonic()
            if left <= 0:
                return
            r, _, _ = select.select([sock], [], [], left)
            if not r:
                return
            try:
                data, (src, _) = sock.recvfrom(2048)
            except OSError:
                continue
            ttl = None
            if raw:
                ihl = (data[0] & 0x0F) * 4
                ttl = data[8]
                icmp = data[ihl:]
                if len(icmp) < 8 or icmp[0] != 0 or struct.unpack("!H", icmp[4:6])[0] != ident:
                    continue
            elif not data or data[0] != 0:
                continue
            if src in targets and src not in replies and src in sent:
                replies[src] = (ttl, (time.monotonic() - sent[src]) * 1000)

    try:
        for rnd in range(rounds):
            for seq, ip in enumerate(ips):
                if ip in replies:
                    continue
                hdr = struct.pack("!BBHHH", 8, 0, 0, ident, (seq + rnd * 4096) & 0xFFFF)
                payload = b"netmap" + bytes(26)
                pkt = struct.pack("!BBHHH", 8, 0, _checksum(hdr + payload), ident,
                                  (seq + rnd * 4096) & 0xFFFF) + payload
                try:
                    sock.sendto(pkt, (ip, 0))
                    sent.setdefault(ip, time.monotonic())
                except OSError:
                    pass
                if seq % 64 == 63:
                    drain(time.monotonic() + 0.01)
            drain(time.monotonic() + timeout)
    finally:
        sock.close()
    return replies


async def _ping_binary(ip: str, timeout: float) -> tuple[int | None, float] | None:
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 2)
    except (OSError, asyncio.TimeoutError):
        return None
    text = out.decode(errors="ignore")
    if proc.returncode != 0 or "ttl=" not in text.lower():
        return None
    ttl = re.search(r"ttl[=:](\d+)", text, re.I)
    rtt = re.search(r"time[=<]\s*([\d.]+)", text, re.I)
    return (int(ttl.group(1)) if ttl else None, float(rtt.group(1)) if rtt else 0.0)


# --------------------------------------------------------------------------- TCP

async def _tcp_state(ip: str, port: int, timeout: float) -> str:
    """'open', 'closed' (RST received - host is alive) or 'filtered'."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except ConnectionRefusedError:
        return "closed"
    except (OSError, asyncio.TimeoutError):
        return "filtered"
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return "open"


async def _probe_alive(ip: str, sem: asyncio.Semaphore, timeout: float) -> bool:
    async with sem:
        tasks = [asyncio.create_task(_tcp_state(ip, p, timeout)) for p in PROBE_PORTS]
        try:
            for fut in asyncio.as_completed(tasks):
                if await fut in ("open", "closed"):
                    return True
        finally:
            for t in tasks:
                t.cancel()
    return False


# --------------------------------------------------------------------------- banners

BANNER_SERVICES = [("SSH-", "ssh"), ("220", "ftp/smtp"), ("RFB ", "vnc"), ("+OK", "pop3"),
                   ("* OK", "imap"), ("HTTP/", "http")]

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


async def _http_info(ip: str, port: int, tls: bool, timeout: float) -> tuple[str, str]:
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # scanning devices with self-signed certs
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx), timeout)
        writer.write(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netmap\r\n\r\n".encode())
        await writer.drain()
        data = b""
        while len(data) < 16384:
            chunk = await asyncio.wait_for(reader.read(4096), timeout)
            if not chunk:
                break
            data += chunk
        writer.close()
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return "", ""
    head, _, body = data.partition(b"\r\n\r\n")
    server = re.search(rb"^server:\s*(.+)$", head, re.I | re.M)
    title = _TITLE_RE.search(body)
    clean = lambda b: re.sub(r"\s+", " ", b.decode(errors="ignore")).strip()[:80]
    return clean(server.group(1)) if server else "", clean(title.group(1)) if title else ""


async def _banner(ip: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        try:
            data = await asyncio.wait_for(reader.read(256), timeout)
        finally:
            writer.close()
    except (OSError, asyncio.TimeoutError):
        return ""
    text = data.decode(errors="ignore").strip().splitlines()
    return re.sub(r"[^\x20-\x7e]", "", text[0])[:80] if text else ""


async def _scan_host_ports(host: Host, ports: list[int], sem: asyncio.Semaphore, timeout: float) -> None:
    async def one(p: int) -> int | None:
        async with sem:
            return p if await _tcp_state(host.ip, p, timeout) == "open" else None

    found = sorted(p for p in await asyncio.gather(*(one(p) for p in ports)) if p)
    host.ports = [Port(p, "tcp", SERVICES.get(p, "")) for p in found]

    async def enrich(port: Port) -> None:
        async with sem:
            if port.port in HTTP_PORTS or port.port in HTTPS_PORTS:
                server, title = await _http_info(host.ip, port.port, port.port in HTTPS_PORTS, timeout * 2)
                port.banner = " - ".join(x for x in (server, title) if x)
                if title and not host.http_title:
                    host.http_title = title
                if server and not host.http_server:
                    host.http_server = server
            else:
                # Many services (SSH, FTP, SMTP, MySQL, VNC...) speak first - read what they say.
                port.banner = await _banner(host.ip, port.port, timeout)
                for prefix, name in BANNER_SERVICES:
                    if port.banner.upper().startswith(prefix):
                        port.service = port.service or name
                        break

    await asyncio.gather(*(enrich(p) for p in host.ports))


# --------------------------------------------------------------------------- names

def _dns_name(buf: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end = [], False, off
    for _ in range(64):
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            off = ((n & 0x3F) << 8) | buf[off + 1]
            jumped = True
            continue
        labels.append(buf[off + 1: off + 1 + n].decode(errors="ignore"))
        off += n + 1
    return ".".join(labels), (end if jumped else off)


def _mdns_query(ip: str, tid: int) -> bytes:
    name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + q + struct.pack("!HH", 12, 1)


def mdns_names(ips: list[str], timeout: float = 2.0) -> dict[str, str]:
    """Reverse-resolve via unicast mDNS (Apple, Linux/Avahi, many IoT devices)."""
    names: dict[str, str] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for i, ip in enumerate(ips):
            try:
                sock.sendto(_mdns_query(ip, i + 1), (ip, 5353))
            except OSError:
                pass
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            if not select.select([sock], [], [], left)[0]:
                break
            try:
                data, (src, _) = sock.recvfrom(4096)
                qd, an = struct.unpack("!HH", data[4:8])
                off = 12
                for _ in range(qd):
                    _, off = _dns_name(data, off)
                    off += 4
                for _ in range(an):
                    _, off = _dns_name(data, off)
                    rtype, _, _, rdlen = struct.unpack("!HHIH", data[off: off + 10])
                    off += 10
                    if rtype == 12:
                        names[src] = _dns_name(data, off)[0].removesuffix(".local").rstrip(".")
                        break
                    off += rdlen
            except (OSError, IndexError, struct.error):
                continue
    finally:
        sock.close()
    return names


def netbios_names(ips: list[str], timeout: float = 2.0) -> dict[str, str]:
    """NBSTAT query (UDP/137) - names for Windows machines and Samba servers."""
    q_name = b"\x20" + b"CK" + b"AA" * 15 + b"\x00"
    names: dict[str, str] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for i, ip in enumerate(ips):
            pkt = struct.pack("!HHHHHH", i + 1, 0, 1, 0, 0, 0) + q_name + struct.pack("!HH", 0x21, 1)
            try:
                sock.sendto(pkt, (ip, 137))
            except OSError:
                pass
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            if not select.select([sock], [], [], left)[0]:
                break
            try:
                data, (src, _) = sock.recvfrom(2048)
                count = data[56]
                for k in range(count):
                    entry = data[57 + 18 * k: 57 + 18 * (k + 1)]
                    flags = struct.unpack("!H", entry[16:18])[0]
                    if entry[15] == 0 and not flags & 0x8000:
                        names[src] = entry[:15].decode(errors="ignore").strip()
                        break
            except (OSError, IndexError, struct.error):
                continue
    finally:
        sock.close()
    return names


def ssdp_devices(timeout: float = 3.0) -> dict[str, dict[str, str]]:
    """UPnP discovery: routers, TVs, NAS, printers announce model/friendly names."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: upnp:rootdevice\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.setblocking(False)
    locations: dict[str, str] = {}
    try:
        for _ in range(2):
            sock.sendto(msg, ("239.255.255.250", 1900))
        end = time.monotonic() + timeout
        while (left := end - time.monotonic()) > 0:
            if not select.select([sock], [], [], left)[0]:
                break
            try:
                data, (src, _) = sock.recvfrom(4096)
            except OSError:
                continue
            m = re.search(rb"^location:\s*(\S+)", data, re.I | re.M)
            if m and src not in locations:
                locations[src] = m.group(1).decode(errors="ignore")
    except OSError:
        return {}
    finally:
        sock.close()

    out: dict[str, dict[str, str]] = {}
    for ip, url in locations.items():
        info = {"location": url}
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                root = ElementTree.fromstring(r.read(65536))
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                if tag in ("friendlyName", "manufacturer", "modelName", "deviceType") and el.text:
                    info.setdefault(tag, el.text.strip())
        except Exception:
            pass
        out[ip] = info
    return out


async def resolve_names(hosts: list[Host], log: Log) -> None:
    loop = asyncio.get_running_loop()
    ips = [h.ip for h in hosts]

    async def rdns(ip: str) -> str:
        try:
            name = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 2)
            return name[0]
        except Exception:
            return ""

    log("  resolving names (reverse DNS, mDNS, NetBIOS)...")
    rd, md, nb = await asyncio.gather(
        asyncio.gather(*(rdns(ip) for ip in ips)),
        asyncio.to_thread(mdns_names, ips),
        asyncio.to_thread(netbios_names, ips),
    )
    for h, r in zip(hosts, rd):
        for src, name in (("dns", r), ("mdns", md.get(h.ip, "")), ("netbios", nb.get(h.ip, ""))):
            if name and name not in h.hostnames and name != h.ip:
                h.hostnames.append(name)
        if h.hostnames:
            # Prefer friendly short names (mDNS/NetBIOS) over e.g. "dsldevice.lan" PTRs.
            h.hostname = md.get(h.ip) or nb.get(h.ip) or h.hostnames[0]


# --------------------------------------------------------------------------- traceroute

def _traceroute_binary(dst: str, max_hops: int) -> list[Hop] | None:
    system = platform.system()
    if system == "Windows" and shutil.which("tracert"):
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", dst]
    elif shutil.which("traceroute"):
        cmd = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", str(max_hops), dst]
    elif shutil.which("tracepath"):
        cmd = ["tracepath", "-n", "-m", str(max_hops), dst]
    else:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * 4).stdout
    except Exception:
        return None
    hops: dict[int, Hop] = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)[:?\s].*?(\d+\.\d+\.\d+\.\d+)", line)
        if m and int(m.group(1)) not in hops:
            rtt = re.search(r"([\d.]+)\s*ms", line)
            hops[int(m.group(1))] = Hop(int(m.group(1)), m.group(2), rtt_ms=float(rtt.group(1)) if rtt else None)
    return [hops[k] for k in sorted(hops)]


def _traceroute_raw(dst: str, max_hops: int, timeout: float = 1.0) -> list[Hop] | None:
    try:
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (PermissionError, OSError):
        return None
    hops: list[Hop] = []
    misses = 0
    try:
        for ttl in range(1, max_hops + 1):
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            t0 = time.monotonic()
            port = 33434 + ttl
            tx.sendto(b"netmap", (dst, port))
            got = None
            end = t0 + timeout
            while (left := end - time.monotonic()) > 0 and got is None:
                if not select.select([rx], [], [], left)[0]:
                    break
                data, (src, _) = rx.recvfrom(1024)
                ihl = (data[0] & 0x0F) * 4
                itype = data[ihl]
                inner = data[ihl + 8:]
                if itype in (11, 3) and len(inner) >= 28:
                    inner_ihl = (inner[0] & 0x0F) * 4
                    if struct.unpack("!H", inner[inner_ihl + 2: inner_ihl + 4])[0] == port:
                        got = (src, itype, (time.monotonic() - t0) * 1000)
            tx.close()
            if got:
                misses = 0
                hops.append(Hop(ttl, got[0], rtt_ms=round(got[2], 1)))
                if got[1] == 3 or got[0] == dst:
                    break
            else:
                misses += 1
                if misses >= 3:
                    break
    finally:
        rx.close()
    return hops


def traceroute(dst: str = "8.8.8.8", max_hops: int = 12) -> list[Hop]:
    hops = _traceroute_binary(dst, max_hops)
    if hops is None:
        hops = _traceroute_raw(dst, max_hops) or []
    for h in hops:
        try:
            socket.setdefaulttimeout(1.5)
            h.hostname = socket.gethostbyaddr(h.ip)[0]
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(None)
    return hops


# --------------------------------------------------------------------------- orchestration

def expand_targets(targets: Iterable[str], max_hosts: int) -> list[tuple[str, list[str]]]:
    out = []
    for t in targets:
        net = ipaddress.ip_network(t, strict=False)
        hosts = [str(ip) for ip in (net.hosts() if net.num_addresses > 2 else net)]
        if len(hosts) > max_hosts:
            raise SystemExit(f"{t} has {len(hosts)} addresses (limit {max_hosts}); "
                             f"narrow the range or raise --max-hosts")
        out.append((str(net), hosts))
    return out


async def scan(targets: list[str], ports: list[int], *, timeout: float = 1.0, concurrency: int = 512,
               do_traceroute: bool = True, max_hosts: int = 4096, log: Log = _stderr) -> ScanResult:
    t0 = time.time()
    result = ScanResult(started=time.strftime("%Y-%m-%d %H:%M:%S"), local_ip=netinfo.local_ip(),
                        gateway=netinfo.default_gateway())
    nets = expand_targets(targets, max_hosts)
    result.subnets = [n for n, _ in nets]
    all_ips = [ip for _, ips in nets for ip in ips]
    subnet_of = {ip: n for n, ips in nets for ip in ips}
    log(f"[1/4] discovering hosts in {', '.join(result.subnets)} ({len(all_ips)} addresses)")

    hosts: dict[str, Host] = {}

    def mark(ip: str, how: str) -> Host:
        h = hosts.setdefault(ip, Host(ip=ip, subnet=subnet_of.get(ip, "")))
        if how not in h.discovered_by:
            h.discovered_by.append(how)
        return h

    # Run SSDP and traceroute alongside discovery - they're slow but independent.
    ssdp_task = asyncio.create_task(asyncio.to_thread(ssdp_devices))
    trace_task = asyncio.create_task(asyncio.to_thread(traceroute)) if do_traceroute else None

    icmp = await asyncio.to_thread(icmp_sweep, all_ips)
    if icmp is not None:
        log(f"  ICMP: {len(icmp)} replies")
    elif shutil.which("ping"):
        sem = asyncio.Semaphore(64)

        async def p(ip: str):
            async with sem:
                return ip, await _ping_binary(ip, timeout)
        icmp = {ip: r for ip, r in await asyncio.gather(*(p(ip) for ip in all_ips)) if r}
        log(f"  ping: {len(icmp)} replies")
    else:
        icmp = {}
        log("  ICMP unavailable (not root, no ping binary) - using TCP probes only")
    for ip, (ttl, rtt) in icmp.items():
        h = mark(ip, "icmp")
        h.ttl, h.latency_ms = ttl, round(rtt, 2)

    sem = asyncio.Semaphore(max(16, concurrency // len(PROBE_PORTS)))
    rest = [ip for ip in all_ips if ip not in hosts]
    alive = await asyncio.gather(*(_probe_alive(ip, sem, timeout) for ip in rest))
    for ip, ok in zip(rest, alive):
        if ok:
            mark(ip, "tcp")
    for ip, mac in netinfo.arp_table().items():
        if ip in subnet_of:
            mark(ip, "arp").mac = mac
    if result.local_ip in subnet_of:
        mark(result.local_ip, "self").is_local = True
    log(f"  {len(hosts)} hosts up")

    ssdp = await ssdp_task
    for ip, info in ssdp.items():
        if ip in hosts:
            h = hosts[ip]
            if info.get("friendlyName"):
                h.hostnames.append(info["friendlyName"])
            h.os_guess = h.os_guess or " ".join(x for x in (info.get("manufacturer"), info.get("modelName")) if x)
            h.discovered_by.append("ssdp")

    host_list = sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))
    log(f"[2/4] scanning {len(ports)} TCP ports on {len(host_list)} hosts")
    psem = asyncio.Semaphore(concurrency)
    done = 0

    async def scan_one(h: Host) -> None:
        nonlocal done
        await _scan_host_ports(h, ports, psem, timeout)
        done += 1
        log(f"  [{done}/{len(host_list)}] {h.ip:<15} {len(h.ports)} open"
            + (f": {', '.join(str(p.port) for p in h.ports[:12])}" if h.ports else ""))

    await asyncio.gather(*(scan_one(h) for h in host_list))

    log("[3/4] identifying devices")
    for h in host_list:
        h.mac = h.mac or netinfo.arp_table().get(h.ip, "")
        h.vendor = oui.lookup(h.mac)
        h.is_gateway = h.ip == result.gateway
    await resolve_names(host_list, log)
    if trace_task:
        log("[4/4] tracing route to the internet")
        result.hops = await trace_task
    result.hosts = host_list
    result.duration_s = round(time.time() - t0, 1)
    return result
