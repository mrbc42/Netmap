"""Optional engine that drives the nmap binary for OS fingerprinting and service versions.

nmap is more accurate (SYN scan, OS detection, `-sV` probes) but must be installed and
needs root/Administrator for OS detection. Output is parsed from `-oX -`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import shutil
import subprocess
import time
from xml.etree import ElementTree

from . import netinfo, oui, scanner
from .models import Host, Port, ScanResult


def available() -> bool:
    return shutil.which("nmap") is not None


def _port_spec(ports: list[int]) -> str:
    if len(ports) >= 65535:
        return "-"
    ports = sorted(set(ports))
    fmt = lambda a, b: str(a) if a == b else f"{a}-{b}"
    ranges, start, prev = [], ports[0], ports[0]
    for p in ports[1:]:
        if p != prev + 1:
            ranges.append(fmt(start, prev))
            start = p
        prev = p
    ranges.append(fmt(start, prev))
    return ",".join(ranges)


async def scan(targets: list[str], ports: list[int], *, do_traceroute: bool = True,
               log: scanner.Log = scanner._stderr, **_) -> ScanResult:
    t0 = time.time()
    root = netinfo.is_root()
    cmd = ["nmap", "-oX", "-", "-T4", "-sV", "--version-light", "--script", "http-title", "-p", _port_spec(ports)]
    cmd += ["-sS", "-O", "--osscan-limit"] if root else ["-sT"]
    cmd += targets
    log(f"running: {' '.join(cmd)}")
    if not root:
        log("  (not root: OS detection disabled, using TCP connect scan)")

    trace_task = asyncio.create_task(asyncio.to_thread(scanner.traceroute)) if do_traceroute else None
    ssdp_task = asyncio.create_task(asyncio.to_thread(scanner.ssdp_devices))
    proc = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"nmap failed: {proc.stderr.strip()}")

    main_ip, my_ips = netinfo.host_addresses()
    result = ScanResult(started=time.strftime("%Y-%m-%d %H:%M:%S"), local_ip=main_ip, local_ips=my_ips,
                        gateway=netinfo.default_gateway(), engine="nmap",
                        subnets=[str(ipaddress.ip_network(t, strict=False)) for t in targets])
    nets = [ipaddress.ip_network(s) for s in result.subnets]
    for hx in ElementTree.fromstring(proc.stdout).iter("host"):
        if hx.find("status").get("state") != "up":
            continue
        h = Host(ip="", discovered_by=["nmap"])
        for a in hx.iter("address"):
            if a.get("addrtype") == "ipv4":
                h.ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                h.mac = a.get("addr", "").lower()
                h.vendor = a.get("vendor", "")
        h.hostnames = [n.get("name") for n in hx.iter("hostname") if n.get("name")]
        h.hostname = h.hostnames[0] if h.hostnames else ""
        for px in hx.iter("port"):
            if px.find("state").get("state") != "open":
                continue
            svc = px.find("service")
            name = svc.get("name", "") if svc is not None else ""
            ver = " ".join(filter(None, (svc.get(k) for k in ("product", "version", "extrainfo")))) if svc is not None else ""
            title = next((sc.get("output", "").strip() for sc in px.iter("script") if sc.get("id") == "http-title"), "")
            if title and not title.startswith("Site doesn't have a title"):
                h.http_title = h.http_title or title
                ver = " - ".join(filter(None, (ver, title)))
            h.ports.append(Port(int(px.get("portid")), px.get("protocol"), name, ver))
        osm = hx.find("os/osmatch")
        if osm is not None:
            h.os_guess = osm.get("name", "")
            cls = osm.find("osclass")
            if cls is not None and cls.get("type"):
                h.os_guess += f" [{cls.get('type')}]"
        times = hx.find("times")
        if times is not None and times.get("srtt"):
            h.latency_ms = round(int(times.get("srtt")) / 1000, 2)
        h.vendor = h.vendor or oui.lookup(h.mac)
        h.is_gateway = h.ip == result.gateway
        h.is_local = h.ip in (result.local_ips or [result.local_ip])
        h.subnet = next((str(n) for n in nets if ipaddress.ip_address(h.ip) in n), "")
        result.hosts.append(h)

    result.hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    log(f"  nmap found {len(result.hosts)} hosts")
    for ip, info in (await ssdp_task).items():
        for h in result.hosts:
            if h.ip == ip and info.get("friendlyName"):
                h.hostnames.append(info["friendlyName"])
    await scanner.resolve_names(result.hosts, log)
    if trace_task:
        result.hops = await trace_task
    result.duration_s = round(time.time() - t0, 1)
    return result
