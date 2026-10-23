"""Optional engine that drives the nmap binary for OS fingerprinting and service versions.

nmap is more accurate (SYN scan, OS detection, `-sV` probes) but must be installed and
needs root/Administrator for OS detection. Output is parsed from `-oX -`.
"""

from __future__ import annotations

import asyncio
import shutil
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


def _merge(hx: ElementTree.Element, h: Host) -> None:
    """Copy one <host> element of nmap's XML into our Host."""
    h.discovered_by.append("nmap")
    for a in hx.iter("address"):
        if a.get("addrtype") == "mac":
            h.mac = h.mac or a.get("addr", "").lower()
            h.vendor = h.vendor or a.get("vendor", "")
    h.hostnames += [n.get("name") for n in hx.iter("hostname") if n.get("name") and n.get("name") not in h.hostnames]
    h.hostname = h.hostname or (h.hostnames[0] if h.hostnames else "")
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
    if times is not None and times.get("srtt") and h.latency_ms is None:
        h.latency_ms = round(int(times.get("srtt")) / 1000, 2)


async def scan(targets: list[str], ports: list[int], *, timeout: float = 1.0, concurrency: int = 512,
               do_traceroute: bool = True, max_hosts: int = 4096, log: scanner.Log = scanner._stderr,
               progress: scanner.Progress = scanner._no_progress, parallel: int = 8) -> ScanResult:
    t0 = time.time()
    trace_task = asyncio.create_task(asyncio.to_thread(scanner.traceroute)) if do_traceroute else None
    # Our own discovery weeds out addresses that only *look* alive (proxies, proxy-ARP),
    # so nmap spends its time on real hosts only.
    result, host_list = await scanner.discover(targets, timeout=timeout, concurrency=concurrency,
                                               max_hosts=max_hosts, log=log, progress=progress)
    result.engine = "nmap"
    scanner.attach_traceroute(result, trace_task)
    to_scan = [h for h in host_list if not h.catch_all]

    root = netinfo.is_root()
    cmd = ["nmap", "-oX", "-", "-T4", "-Pn", "--max-retries", "2", "--host-timeout", "5m",
           "-sV", "--version-light", "--script", "http-title", "-p", _port_spec(ports)]
    cmd += ["-sS", "-O", "--osscan-limit"] if root else ["-sT"]
    log(f"[2/4] nmap scanning {len(to_scan)} hosts, {parallel} at a time: {' '.join(cmd)} <ip>")
    if not root:
        log("  (not root: OS detection disabled, using TCP connect scan)")

    # One nmap per host: results stream in as each finishes and a slow host can't stall the rest.
    sem = asyncio.Semaphore(parallel)
    done = 0

    async def one(h: Host) -> None:
        nonlocal done
        async with sem:
            proc = await asyncio.create_subprocess_exec(*cmd, h.ip, stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            out, err = await proc.communicate()
        done += 1
        if proc.returncode != 0:
            log(f"  [{done}/{len(to_scan)}] {h.ip:<15} nmap failed: {err.decode(errors='ignore').strip()[:120]}")
            return
        for hx in ElementTree.fromstring(out).iter("host"):
            _merge(hx, h)
        log(f"  [{done}/{len(to_scan)}] {h.ip:<15} {len(h.ports)} open"
            + (f": {', '.join(str(p.port) for p in h.ports[:12])}" if h.ports else ""))
        progress(result, host_list, f"nmap {done}/{len(to_scan)} hosts")

    await asyncio.gather(*(one(h) for h in to_scan))

    scanner._shared_port_warning(result, to_scan)
    log("[3/4] identifying devices")
    arp = netinfo.arp_table()
    for h in host_list:
        h.mac = h.mac or arp.get(h.ip, "")
        h.vendor = h.vendor or oui.lookup(h.mac)
        h.is_gateway = h.ip == result.gateway
    await scanner.resolve_names(host_list, log)
    progress(result, host_list, "names resolved")
    if trace_task:
        log("[4/4] tracing route to the internet")
        result.hops = await trace_task
    result.hosts = host_list
    result.duration_s = round(time.time() - t0, 1)
    return result
