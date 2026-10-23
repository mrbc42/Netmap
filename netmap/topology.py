"""Turn a ScanResult into a graph of nodes and edges.

What can be known from an IP scan: subnets, the gateway, the routed path to the
internet (traceroute) and which devices are infrastructure. What cannot: which
switch port each device is plugged into - that needs LLDP/CDP/SNMP bridge tables.
So hosts hang off a per-subnet "LAN segment" node, and links that are guesses
(e.g. wireless clients behind an AP) are drawn dashed and marked as inferred.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict

from .classify import DEVICE_TYPES
from .models import Host, ScanResult

WIRELESS_TYPES = {"phone", "iot", "media"}


def _ports_line(h: Host, limit: int = 5) -> str:
    ports = [str(p.port) for p in h.ports]
    if not ports:
        return ""
    more = f" +{len(ports) - limit}" if len(ports) > limit else ""
    return " ".join(ports[:limit]) + more


def build_graph(result: ScanResult) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    by_ip = {h.ip: h for h in result.hosts}

    def add_edge(a: str, b: str, *, inferred: bool = False, label: str = "", kind: str = "lan") -> None:
        edges.append({"from": a, "to": b, "inferred": inferred, "label": label, "kind": kind})

    for h in result.hosts:
        label = h.hostname.split(".")[0] if h.hostname and not h.hostname[0].isdigit() else ""
        nodes.append({
            "id": h.ip, "kind": h.device_type, "name": label or h.ip, "ip": h.ip,
            "ports_line": _ports_line(h), "host": asdict(h),
            "type_label": DEVICE_TYPES.get(h.device_type, ("Unknown",))[0],
        })

    gw = by_ip.get(result.gateway)

    # Internet + upstream path (hops after our gateway).
    upstream = [hop for hop in result.hops if hop.ip != result.gateway and hop.ip not in by_ip]
    if gw or upstream:
        nodes.append({"id": "internet", "kind": "internet", "name": "Internet", "ip": "", "ports_line": ""})
        prev = result.gateway or None
        for hop in upstream[:6]:   # beyond ~6 hops it's someone else's backbone
            hid = f"hop:{hop.ip}"
            private = ipaddress.ip_address(hop.ip).is_private
            nodes.append({"id": hid, "kind": "hop", "name": (hop.hostname or hop.ip).split(".")[0] if hop.hostname else hop.ip,
                          "ip": hop.ip, "ports_line": f"hop {hop.ttl}" + (f" · {hop.rtt_ms:.0f} ms" if hop.rtt_ms else ""),
                          "hop": asdict(hop), "type_label": "Upstream router" + (" (private)" if private else " (ISP)")})
            if prev:
                add_edge(prev, hid, kind="wan")
            prev = hid
        if prev:
            add_edge(prev, "internet", kind="wan")

    # One segment per subnet; infrastructure first, then endpoints.
    for subnet in result.subnets or sorted({h.subnet for h in result.hosts}):
        members = [h for h in result.hosts if h.subnet == subnet]
        if not members:
            continue
        switches = [h for h in members if h.device_type == "switch"]
        aps = [h for h in members if h.device_type == "access_point"]
        seg_id = f"seg:{subnet}"
        if len(switches) == 1:
            seg_id = switches[0].ip   # a single managed switch is almost certainly the LAN core
        else:
            nodes.append({"id": seg_id, "kind": "segment", "name": subnet, "ip": subnet,
                          "ports_line": f"{len(members)} host{'s' if len(members) != 1 else ''}", "type_label": "LAN segment (layer 2)"})

        routers = [h for h in members if h.device_type in ("router", "firewall")]
        # A container/VM bridge: this machine's own address on it is the way in.
        bridge = next((h for h in members if h.is_local and h.ip != result.local_ip), None)
        uplink = gw if gw and gw in members else bridge or (routers[0] if routers else None)
        if bridge and uplink is bridge and result.local_ip in by_ip:
            add_edge(uplink.ip, seg_id, kind="core")
            add_edge(result.local_ip, bridge.ip, kind="core", label="same host")
        elif uplink and uplink.ip != seg_id:
            add_edge(uplink.ip, seg_id, kind="core")
            if result.gateway and uplink.ip != result.gateway:
                # A second router (lab, DMZ, VPN...) - reachable through the main gateway.
                add_edge(result.gateway, uplink.ip, kind="routed", inferred=True, label="routed")
        elif not uplink and result.gateway:
            add_edge(result.gateway, seg_id, kind="routed", inferred=True, label="routed")

        for h in members:
            if h.ip in (seg_id, uplink.ip if uplink else None):
                continue
            if aps and h.device_type in WIRELESS_TYPES and h not in aps:
                add_edge(aps[0].ip, h.ip, inferred=True, kind="wifi")
            else:
                add_edge(seg_id, h.ip, kind="core" if h.device_type in ("switch", "access_point", "router", "firewall") else "lan")

    # Gateway that isn't inside any scanned subnet still needs to be shown.
    if result.gateway and not gw and any(result.gateway in (e["from"], e["to"]) for e in edges):
        nodes.append({"id": result.gateway, "kind": "router", "name": "Gateway", "ip": result.gateway,
                      "ports_line": "not scanned", "type_label": "Router / Gateway"})
    return {"nodes": nodes, "edges": edges}
