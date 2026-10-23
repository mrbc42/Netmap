"""Plain data classes shared by the scanner, classifier and renderer."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    service: str = ""
    banner: str = ""


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    hostnames: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    ttl: Optional[int] = None
    latency_ms: Optional[float] = None
    os_guess: str = ""
    http_title: str = ""
    http_server: str = ""
    device_type: str = "unknown"
    is_gateway: bool = False
    is_local: bool = False
    subnet: str = ""
    discovered_by: list[str] = field(default_factory=list)
    catch_all: bool = False                               # answers on every port - real ports unknown
    notes: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> set[int]:
        return {p.port for p in self.ports}

    @property
    def display_name(self) -> str:
        return self.hostname or self.ip


@dataclass
class Hop:
    ttl: int
    ip: str
    hostname: str = ""
    rtt_ms: Optional[float] = None


@dataclass
class ScanResult:
    hosts: list[Host] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)
    gateway: str = ""
    local_ip: str = ""
    local_ips: list[str] = field(default_factory=list)   # every address of this host (LAN, bridges, VPNs)
    hops: list[Hop] = field(default_factory=list)   # traceroute towards the internet
    started: str = ""
    duration_s: float = 0.0
    engine: str = "builtin"
    warnings: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        hosts = []
        for h in d.get("hosts", []):
            h = dict(h)
            h["ports"] = [Port(**p) for p in h.get("ports", [])]
            hosts.append(Host(**h))
        hops = [Hop(**x) for x in d.get("hops", [])]
        rest = {k: v for k, v in d.items() if k not in ("hosts", "hops")}
        return cls(hosts=hosts, hops=hops, **rest)
