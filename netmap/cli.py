"""Command line interface: `netmap scan`, `netmap render`, `netmap demo`, `netmap oui-update`."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__, classify, netinfo, nmap_engine, oui, render, scanner
from .demo import demo_result
from .models import ScanResult
from .render import write_html
from .services import parse_ports


def _finish(result: ScanResult, args) -> None:
    classify.classify_all(result)
    out = write_html(result, args.output)
    if getattr(args, "json", None):
        Path(args.json).write_text(result.to_json(), encoding="utf-8")
        print(f"scan data  -> {args.json}", file=sys.stderr)
    print(f"diagram    -> {out.resolve()}", file=sys.stderr)
    _summary(result)
    if args.open:
        webbrowser.open(out.resolve().as_uri())


def _summary(result: ScanResult) -> None:
    print(f"\n{'IP':<16}{'TYPE':<14}{'NAME':<26}{'VENDOR':<22}PORTS")
    for h in result.hosts:
        ports = ",".join(str(p.port) for p in h.ports)
        print(f"{h.ip:<16}{h.device_type:<14}{h.display_name[:25]:<26}{h.vendor[:21]:<22}{ports}")
    print(f"\n{len(result.hosts)} hosts, {sum(len(h.ports) for h in result.hosts)} open ports, {result.duration_s}s")


def _clamp(network: str, near_ip: str | None, label: str, max_hosts: int) -> str:
    net = ipaddress.ip_network(network)
    if net.num_addresses <= max_hosts:
        return str(net)
    # Container/VM bridges are often /16 but hand out addresses from the bottom up.
    small = str(ipaddress.ip_network(f"{near_ip or net.network_address}/24", strict=False))
    print(f"  {label}: {net} has {net.num_addresses} addresses - scanning {small} "
          f"(raise --max-hosts to sweep all of it)", file=sys.stderr)
    return small


def auto_targets(lan_only: bool, max_hosts: int) -> list[str]:
    """Every network this host can see: its LAN first, then other interfaces and routed networks."""
    if netinfo.in_container():
        print("warning: running inside a container - only the container network is visible.\n"
              "         Run netmap on the host (or with --network host) to map your LAN.", file=sys.stderr)
    primary = netinfo.primary_interface()
    if not primary:
        return [netinfo.local_subnet(max_hosts)]
    ifaces = [primary] + [i for i in netinfo.interfaces() if i is not primary and i != primary]
    if lan_only:
        ifaces = [primary]
    found = [(i["network"], i["ip"], f"{i['name']}" + (" (container/VM/VPN)" if i["virtual"] else "")) for i in ifaces]
    if not lan_only:
        found += [(n, None, "routed") for n in netinfo.routed_networks()]
    targets = []
    for network, ip, label in found:
        t = _clamp(network, ip, label, max_hosts)
        if not any(ipaddress.ip_network(t).subnet_of(ipaddress.ip_network(x)) for x in targets):
            targets.append(t)
            print(f"network: {t:<18} {label}", file=sys.stderr)
    return targets


def cmd_scan(args) -> None:
    targets = args.target or auto_targets(args.lan_only, args.max_hosts)
    ports = parse_ports(args.ports)
    engine = args.engine
    if engine == "auto":
        engine = "nmap" if nmap_engine.available() else "builtin"
    if engine == "nmap" and not nmap_engine.available():
        sys.exit("nmap is not installed - use --engine builtin")
    if not netinfo.is_root():
        print("note: not running as root/admin - ICMP and MAC discovery may be limited", file=sys.stderr)
    run = nmap_engine.scan if engine == "nmap" else scanner.scan
    result = asyncio.run(run(targets, ports, timeout=args.timeout, concurrency=args.concurrency,
                             do_traceroute=not args.no_traceroute, max_hosts=args.max_hosts))
    _finish(result, args)


def cmd_render(args) -> None:
    result = ScanResult.from_dict(json.loads(Path(args.input).read_text(encoding="utf-8")))
    if args.reclassify:
        classify.classify_all(result)
    out = write_html(result, args.output)
    print(f"diagram -> {out.resolve()}", file=sys.stderr)
    if args.open:
        webbrowser.open(out.resolve().as_uri())


def cmd_demo(args) -> None:
    _finish(demo_result(), args)


def cmd_info(_args) -> None:
    primary = netinfo.primary_interface() or {}
    print(f"lan      : {netinfo.local_subnet()} on {primary.get('name', '?')} (this host {primary.get('ip', '?')})")
    print(f"gateway  : {netinfo.default_gateway() or '?'}")
    for i in netinfo.interfaces():
        tag = "  <- main LAN" if i["name"] == primary.get("name") else "  (container/VM/VPN)" if i["virtual"] else ""
        print(f"  {i['name']:<14} {i['ip']:<16} {i['network']:<19}{tag}")
    for n in netinfo.routed_networks():
        print(f"  {'(routed)':<14} {'':<16} {n}")
    if netinfo.in_container():
        print("container: yes - run on the host to see your real LAN")
    print(f"root     : {netinfo.is_root()}\nnmap     : {nmap_engine.available()}")
    print(f"oui db   : {'full (' + str(oui.CACHE) + ')' if oui.CACHE.exists() else 'built-in only - run `netmap oui-update`'}")
    print(f"offline  : {'yes' if render.VIS_CACHE.exists() else 'no - run `netmap offline` to inline the diagram library'}")


def cmd_oui(_args) -> None:
    print(f"downloaded vendor database -> {oui.update()}")


def cmd_offline(_args) -> None:
    print(f"cached diagram library -> {render.fetch_vis()}\nreports will now be fully self-contained")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="netmap", description="Discover, port-scan and diagram your network.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def outputs(sp, default="network-map.html"):
        sp.add_argument("-o", "--output", default=default, help="HTML diagram to write (default: %(default)s)")
        sp.add_argument("--open", action="store_true", help="open the diagram in a browser when done")

    s = sub.add_parser("scan", help="scan the network and build a diagram")
    s.add_argument("target", nargs="*", help="CIDRs/IPs to scan (default: every network this host can see)")
    s.add_argument("-p", "--ports", default="top", help="'top' (~90 common), 'top200', 'all', or '22,80,8000-8100'")
    s.add_argument("-e", "--engine", choices=["auto", "builtin", "nmap"], default="auto",
                   help="scanning engine; auto uses nmap if installed (default: %(default)s)")
    s.add_argument("-j", "--json", default="network-scan.json", help="raw scan data to write (default: %(default)s)")
    s.add_argument("-t", "--timeout", type=float, default=1.0, help="per-connection timeout in seconds")
    s.add_argument("-c", "--concurrency", type=int, default=512, help="simultaneous connections")
    s.add_argument("--max-hosts", type=int, default=4096, help="refuse to scan ranges bigger than this")
    s.add_argument("--lan-only", action="store_true",
                   help="only scan the main LAN, not container/VM bridges, VPNs or routed networks")
    s.add_argument("--no-traceroute", action="store_true", help="skip the traceroute to the internet")
    outputs(s)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("render", help="re-render a diagram from a saved JSON scan")
    r.add_argument("input")
    r.add_argument("--reclassify", action="store_true", help="re-run device classification")
    outputs(r)
    r.set_defaults(func=cmd_render)

    d = sub.add_parser("demo", help="render a sample network (no scanning)")
    outputs(d, "netmap-demo.html")
    d.set_defaults(func=cmd_demo, json=None)

    sub.add_parser("info", help="show detected local network settings").set_defaults(func=cmd_info)
    sub.add_parser("oui-update", help="download the full MAC vendor database").set_defaults(func=cmd_oui)
    sub.add_parser("offline", help="cache the diagram library so reports work without internet").set_defaults(func=cmd_offline)

    args = p.parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")


if __name__ == "__main__":
    main()
