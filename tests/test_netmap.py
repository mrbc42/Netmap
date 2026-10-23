import json
import unittest

from netmap import classify, render
from netmap.demo import demo_result
from netmap.models import Host, Port, ScanResult
from netmap.nmap_engine import _port_spec
from netmap.oui import is_randomized, lookup
from netmap.scanner import _dns_name, _mdns_query
from netmap.services import parse_ports
from netmap.topology import build_graph


class PortSpecTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_ports("22,80-82"), [22, 80, 81, 82])
        self.assertIn(2222, parse_ports("top,2222"))
        self.assertEqual(len(parse_ports("top200")), 200)
        self.assertEqual(len(parse_ports("all")), 65535)

    def test_nmap_spec(self):
        self.assertEqual(_port_spec([1, 2, 3, 5, 80, 81, 443]), "1-3,5,80-81,443")


class ClassifyTests(unittest.TestCase):
    def kind(self, **kw):
        return classify.classify(Host(ip="10.0.0.5", **kw))

    def test_rules(self):
        self.assertEqual(self.kind(is_gateway=True, ports=[Port(80)]), "router")
        self.assertEqual(self.kind(ports=[Port(9100), Port(631)]), "printer")
        self.assertEqual(self.kind(ports=[Port(62078)]), "phone")
        self.assertEqual(self.kind(ports=[Port(8006), Port(22)]), "hypervisor")
        self.assertEqual(self.kind(ports=[Port(135), Port(445), Port(3389)], ttl=128), "workstation")
        self.assertEqual(self.kind(vendor="Synology", ports=[Port(5000), Port(5001)]), "nas")
        self.assertEqual(self.kind(hostname="core-sw-01", ttl=255, ports=[Port(22), Port(161)]), "switch")
        self.assertEqual(self.kind(), "unknown")

    def test_demo_types(self):
        r = demo_result()
        classify.classify_all(r)
        kinds = {h.hostname: h.device_type for h in r.hosts}
        self.assertEqual(kinds["udm-pro"], "router")
        self.assertEqual(kinds["core-switch-24"], "switch")
        self.assertEqual(kinds["ap-office"], "access_point")
        self.assertEqual(kinds["cam-yard"], "camera")


class OuiTests(unittest.TestCase):
    def test_lookup(self):
        self.assertEqual(lookup("B8:27:EB:00:00:01"), "Raspberry Pi")
        self.assertTrue(is_randomized("2a:00:00:00:00:00"))
        self.assertEqual(lookup("2a:00:00:00:00:00"), "Private (randomized MAC)")


class DnsTests(unittest.TestCase):
    def test_query_roundtrip(self):
        q = _mdns_query("192.168.1.20", 1)
        self.assertEqual(_dns_name(q, 12)[0], "20.1.168.192.in-addr.arpa")


class GraphTests(unittest.TestCase):
    def test_edges_reference_nodes(self):
        r = demo_result()
        classify.classify_all(r)
        g = build_graph(r)
        ids = {n["id"] for n in g["nodes"]}
        for e in g["edges"]:
            self.assertIn(e["from"], ids)
            self.assertIn(e["to"], ids)
        self.assertIn("internet", ids)

    def test_gateway_outside_scan(self):
        r = ScanResult(hosts=[Host(ip="10.1.1.5", subnet="10.1.1.0/24")], subnets=["10.1.1.0/24"], gateway="10.9.9.1")
        g = build_graph(r)
        self.assertIn("10.9.9.1", {n["id"] for n in g["nodes"]})

    def test_render_and_json_roundtrip(self):
        r = demo_result()
        r.hosts[0].http_title = "</script><script>alert(1)</script>"
        html = render.render_html(r)
        self.assertNotIn("</script><script>alert(1)", html)
        again = ScanResult.from_dict(json.loads(r.to_json()))
        self.assertEqual(len(again.hosts), len(r.hosts))


class InterfaceTests(unittest.TestCase):
    def setUp(self):
        from netmap import netinfo
        self.n = netinfo
        self.saved = {k: getattr(netinfo, k) for k in ("interfaces", "default_gateway", "default_route_interface", "local_ip")}
        netinfo.interfaces = lambda: [
            {"name": "podman0", "ip": "10.88.0.1", "netmask": "255.255.0.0", "network": "10.88.0.0/16", "virtual": True},
            {"name": "wlp2s0", "ip": "192.168.1.50", "netmask": "255.255.255.0", "network": "192.168.1.0/24", "virtual": False},
        ]
        netinfo.default_gateway = lambda: "192.168.1.1"
        netinfo.local_ip = lambda: "10.88.0.1"   # the lookup that went wrong

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(self.n, k, v)

    def test_prefers_lan_over_container_bridge(self):
        for route_if in ("wlp2s0", ""):
            self.n.default_route_interface = lambda: route_if
            self.assertEqual(self.n.primary_interface()["name"], "wlp2s0")
            self.assertEqual(self.n.local_subnet(), "192.168.1.0/24")

    def test_scans_every_network_by_default(self):
        from netmap.cli import auto_targets
        self.n.default_route_interface = lambda: "wlp2s0"
        saved = self.n.routed_networks
        self.n.routed_networks = lambda: ["10.10.20.0/24", "192.168.1.0/25"]
        try:
            self.assertEqual(auto_targets(False, 4096), ["192.168.1.0/24", "10.88.0.0/24", "10.10.20.0/24"])
            self.assertEqual(auto_targets(True, 4096), ["192.168.1.0/24"])
        finally:
            self.n.routed_networks = saved


class PhantomHostTests(unittest.TestCase):
    """Networks where something answers for addresses that have no device behind them."""

    def run_discover(self, tcp_state, icmp_ips, arp):
        import asyncio
        from unittest import mock
        from netmap import scanner

        async def fake_tcp(ip, port, timeout):
            return tcp_state(ip, port)

        with mock.patch.object(scanner, "_tcp_state", fake_tcp), \
             mock.patch.object(scanner, "icmp_sweep", lambda ips, **k: {ip: (64, 1.0) for ip in ips if ip in icmp_ips}), \
             mock.patch.object(scanner, "ssdp_devices", lambda *a, **k: {}), \
             mock.patch.object(scanner.netinfo, "arp_table", lambda: dict(arp)), \
             mock.patch.object(scanner.netinfo, "host_addresses", lambda: ("192.168.1.50", ["192.168.1.50"])), \
             mock.patch.object(scanner.netinfo, "default_gateway", lambda: "192.168.1.1"):
            return asyncio.run(scanner.discover(["192.168.1.0/24"], timeout=0.1, log=lambda m: None))

    def test_interceptor_answering_everything(self):
        real = {"192.168.1.1", "192.168.1.10", "192.168.1.50"}
        result, hosts = self.run_discover(lambda ip, port: "open", real,
                                          {"192.168.1.1": "aa:00:00:00:00:01", "192.168.1.10": "aa:00:00:00:00:10"})
        self.assertEqual({h.ip for h in hosts}, real)
        self.assertTrue(all(h.catch_all for h in hosts))
        self.assertTrue(any("intercepting" in w for w in result.warnings))

    def test_proxy_arp_router(self):
        real = {f"192.168.1.{i}" for i in range(1, 51)} | {"192.168.1.50"}
        arp = {ip: f"aa:00:00:00:00:{int(ip.split('.')[-1]):02x}" for ip in real}
        arp.update({f"192.168.1.{i}": "aa:00:00:00:00:01" for i in range(51, 255)})   # router claims the rest
        web = lambda ip, port: "open" if port in (80, 443) and ip.startswith("192.168.1.") else "filtered"
        result, hosts = self.run_discover(web, real, arp)
        self.assertEqual({h.ip for h in hosts}, real)
        self.assertTrue(any("proxy-ARP" in w for w in result.warnings))

    def test_normal_network_untouched(self):
        real = {"192.168.1.1", "192.168.1.7", "192.168.1.50"}
        arp = {"192.168.1.1": "aa:00:00:00:00:01", "192.168.1.7": "aa:00:00:00:00:07", "192.168.1.9": "aa:00:00:00:00:09"}
        tcp = lambda ip, port: ("open" if port == 22 else "closed") if ip in real | {"192.168.1.9"} else "filtered"
        result, hosts = self.run_discover(tcp, real, arp)
        # .9 ignores ping but is in the ARP table and answers TCP: a real, firewalled host.
        self.assertEqual({h.ip for h in hosts}, real | {"192.168.1.9"})
        self.assertFalse(any(h.catch_all for h in hosts))
        self.assertEqual(result.warnings, [])


class LiveViewTests(unittest.TestCase):
    def test_serves_page_and_updates(self):
        import urllib.request
        from netmap.live import LiveView
        r = demo_result()
        live = LiveView(0).start()
        try:
            page = urllib.request.urlopen(live.url, timeout=5).read().decode()
            self.assertIn('"live": true', page)
            live.publish(r, r.hosts[:3], "port scan 3/28", force=True)
            d = json.loads(urllib.request.urlopen(live.url + "data.json", timeout=5).read())
            self.assertEqual((len(d["scan"]["hosts"]), d["done"]), (3, False))
            live.publish(r, r.hosts, "scan complete", done=True)
            d = json.loads(urllib.request.urlopen(live.url + "data.json", timeout=5).read())
            self.assertEqual((len(d["scan"]["hosts"]), d["done"]), (28, True))
        finally:
            live.stop(grace=0)


if __name__ == "__main__":
    unittest.main()
