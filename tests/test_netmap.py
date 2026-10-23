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


if __name__ == "__main__":
    unittest.main()
