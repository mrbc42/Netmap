"""Render a ScanResult as a single self-contained interactive HTML file."""

from __future__ import annotations

import io
import json
import tarfile
import urllib.request
from dataclasses import asdict
from pathlib import Path

from . import icons, oui
from .classify import DEVICE_TYPES
from .models import ScanResult
from .topology import build_graph

TEMPLATE = Path(__file__).with_name("template.html")
VIS_VERSION = "9.1.9"
VIS_CDN = f'<script src="https://unpkg.com/vis-network@{VIS_VERSION}/standalone/umd/vis-network.min.js"></script>'
VIS_CACHE = oui.CACHE.parent / f"vis-network-{VIS_VERSION}.min.js"


def fetch_vis() -> Path:
    """Download vis-network once so reports work without internet access."""
    url = f"https://registry.npmjs.org/vis-network/-/vis-network-{VIS_VERSION}.tgz"
    with urllib.request.urlopen(url, timeout=60) as r:
        tar = tarfile.open(fileobj=io.BytesIO(r.read()))
    js = tar.extractfile("package/standalone/umd/vis-network.min.js").read()
    VIS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    VIS_CACHE.write_bytes(js)
    return VIS_CACHE


def render_html(result: ScanResult) -> str:
    types = {k: list(v) for k, v in DEVICE_TYPES.items()}
    types.update({"internet": ["Internet", icons.colour("internet")],
                  "segment": ["LAN segment", icons.colour("segment")],
                  "hop": ["Upstream router", icons.colour("hop")]})
    data = {"scan": asdict(result), "graph": build_graph(result), "icons": icons.all_icons(), "types": types}
    payload = json.dumps(data).replace("</", "<\\/")  # never let data close the <script>
    html = TEMPLATE.read_text(encoding="utf-8")
    if VIS_CACHE.exists():  # inline the library -> a single file that works offline
        html = html.replace(VIS_CDN, "<script>" + VIS_CACHE.read_text(encoding="utf-8").replace("</script", "<\\/script") + "</script>")
    return html.replace("__DATA__", payload)


def write_html(result: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_html(result), encoding="utf-8")
    return path
