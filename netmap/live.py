"""Live view: serve the diagram over HTTP while the scan runs, so the map grows as hosts are found.

The server binds to 127.0.0.1 only. The page polls /data.json about once a second; the scanner
calls publish() whenever it learns something, which swaps in a fresh JSON snapshot.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import classify
from .models import Host, ScanResult
from .render import payload, render_html


class LiveView:
    def __init__(self, port: int = 8765):
        self.port = port
        self.version = 0
        self._html = b""
        self._data = b"{}"
        self._last = 0.0
        self._server: ThreadingHTTPServer | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def start(self) -> "LiveView":
        self._html = render_html(ScanResult(engine="…"), live=True).encode()
        self.publish(ScanResult(engine="…"), [], "starting", force=True)
        view = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split("?")[0]
                if path == "/":
                    body, kind = view._html, "text/html; charset=utf-8"
                elif path == "/data.json":
                    body, kind = view._data, "application/json"
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        for port in [self.port, *range(self.port + 1, self.port + 10), 0]:
            try:
                self._server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
                break
            except OSError:
                continue
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def publish(self, result: ScanResult, hosts: list[Host], status: str, *, done: bool = False,
                force: bool = False) -> None:
        """Snapshot the scan so far. Cheap enough to call per host; throttled to ~3/s."""
        now = time.monotonic()
        if not (done or force) and now - self._last < 0.3:
            return
        self._last = now
        snap = copy.copy(result)
        snap.hosts = copy.deepcopy(sorted(hosts, key=lambda h: tuple(int(o) for o in h.ip.split("."))))
        classify.classify_all(snap)
        self.version += 1
        self._data = json.dumps({**payload(snap), "version": self.version, "done": done, "status": status}).encode()

    def stop(self, grace: float = 3.0) -> None:
        """Give the page time to fetch the final snapshot, then shut down."""
        if self._server:
            time.sleep(grace)
            self._server.shutdown()
