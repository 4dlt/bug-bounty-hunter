#!/usr/bin/env python3
"""Mock HTTP server with an intentionally race-prone counter endpoint.

Used by tests/smoke/test_race_detection.sh to prove that lib/race-test.sh
can detect TOCTOU-style counter races — the exact class of bug attack-m
is supposed to find in real targets.

Usage:  python3 mock-race-server.py <port>
Endpoints:
  POST /increment     → returns {"counter": <n>, "allowed": true|false}
                        Has a 10ms sleep between `check` and `apply` so
                        parallel POSTs can exceed the `MAX` limit (race win).
  GET  /reset         → reset counter to 0 (test harness only)
  GET  /counter       → read current counter
"""

import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX = 10
counter = 0
counter_lock = threading.Lock()  # only used by /reset and /counter; /increment is intentionally unprotected


class RaceHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, body):
        import json
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        global counter
        if self.path == "/increment":
            current = counter
            if current >= MAX:
                self._send_json(200, {"counter": current, "allowed": False})
                return
            time.sleep(0.01)  # 10ms race window between check and apply
            counter = current + 1
            self._send_json(200, {"counter": counter, "allowed": True})
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        global counter
        if self.path == "/reset":
            with counter_lock:
                counter = 0
            self._send_json(200, {"counter": 0, "reset": True})
        elif self.path == "/counter":
            with counter_lock:
                self._send_json(200, {"counter": counter})
        else:
            self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        pass  # silence default access log


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = ThreadingHTTPServer(("127.0.0.1", port), RaceHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
