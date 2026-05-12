#!/usr/bin/env python3
"""Tiny HTTP server that simulates an OAuth refresh endpoint.
Returns: {"access_token": "new.token.<counter>", "expires_in": 60}
Counts requests for the smoke test to assert exactly N refreshes happened."""
import http.server
import json
import os

COUNTER_FILE = "/tmp/mock-refresh-counter.txt"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/fail-token":
            body = b'{"error":"invalid_grant","error_description":"refresh token revoked"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Default success path (existing behavior)
        n = 0
        if os.path.exists(COUNTER_FILE):
            n = int(open(COUNTER_FILE).read().strip() or "0")
        n += 1
        open(COUNTER_FILE, "w").write(str(n))
        body = json.dumps({"access_token": f"new.token.{n}", "expires_in": 60})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args, **kwargs):
        pass  # silence


if __name__ == "__main__":
    if os.path.exists(COUNTER_FILE):
        os.remove(COUNTER_FILE)
    http.server.HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
