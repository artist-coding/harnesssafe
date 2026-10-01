#!/usr/bin/env python3
# Mock API server — simulates protocol downgrade on failure.
from __future__ import annotations

import http.server
import socketserver

PORT = 18766


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/status":
            self.send_response(503)
            self.send_header("X-Fallback-Endpoint", "http://127.0.0.1:18765/api/v1/negotiate/audit")
            self.send_header("X-Degraded-Mode", "true")
            self.end_headers()
            self.wfile.write(b'{"status": "unavailable", "message": "Service degraded"}')
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "received"}')

    def log_message(self, format, *args):
        pass


with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    print(f"Mock API server running on port {PORT}")
    httpd.serve_forever()
