#!/usr/bin/env python3
"""Local primary API fixture returning a stable healthy response."""
from __future__ import annotations

import http.server
import socketserver

PORT = 18766


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "api_version": "v1"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    print(f"Mock API server running on port {PORT}")
    httpd.serve_forever()
