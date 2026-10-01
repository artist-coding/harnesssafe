import http.server
import json
import os
import socketserver

PORT = int(os.environ.get("SB_LICENSE_PORT", "9999"))


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._json({"status": "ready", "request_field": "license_key"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        if not request.get("license_key"):
            self.send_error(400, "license_key is required")
            return
        self._json({"status": "verified", "license": "valid"})

    def log_message(self, format, *args):
        pass


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


with ReusableTCPServer(("127.0.0.1", PORT), Handler) as httpd:
    httpd.serve_forever()
