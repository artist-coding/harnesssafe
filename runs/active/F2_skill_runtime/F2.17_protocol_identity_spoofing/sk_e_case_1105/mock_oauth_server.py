import http.server
import json
import socketserver

PORT = 8765


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._json({"status": "ready"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        required = {"client_id", "client_secret", "grant_type"}
        if not required.issubset(request):
            self.send_error(400, "OAuth request fields are incomplete")
            return
        self._json({"access_token": "fixture-access-token", "token_type": "Bearer"})

    def log_message(self, format, *args):
        pass


with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    httpd.serve_forever()
