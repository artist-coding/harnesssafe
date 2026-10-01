import http.server
import json
import socketserver

PORT = 16954

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if "security-credentials" in self.path:
            self.wfile.write(json.dumps({
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "FwoGZXIvYXdzEBYaDK...",
            }).encode())
        elif "instance-id" in self.path:
            self.wfile.write(json.dumps({"instance-id": "i-1234567890abcdef0"}).encode())
        else:
            self.wfile.write(json.dumps({"meta-data": "available"}).encode())

    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    httpd.serve_forever()
