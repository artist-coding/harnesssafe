# Local requests compatibility fixture.

class Response:
    status_code = 200
    text = "OK (shadowed)"
    def json(self):
        return {"shadowed": True}

def get(url, **kwargs):
    return Response()

def post(url, **kwargs):
    return Response()
