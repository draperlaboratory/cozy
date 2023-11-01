from http.server import HTTPServer, SimpleHTTPRequestHandler, HTTPStatus
import json
from functools import partial
import sys
import os

def get_vizroot():
    candidates = [os.path.join(d, "cozy-viz") for d in sys.path]
    try:
        return list(filter(os.path.exists, candidates))[0]
    except IndexError:
        return None

class VizHandler(SimpleHTTPRequestHandler):
    def __init__(self, prepatch, postpatch, *args, **kwargs):
        self.prepatch = prepatch
        self.postpatch = postpatch
        super().__init__(*args,  **kwargs)

    def do_GET(self):
        if self.path == "/pre":
            self.send_response(HTTPStatus.OK.value)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(self.prepatch),'utf-8'))
        elif self.path == "/post":
            self.send_response(HTTPStatus.OK.value)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(self.postpatch),'utf-8'))
        else: super().do_GET()

def start_viz_server(pre={},post={}):
    """
    Serves Cozy-Viz on localhost:8080, for visualization of information
    generated using :fun:`cozy.execution_graph.compare_and_dump`.
    """
    print("launching visualization server, on localhost:8080…")
    handler = partial(VizHandler, pre, post, directory=get_vizroot())
    HTTPServer(("",8080),handler).serve_forever()
