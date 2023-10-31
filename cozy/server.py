import http.server
import sys
import os

def get_vizroot():
    candidates = [os.path.join(d, "cozy-viz") for d in sys.path]
    try:
        return list(filter(os.path.exists, candidates))[0]
    except IndexError:
        return None

class VizServer(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=get_vizroot(), **kwargs)

def start_viz_server():
    """
    Serves Cozy-Viz on localhost:8080, for visualization of information
    generated using :fun:`cozy.execution_graph.compare_and_dump`.
    """
    print("launching visualization server, on localhost:8080…")
    http.server.HTTPServer(("",8080),VizServer).serve_forever()
