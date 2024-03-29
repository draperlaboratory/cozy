from http.server import HTTPServer, SimpleHTTPRequestHandler, HTTPStatus
import json
from functools import partial
import sys
import time
import os
import threading
import webbrowser

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

def start_viz_server(pre={}, post={}, open_browser=False, port=8080):
    """
    Serves Cozy-Viz on localhost:8080.

    Useful for visualization of information generated using
    :func:`cozy.execution_graph.compare_and_dump`.

    To include comparison data, use the `pre` and `post` arguments, and add
    a query string to the URL, like so: `localhost:8080?pre=/pre&post=/post`.

    :param dict, optional pre: served as JSON at `/pre` on the server. Default {}.
    :param dict, optional post: served as JSON at `/post` on the server. Default {}.
    :param int, optional port: An alternative port to serve on. Default 8080.
    """
    print("launching visualization server, on localhost:8080…")
    handler = partial(VizHandler, pre, post, directory=get_vizroot())
    thread = threading.Thread(None,HTTPServer(("",port),handler).serve_forever)
    thread.daemon = True
    thread.start()
    if open_browser:
        webbrowser.open_new("localhost:" + str(port) + "/?pre=/pre&post=/post")
    while True:
        time.sleep(1)
    
