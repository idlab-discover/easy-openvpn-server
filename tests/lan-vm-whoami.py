"""HTTP server for the lan VM of tests/harness.sh.

Answers every request with the source address it came from, so the harness
can tell whether a request from a client VM went through the VPN: then the
source is the server's lan address, because of NAT.
"""
import http.server


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode() + b"\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
