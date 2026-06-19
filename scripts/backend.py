#!/usr/bin/env python3
"""Tiny HTTP backend for the demo: replies with its own name."""
import http.server
import os

NAME = os.environ.get("NAME", "backend")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"served by {NAME}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
