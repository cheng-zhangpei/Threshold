#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._handle("GET")
    def do_POST(self):
        self._handle("POST")
    def do_PUT(self):
        self._handle("PUT")
    def do_DELETE(self):
        self._handle("DELETE")

    def _handle(self, method):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        # 打印请求信息
        print(f"\n{'='*60}")
        print(f"[HTTP] {method} {self.path}")
        print(f"[HTTP] Client: {self.client_address[0]}:{self.client_address[1]}")
        for k, v in self.headers.items():
            print(f"[HTTP] Header: {k} = {v}")
        if body:
            print(f"[HTTP] Body: {body[:200]}...")
        print(f"{'='*60}\n")

        # 响应
        response = {
            "status": "ok",
            "method": method,
            "path": self.path,
            "timestamp": time.time()
        }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8080), Handler)
    print("HTTP Pong server listening on port 8080")
    server.serve_forever()