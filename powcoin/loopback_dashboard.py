"""Read-only loopback dashboard for a token-protected PowCoin node."""

import argparse
import json
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .dashboard import DASHBOARD


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path)
        if path.path == "/":
            body = DASHBOARD.encode("utf-8")
            content_type = "text/html; charset=utf-8"
            status = 200
        elif (path.path in ("/status", "/blocks", "/mempool/details")
              or path.path.startswith("/accounts/")):
            request = urllib.request.Request(
                self.server.node_url + self.path,
                headers={"Authorization": "Bearer " + self.server.token},
            )
            try:
                with self.server.opener.open(request, timeout=5) as response:
                    body = response.read(8 * 1024 * 1024 + 1)
                    if len(body) > 8 * 1024 * 1024:
                        raise ValueError("Node response is too large")
                    content_type = "application/json"
                    status = response.status
            except urllib.error.HTTPError as exc:
                body = exc.read(4096)
                content_type = "application/json"
                status = exc.code
            except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                body = json.dumps({"error": str(exc)}).encode("utf-8")
                content_type = "application/json"
                status = 502
        else:
            body = b'{"error":"Unknown endpoint"}'
            content_type = "application/json"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="Local dashboard for a protected PowCoin node")
    parser.add_argument("--node-url", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--port", type=int, default=8844)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.node_url = args.node_url.rstrip("/")
    server.token = Path(args.token_file).read_text(encoding="utf-8").strip()
    server.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    print(f"Dashboard: http://127.0.0.1:{args.port}/", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
