# Realistic test origin (item 7 acceptance). Python stdlib ONLY — no
# dependencies to add, nothing to install beyond the base image. One
# process, TWO listeners (9001, 9002): the same site behind two "deploy
# versions", so an origin change through the API is visible in the body
# ("... port 9001" -> "... port 9002") without a second container.
#
# Endpoints (what the edge must pass through, not interpret):
#   /ok            plain 200; body names the serving port
#   /slow          200 after a 2s delay (bounded slow origin)
#   /big           5 MiB streamed in 64 KiB flushes (Content-Length known)
#   /redirect      302 + Location: /ok — the EDGE passes it through; only
#                  a client that follows it lands on /ok
#   /cookie        200 + Set-Cookie (response-header passthrough)
#   /echo-headers  what the ORIGIN sees: Host, X-Forwarded-For, method,
#                  User-Agent, proto — one line, parseable by the script
#   /status/<N>    echoes N as the status code
#   /chunked       hand-framed chunked transfer-encoding, flushed per chunk
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import sleep

PORTS = (9001, 9002)


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive; lengths always sent

    def log_message(self, *a):  # quiet: the edge's logs are the subject here
        pass

    def do_GET(self):
        try:
            self.route()
        except (BrokenPipeError, ConnectionResetError):
            pass  # a client that hangs up mid-stream is not a crash

    def route(self):
        port = self.server.server_address[1]
        path = self.path.split("?", 1)[0]
        if path == "/ok":
            self.body(f"ok from origin-test port {port}\n")
        elif path == "/slow":
            sleep(2)
            self.body(f"slow ok from origin-test port {port}\n")
        elif path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(64 * 1024 * 80))
            self.end_headers()
            chunk = b"0123456789abcdef" * 4096  # 64 KiB
            for _ in range(80):
                self.wfile.write(chunk)
                self.wfile.flush()
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/cookie":
            self.body(f"cookie set by origin-test port {port}\n",
                      extra_headers=[("Set-Cookie", f"gporigin=port-{port}; Path=/")])
        elif path == "/echo-headers":
            xff = self.headers.get("X-Forwarded-For", "(none)")
            ua = self.headers.get("User-Agent", "(none)")
            self.body(
                f"host={self.headers.get('Host', '(none)')} xff={xff} "
                f"method={self.command} ua={ua} proto={self.request_version} "
                f"port={port}\n"
            )
        elif path.startswith("/status/"):
            try:
                code = int(path.rsplit("/", 1)[1])
            except ValueError:
                code = 400
            if not 200 <= code < 600:
                code = 400
            self.send_response(code)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for piece in (b"chunk-one ", b"chunk-two ", b"chunk-three"):
                self.wfile.write(f"{len(piece):x}\r\n".encode())
                self.wfile.write(piece + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        else:
            self.send_response(404)
            self.body(f"not found on origin-test port {port}\n")

    def body(self, text, extra_headers=()):
        data = text.encode()
        self.send_response(200)
        for k, v in extra_headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    servers = [ThreadingHTTPServer(("0.0.0.0", p), OriginHandler) for p in PORTS]
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    print(f"origin-test up on ports {PORTS}", flush=True)
    threads[0].join()


if __name__ == "__main__":
    main()
