#!/usr/bin/env python3
"""dumb-update-server.py — Phase-0 self-signed TLS firmware server (WORKPLAN T0.6).

Serves an ESP-IDF firmware .bin over HTTPS so the device can exercise
esp_https_ota end-to-end without any Uptane backend. It publishes two targets:

    GET /firmware.bin           the real image (installs + boots + confirms)
    GET /firmware-corrupt.bin   a byte-flipped copy (must fail verify -> rollback)
    GET /                       a plain-text index of both

Both are sent as application/octet-stream with a correct Content-Length and no
gzip, so the streamed bytes match exactly (mirrors the gateway's no-gzip rule,
SPEC §3). This is a *dumb* server: no signatures, no auth — Phase 0 only.

Self-signed cert/key are auto-generated (via `openssl`) next to this script if
absent; pass the printed CA PEM to the device as the pinned server CA, or run
the client with CN checking disabled (aktualino_net skip_server_cn_check).

Usage:
    tools/dumb-update-server.py --bin build-esp32/aktualino.bin
    tools/dumb-update-server.py --bin fw.bin --host 0.0.0.0 --port 8443
"""
import argparse
import http.server
import os
import ssl
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CERT = SCRIPT_DIR / "dumb-server-cert.pem"
DEFAULT_KEY = SCRIPT_DIR / "dumb-server-key.pem"


def ensure_cert(cert_path: Path, key_path: Path, cn: str) -> None:
    """Generate a self-signed cert/key with openssl if they don't exist."""
    if cert_path.exists() and key_path.exists():
        return
    print(f"[dumb-server] generating self-signed cert (CN={cn}) ...")
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "365", "-nodes",
            "-subj", f"/CN={cn}",
            "-addext", f"subjectAltName=DNS:{cn},IP:127.0.0.1",
        ],
        check=True,
    )
    print(f"[dumb-server] wrote {cert_path} and {key_path}")


def corrupt(data: bytes) -> bytes:
    """Return a variant that fails image verification.

    Flip bits inside the app body (past the esp_image header/segment table) so
    the *download hash* mismatches and, if it slipped past that, esp_ota_end's
    validation of the image would reject it too.
    """
    b = bytearray(data)
    if len(b) > 4096:
        for off in range(2048, min(len(b), 2048 + 256)):
            b[off] ^= 0xFF
    else:  # tiny file: just flip everything we can
        for i in range(len(b)):
            b[i] ^= 0xFF
    return bytes(b)


def make_handler(real: bytes, bad: bytes):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "aktualino-dumb/0.1"

        def _send_blob(self, blob: bytes):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(blob)

        def do_GET(self):  # noqa: N802 (http.server API)
            if self.path in ("/firmware.bin", "/aktualino.bin"):
                print(f"[dumb-server] serving REAL image ({len(real)} bytes)")
                self._send_blob(real)
            elif self.path in ("/firmware-corrupt.bin", "/corrupt.bin"):
                print(f"[dumb-server] serving CORRUPT image ({len(bad)} bytes)")
                self._send_blob(bad)
            elif self.path == "/":
                body = (
                    "Aktualino dumb update server\n"
                    f"  /firmware.bin          {len(real)} bytes (good)\n"
                    f"  /firmware-corrupt.bin  {len(bad)} bytes (rollback test)\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404, "no such target")

        def log_message(self, fmt, *args):
            sys.stderr.write("[dumb-server] %s - %s\n"
                             % (self.address_string(), fmt % args))

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True, help="firmware .bin to serve")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY)
    ap.add_argument("--cn", default="aktualino-dumb.local",
                    help="CN/SAN for the generated self-signed cert")
    args = ap.parse_args()

    bin_path = Path(args.bin)
    if not bin_path.is_file():
        print(f"[dumb-server] ERROR: {bin_path} not found", file=sys.stderr)
        return 1
    real = bin_path.read_bytes()
    bad = corrupt(real)

    ensure_cert(args.cert, args.key, args.cn)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))

    httpd = http.server.ThreadingHTTPServer(
        (args.host, args.port), make_handler(real, bad))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"[dumb-server] serving {bin_path} ({len(real)} bytes) on "
          f"https://{args.host}:{args.port}/  (CA: {args.cert})")
    print("[dumb-server] Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dumb-server] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
