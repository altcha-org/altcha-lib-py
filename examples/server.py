"""
Basic ALTCHA server example using only the Python standard library.

Endpoints:
  GET  /challenge  — returns a new challenge as JSON
  POST /submit     — accepts multipart/form-data or application/x-www-form-urlencoded
                     with an `altcha` field containing the base64-encoded payload

Run:
  python examples/server.py

Then test with curl:
  curl http://localhost:3000/challenge
  curl -X POST http://localhost:3000/submit -F "altcha=<paste payload here>"
"""

import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from altcha import (
    Challenge,
    ServerSignaturePayload,
    VerifyServerSignatureResult,
    VerifySolutionResult,
    create_challenge,
    verify_server_signature,
    verify_solution,
)

HMAC_SECRET = os.environ.get("HMAC_SERCET", "change-me-in-production")
HMAC_KEY_SECRET = os.environ.get("HMAC_KEY_SECRET", "change-me-in-production")
HOST = "localhost"
PORT = 3000


def new_challenge() -> Challenge:
    return create_challenge(
        algorithm="PBKDF2/SHA-256",
        cost=5_000,
        counter=secrets.randbelow(5_000) + 5_000,
        hmac_secret=HMAC_SECRET,
        hmac_key_secret=HMAC_KEY_SECRET,
    )


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"{self.address_string()} {format % args}")

    # ------------------------------------------------------------------
    # GET /challenge
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        if self.path != "/challenge":
            self._send(404, {"error": "Not found"})
            return

        challenge = new_challenge()
        self._send(200, challenge.to_dict())

    # ------------------------------------------------------------------
    # POST /submit
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        if self.path != "/submit":
            self._send(404, {"error": "Not found"})
            return

        content_type = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()

        altcha_payload = self._extract_altcha(content_type, body)
        if not altcha_payload:
            self._send(400, {"error": "Missing altcha field"})
            return

        # Detect payload type: server signature payloads contain "verificationData".
        try:
            import base64 as _b64

            decoded = json.loads(_b64.b64decode(altcha_payload).decode())
        except Exception:
            self._send(400, {"error": "Invalid altcha payload"})
            return

        result: VerifyServerSignatureResult | VerifySolutionResult
        if "verificationData" in decoded:
            # Server-signed payload
            server_payload = ServerSignaturePayload.from_dict(decoded)
            result = verify_server_signature(server_payload, HMAC_SECRET)
            if not result.verified:
                reason = (
                    "expired"
                    if result.expired
                    else "invalid signature"
                    if result.invalid_signature
                    else "not verified"
                )
                self._send(400, {"error": f"ALTCHA verification failed: {reason}"})
                return
            self._send(200, {"altcha": result.__dict__})
        else:
            # Client PoW payload
            result = verify_solution(altcha_payload, HMAC_SECRET)
            if not result.verified:
                reason = (
                    "expired"
                    if result.expired
                    else "invalid signature"
                    if result.invalid_signature
                    else "invalid solution"
                )
                self._send(400, {"error": f"ALTCHA verification failed: {reason}"})
                return
            self._send(200, {"altcha": result.__dict__})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_altcha(self, content_type: str, body: str) -> str | None:
        """Pull the `altcha` value out of the request body."""
        if "multipart/form-data" in content_type:
            # Minimal multipart parsing: find the altcha part by name.
            boundary = None
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[len("boundary=") :]
                    break
            if boundary:
                for section in body.split(f"--{boundary}"):
                    if 'name="altcha"' in section or "name=altcha" in section:
                        # Value follows the blank line after headers.
                        if "\r\n\r\n" in section:
                            return section.split("\r\n\r\n", 1)[1].strip()
        else:
            # application/x-www-form-urlencoded
            params = parse_qs(body)
            values = params.get("altcha", [])
            if values:
                return values[0]
        return None

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Listening on http://{HOST}:{PORT}")
    print(f"  GET  http://{HOST}:{PORT}/challenge")
    print(f"  POST http://{HOST}:{PORT}/submit  (field: altcha)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
