"""
aletheia.server — Phase 2.3: REST API (stdlib-only WSGI)

A thin HTTP API over the existing Aletheia Python API.
No external dependencies — uses http.server from the stdlib.
Every endpoint maps directly to an existing function.
The Spine stays on disk. The API is stateless between requests.

Endpoints:
  POST /ingest              IngestGate.ingest()
  POST /seal/<window_id>    SpineLedger.seal_window()
  GET  /verify              verify_spine()
  POST /export              build_case_zip() → returns zip bytes
  POST /claimcheck          Upload case.zip, run ClaimCheck
  GET  /siren/state         Current Siren state
  GET  /health              Liveness: OK or DEGRADED
  GET  /windows             List open + sealed windows

All responses are JSON unless /export (returns application/zip).
Errors always return {"error": "...", "code": "..."} with appropriate status.

Usage:
    from aletheia.server import AletheiaServer
    srv = AletheiaServer(root_dir="./evidence_root", port=8741)
    srv.start()   # blocks
    # or:
    srv.start_background()  # daemon thread
    srv.stop()

Security note:
    This server has NO authentication. It is designed for:
    - Local use (loopback only by default)
    - Internal network with external auth proxy (nginx, Tailscale, etc.)
    Bind to 0.0.0.0 only if you add authentication upstream.
"""
from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from aletheia.spine.ledger import SpineLedger
from aletheia.spine.verify import verify_spine
from aletheia.siren.state_machine import Siren, SirenState, MaydayCode
from aletheia.ingest.gate import IngestGate, IngestConfig, IngestDecision
from aletheia.chronicle.export import build_case_zip
from aletheia.claims.claimcheck import check_claim


SERVER_VERSION = "2.1"


class AletheiaServer:
    """
    Lightweight HTTP server wrapping Aletheia core.

    Args:
        root_dir:   evidence root directory (same as SpineLedger root)
        host:       bind address (default: 127.0.0.1 — loopback only)
        port:       TCP port (default: 8741)
        signer:     optional signing key (HMACSigner / NullSigner)
        ingest_config: optional IngestConfig override
    """

    def __init__(
        self,
        root_dir: str,
        *,
        host: str = "127.0.0.1",
        port: int = 8741,
        signer=None,
        ingest_config: Optional[IngestConfig] = None,
    ) -> None:
        self.root_dir = str(root_dir)
        self.host = host
        self.port = port
        self.signer = signer

        # Shared state — initialised once, used by all requests
        self.ledger = SpineLedger(self.root_dir, signer=signer)
        self.siren = Siren(self.ledger)
        cfg = ingest_config or IngestConfig()
        self.gate = IngestGate(self.ledger, siren=self.siren, config=cfg)

        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start server. Blocks until stop() is called or KeyboardInterrupt."""
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.ledger.close_clean()

    def start_background(self) -> None:
        """Start server in a background daemon thread."""
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="aletheia-server",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop server and seal ledger cleanly."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        self.ledger.close_clean()

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # suppress default access log; use structured logging if needed

            def _send_json(self, status: int, obj: Any) -> None:
                body = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_zip(self, data: bytes) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", 'attachment; filename="case.zip"')
                self.end_headers()
                self.wfile.write(data)

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length", 0))
                return self.rfile.read(length) if length > 0 else b""

            def _parse_path(self) -> Tuple[str, Dict[str, str]]:
                parsed = urllib.parse.urlparse(self.path)
                params = dict(urllib.parse.parse_qsl(parsed.query))
                return parsed.path.rstrip("/"), params

            def do_GET(self):
                path, _ = self._parse_path()
                try:
                    if path == "/health":
                        self._handle_health()
                    elif path == "/verify":
                        self._handle_verify()
                    elif path == "/siren/state":
                        self._handle_siren_state()
                    elif path == "/windows":
                        self._handle_windows()
                    else:
                        self._send_json(404, {"error": "Not found", "code": "NOT_FOUND"})
                except Exception as e:
                    self._send_json(500, {"error": str(e), "code": "INTERNAL_ERROR",
                                          "trace": traceback.format_exc()[-500:]})

            def do_POST(self):
                path, _ = self._parse_path()
                try:
                    if path == "/ingest":
                        self._handle_ingest()
                    elif path == "/export":
                        self._handle_export()
                    elif path == "/claimcheck":
                        self._handle_claimcheck()
                    elif path.startswith("/seal/"):
                        window_id = path[6:]
                        self._handle_seal(window_id)
                    else:
                        self._send_json(404, {"error": "Not found", "code": "NOT_FOUND"})
                except Exception as e:
                    self._send_json(500, {"error": str(e), "code": "INTERNAL_ERROR",
                                          "trace": traceback.format_exc()[-500:]})

            # ── Handlers ──────────────────────────────────────────────────────

            def _handle_health(self):
                siren_state = server.siren.state.value
                ok = siren_state in ("NORMAL", "DEGRADED_CAPTURE")
                self._send_json(200 if ok else 503, {
                    "status": "OK" if ok else "DEGRADED",
                    "siren_state": siren_state,
                    "server_version": SERVER_VERSION,
                })

            def _handle_verify(self):
                report = verify_spine(server.root_dir, signer=server.signer)
                self._send_json(200, report)

            def _handle_siren_state(self):
                self._send_json(200, {
                    "state": server.siren.state.value,
                    "server_version": SERVER_VERSION,
                })

            def _handle_windows(self):
                windows_dir = Path(server.root_dir) / "spine" / "windows"
                open_w, sealed_w = [], []
                if windows_dir.exists():
                    for wdir in sorted(windows_dir.iterdir()):
                        if not wdir.is_dir():
                            continue
                        if (wdir / "sealed.json").exists():
                            sealed_w.append(wdir.name)
                        elif (wdir / "open.json").exists():
                            open_w.append(wdir.name)
                self._send_json(200, {
                    "open": open_w,
                    "sealed": sealed_w,
                    "total": len(open_w) + len(sealed_w),
                })

            def _handle_ingest(self):
                body = self._read_body()
                if not body:
                    self._send_json(400, {"error": "Empty body", "code": "BAD_REQUEST"})
                    return
                try:
                    record = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError as e:
                    self._send_json(400, {"error": f"Invalid JSON: {e}", "code": "BAD_JSON"})
                    return

                result = server.gate.ingest(record)
                if result.decision == IngestDecision.ACCEPT:
                    self._send_json(200, {
                        "accepted": True,
                        "window_id": result.window_id,
                        "event_type": result.event_type,
                    })
                else:
                    self._send_json(422, {
                        "accepted": False,
                        "reason": result.reason.value if result.reason else "UNKNOWN",
                        "detail": result.detail or {},
                    })

            def _handle_seal(self, window_id: str):
                if not window_id:
                    self._send_json(400, {"error": "window_id required", "code": "BAD_REQUEST"})
                    return
                try:
                    seal = server.ledger.seal_window(window_id)
                    self._send_json(200, {
                        "sealed": True,
                        "window_id": window_id,
                        "window_root_hash": seal.window_root_hash,
                        "signing_mode": seal.signing_mode,
                    })
                except Exception as e:
                    self._send_json(409, {"error": str(e), "code": "SEAL_FAILED"})

            def _handle_export(self):
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp_path = tmp.name
                try:
                    build_case_zip(server.root_dir, tmp_path)
                    data = Path(tmp_path).read_bytes()
                    self._send_zip(data)
                except Exception as e:
                    self._send_json(500, {"error": str(e), "code": "EXPORT_FAILED"})
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

            def _handle_claimcheck(self):
                body = self._read_body()
                if not body:
                    self._send_json(400, {"error": "Empty body — upload case.zip", "code": "BAD_REQUEST"})
                    return
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                    tmp.write(body)
                    tmp_path = tmp.name
                try:
                    # Check all claims in the uploaded bundle
                    from aletheia.claims.claimcheck import check_all_claims
                    results = check_all_claims(tmp_path)
                    self._send_json(200, {
                        "claims": [
                            {
                                "claim_id": r.claim_id,
                                "verdict": r.verdict,
                                "reasons": r.reasons,
                                "pins_checked": r.pins_checked,
                            }
                            for r in results
                        ],
                        "total": len(results),
                    })
                except Exception as e:
                    self._send_json(422, {"error": str(e), "code": "CLAIMCHECK_FAILED"})
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        return Handler
