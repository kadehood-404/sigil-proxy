#!/usr/bin/env python3
"""
SiGiL IPC v1 client for sigil-proxy / Sentry -> sentinel-x (sigil.sock).
Zero external dependencies (Python standard library only).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import socket
import uuid
from typing import Iterable, Optional


def default_sigil_sock_path() -> str:
    env_sock = os.environ.get("SIGIL_SOCK", "").strip()
    if env_sock:
        return env_sock
    xdg = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if xdg:
        return os.path.join(xdg, "sigil.sock")
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    return f"/tmp/sigil-{uid}.sock"


def _utc_now_iso() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _severity_and_lock(matched_types: list[str]) -> tuple[str, str, str]:
    upper = {m.upper() for m in matched_types}
    if any(k in upper for k in ("INJECTION", "PROMPT_INJECTION", "JAILBREAK")):
        return ("high", "prompt_injection", "locked")
    if any(k in upper for k in ("SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY")):
        return ("high", "secret_leak", "elevated")
    if any(k in upper for k in ("PII", "SSN", "EMAIL", "PHONE")):
        return ("medium", "pii_leak", "elevated")
    return ("medium", "anomalous_prompt", "elevated")


class SigilSockEmitter:
    """Best-effort NDJSON emitter over AF_UNIX SOCK_STREAM to sentinel-x."""

    def __init__(
        self,
        sock_path: Optional[str] = None,
        source: str = "sigil-proxy",
        timeout: float = 0.5,
    ) -> None:
        self.sock_path = sock_path or default_sigil_sock_path()
        self.source = source
        self.timeout = timeout

    def send_envelope(self, msg_type: str, payload: dict) -> bool:
        envelope = {
            "v": 1,
            "id": str(uuid.uuid4()),
            "ts": _utc_now_iso(),
            "source": self.source,
            "type": msg_type,
            "payload": payload,
        }
        wire = (json.dumps(envelope, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(self.sock_path)
                client.sendall(wire)
            return True
        except OSError:
            # Fail open: sentinel-x may not be running in standalone proxy mode.
            return False

    def emit_threat_signal(
        self,
        *,
        session: str,
        path: str,
        matched_types: Iterable[str],
        rule_id: str = "sigil-proxy-match",
        confidence: float = 0.90,
        ttl_seconds: int = 300,
        note: Optional[str] = None,
    ) -> bool:
        types_list = [str(t) for t in matched_types if str(t).strip()]
        if not types_list:
            return False
        severity, category, recommended_lock = _severity_and_lock(types_list)
        payload = {
            "session": session or "default",
            "severity": severity,
            "category": category,
            "rule_id": rule_id,
            "confidence": confidence,
            "recommended_lock": recommended_lock,
            "ttl_seconds": ttl_seconds,
            "matched_types": types_list,
            "note": note or f"Matched {','.join(types_list)} on {path}",
        }
        return self.send_envelope("threat_signal", payload)


if __name__ == "__main__":
    emitter = SigilSockEmitter()
    ok = emitter.emit_threat_signal(
        session="sentry-smoke-1",
        path="/v1/chat/completions",
        matched_types=["INJECTION"],
        note="Live sigil-proxy -> sentinel-x IPC smoke test",
    )
    print(f"sent={ok} sock={emitter.sock_path}")
