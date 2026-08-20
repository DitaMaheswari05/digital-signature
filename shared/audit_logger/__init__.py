import json
import os
import sys
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone

AUDIT_API_URL = os.environ.get("AUDIT_API_URL", "http://audit_api:8000/logs")
_TIMEOUT = float(os.environ.get("AUDIT_API_TIMEOUT", "2.0"))


def _post_event(event: dict) -> None:
    try:
        body = json.dumps(event, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url=AUDIT_API_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            _ = resp.read()
    except urllib.error.URLError as exc:
        print(
            f"[audit_logger] WARNING: audit_api not reachable ({AUDIT_API_URL}): {exc}",
            file=sys.stderr,
        )
    except Exception as exc:
        print(f"[audit_logger] ERROR: {exc}", file=sys.stderr)


def log_event(
    request_id: str,
    step: int,
    service: str,
    client_subject: str,
    result: str,
    reason: str,
    latency_ms: int,
) -> None:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    event = {
        "ts":             now,
        "request_id":     request_id,
        "step":           step,
        "service":        service,
        "client_subject": client_subject,
        "result":         result,
        "reason":         reason,
        "latency_ms":     latency_ms,
    }
    t = threading.Thread(target=_post_event, args=(event,), daemon=True)
    t.start()