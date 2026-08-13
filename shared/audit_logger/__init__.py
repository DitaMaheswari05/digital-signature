import os
import sys
import json
from datetime import datetime, timezone
if sys.platform == "win32":
    import msvcrt
else:
    import fcntl
AUDIT_LOG_DIR = os.environ.get("AUDIT_LOG_DIR", "/audit_logs")


def log_event(
    request_id: str,
    step: int,
    service: str,
    client_subject: str,
    result: str,
    reason: str,
    latency_ms: int,
) -> None:

    try:
        os.makedirs(AUDIT_LOG_DIR, exist_ok=True)
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y-%m-%d")
        filepath = os.path.join(AUDIT_LOG_DIR, f"audit_{date_str}.jsonl")
        timestamp = now.isoformat().replace("+00:00", "Z")
        event = {
            "ts": timestamp,
            "request_id": request_id,
            "step": step,
            "service": service,
            "client_subject": client_subject,
            "result": result,
            "reason": reason,
            "latency_ms": latency_ms,
        }
        json_line = json.dumps(event, ensure_ascii=False) + "\n"
        f = None
        try:
            f = open(filepath, "a", encoding="utf-8")
            if sys.platform == "win32":
                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(json_line)
            f.flush()
        finally:
            if f is not None:
                try:
                    if sys.platform == "win32":
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass  
                f.close()
    except Exception as e:
        print(f"[audit_logger] ERROR: {e}", file=sys.stderr)