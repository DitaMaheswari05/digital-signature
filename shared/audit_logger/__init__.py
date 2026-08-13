"""
shared/audit_logger/__init__.py
Structured audit event logger for mTLS Proxy system.
Writes JSONL (JSON Lines) files — one event per line — to a local directory.
Thread-safe and multi-process-safe via file-level exclusive locking (fcntl on Linux).
All exceptions are swallowed and logged to stderr to prevent log failures
from propagating to request handlers.
Usage:
    from audit_logger import log_event
    log_event(
        request_id="abc-123",
        step=3,
        service="waf_service",
        client_subject="CN=client.local",
        result="success",
        reason="All 3 verification layers passed",
        latency_ms=42,
    )
"""
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
    """
    Write a single structured audit event to today's JSONL file.
    Args:
        request_id: Unique request identifier (X-Request-ID)
        step: Processing step number (e.g., 1=Proxy, 3=WAF, 4=WebApp)
        service: Service name ("proxy", "waf_service", "webapp")
        client_subject: Client certificate subject DN (empty string if N/A)
        result: Outcome ("success", "rejected", "error", "passed", etc.)
        reason: Human-readable reason or error message
        latency_ms: Processing latency in milliseconds
    File format:
        - Directory: AUDIT_LOG_DIR (default: /audit_logs)
        - Filename: audit_YYYY-MM-DD.jsonl (UTC date)
        - Each line: JSON object with fields ts, request_id, step, service,
                     client_subject, result, reason, latency_ms
        - Timestamp (ts): ISO-8601 UTC format (e.g., "2025-01-17T12:34:56.789012Z")
    Concurrency:
        - Uses fcntl.flock(LOCK_EX) for file-level exclusive locking on Linux/Mac
        - Fallback to msvcrt.locking on Windows (not used in Docker)
        - File is opened, locked, written, unlocked, closed per call (crash-safe)
    Exceptions:
        - All exceptions are caught, logged to stderr, and swallowed
        - Never raises (safe to call from request handlers)
    Example:
        log_event(
            request_id="abc-123",
            step=3,
            service="waf_service",
            client_subject="CN=client.example.com",
            result="success",
            reason="CMS signature valid",
            latency_ms=42,
        )
        Writes to /audit_logs/audit_2025-01-17.jsonl:
        {"ts":"2025-01-17T12:34:56.789012Z","request_id":"abc-123","step":3,...}
    """
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