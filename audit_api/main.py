import logging
from datetime import datetime, timezone
from typing import Optional
import asyncio
import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import db

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [audit-api] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("audit_api")

app = FastAPI(
    title="Audit Log API",
    description="REST API for mTLS Proxy audit log storage and retrieval (PostgreSQL backend).",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    log.info("Waiting for PostgreSQL...")
    db.wait_for_db()
    db.init_schema()
    log.info("Audit API ready.")
    
    retention_months = int(os.environ.get("AUDIT_RETENTION_MONTHS", 60))
    asyncio.create_task(run_retention_task(retention_months))

async def run_retention_task(months: int):
    log.info(f"Log retention task started. Retention set to {months} months.")
    while True:
        try:
            db.delete_old_logs(months)
        except Exception as exc:
            log.error("Failed to run log retention cleanup: %s", exc)
        await asyncio.sleep(86400)


class AuditEvent(BaseModel):
    ts: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp; defaults to server time if omitted.",
    )
    request_id:     str = Field(default="", description="UUID of the originating request.")
    step:           int = Field(default=0,  description="Pipeline step number (e.g. 3).")
    service:        str = Field(default="", description="Reporting service (proxy|waf_service).")
    client_subject: str = Field(default="", description="mTLS client DN.")
    result:         str = Field(default="", description="success | rejected | failed | cert_mismatch | ...")
    reason:         str = Field(default="", description="Human-readable reason for the result.")
    latency_ms:     int = Field(default=0,  description="Processing latency in milliseconds.")


class AuditEventResponse(AuditEvent):
    id: int


class LogsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[dict]


class StatsResponse(BaseModel):
    total: int
    success_count: int
    rejected_count: int
    failed_count: int
    avg_latency_ms: Optional[float]
    max_latency_ms: Optional[int]
    min_latency_ms: Optional[int]


@app.get("/healthz", tags=["system"])
def health_check():
    """Liveness probe."""
    try:
        conn = db.get_conn()
        conn.cursor().execute("SELECT 1")
        return {"status": "ok", "db": "connected"}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"DB unavailable: {exc}")


@app.post("/logs", status_code=201, tags=["audit"])
def create_log(event: AuditEvent):
    ts = event.ts or datetime.now(timezone.utc).isoformat()
    row = {
        "ts":             ts,
        "request_id":     event.request_id,
        "step":           event.step,
        "service":        event.service,
        "client_subject": event.client_subject,
        "result":         event.result,
        "reason":         event.reason,
        "latency_ms":     event.latency_ms,
    }
    try:
        row_id = db.insert_log(row)
        log.info(
            "Logged | id=%d service=%s result=%s latency=%dms",
            row_id, event.service, event.result, event.latency_ms,
        )
        return {"id": row_id, **row}
    except Exception as exc:
        log.error("Failed to insert log: %s", exc)
        raise HTTPException(status_code=500, detail=f"DB insert failed: {exc}")


@app.get("/logs", response_model=LogsResponse, tags=["audit"])
def list_logs(
    service:     Optional[str] = Query(None, description="Filter by service name"),
    result:      Optional[str] = Query(None, description="Filter by result value"),
    request_id:  Optional[str] = Query(None, alias="request_id", description="Filter by request UUID"),
    date_from:   Optional[str] = Query(None, description="ISO-8601 datetime lower bound"),
    date_to:     Optional[str] = Query(None, description="ISO-8601 datetime upper bound"),
    search:      Optional[str] = Query(None, description="Full-text search in reason/subject/request_id"),
    limit:       int           = Query(50,  ge=1, le=500, description="Page size"),
    offset:      int           = Query(0, ge=0,description="Page offset"),
):

    try:
        items = db.query_logs(
            service=service,
            result=result,
            request_id=request_id,
            date_from=date_from,
            date_to=date_to,
            search=search,
            limit=limit,
            offset=offset,
        )
        total = db.count_logs(
            service=service,
            result=result,
            date_from=date_from,
            date_to=date_to,
            search=search,
        )
        return {"total": total, "limit": limit, "offset": offset, "items": items}
    except Exception as exc:
        log.error("Query failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Query failed: {exc}")


@app.get("/logs/stats", response_model=StatsResponse, tags=["audit"])
def get_stats():
    try:
        return db.get_stats()
    except Exception as exc:
        log.error("Stats query failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Stats query failed: {exc}")


@app.get("/logs/{log_id}", tags=["audit"])
def get_log(log_id: int):
    try:
        row = db.get_log_by_id(log_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Query failed: {exc}")
    if row is None:
        raise HTTPException(status_code=404, detail=f"Log id={log_id} not found.")
    return row
