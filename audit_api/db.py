import os
import time
import logging
import psycopg2
import psycopg2.extras

log = logging.getLogger("audit_api.db")

DB_HOST = os.environ.get("POSTGRES_HOST", "postgres")
DB_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
DB_NAME = os.environ.get("POSTGRES_DB", "audit_db")
DB_USER = os.environ.get("POSTGRES_USER", "audituser")
DB_PASS = os.environ.get("POSTGRES_PASSWORD")

if not DB_PASS:
    raise ValueError("POSTGRES_PASSWORD environment variable must be set")

_CONN: psycopg2.extensions.connection | None = None

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_id    TEXT        NOT NULL DEFAULT '',
    step          INT         NOT NULL DEFAULT 0,
    service       TEXT        NOT NULL DEFAULT '',
    client_subject TEXT       NOT NULL DEFAULT '',
    result        TEXT        NOT NULL DEFAULT '',
    reason        TEXT        NOT NULL DEFAULT '',
    latency_ms    INT         NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_ts         ON audit_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_result     ON audit_logs (result);
CREATE INDEX IF NOT EXISTS idx_audit_logs_service    ON audit_logs (service);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs (request_id);
"""


def _dsn() -> str:
    return (
        f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} "
        f"user={DB_USER} password={DB_PASS} "
        "connect_timeout=5 options='-c statement_timeout=10000'"
    )


def get_conn() -> psycopg2.extensions.connection:
    global _CONN
    try:
        if _CONN is not None and not _CONN.closed:
            # Cheap ping to verify connection is still alive
            _CONN.cursor().execute("SELECT 1")
            return _CONN
    except Exception:
        _CONN = None

    _CONN = psycopg2.connect(_dsn())
    _CONN.autocommit = True
    return _CONN


def wait_for_db(max_retries: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, max_retries + 1):
        try:
            conn = psycopg2.connect(_dsn())
            conn.close()
            log.info("PostgreSQL ready after %d attempt(s).", attempt)
            return
        except psycopg2.OperationalError as exc:
            log.warning("DB not ready (attempt %d/%d): %s", attempt, max_retries, exc)
            time.sleep(delay)
    raise RuntimeError(f"PostgreSQL not available after {max_retries} retries.")


def init_schema() -> None:
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)
    log.info("Schema initialized (audit_logs table ready).")


def insert_log(event: dict) -> int:
    conn = get_conn()
    sql = """
        INSERT INTO audit_logs
            (ts, request_id, step, service, client_subject, result, reason, latency_ms)
        VALUES
            (%(ts)s, %(request_id)s, %(step)s, %(service)s,
             %(client_subject)s, %(result)s, %(reason)s, %(latency_ms)s)
        RETURNING id
    """
    with conn.cursor() as cur:
        cur.execute(sql, event)
        row_id = cur.fetchone()[0]
    return row_id


def query_logs(
    service: str | None = None,
    result: str | None = None,
    request_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    if service:
        conditions.append("service = %(service)s")
        params["service"] = service
    if result:
        conditions.append("result = %(result)s")
        params["result"] = result
    if request_id:
        conditions.append("request_id = %(request_id)s")
        params["request_id"] = request_id
    if date_from:
        conditions.append("ts >= %(date_from)s::timestamptz")
        params["date_from"] = date_from
    if date_to:
        conditions.append("ts <= %(date_to)s::timestamptz")
        params["date_to"] = date_to
    if search:
        conditions.append(
            "(reason ILIKE %(search)s OR client_subject ILIKE %(search)s "
            "OR request_id ILIKE %(search)s)"
        )
        params["search"] = f"%{search}%"

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"""
        SELECT id, ts, request_id, step, service, client_subject, result, reason, latency_ms
        FROM   audit_logs
        {where}
        ORDER BY ts DESC
        LIMIT %(limit)s OFFSET %(offset)s
    """
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    # Convert timestamp to ISO string for JSON serialisation
    result_list = []
    for row in rows:
        d = dict(row)
        if d.get("ts"):
            d["ts"] = d["ts"].isoformat()
        result_list.append(d)
    return result_list


def count_logs(
    service: str | None = None,
    result: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    search: str | None = None,
) -> int:
    conditions = []
    params: dict = {}

    if service:
        conditions.append("service = %(service)s")
        params["service"] = service
    if result:
        conditions.append("result = %(result)s")
        params["result"] = result
    if date_from:
        conditions.append("ts >= %(date_from)s::timestamptz")
        params["date_from"] = date_from
    if date_to:
        conditions.append("ts <= %(date_to)s::timestamptz")
        params["date_to"] = date_to
    if search:
        conditions.append(
            "(reason ILIKE %(search)s OR client_subject ILIKE %(search)s "
            "OR request_id ILIKE %(search)s)"
        )
        params["search"] = f"%{search}%"

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT COUNT(*) FROM audit_logs {where}"
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()[0]


def get_stats() -> dict:
    sql = """
        SELECT
            COUNT(*)                                              AS total,
            COUNT(*) FILTER (WHERE result = 'success')           AS success_count,
            COUNT(*) FILTER (WHERE result = 'rejected')          AS rejected_count,
            COUNT(*) FILTER (WHERE result NOT IN ('success','rejected')) AS failed_count,
            ROUND(AVG(latency_ms)::numeric, 2)                   AS avg_latency_ms,
            MAX(latency_ms)                                       AS max_latency_ms,
            MIN(latency_ms)                                       AS min_latency_ms
        FROM audit_logs
        WHERE ts >= NOW() - INTERVAL '24 hours'
    """
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql)
        row = dict(cur.fetchone())
    # psycopg2 returns Decimal for ROUND; cast to float
    for k in ("avg_latency_ms",):
        if row.get(k) is not None:
            row[k] = float(row[k])
    return row


def get_log_by_id(log_id: int) -> dict | None:
    sql = """
        SELECT id, ts, request_id, step, service, client_subject, result, reason, latency_ms
        FROM   audit_logs
        WHERE  id = %s
    """
    conn = get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (log_id,))
        row = cur.fetchone()
    if row is None:
        return None
    d = dict(row)
    if d.get("ts"):
        d["ts"] = d["ts"].isoformat()
    return d


def delete_old_logs(months: int) -> int:
    if months <= 0:
        return 0
    sql = "DELETE FROM audit_logs WHERE ts < NOW() - INTERVAL '%s months'"
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(sql, (months,))
        deleted_count = cur.rowcount
    log.info("Deleted %d old log entries (older than %d months).", deleted_count, months)
    return deleted_count
