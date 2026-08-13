import os
import sys
import time
import logging
import urllib.parse
from pathlib import Path
from functools import lru_cache
from fastapi import FastAPI, Request, HTTPException, Header
from typing import Optional
from crypto_utils import (
    load_cert_from_pem_string,
    load_trusted_ca_bundle,
    verify_cert_trusted,
)
from cms_verifier import verify_cms_signature
from metrics import record_mtls_result
_SHARED_LIB = Path(__file__).resolve().parent.parent.parent / "shared"
if str(_SHARED_LIB) not in sys.path:
    sys.path.insert(0, str(_SHARED_LIB))
try:
    from audit_logger import log_event as _audit_log_event
except Exception:
    def _audit_log_event(*args, **kwargs):
        pass
app = FastAPI()
try:
    from metrics import setup_waf_metrics
    setup_waf_metrics(app)
except Exception:
    pass
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [waf-service] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("waf-service")
_SEP = "-" * 55
_DOCKER_KEYCERT = Path("/key_cert")
_LOCAL_KEYCERT  = Path(__file__).resolve().parent.parent.parent.parent / "key_cert"
KEYCERT_DIR = _DOCKER_KEYCERT if _DOCKER_KEYCERT.is_dir() else _LOCAL_KEYCERT
_CA_BUNDLE_FILE = KEYCERT_DIR / "clientca_rootca_.pem"


@lru_cache(maxsize=1)
def _get_trusted_cas():
    if not _CA_BUNDLE_FILE.exists():
        raise RuntimeError(
            f"CA bundle tidak ditemukan: {_CA_BUNDLE_FILE}. "
            "Pastikan volume /key_cert sudah di-mount ke waf_service."
        )
    cas = load_trusted_ca_bundle(_CA_BUNDLE_FILE)
    if not cas:
        raise RuntimeError(f"CA bundle kosong atau tidak valid: {_CA_BUNDLE_FILE}")
    return cas


@app.on_event("startup")
async def startup_event():
    try:
        cas = _get_trusted_cas()
        log.info("CA bundle loaded: %d CA cert(s) dari %s", len(cas), _CA_BUNDLE_FILE)
    except Exception as e:
        log.warning("Gagal load CA bundle saat startup: %s", e)


@app.post("/verify")
async def verify_request(
    request: Request,
    x_ssl_client_verify: Optional[str] = Header(None),
    x_ssl_client_cert:   Optional[str] = Header(None),
    x_ssl_client_s_dn:   Optional[str] = Header(None),
    x_original_method:   Optional[str] = Header(None),
):
    _request_start = time.perf_counter()
    method = (x_original_method or request.method).upper()
    log.info(_SEP)
    log.info("[Step 3] Menerima subrequest verifikasi | method=%s", method)
    log.info("[Step 3 | Layer 1] Verifikasi mTLS transport ...")
    log.debug("[Step 3 | Layer 1]   X-SSL-Client-Verify : %s", x_ssl_client_verify)
    log.debug("[Step 3 | Layer 1]   X-SSL-Client-S-DN   : %s", x_ssl_client_s_dn)
    if not x_ssl_client_verify or x_ssl_client_verify.upper() != "SUCCESS":
        log.warning(
            "[Step 3 | Layer 1]  GAGAL — X-SSL-Client-Verify='%s'",
            x_ssl_client_verify,
        )
        record_mtls_result(success=False)
        _audit_log_event(
            request_id=request.headers.get("x-request-id", ""),
            step=3,
            service="waf_service",
            client_subject=x_ssl_client_s_dn or "",
            result="rejected",
            reason=f"mTLS transport gagal: X-SSL-Client-Verify='{x_ssl_client_verify}'",
            latency_ms=int((time.perf_counter() - _request_start) * 1000),
        )
        raise HTTPException(
            status_code=401,
            detail=(
                f"[Layer 1] mTLS transport verification gagal: "
                f"X-SSL-Client-Verify='{x_ssl_client_verify}'. "
                "Client certificate tidak ada atau tidak valid di TLS layer."
            ),
        )
    log.info("[Step 3 | Layer 1]  mTLS transport OK — client cert diterima nginx")
    record_mtls_result(success=True)
    client_cert = None
    cert_source = None
    if x_ssl_client_cert:
        try:
            client_cert_pem = urllib.parse.unquote(x_ssl_client_cert)
            client_cert = load_cert_from_pem_string(client_cert_pem)
            cert_source = "mTLS header (X-SSL-Client-Cert)"
            log.debug("[Step 3 | Layer 1]   cert subject: %s", client_cert.subject.rfc4514_string())
        except Exception as e:
            log.warning("[Step 3 | Layer 1]  Gagal parse client cert: %s", e)
            raise HTTPException(
                status_code=401,
                detail=f"[Layer 1] Gagal parse client cert dari header: {e}",
            )
    if client_cert is None:
        log.warning("[Step 3 | Layer 1]  X-SSL-Client-Cert header kosong")
        raise HTTPException(
            status_code=401,
            detail=(
                "[Layer 1] Client certificate tidak ditemukan di header "
                "X-SSL-Client-Cert meskipun X-SSL-Client-Verify=SUCCESS."
            ),
        )
    log.info("[Step 3 | Layer 2] Verifikasi trust anchor (CA chain) ...")
    try:
        trusted_cas = _get_trusted_cas()
        log.debug("[Step 3 | Layer 2]   trusted CAs loaded: %d cert(s)", len(trusted_cas))
    except Exception as e:
        log.error("[Step 3 | Layer 2]  CA bundle tidak tersedia: %s", e)
        raise HTTPException(status_code=503, detail=f"[Layer 2] CA bundle tidak tersedia: {e}")
    if not verify_cert_trusted(client_cert, trusted_cas):
        subject = x_ssl_client_s_dn or str(client_cert.subject)
        log.warning("[Step 3 | Layer 2]  GAGAL — cert tidak ditandatangani CA yang dikenal: %s", subject)
        raise HTTPException(
            status_code=401,
            detail=(
                f"[Layer 2] Client certificate tidak trusted: "
                f"cert '{subject}' tidak ditandatangani oleh CA yang dikenal."
            ),
        )
    log.info("[Step 3 | Layer 2]  Trust anchor OK — cert ditandatangani CA yang valid")
    try:
        body_bytes = await request.body()
        log.debug("[Step 3 | Layer 3]   body_bytes diterima: %d bytes", len(body_bytes))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Gagal membaca request body: {e}")
    log.info("[Step 3 | Layer 3] Verifikasi CMS Signature...")
    cms_header = request.headers.get("x-cms-payload", "")
    log.debug("[Step 3 | Layer 3]   X-CMS-Payload : %s...", cms_header[:60] if cms_header else "(none)")
    await verify_cms_signature(request, client_cert, body_bytes)
    log.info("[Step 3 | Layer 3]  CMS Signature valid — signed_attributes (content-type, message-digest, signing-time) terverifikasi")
    log.info("[Step 3 | Layer 3b] Header digest verified — canonical headers cocok dengan yang di-sign (via cms_lib.header_verifier)")
    subject_str = x_ssl_client_s_dn or str(client_cert.subject)
    log.info("[Step 3]  SEMUA LAYER PASSED — request diotorisasi untuk diteruskan ke WebApp")
    log.info("[Step 3]   client: %s", subject_str)
    log.info(_SEP)
    _audit_log_event(
        request_id=request.headers.get("x-request-id", ""),
        step=3,
        service="waf_service",
        client_subject=subject_str,
        result="success",
        reason="Semua 3 layer verifikasi passed (mTLS + CA + CMS)",
        latency_ms=int((time.perf_counter() - _request_start) * 1000),
    )
    return {
        "status": "ok",
        "cert_source": cert_source,
        "layers_passed": ["transport", "trust_anchor", "cms_signature", "header_digest"],
        "client_subject": subject_str,
    }