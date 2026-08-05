import base64
import json
import logging
import sys
from pathlib import Path
from fastapi import FastAPI, Request, Response
from cryptography import x509
from cryptography.hazmat.primitives import serialization
_SHARED_LIB = Path(__file__).resolve().parent.parent / "shared"
if str(_SHARED_LIB) not in sys.path:
    sys.path.insert(0, str(_SHARED_LIB))
from cms_core import cms_decrypt_request, cms_pack_response
from web_sdk import load_private_key, load_public_key
import os
app = FastAPI()
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] [webapp] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("webapp")
_SEP = "-" * 55
_DOCKER_KEYCERT = Path("/etc/pki/key_cert")
_LOCAL_KEYCERT  = Path(__file__).resolve().parent.parent / "key_cert"
KEYCERT_DIR = _DOCKER_KEYCERT if _DOCKER_KEYCERT.is_dir() else _LOCAL_KEYCERT
try:
    WEBAPP_PRIV_KEY = load_private_key(str(KEYCERT_DIR / "webappcert.key"))
    with open(KEYCERT_DIR / "webappcert.crt", "rb") as _f:
        WEBAPP_CERT = x509.load_pem_x509_certificate(_f.read())
    with open(KEYCERT_DIR / "clientcert.crt", "rb") as _f:
        CLIENT_CERT = x509.load_pem_x509_certificate(_f.read())
    CLIENT_PUB_KEY = CLIENT_CERT.public_key()
    log.info("Kunci kriptografi berhasil dimuat")
    log.debug("webapp priv key : webappcert.key")
    log.debug("webapp cert     : webappcert.crt")
    log.debug("client cert     : clientcert.crt")
except FileNotFoundError as e:
    log.error("Gagal memuat sertifikat: %s", e)
    WEBAPP_PRIV_KEY = WEBAPP_CERT = CLIENT_CERT = CLIENT_PUB_KEY = None
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def handle_all(path: str, request: Request):
    try:
        log.info(_SEP)
        log.info("[Step 4] Request masuk dari WAF | %s /%s", request.method, path)
        request_id = request.headers.get("x-request-id", request.headers.get("X-Request-ID", ""))
        if request_id:
            log.info("[Step 4] X-Request-ID : %s", request_id)
        body_bytes = await request.body()
        log.debug("[Step 4]   body diterima: %d bytes", len(body_bytes))
        request_payload = {}
        if body_bytes:
            cms_b64 = None
            try:
                body_json = json.loads(body_bytes.decode("utf-8"))
                cms_b64 = body_json.get("cms_payload")
            except Exception:
                pass
            if cms_b64:
                log.info("[Step 4] Mendekripsi CMS package...")
                log.debug("[Step 4] cms_payload panjang: %d karakter", len(cms_b64))
                try:
                    cms_der = base64.b64decode(cms_b64)
                except Exception as e:
                    log.warning("[Step 4] Gagal decode base64 CMS: %s", e)
                    return Response(status_code=400, content=f"Invalid CMS base64: {e}")
                if WEBAPP_PRIV_KEY is None or CLIENT_CERT is None:
                    log.error("[Step 4] Kunci kripto belum dimuat")
                    return Response(status_code=503, content="Crypto keys not loaded")
                try:
                    decrypted_bytes, sig_valid = cms_decrypt_request(
                        cms_der, WEBAPP_PRIV_KEY, CLIENT_CERT
                    )
                    if not sig_valid:
                        log.warning("[Step 4] CMS signature TIDAK VALID — request mungkin dimanipulasi")
                        return Response(
                            status_code=403,
                            content="CMS signature verification failed"
                        )
                    log.info("[Step 4] CMS decrypt + verify BERHASIL (signature valid)")
                    log.debug("[CMS] signed_attributes: content-type, headers-digest, message-digest, signing-time")
                    request_payload = json.loads(decrypted_bytes)
                    log.info("[Step 4] Payload: %s", request_payload)
                except Exception as e:
                    log.warning("[Step 4] CMS decrypt/verify gagal: %s", e)
                    return Response(status_code=400, content=f"CMS decryption failed: {e}")
            else:
                log.debug("[Step 4] Tidak ada field cms_payload, body diproses apa adanya")
        response_data = {
            "status": "success",
            "message": "Data berhasil diproses secara rahasia di backend.",
            "echo_path": f"/{path}",
            "processed_payload": request_payload,
        }
        response_json = json.dumps(response_data).encode("utf-8")
        log.debug("[Step 4] response data disiapkan: %d bytes", len(response_json))
        response_headers_to_sign = {
            "content-type": "application/cms",
            "x-cms-response": "true",
            "x-cms-verified": "true",
            "x-signature-algorithm": "rsa-pss-sha256",
        }
        if request_id:
            response_headers_to_sign["x-request-id"] = request_id
        log.debug("[Step 4] Response headers yang akan di-sign (sebelum di-sort):")
        for k, v in response_headers_to_sign.items():
            log.debug("[Step 4]   %-30s : %s", k, v)
        cms_response_der = cms_pack_response(
            body=response_json,
            signer_key=WEBAPP_PRIV_KEY,
            signer_cert=WEBAPP_CERT,
            recipient_pubkey=CLIENT_PUB_KEY,
            content_type="application/json",
            headers=response_headers_to_sign,
        )
        cms_response_b64 = base64.b64encode(cms_response_der).decode("ascii")
        body_content = cms_response_b64.encode("ascii")
        log.debug("[Step 4] CMS response DER: %d bytes -> base64: %d chars",
                  len(cms_response_der), len(cms_response_b64))
        log.debug("[CMS] response signed_attributes: content-type, headers-digest, message-digest, signing-time")
        log.info("[Step 4] CMS response siap dikirim ke Proxy (base64, application/cms)")
        log.info(_SEP)
        http_resp_headers = {
            "X-CMS-Response": "true",
            "X-CMS-Verified": "true",
            "X-Signature-Algorithm": "rsa-pss-sha256",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control":"no-store, no-cache, must-revalidate, private",
        }
        if request_id:
            http_resp_headers["X-Request-ID"] = request_id
        return Response(
            content=body_content,
            status_code=200,
            media_type="application/cms",
            headers=http_resp_headers,
        )
    except Exception as e:
        log.error("[Step 4]  Internal Server Error: %s", e)
        return Response(status_code=500, content=f"Internal Server Error: {str(e)}")
