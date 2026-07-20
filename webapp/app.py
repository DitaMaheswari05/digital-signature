import json
import logging
import sys
from fastapi import FastAPI, Request, Response
from web_sdk import load_private_key, load_public_key, decrypt_payload, encrypt_payload

from http_response_signer import sign_response

import os
from pathlib import Path

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
    CLIENT_PUB_KEY  = load_public_key(str(KEYCERT_DIR / "clientcert.crt"))
    log.info("Kunci kriptografi berhasil dimuat")
    log.debug("webapp priv key : webappcert.key")
    log.debug("client pub key  : clientcert.crt")
except FileNotFoundError as e:
    log.error("Gagal memuat sertifikat: %s", e)

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def handle_all(path: str, request: Request):
    try:
        log.info(_SEP)
        log.info("[Step 4] Request masuk dari WAF | %s /%s", request.method, path)

        body_bytes = await request.body()
        log.debug("[Step 4]   body diterima: %d bytes", len(body_bytes))

        request_payload = {}
        if body_bytes:
            log.info("[Step 4] Mendekripsi body dengan WebApp private key (RSA-OAEP SHA-256) ...")
            try:
                body_json = json.loads(body_bytes.decode("utf-8"))
                ciphertext_b64 = body_json.get("encrypted_body")

                if ciphertext_b64:
                    log.debug("[Step 4] encrypted_body panjang: %d karakter", len(ciphertext_b64))
                    decrypted_bytes = decrypt_payload(ciphertext_b64, WEBAPP_PRIV_KEY)
                    request_payload = json.loads(decrypted_bytes)
                    log.info("[Step 4] Dekripsi berhasil — payload: %s", request_payload)
                    log.debug("[Crypto] encrypted_body (request) (%d chars) = %s...",
                              len(ciphertext_b64), ciphertext_b64[:60])
                else:
                    log.debug("[Step 4] Tidak ada field encrypted_body, body diproses apa adanya")
            except Exception as e:
                log.warning("[Step 4] Dekripsi gagal: %s", e)
                return Response(status_code=400, content=f"Malformed Encrypted Body: {e}")

        response_data = {
            "status": "success",
            "message": "Data berhasil diproses secara rahasia di backend.",
            "echo_path": f"/{path}",
            "processed_payload": request_payload,
        }
        response_json = json.dumps(response_data).encode("utf-8")
        log.debug("[Step 4] response data disiapkan: %d bytes", len(response_json))

        log.info("[Step 4] Mengenkripsi response dengan Client public key (RSA-OAEP SHA-256) ...")
        encrypted_resp_b64 = encrypt_payload(response_json, CLIENT_PUB_KEY)
        body_content = encrypted_resp_b64.encode("ascii")
        log.debug("[Step 4] encrypted_body panjang: %d karakter", len(encrypted_resp_b64))
        log.debug("[Crypto] encrypted_body (response) (%d chars) = %s...",
                  len(encrypted_resp_b64), encrypted_resp_b64[:60])

        log.info("[Step 4] Menandatangani response dengan WebApp private key (RSA-PSS SHA-512, RFC 9421) ...")
        sig_headers = sign_response(body_content, WEBAPP_PRIV_KEY, status_code=200)
        log.debug("[Step 4] Content-Digest  : %s...", sig_headers["Content-Digest"][:40])
        log.debug("[Step 4] Signature-Input : %s...", sig_headers["Signature-Input"][:60])
        log.debug("[Step 4] Signature       : %s...", sig_headers["Signature"][:60])
        log.info("[Step 4] Response terenkripsi + RFC 9421 signature siap dikirim ke Proxy")
        log.info(_SEP)

        return Response(
            content=body_content,
            status_code=200,
            media_type="application/octet-stream",
            headers=sig_headers,
        )

    except Exception as e:
        log.error("[Step 4]  Internal Server Error: %s", e)
        return Response(status_code=500, content=f"Internal Server Error: {str(e)}")