import base64
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from flask import Flask, request, Response
import requests as http_requests
from requests.adapters import HTTPAdapter
from cryptography import x509
sys.path.append(str(Path(__file__).parent / "crypto"))
_SHARED_LIB = Path(__file__).resolve().parent.parent / "shared"
if str(_SHARED_LIB) not in sys.path:
    sys.path.insert(0, str(_SHARED_LIB))
from crypto import load_cert_from_pem, load_private_key_from_pem
from crypto.cms_core import cms_pack, cms_unpack
from cms_lib.header_verifier import verify_cms_headers, IGNORED_HEADERS
from urllib3.util.retry import Retry
import log as plog
app = Flask(__name__)
_DOCKER_KEYCERT = Path("/key_cert")
_LOCAL_KEYCERT  = Path(__file__).resolve().parent.parent / "key_cert"
KEYCERT_DIR = _DOCKER_KEYCERT if _DOCKER_KEYCERT.is_dir() else _LOCAL_KEYCERT
CLIENT_CERT_PATH = KEYCERT_DIR / "clientcert.crt"
CLIENT_KEY       = KEYCERT_DIR / "clientcert.key"
CLIENT_CA        = KEYCERT_DIR / "clientca_rootca_.pem"
WEBAPP_CERT_PATH = KEYCERT_DIR / "webappcert.crt"
SERVER_CA_CERT   = KEYCERT_DIR / "serverca_rootca_.pem"
ROOT_CA_CERT     = KEYCERT_DIR / "rootca.pem"
WAF_BASE_URL = "https://waf:8443"
def _build_server_ca_bundle() -> str:
    server_ca_raw = SERVER_CA_CERT.read_bytes()
    root_ca_raw   = ROOT_CA_CERT.read_bytes()
    def _extract_certs(raw: bytes) -> list[bytes]:
        blocks  = []
        current = []
        in_block = False
        for line in raw.splitlines(keepends=True):
            line_s = line.strip()
            if line_s.startswith(b"-----BEGIN CERTIFICATE"):
                in_block = True
                current  = [line]
            elif line_s.startswith(b"-----END CERTIFICATE") and in_block:
                current.append(line)
                blocks.append(b"".join(current))
                in_block = False
                current  = []
            elif in_block:
                current.append(line)
        return blocks
    certs = _extract_certs(server_ca_raw) + _extract_certs(root_ca_raw)
    ca_tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_ca-bundle.crt")
    ca_tmp.write(b"".join(certs))
    ca_tmp.flush()
    ca_tmp.close()
    return ca_tmp.name
try:
    _CLIENT_CERT_FILE = str(CLIENT_CERT_PATH)
    _CLIENT_KEY_FILE  = str(CLIENT_KEY)
    _SERVER_CA_BUNDLE = _build_server_ca_bundle()
    plog.log_mtls_ready(_CLIENT_CERT_FILE, _CLIENT_KEY_FILE, _SERVER_CA_BUNDLE)
    with open(CLIENT_CERT_PATH, "rb") as _f:
        _CLIENT_CERT_OBJ = x509.load_pem_x509_certificate(_f.read())
    with open(WEBAPP_CERT_PATH, "rb") as _f:
        _WEBAPP_CERT_OBJ = x509.load_pem_x509_certificate(_f.read())
    _WEBAPP_PUBKEY = _WEBAPP_CERT_OBJ.public_key()
except Exception as _init_err:
    plog.log_mtls_init_failed(_init_err)
    _CLIENT_CERT_FILE = _CLIENT_KEY_FILE = _SERVER_CA_BUNDLE = None
    _CLIENT_CERT_OBJ = _WEBAPP_CERT_OBJ = _WEBAPP_PUBKEY = None
def build_request_body(api_body: dict, req_headers: dict | None = None) -> tuple[dict, str]:
    plog.log_build_start()
    payload_str   = json.dumps(api_body, separators=(",", ":"), ensure_ascii=False)
    payload_bytes = payload_str.encode("utf-8")
    plog.log_payload_serialized(len(payload_str))
    plog.log_encrypt_start()
    client_key = load_private_key_from_pem(str(CLIENT_KEY))
    cms_der    = cms_pack(
        body=payload_bytes,
        signer_key=client_key,
        signer_cert=_CLIENT_CERT_OBJ,
        recipient_pubkey=_WEBAPP_PUBKEY,
        content_type="application/json",
        headers=req_headers,
    )
    cms_b64 = base64.b64encode(cms_der).decode("ascii")
    plog.log_encrypt_done(len(cms_b64))
    plog.log_encrypted_value("cms_payload (request)", cms_b64[:80] + "...")
    plog.log_build_done()
    return {"cms_payload": cms_b64}, cms_b64
def process_response(waf_resp: http_requests.Response) -> bytes:
    plog.log_response_processing()
    body_bytes = waf_resp.content
    headers    = dict(waf_resp.headers)
    is_cms = (
        headers.get("X-CMS-Response") == "true"
        or headers.get("x-cms-response") == "true"
        or (headers.get("Content-Type", "") or headers.get("content-type", "")).startswith("application/cms")
    )
    if not is_cms:
        plog.log_response_not_encrypted()
        return body_bytes
    plog.log_response_encrypted_found()
    cms_b64 = body_bytes.decode("ascii", errors="replace").strip()
    plog.log_encrypted_value("cms_payload (response)", cms_b64[:80] + "...")
    try:
        cms_der = base64.b64decode(cms_b64)
    except Exception as e:
        raise ValueError(f"[Step 5] Gagal decode base64 CMS response: {e}")
    client_key = load_private_key_from_pem(str(CLIENT_KEY))
    plaintext, sig_valid = cms_unpack(cms_der, client_key)
    if not sig_valid:
        plog.log_response_signature_invalid()
        raise ValueError(
            "[Step 5] Verifikasi CMS signature webapp GAGAL — "
            "response mungkin dimanipulasi atau bukan dari webapp asli "
            f"(cert: {WEBAPP_CERT_PATH.name})."
        )
    plog.log_response_signature_valid()
    plog.log_response_decrypted(len(plaintext))
    plog.log_decrypted_value(plaintext)
    resp_cms_b64 = waf_resp.headers.get("X-CMS-Response") or waf_resp.headers.get("x-cms-response")
    resp_cms_payload = waf_resp.headers.get("X-CMS-Payload") or waf_resp.headers.get("x-cms-payload")
    _cms_hdr_val = resp_cms_payload or resp_cms_b64 if (resp_cms_b64 not in ("true", "false", None)) else None
    if _cms_hdr_val and _cms_hdr_val not in ("true", "false"):
        hdr_ok, hdr_reason = verify_cms_headers(
            dict(waf_resp.headers),
            _cms_hdr_val,
            context="response",
        )
        if hdr_ok:
            plog.log_response_header_verified(hdr_reason)
        else:
            plog.log_response_header_verify_failed(hdr_reason)
    else:
        plog.log_response_header_no_digest()
    return plaintext
def _make_headers(
    request_id:   str,
    cms_verified: bool | None = None,
) -> dict:
    h = {
        "X-Request-ID": request_id,
        "X-Proxy": "mTLS-Proxy/1.0",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    if cms_verified is True:
        h["X-CMS-Verified"] = "true"
    elif cms_verified is False:
        h["X-CMS-Verified"] = "false"
    return h
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>",             methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy_handler(path: str):
    request_id = str(uuid.uuid4())
    plog.log_request_received(request.method, path)
    plog.log_request_id(request_id)
    if not _CLIENT_CERT_FILE or not _CLIENT_KEY_FILE or not _SERVER_CA_BUNDLE:
        plog.log_mtls_not_ready()
        return Response(
            json.dumps({"error": "File mTLS belum siap. Periksa log startup."}),
            status=503,
            content_type="application/json",
            headers=_make_headers(request_id),
        )
    _METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}
    try:
        client_body = request.get_json(silent=True) or {}
    except Exception:
        client_body = {}
    plog.log_request_body(client_body)
    if request.method in _METHODS_WITH_BODY:
        plog.log_body_needed(request.method)
        outbound_headers = {
            "Content-Type":   "application/json",
            "User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) mTLS-Proxy/1.0",
            "X-Request-ID":   request_id,
        }
        for k, v in request.headers.items():
            if k.lower() not in IGNORED_HEADERS and k.lower() not in ["content-type", "user-agent", "x-request-id"]:
                outbound_headers[k] = v
        try:
            request_body, cms_b64 = build_request_body(client_body, outbound_headers)
            outbound_headers["X-CMS-Payload"] = cms_b64
            waf_kwargs = {
                "json": request_body,
                "headers": outbound_headers,
            }
        except Exception as e:
            plog.log_build_failed(e)
            return Response(
                json.dumps({"error": f"Gagal membangun request: {e}"}),
                status=500,
                content_type="application/json",
                headers=_make_headers(request_id),
            )
    else:
        plog.log_no_body_needed(request.method)
        waf_kwargs = {}
    target_url = f"{WAF_BASE_URL}/{path}"
    query = request.query_string.decode()
    if query:
        target_url = f"{target_url}?{query}"
    try:
        session = http_requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST", "PUT", "PATCH", "GET", "DELETE"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        req = http_requests.Request(
            method=request.method,
            url=target_url,
            **waf_kwargs,
        )
        prepared = session.prepare_request(req)
        waf_resp = session.send(
            prepared,
            cert=(_CLIENT_CERT_FILE, _CLIENT_KEY_FILE),
            verify=_SERVER_CA_BUNDLE,
            timeout=(10.0, 60.0),
        )
        plog.log_waf_response(waf_resp.status_code)
        if waf_resp.status_code >= 400:
            plog.log_waf_error(waf_resp.status_code, waf_resp.text)
            return Response(
                json.dumps({
                    "error": "WAF memblokir request atau terjadi error di sisi server.",
                    "status_code": waf_resp.status_code,
                    "waf_response_text": waf_resp.text,
                }),
                status=waf_resp.status_code,
                content_type="application/json",
                headers=_make_headers(request_id, cms_verified=False),
            )
    except Exception as e:
        plog.log_waf_unreachable(e)
        return Response(
            json.dumps({"error": f"Gagal menghubungi WAF: {e}"}),
            status=502,
            content_type="application/json",
            headers=_make_headers(request_id),
        )
    try:
        plaintext = process_response(waf_resp)
    except ValueError as e:
        plog.log_response_validation_failed(e)
        return Response(
            json.dumps({"error": str(e)}),
            status=400,
            content_type="application/json",
            headers=_make_headers(request_id, cms_verified=False),
        )
    except Exception as e:
        plog.log_response_process_failed(e)
        return Response(
            json.dumps({"error": f"Gagal memproses response: {e}"}),
            status=500,
            content_type="application/json",
            headers=_make_headers(request_id),
        )
    plog.log_return_plaintext()
    if isinstance(plaintext, bytes):
        try:
            plaintext_str = plaintext.decode("utf-8", errors="replace")
        except Exception:
            plaintext_str = str(plaintext)
    else:
        plaintext_str = str(plaintext) if plaintext else ""
    resp_headers = _make_headers(request_id, cms_verified=True)
    plog.log_response_headers(resp_headers)
    try:
        parsed = json.loads(plaintext_str)
        plog.log_done(waf_resp.status_code)
        return Response(
            json.dumps(parsed),
            status=waf_resp.status_code,
            content_type="application/json",
            headers=resp_headers,
        )
    except Exception:
        return Response(
            plaintext_str,
            status=waf_resp.status_code,
            content_type="text/plain",
            headers=resp_headers,
        )
def _wait_for_waf(max_retries: int = 30, retry_delay: float = 2.0) -> bool:
    for attempt in range(max_retries):
        try:
            resp = http_requests.get(
                f"{WAF_BASE_URL}/healthz",
                verify=_SERVER_CA_BUNDLE if _SERVER_CA_BUNDLE else False,
                timeout=5.0,
            )
            if resp.status_code == 200:
                print(f"[WAF] Ready after {attempt + 1} attempts")
                return True
            print(f"[WAF] Retry {attempt + 1}: status {resp.status_code}")
        except Exception as e:
            print(f"[WAF] Retry {attempt + 1}: error {type(e).__name__}: {e}")
        if attempt < max_retries - 1:
            time.sleep(retry_delay)
    print("[WAF] Timeout waiting for WAF health, starting proxy anyway...")
    return False
if __name__ == "__main__":
    _wait_for_waf()
    app.run(host="0.0.0.0", port=8080, debug=False)
