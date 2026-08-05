import hashlib
import logging
import sys
LOG_FORMAT  = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_logger = logging.getLogger("proxy")
if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setLevel(logging.DEBUG)
    _handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)
    _logger.propagate = False
_SEP  = "-" * 55
_DSEP = "=" * 55
def log_mtls_ready(cert_file: str, key_file: str, ca_bundle: str):
    _logger.info("mTLS siap, sertifikat dan CA bundle berhasil dimuat")
    _logger.debug(" cert : %s", cert_file)
    _logger.debug(" key  : %s", key_file)
    _logger.debug(" CA   : %s", ca_bundle)
def log_mtls_init_failed(error: Exception):
    _logger.error("Gagal menyiapkan sertifikat mTLS saat startup: %s", error)
def log_mtls_not_ready():
    _logger.error("Sertifikat mTLS belum siap, request ditolak")
def log_request_received(method: str, path: str):
    _logger.info(_SEP)
    _logger.info("REQUEST MASUK  %s /%s", method, path.lstrip("/"))
    _logger.info(_SEP)
    _logger.info("[Step 1] Menerima request plain dari Client Application")
def log_request_id(request_id: str):
    _logger.info("[Step 1] X-Request-ID : %s", request_id)
def log_request_body(body: dict):
    _logger.debug("[Step 1] Body plain dari client: %s", body)
def log_body_needed(method: str):
    _logger.info("[Step 1] Metode %s → membangun CMS package", method)
def log_no_body_needed(method: str):
    _logger.info("[Step 1] Metode %s → tidak ada body, hanya mTLS handshake", method)
def log_build_start():
    _logger.info("[Step 1] Memulai pembuatan CMS package")
def log_payload_serialized(length: int):
    _logger.debug("[Step 1] Payload JSON diserialkan: %d karakter", length)
def log_encrypt_start():
    _logger.info("[Step 1] Membuat CMS package: sign (RSA-PSS-SHA256) + encrypt (AES-256-GCM)")
def log_headers_before_sign(headers: dict):
    _logger.debug("[CMS] Headers diterima (belum di-sort) - %d header:", len(headers))
    for k, v in headers.items():
        v_str = v if isinstance(v, str) else str(v)
        preview = v_str[:80] + "..." if len(v_str) > 80 else v_str
        _logger.debug("[CMS]   %-30s : %s", k, preview)
def log_headers_canonical(canonical_bytes: bytes):
    lines = canonical_bytes.decode("utf-8").splitlines()
    _logger.debug("[CMS] Headers setelah di-sort & normalisasi (canonical form):")
    for line in lines:
        _logger.debug("[CMS]   %s", line)
def log_headers_digest(hdr_digest: bytes):
    hex_digest = hdr_digest.hex()
    _logger.debug(
        "[CMS] headers-digest = SHA-256(canonical_headers) = %s...%s  (%d bytes)",
        hex_digest[:16], hex_digest[-8:], len(hdr_digest),
    )
def log_body_digest(body_digest: bytes):
    hex_digest = body_digest.hex()
    _logger.debug(
        "[CMS] message-digest = SHA-256(payload_bytes) = %s...%s  (%d bytes)",
        hex_digest[:16], hex_digest[-8:], len(body_digest),
    )
def log_signed_attributes_built(signed_attrs_der: bytes, has_headers: bool):
    _logger.debug("[CMS] SignedAttributes SET  berhasil dibangun:")
    _logger.debug("[CMS] - content-type    : application/json")
    if has_headers:
        _logger.debug("[CMS] - headers-digest  : SHA-256(canonical_headers) <- BARU")
    _logger.debug("[CMS] - message-digest  : SHA-256(payload_bytes)")
    _logger.debug("[CMS] - signing-time    : [UTC timestamp]")
    _logger.debug("[CMS] DER total: %d bytes", len(signed_attrs_der))
def log_digital_signature_process(signed_attrs_der: bytes, signature: bytes):
    import hashlib
    sa_digest = hashlib.sha256(signed_attrs_der).digest()
    _logger.debug("[CMS] -- Digital Signature Process --")
    _logger.debug("[CMS] Input  : DER(SignedAttributes SET)  = %d bytes", len(signed_attrs_der))
    _logger.debug(
        "[CMS]   Step 1 : SHA-256(DER) = %s...%s",
        sa_digest.hex()[:16], sa_digest.hex()[-8:],
    )
    _logger.debug("[CMS] Step 2 : RSA-PSS-SHA256.sign(SHA-256(DER), client_private_key)")
    _logger.debug(
        "[CMS] Output : signature = %s...%s  (%d bytes)",
        signature.hex()[:16], signature.hex()[-8:], len(signature),
    )
    _logger.debug("[CMS] -- Signature selesai --")
def log_encrypt_done(length: int):
    _logger.debug("[Step 1] CMS package (base64): %d karakter", length)
def log_build_done():
    _logger.info(
        "[Step 1] CMS package siap: signed_attributes + AES-256-GCM + RSA-OAEP key wrap"
    )
def log_build_failed(error: Exception):
    _logger.error("[Step 1] Gagal membangun CMS package: %s", error)
def log_waf_response(status_code: int):
    _logger.info("[Step 3] WAF merespons dengan status HTTP %d", status_code)
def log_waf_error(status_code: int, body_preview: str):
    _logger.warning("[Step 3] WAF mengembalikan error status: %d", status_code)
    _logger.debug("[Step 3]   body error: %s", body_preview[:500])
def log_waf_unreachable(error: Exception):
    _logger.error("[Step 3] Gagal menghubungi WAF: %s", error)
def log_response_processing():
    _logger.info("[Step 5] Memproses response CMS dari WAF/WebApp")
def log_response_encrypted_found():
    _logger.info("[Step 5] CMS response ditemukan (X-CMS-Response: true)")
    _logger.info("[Step 5] Mendekripsi + memverifikasi CMS signature WebApp...")
def log_response_signature_valid():
    _logger.info(
        "[Step 5] CMS signature WebApp VALID"
        " — signed_attributes (content-type, headers-digest, message-digest, signing-time)"
        " terverifikasi RSA-PSS-SHA256"
    )
def log_response_signature_invalid():
    _logger.warning(
        "[Step 5] CMS signature WebApp TIDAK VALID - response mungkin dimanipulasi!"
    )
def log_response_decrypted(length: int):
    _logger.info("[Step 5] Response berhasil didekripsi dengan Client private key (RSA-OAEP)")
    _logger.debug("[Step 5]   plaintext panjang: %d bytes", length)
def log_response_not_encrypted():
    _logger.info("[Step 5] Response bukan CMS, dikembalikan apa adanya")
def log_response_validation_failed(error):
    _logger.warning("[Step 5] Validasi CMS response gagal: %s", error)
def log_response_process_failed(error: Exception):
    _logger.error("[Step 5] Gagal memproses CMS response: %s", error)
def log_return_plaintext():
    _logger.info("[Step 5] Mengembalikan plaintext ke Client Application")
def log_encrypted_value(label: str, value: str):
    preview = value[:60] + "..." if len(value) > 60 else value
    _logger.debug("[Crypto] %s (%d chars) = %s", label, len(value), preview)
def log_decrypted_value(plaintext: bytes):
    try:
        text    = plaintext.decode("utf-8")
        preview = text[:120] + "..." if len(text) > 120 else text
        _logger.debug("[Crypto] plaintext hasil dekripsi = %s", preview)
    except Exception:
        _logger.debug("[Crypto] plaintext hasil dekripsi (binary) = %d bytes", len(plaintext))
def log_response_headers(headers: dict):
    _logger.debug("[Step 5] Response headers ke client:")
    for k, v in headers.items():
        _logger.debug("[Step 5]   %-30s : %s", k, v)
def log_done(status_code: int):
    _logger.info("RESPONSE SELESAI  status=%d", status_code)
    _logger.info(_SEP)
def log_response_header_verified(reason: str):
    _logger.info(
        "[Step 5b] Header response verified OK via cms_lib.header_verifier — %s", reason
    )
def log_response_header_verify_failed(reason: str):
    _logger.warning(
        "[Step 5b] Header response digest TIDAK COCOK (non-blocking) — %s", reason
    )
def log_response_header_no_digest():
    _logger.debug(
        "[Step 5b] Response tidak mengandung CMS header payload untuk verifikasi — skip."
    )
