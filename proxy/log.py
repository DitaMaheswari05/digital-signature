import logging
import sys

LOG_FORMAT = "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_logger = logging.getLogger("proxy")

if not _logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setLevel(logging.DEBUG)
    _handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.DEBUG)
    _logger.propagate = False

_SEP = "-" * 55


def log_mtls_ready(cert_file: str, key_file: str, ca_bundle: str):
    _logger.info("projek sudah siap")
    _logger.debug("  cert  : %s", cert_file)
    _logger.debug("  key   : %s", key_file)
    _logger.debug("  ca    : %s", ca_bundle)

def log_mtls_init_failed(error: Exception):
    _logger.error("gagal menyiapkan file mTLS saat startup: %s", error)

def log_mtls_not_ready():
    _logger.error("file mTLS belum siap, request ditolak")


def log_request_received(method: str, path: str):
    _logger.info(_SEP)
    _logger.info("REQUEST MASUK  %s /%s", method, path.lstrip("/"))
    _logger.info(_SEP)
    _logger.info("[Step 1] Menerima request plain dari Client Application")

def log_request_body(body: dict):
    _logger.debug("[Step 1] Body plain dari client: %s", body)


def log_body_needed(method: str):
    _logger.info("[Step 1] Metode %s -> membangun request body terenkripsi", method)

def log_no_body_needed(method: str):
    _logger.info("[Step 1] Metode %s -> tidak ada body, mTLS handshake sudah cukup", method)

def log_build_start():
    _logger.info("[Step 1] Memulai proses enkripsi request body")

def log_payload_serialized(length: int):
    _logger.debug("[Step 1] Payload JSON diserialkan: %d karakter", length)

def log_encrypt_start():
    _logger.info("[Step 1] Mengenkripsi payload dengan public key WebApp (RSA-OAEP SHA-256)")

def log_encrypt_done(length: int):
    _logger.debug("[Step 1] encrypted_body: %d karakter", length)

def log_sign_start():
    _logger.info("[Step 1] Menandatangani request dengan private key Client (RSA-PSS SHA-512)")

def log_sign_done(length: int):
    _logger.debug("[Step 1] Signature dibuat: %d karakter", length)

def log_attach_cert():
    _logger.info("[Step 1] Melampirkan client certificate ke request")

def log_build_done():
    _logger.info("[Step 1]  Request body siap: terenkripsi + akan ditandatangani via RFC 9421")

def log_build_failed(error: Exception):
    _logger.error("[Step 1]  Gagal membangun request body: %s", error)


def log_forward_start(method: str, url: str):
    _logger.info("[Step 2] Meneruskan request ke WAF via mTLS")
    _logger.info("[Step 2]   URL    : %s %s", method, url)

def log_forward_cert_info(cert_file: str, ca_bundle: str):
    _logger.debug("[Step 2]   cert   : %s", cert_file)
    _logger.debug("[Step 2]   verify : %s", ca_bundle)


def log_encrypted_value(label: str, value: str):
    preview = value[:60] + "..." if len(value) > 60 else value
    _logger.debug("[Crypto] %s (%d chars) = %s", label, len(value), preview)

def log_decrypted_value(plaintext: bytes):
    try:
        text = plaintext.decode("utf-8")
        preview = text[:120] + "..." if len(text) > 120 else text
        _logger.debug("[Crypto] plaintext hasil dekripsi = %s", preview)
    except Exception:
        _logger.debug("[Crypto] plaintext hasil dekripsi (binary) = %d bytes", len(plaintext))


def log_http_sig_built(key_id: str):
    _logger.info(
        "[Step 2]  HTTP Message Signature (RFC 9421) dibuat"
        " | keyid=%s | alg=rsa-pss-sha512 | window=300s",
        key_id,
    )

def log_response_rfc9421_verified(key_id: str = "webapp-key"):
    _logger.info(
        "[Step 5]  RFC 9421 Signature WebApp VALID"
        " | keyid=%s | alg=rsa-pss-sha512 — response autentik dari webapp",
        key_id,
    )

def log_http_sig_failed(error: Exception):
    _logger.error("[Step 2]  Gagal membuat HTTP Message Signature (RFC 9421): %s", error)

def log_digest_computed(digest_value: str):
    _logger.debug("[Step 2] Content-Digest (RFC 9530): %s...", digest_value[:40])


def log_waf_response(status_code: int):
    _logger.info("[Step 3]  WAF merespons dengan status HTTP %d", status_code)

def log_waf_error(status_code: int, body_preview: str):
    _logger.warning("[Step 3]  WAF mengembalikan error status: %d", status_code)
    _logger.debug("[Step 3]   body error: %s", body_preview[:500])

def log_waf_unreachable(error: Exception):
    _logger.error("[Step 3]  Gagal menghubungi WAF: %s", error)


def log_response_processing():
    _logger.info("[Step 5] Memproses response dari WAF/WebApp")

def log_response_encrypted_found():
    _logger.info("[Step 5] Response terenkripsi ditemukan")
    _logger.info("[Step 5] Memverifikasi signature WebApp (RSA-PSS SHA-256) ...")

def log_response_signature_valid():
    _logger.info("[Step 5]  Signature WebApp valid — response autentik dan tidak dimanipulasi")

def log_response_signature_invalid():
    _logger.warning("[Step 5]  Signature WebApp TIDAK VALID — response mungkin dimanipulasi!")

def log_response_decrypted(length: int):
    _logger.info("[Step 5]  Response berhasil didekripsi dengan Client private key")
    _logger.debug("[Step 5]   plaintext panjang: %d bytes", length)

def log_response_not_encrypted():
    _logger.info("[Step 5] Response tidak terenkripsi, dikembalikan apa adanya")

def log_response_validation_failed(error):
    _logger.warning("[Step 5]  Validasi response gagal: %s", error)

def log_response_process_failed(error: Exception):
    _logger.error("[Step 5]  Gagal memproses response: %s", error)


def log_return_plaintext():
    _logger.info("[Step 5] Mengembalikan plaintext ke Client Application")

def log_done(status_code: int):
    _logger.info("RESPONSE SELESAI  status=%d", status_code)
    _logger.info(_SEP)