from datetime import timedelta

from cryptography.x509 import Certificate
from fastapi import HTTPException, Request
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    algorithms,
)
from starlette.datastructures import MutableHeaders


def _problem(status: int, title: str, detail: str) -> dict:
    return {
        "type":   "urn:ietf:rfc:9421",
        "title":  title,
        "status": status,
        "detail": detail,
    }


class _CertKeyResolver(HTTPSignatureKeyResolver):

    def __init__(self, cert: Certificate):
        self._cert = cert

    def resolve_public_key(self, key_id: str):
        return self._cert.public_key()

    def resolve_private_key(self, key_id: str):
        raise NotImplementedError("WAF tidak menyimpan private key client")


class _StarletteRequestAdapter:

    def __init__(self, request: Request, body_bytes: bytes):
        self.method = request.headers.get(
            "x-original-method", request.method
        ).upper()

        original_authority = request.headers.get("x-original-authority", "waf:8443")
        original_path      = request.headers.get("x-original-path", request.url.path)

        self.url = f"https://{original_authority}{original_path}"

        self.headers = MutableHeaders(request.headers)
        self.headers["host"] = original_authority

        self.body = body_bytes


_METHODS_WITHOUT_BODY = {"GET", "HEAD", "DELETE"}
_REPLAY_WINDOW        = timedelta(seconds=300)


async def verify_http_signature(
    request:     Request,
    client_cert: Certificate,
    body_bytes:  bytes,
) -> None:
    signature_header = request.headers.get("signature")
    sig_input_header = request.headers.get("signature-input")
    original_method  = request.headers.get(
        "x-original-method", request.method
    ).upper()

    if not signature_header:
        if original_method in _METHODS_WITHOUT_BODY:
            return
        print(f"DEBUG: Missing Signature header for method {original_method}", flush=True)
        raise HTTPException(
            status_code=401,
            detail=_problem(
                401,
                "Missing HTTP Message Signature",
                f"[Layer 3] Header 'Signature' wajib ada untuk metode "
                f"{original_method} (RFC 9421 §4.2).",
            ),
        )

    if not sig_input_header:
        print("DEBUG: Missing Signature-Input header", flush=True)
        raise HTTPException(
            status_code=401,
            detail=_problem(
                401,
                "Missing Signature-Input Header",
                "[Layer 3] Header 'Signature-Input' harus ada bersama "
                "'Signature' (RFC 9421 §4.1).",
            ),
        )
    adapted  = _StarletteRequestAdapter(request, b"")
    verifier = HTTPMessageVerifier(
        signature_algorithm=algorithms.RSA_PSS_SHA512,
        key_resolver=_CertKeyResolver(client_cert),
    )

    try:
        print(f"DEBUG: adapted method={adapted.method} url={adapted.url}", flush=True)
        print(f"DEBUG: content-digest header: {adapted.headers.get('content-digest')}", flush=True)
        verifier.verify(adapted, max_age=_REPLAY_WINDOW)

    except Exception as exc:
        exc_msg = str(exc).lower()

        if any(kw in exc_msg for kw in ("expir", "creat", "age", "valid", "time")):
            print(f"DEBUG REPLAY ERROR: {exc_msg}")
            raise HTTPException(
                status_code=401,
                detail=_problem(
                    401,
                    "Signature Expired or Not Yet Valid",
                    f"[Layer 3] Replay attack terdeteksi atau signature sudah expired: "
                    f"{exc} (RFC 9421 §2.3).",
                ),
            )

        import traceback
        print(f"DEBUG 403 ERROR: {exc_msg}\n{traceback.format_exc()}", flush=True)
        raise HTTPException(
            status_code=403,
            detail=_problem(
                403,
                "HTTP Message Signature Verification Failed",
                f"[Layer 3] Signature tidak valid: {exc}. "
                "Kemungkinan body dimanipulasi atau key tidak cocok "
                "(RFC 9421 §3.3.1, RFC 9530 §2).",
            ),
        )
