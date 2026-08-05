import base64
import hashlib
import sys
from pathlib import Path
from typing import Union
from asn1crypto import core as asn1_core
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509 import Certificate
from fastapi import HTTPException, Request
_SHARED_LIB = Path(__file__).resolve().parent.parent.parent / "shared"
if str(_SHARED_LIB) not in sys.path:
    sys.path.insert(0, str(_SHARED_LIB))
from cms_lib.header_verifier import verify_cms_headers
class _SignerInfoSeq(asn1_core.Sequence):
    _fields = [
        ("signer_certificate",  asn1_core.OctetString),
        ("digest_algorithm",    asn1_core.UTF8String),
        ("signature_algorithm", asn1_core.UTF8String),
        ("signed_attributes",   asn1_core.OctetString),
        ("signature",           asn1_core.OctetString),
    ]
class _RecipientInfoSeq(asn1_core.Sequence):
    _fields = [
        ("key_encryption_algorithm", asn1_core.UTF8String),
        ("encrypted_key",            asn1_core.OctetString),
    ]
class _EncryptedContentInfoSeq(asn1_core.Sequence):
    _fields = [
        ("content_encryption_algorithm", asn1_core.UTF8String),
        ("iv",                           asn1_core.OctetString),
        ("encrypted_content",            asn1_core.OctetString),
    ]
class _CMSPackageSeq(asn1_core.Sequence):
    _fields = [
        ("version",                asn1_core.Integer),
        ("signer_info",            _SignerInfoSeq),
        ("recipient_info",         _RecipientInfoSeq),
        ("encrypted_content_info", _EncryptedContentInfoSeq),
    ]
def _pss_padding() -> asym_padding.PSS:
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.DIGEST_LENGTH,
    )
def _problem(status: int, title: str, detail: str) -> dict:
    return {
        "type":   "urn:ietf:rfc:5652",
        "title":  title,
        "status": status,
        "detail": detail,
    }
async def verify_cms_signature(
    request:     Request,
    client_cert: Certificate,
    body_bytes:  bytes,
) -> None:
    original_method = request.headers.get("x-original-method", request.method).upper()
    _NO_BODY_METHODS = {"GET", "HEAD", "DELETE"}
    if original_method in _NO_BODY_METHODS:
        return
    cms_b64 = request.headers.get("x-cms-payload")
    if not cms_b64:
        print(f"DEBUG: Missing X-CMS-Payload header for method {original_method}", flush=True)
        raise HTTPException(
            status_code=401,
            detail=_problem(
                401,
                "Missing CMS Payload",
                f"[Layer 3] Header 'X-CMS-Payload' wajib ada untuk metode "
                f"{original_method} (CMS RFC 5652).",
            ),
        )
    try:
        cms_der = base64.b64decode(cms_b64)
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=_problem(401, "Invalid CMS Encoding", f"[Layer 3] X-CMS-Payload bukan base64 valid: {exc}"),
        )
    try:
        pkg              = _CMSPackageSeq.load(cms_der)
        signer_cert_der  = bytes(pkg["signer_info"]["signer_certificate"].native)
        signed_attrs_der = bytes(pkg["signer_info"]["signed_attributes"].native)
        signature        = bytes(pkg["signer_info"]["signature"].native)
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=_problem(401, "CMS Parse Error", f"[Layer 3] Gagal parse CMS package: {exc}"),
        )
    trusted_der = client_cert.public_bytes(serialization.Encoding.DER)
    if signer_cert_der != trusted_der:
        print("DEBUG: CMS signer cert does not match mTLS client cert", flush=True)
        raise HTTPException(
            status_code=403,
            detail=_problem(
                403,
                "Certificate Mismatch",
                "[Layer 3] Sertifikat dalam CMS SignerInfo tidak cocok dengan "
                "client certificate dari mTLS handshake.",
            ),
        )
    try:
        signer_cert    = x509.load_der_x509_certificate(signer_cert_der)
        signing_digest = hashlib.sha256(signed_attrs_der).digest()
        signer_cert.public_key().verify(
            signature, signing_digest, _pss_padding(), hashes.SHA256()
        )
    except InvalidSignature:
        print("DEBUG: CMS signature verification FAILED (InvalidSignature)", flush=True)
        raise HTTPException(
            status_code=403,
            detail=_problem(
                403,
                "CMS Signature Verification Failed",
                "[Layer 3] Signature CMS tidak valid — kemungkinan signed_attributes "
                "dimanipulasi atau key tidak cocok (CMS RFC 5652, 5.3).",
            ),
        )
    except Exception as exc:
        import traceback
        print(f"DEBUG: CMS verify error: {exc}\n{traceback.format_exc()}", flush=True)
        raise HTTPException(
            status_code=403,
            detail=_problem(403, "CMS Verification Error", f"[Layer 3] Error saat verifikasi CMS: {exc}"),
        )
    hdr_ok, hdr_reason = verify_cms_headers(
        dict(request.headers),
        cms_b64,
        context="request",
    )
    if not hdr_ok:
        print(f"DEBUG: Header digest verification FAILED — {hdr_reason}", flush=True)
        raise HTTPException(
            status_code=403,
            detail=_problem(
                403,
                "Header Digest Mismatch",
                f"[Layer 3b] Header request tidak cocok dengan yang di-sign: {hdr_reason}",
            ),
        )
    print(f"DEBUG: Header digest verification OK — {hdr_reason}", flush=True)
