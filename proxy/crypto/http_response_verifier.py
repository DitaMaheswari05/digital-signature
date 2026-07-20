import base64
import hashlib
import re
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

from component import _extract_public_key

_REPLAY_WINDOW_SECONDS = 300


def _pss_padding() -> asym_padding.PSS:
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA512()),
        salt_length=asym_padding.PSS.DIGEST_LENGTH,
    )


def _get_header(headers: dict, name: str) -> str | None:
    return headers.get(name) or headers.get(name.lower()) or headers.get(name.upper())


def verify_content_digest(body_bytes: bytes, content_digest_header: str) -> bool:
    match = re.search(r"sha-256=:([^:]+):", content_digest_header)
    if not match:
        return False
    expected_b64 = match.group(1)
    actual_b64 = base64.b64encode(hashlib.sha256(body_bytes).digest()).decode("ascii")
    return expected_b64 == actual_b64


def _parse_sig_bytes(signature_header: str) -> bytes:
    match = re.search(r"sig1=:([^:]+):", signature_header)
    if not match:
        raise ValueError(f"Format Signature header tidak valid: {signature_header!r}")
    return base64.b64decode(match.group(1))


def _parse_sig_params(sig_input_header: str) -> str:
    if sig_input_header.startswith("sig1="):
        return sig_input_header[5:]
    raise ValueError(f"Format Signature-Input header tidak valid: {sig_input_header!r}")


def verify_response_signature(
    body_bytes: bytes,
    headers: dict,
    public_key: Union[RSAPublicKey, Certificate],
    status_code: int = 200,
) -> bool:
    pub_key = _extract_public_key(public_key)

    content_digest = _get_header(headers, "Content-Digest")
    sig_input      = _get_header(headers, "Signature-Input")
    signature      = _get_header(headers, "Signature")

    if not all([content_digest, sig_input, signature]):
        return False

    if not verify_content_digest(body_bytes, content_digest):
        return False

    try:
        sig_params = _parse_sig_params(sig_input)
        sig_bytes  = _parse_sig_bytes(signature)
    except ValueError:
        return False

    sig_base = (
        f'"@status": {status_code}\n'
        f'"content-digest": {content_digest}\n'
        f'"@signature-params": {sig_params}'
    )

    try:
        pub_key.verify(sig_bytes, sig_base.encode("utf-8"), _pss_padding(), hashes.SHA512())
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
