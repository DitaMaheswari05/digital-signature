import base64
import hashlib
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

_REPLAY_WINDOW_SECONDS = 300


def _pss_padding() -> asym_padding.PSS:
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA512()),
        salt_length=asym_padding.PSS.DIGEST_LENGTH,
    )


def compute_content_digest(body_bytes: bytes) -> str:
    raw_digest = hashlib.sha256(body_bytes).digest()
    b64 = base64.b64encode(raw_digest).decode("ascii")
    return f"sha-256=:{b64}:"


def sign_response(
    body_bytes: bytes,
    private_key: RSAPrivateKey,
    status_code: int = 200,
    key_id: str = "webapp-key",
    created: int | None = None,
    expires: int | None = None,
) -> dict:
    now = created if created is not None else int(time.time())
    exp = expires if expires is not None else now + _REPLAY_WINDOW_SECONDS

    content_digest = compute_content_digest(body_bytes)

    sig_params = (
        f'("@status" "content-digest")'
        f';created={now}'
        f';expires={exp}'
        f';keyid="{key_id}"'
        f';alg="rsa-pss-sha512"'
    )

    sig_base = (
        f'"@status": {status_code}\n'
        f'"content-digest": {content_digest}\n'
        f'"@signature-params": {sig_params}'
    )

    sig_bytes = private_key.sign(sig_base.encode("utf-8"), _pss_padding(), hashes.SHA512())
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    return {
        "Content-Digest":  content_digest,
        "Signature-Input": f"sig1={sig_params}",
        "Signature":       f"sig1=:{sig_b64}:",
    }
