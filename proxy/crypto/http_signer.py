import base64
import hashlib
import json
import time
from datetime import datetime, timezone, timedelta

import requests as http_requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from http_message_signatures import (
    HTTPMessageSigner,
    HTTPSignatureKeyResolver,
    algorithms,
)

def compute_jwk_thumbprint(public_key: RSAPublicKey) -> str:
    pub_numbers = public_key.public_numbers()

    def _b64url(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(
            n.to_bytes(byte_len, "big")
        ).rstrip(b"=").decode("ascii")

    jwk = json.dumps(
        {
            "e":   _b64url(pub_numbers.e),
            "kty": "RSA",
            "n":   _b64url(pub_numbers.n),
        },
        separators=(",", ":"),
        sort_keys=True
    )
    digest = hashlib.sha256(jwk.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class _ClientKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, private_key: RSAPrivateKey):
        self._private_key = private_key

    def resolve_private_key(self, key_id: str) -> RSAPrivateKey:
        return self._private_key

    def resolve_public_key(self, key_id: str) -> RSAPublicKey:
        return self._private_key.public_key()


def compute_content_digest(body_bytes: bytes) -> str:
    raw_digest = hashlib.sha256(body_bytes).digest()
    b64        = base64.b64encode(raw_digest).decode("ascii")
    return f"sha-256=:{b64}:"


_REPLAY_WINDOW_SECONDS = 300

def sign_request(
    prepared:    http_requests.PreparedRequest,
    private_key: RSAPrivateKey,
    created:     int | None = None,
    expires:     int | None = None,
) -> str:
    if isinstance(prepared.body, bytes):
        body_bytes: bytes = prepared.body
    elif isinstance(prepared.body, str):
        body_bytes = prepared.body.encode("utf-8")
    else:
        body_bytes = b""

    digest_value = compute_content_digest(body_bytes)
    prepared.headers["Content-Digest"] = digest_value

    pub_key = private_key.public_key()
    key_id  = compute_jwk_thumbprint(pub_key)

    now = created if created is not None else int(time.time())
    exp = expires if expires is not None else now + _REPLAY_WINDOW_SECONDS

    created_dt = datetime.fromtimestamp(now, tz=timezone.utc)
    expires_dt = datetime.fromtimestamp(exp, tz=timezone.utc)

    signer = HTTPMessageSigner(
        signature_algorithm=algorithms.RSA_PSS_SHA512,
        key_resolver=_ClientKeyResolver(private_key),
    )
    signer.sign(
        prepared,
        key_id=key_id,
        covered_component_ids=[
            "content-digest", 
            "@method", 
            "@path", 
            "@authority",
        ],
        created=created_dt,
        expires=expires_dt,
    )

    return key_id
