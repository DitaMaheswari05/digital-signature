import base64
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

from component import _to_bytes, _extract_public_key


def _pss_padding() -> asym_padding.PSS:
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=asym_padding.PSS.DIGEST_LENGTH
    )


def _decode_signature(signature: Union[str, bytes]) -> bytes:
    raw = _to_bytes(signature)
    padding_needed = (4 - len(raw) % 4) % 4
    raw += b"=" * padding_needed
    return base64.urlsafe_b64decode(raw)


def verify_signature(payload: Union[str, bytes], signature: Union[str, bytes], public_key: Union[RSAPublicKey, Certificate]) -> bool:
    pub_key = _extract_public_key(public_key)
    payload_bytes = _to_bytes(payload)

    try:
        sig_bytes = _decode_signature(signature)
    except Exception:
        return False

    try:
        pub_key.verify(sig_bytes, payload_bytes, _pss_padding(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False

def load_public_key_from_pem(pem_path: str) -> RSAPublicKey:
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    if b"CERTIFICATE" in pem_data:
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert.public_key()
    return serialization.load_pem_public_key(pem_data)

def load_cert_from_pem(pem_path: str) -> Certificate:
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    return x509.load_pem_x509_certificate(pem_data)


def load_cert_from_pem_string(pem_string: Union[str, bytes]) -> Certificate:
    pem_bytes = _to_bytes(pem_string)
    return x509.load_pem_x509_certificate(pem_bytes)
