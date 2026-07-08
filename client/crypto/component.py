from typing import Union
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate


def _to_bytes(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def _extract_public_key(key_or_cert: Union[RSAPublicKey, Certificate]) -> RSAPublicKey:
    if isinstance(key_or_cert, Certificate):
        return key_or_cert.public_key()
    return key_or_cert


def load_public_key_from_pem(pem_path: str) -> RSAPublicKey:
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    if b"CERTIFICATE" in pem_data:
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert.public_key()
    return serialization.load_pem_public_key(pem_data)