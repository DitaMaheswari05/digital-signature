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
