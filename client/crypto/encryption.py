import base64
from typing import Union
from cryptography import x509

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.x509 import Certificate

from component import _to_bytes, _extract_public_key


def _oaep_padding() -> asym_padding.OAEP:
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _max_plaintext_bytes(pub_key: RSAPublicKey) -> int:
    key_size_bytes = pub_key.key_size // 8
    hash_size_bytes = 32
    return key_size_bytes - 2 * hash_size_bytes - 2


def encrypt(data: Union[str, bytes], recipient_public_key: Union[RSAPublicKey, Certificate]) -> str:
    pub_key = _extract_public_key(recipient_public_key)
    plaintext = _to_bytes(data)

    max_bytes = _max_plaintext_bytes(pub_key)
    if len(plaintext) > max_bytes:
        raise ValueError(
            f"Plaintext terlalu besar untuk RSA-{pub_key.key_size} OAEP-SHA256: "
            f"{len(plaintext)} byte (maks {max_bytes} byte). "
        )

    ciphertext: bytes = pub_key.encrypt(plaintext, _oaep_padding())
    return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")


def decrypt(data: Union[str, bytes], own_private_key: RSAPrivateKey) -> bytes:

    raw = _to_bytes(data)
    padding_needed = (4 - len(raw) % 4) % 4
    raw += b"=" * padding_needed
    ciphertext = base64.urlsafe_b64decode(raw)

    # Dekripsi langsung dengan RSA-OAEP private key
    plaintext: bytes = own_private_key.decrypt(ciphertext, _oaep_padding())

    return plaintext


def load_public_key_from_pem(pem_path: str) -> RSAPublicKey:
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    if b"CERTIFICATE" in pem_data:
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert.public_key()

    return serialization.load_pem_public_key(pem_data)


def load_private_key_from_pem(
    pem_path: str,
    password: bytes | None = None,
) -> RSAPrivateKey:
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=password)
