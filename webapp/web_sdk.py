import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography import x509


def _oaep_padding() -> asym_padding.OAEP:
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def load_private_key(pem_path: str, password: bytes = None) -> RSAPrivateKey:
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def load_public_key(pem_path: str) -> RSAPublicKey:
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    if b"CERTIFICATE" in pem_data:
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert.public_key()
    return serialization.load_pem_public_key(pem_data)


def decrypt_payload(ciphertext_b64: str, private_key: RSAPrivateKey) -> bytes:
    raw = ciphertext_b64.encode("ascii")
    padding_needed = (4 - len(raw) % 4) % 4
    raw += b"=" * padding_needed
    ciphertext = base64.urlsafe_b64decode(raw)
    return private_key.decrypt(ciphertext, _oaep_padding())


def encrypt_payload(plaintext: bytes, public_key: RSAPublicKey) -> str:
    ciphertext = public_key.encrypt(plaintext, _oaep_padding())
    return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")