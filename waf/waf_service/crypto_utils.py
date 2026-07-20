import base64
from pathlib import Path
from typing import Union, List
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
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


def load_cert_from_pem_string(pem_string: Union[str, bytes]) -> Certificate:
    pem_bytes = _to_bytes(pem_string)
    return x509.load_pem_x509_certificate(pem_bytes)


def load_trusted_ca_bundle(ca_bundle_path: Union[str, Path]) -> List[Certificate]:
    raw = Path(ca_bundle_path).read_bytes()
    certs: List[Certificate] = []

    current: List[bytes] = []
    in_block = False

    for line in raw.splitlines(keepends=True):
        line_s = line.strip()
        if line_s.startswith(b"-----BEGIN CERTIFICATE"):
            in_block = True
            current = [line]
        elif line_s.startswith(b"-----END CERTIFICATE") and in_block:
            current.append(line)
            try:
                certs.append(x509.load_pem_x509_certificate(b"".join(current)))
            except Exception:
                pass
            in_block = False
            current = []
        elif in_block:
            current.append(line)

    return certs


def verify_cert_trusted(client_cert: Certificate, trusted_cas: List[Certificate]) -> bool:
    tbs_bytes = client_cert.tbs_certificate_bytes

    sig_algorithm = client_cert.signature_hash_algorithm
    if sig_algorithm is None:
        return False

    sig_bytes = client_cert.signature

    for ca_cert in trusted_cas:
        try:
            ca_pubkey = ca_cert.public_key()
            ca_pubkey.verify(
                sig_bytes,
                tbs_bytes,
                asym_padding.PKCS1v15(),
                sig_algorithm,
            )
            return True
        except InvalidSignature:
            continue
        except Exception:
            continue

    return False


def verify_signature(
    payload: Union[str, bytes],
    signature: Union[str, bytes],
    public_key: Union[RSAPublicKey, Certificate],
) -> bool:
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
