"""
crypto/encryption.py
====================
Pure asymmetric encryption (RSA-OAEP) untuk body REST API.

Skema:
  - RSA-OAEP dengan SHA-256 → enkripsi/dekripsi langsung menggunakan
    pasangan kunci asimetrik penerima.

Batas ukuran plaintext (berlaku per key size):
  RSA-2048  →  maks 190 byte plaintext
  RSA-4096  →  maks 446 byte plaintext
  (cukup untuk password, token, API key, dsb.)

Wire format (setelah base64url-decode):
  ┌──────────────────────────────┐
  │ N bytes │ RSA-OAEP ciphertext│
  └──────────────────────────────┘
  N = key_size_bits / 8  (mis. 256 byte untuk RSA-2048)

Fungsi publik:
  encrypt(data, recipient_public_key) -> str
      Enkripsi `data` (bytes/str) langsung dengan RSA public key penerima.
      Return: base64url string (siap ditaruh di JSON value / HTTP header).

  decrypt(data, own_private_key) -> bytes
      Dekripsi blob (bytes/str base64url) dengan RSA private key sendiri.
      Return: plaintext bytes.
"""

import base64
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.x509 import Certificate


# ──────────────────────────────────────────────────────────────────────────────
# Helper internal
# ──────────────────────────────────────────────────────────────────────────────

def _oaep_padding() -> asym_padding.OAEP:
    """RSA-OAEP dengan SHA-256 (lebih aman dari PKCS#1 v1.5)."""
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Konversi str → bytes (UTF-8). Bytes dibiarkan apa adanya."""
    if isinstance(data, str):
        return data.encode("utf-8")
    return data


def _extract_public_key(key_or_cert: Union[RSAPublicKey, Certificate]) -> RSAPublicKey:
    """Terima RSAPublicKey langsung *atau* objek x509.Certificate."""
    if isinstance(key_or_cert, Certificate):
        return key_or_cert.public_key()
    return key_or_cert


def _max_plaintext_bytes(pub_key: RSAPublicKey) -> int:
    """
    Hitung batas maksimum plaintext untuk RSA-OAEP SHA-256.
    Rumus: key_size_bytes - 2 * hash_size_bytes - 2
           = key_size_bytes - 66
    """
    key_size_bytes = pub_key.key_size // 8  # key_size dalam bits
    hash_size_bytes = 32                    # SHA-256 → 32 byte
    return key_size_bytes - 2 * hash_size_bytes - 2


# ──────────────────────────────────────────────────────────────────────────────
# API publik
# ──────────────────────────────────────────────────────────────────────────────

def encrypt(
    data: Union[str, bytes],
    recipient_public_key: Union[RSAPublicKey, Certificate],
) -> str:
    """
    Enkripsi `data` secara asimetrik menggunakan RSA public key penerima.

    Cocok dipakai oleh Client untuk mengenkripsi *body* request sebelum
    dikirim ke Proxy → WAF → Web Application.

    Parameters
    ----------
    data : str | bytes
        Plaintext body yang akan dienkripsi.
        Ukuran maksimum bergantung pada key size penerima:
          RSA-2048 → maks 190 byte  |  RSA-4096 → maks 446 byte
    recipient_public_key : RSAPublicKey | x509.Certificate
        Public key penerima. Bisa berupa objek RSAPublicKey langsung
        atau objek Certificate (public key-nya diekstrak otomatis).

    Returns
    -------
    str
        Ciphertext dalam format base64url (URL-safe, tanpa padding '=').
        Aman disimpan sebagai JSON value atau HTTP header value.

    Raises
    ------
    ValueError
        Jika plaintext melebihi batas ukuran RSA-OAEP untuk key tersebut.
    TypeError
        Jika `recipient_public_key` bukan RSAPublicKey atau Certificate.
    cryptography.exceptions.UnsupportedAlgorithm
        Jika key bukan RSA.
    """
    pub_key = _extract_public_key(recipient_public_key)
    plaintext = _to_bytes(data)

    # Validasi ukuran sebelum enkripsi agar error message jelas
    max_bytes = _max_plaintext_bytes(pub_key)
    if len(plaintext) > max_bytes:
        raise ValueError(
            f"Plaintext terlalu besar untuk RSA-{pub_key.key_size} OAEP-SHA256: "
            f"{len(plaintext)} byte (maks {max_bytes} byte). "
            "Kurangi ukuran body atau gunakan hybrid encryption."
        )

    # Enkripsi langsung dengan RSA-OAEP
    ciphertext: bytes = pub_key.encrypt(plaintext, _oaep_padding())

    # Encode base64url tanpa padding '='
    return base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode("ascii")


def decrypt(
    data: Union[str, bytes],
    own_private_key: RSAPrivateKey,
) -> bytes:
    """
    Dekripsi blob RSA-OAEP yang dienkripsi dengan *public key* milik kita.

    Cocok dipakai oleh Client untuk mendekripsi *body* response yang
    dienkripsi oleh Web Application menggunakan Client public key.

    Parameters
    ----------
    data : str | bytes
        Ciphertext dalam format base64url (output dari `encrypt()`).
    own_private_key : RSAPrivateKey
        Private key milik kita (pasangan dari public key yang dipakai
        pihak pengirim saat enkripsi).

    Returns
    -------
    bytes
        Plaintext body hasil dekripsi.

    Raises
    ------
    ValueError
        Jika blob tidak valid (bukan base64url yang benar).
    cryptography.exceptions.ValueError
        Jika dekripsi RSA gagal (kunci salah atau data rusak).
    """
    # Decode base64url — tambahkan padding '=' yang mungkin dihapus
    raw = _to_bytes(data)
    padding_needed = (4 - len(raw) % 4) % 4
    raw += b"=" * padding_needed
    ciphertext = base64.urlsafe_b64decode(raw)

    # Dekripsi langsung dengan RSA-OAEP private key
    plaintext: bytes = own_private_key.decrypt(ciphertext, _oaep_padding())

    return plaintext


# ──────────────────────────────────────────────────────────────────────────────
# Helper: load key / cert dari file PEM
# ──────────────────────────────────────────────────────────────────────────────

def load_public_key_from_pem(pem_path: str) -> RSAPublicKey:
    """
    Baca public key dari file PEM.
    Mendukung dua format:
      - File CERTIFICATE   → public key diekstrak dari sertifikat
      - File PUBLIC KEY    → hasil ``openssl rsa -pubout``
    """
    with open(pem_path, "rb") as f:
        pem_data = f.read()

    if b"CERTIFICATE" in pem_data:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(pem_data)
        return cert.public_key()

    return serialization.load_pem_public_key(pem_data)


def load_private_key_from_pem(
    pem_path: str,
    password: bytes | None = None,
) -> RSAPrivateKey:
    """
    Baca private key dari file PEM (mendukung key terenkripsi passphrase).

    Parameters
    ----------
    pem_path : str
        Path ke file PEM yang berisi private key.
    password : bytes | None
        Passphrase jika key dienkripsi, ``None`` jika tidak.
    """
    with open(pem_path, "rb") as f:
        pem_data = f.read()
    return serialization.load_pem_private_key(pem_data, password=password)
