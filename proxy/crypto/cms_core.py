import base64
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Union

from asn1crypto import core as asn1_core
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509 import Certificate

_cms_log = logging.getLogger("proxy")

CMS_VERSION: int = 1
_DIGEST_ALG      = "sha256"
_SIG_ALG         = "rsa_pss_sha256"
_KEY_ENC_ALG     = "rsa_oaep_sha256"
_CONTENT_ENC_ALG = "aes256_gcm"

def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n <= 0xFF:
        return bytes([0x81, n])
    elif n <= 0xFFFF:
        return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    elif n <= 0xFFFFFF:
        return bytes([0x83, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])
    else:
        raise ValueError(f"DER value too large to encode: {n} bytes")

def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value

def _der_seq(*fields: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(fields))

def _der_set(*fields: bytes) -> bytes:
    return _der_tlv(0x31, b"".join(fields))

def _der_octet(data: bytes) -> bytes:
    return _der_tlv(0x04, data)

def _der_utf8(s: str) -> bytes:
    return _der_tlv(0x0C, s.encode("utf-8"))

def _der_int(n: int) -> bytes:
    if n == 0:
        return _der_tlv(0x02, b"\x00")
    octets: list[int] = []
    while n > 0:
        octets.insert(0, n & 0xFF)
        n >>= 8
    if octets[0] & 0x80:
        octets.insert(0, 0x00)
    return _der_tlv(0x02, bytes(octets))

class _SignerInfoSeq(asn1_core.Sequence):
    _fields = [
        ("signer_certificate",  asn1_core.OctetString),
        ("digest_algorithm",    asn1_core.UTF8String),
        ("signature_algorithm", asn1_core.UTF8String),
        ("signed_attributes",   asn1_core.OctetString),
        ("signature",           asn1_core.OctetString),
    ]

class _RecipientInfoSeq(asn1_core.Sequence):
    _fields = [
        ("key_encryption_algorithm", asn1_core.UTF8String),
        ("encrypted_key",            asn1_core.OctetString),
    ]

class _EncryptedContentInfoSeq(asn1_core.Sequence):
    _fields = [
        ("content_encryption_algorithm", asn1_core.UTF8String),
        ("iv",                           asn1_core.OctetString),
        ("encrypted_content",            asn1_core.OctetString),
    ]

class _CMSPackageSeq(asn1_core.Sequence):
    _fields = [
        ("version",                asn1_core.Integer),
        ("signer_info",            _SignerInfoSeq),
        ("recipient_info",         _RecipientInfoSeq),
        ("encrypted_content_info", _EncryptedContentInfoSeq),
    ]

from cms_lib.canonical import canonical_headers, IGNORED_HEADERS


def _build_signed_attributes(
    body:         bytes,
    content_type: str  = "application/json",
    headers:      dict | None = None,
) -> bytes:
    body_digest  = hashlib.sha256(body).digest()
    signing_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _cms_log.debug(
        "[CMS] message-digest = SHA-256(payload) = %s...%s  (%d bytes)",
        body_digest.hex()[:16], body_digest.hex()[-8:], len(body_digest),
    )

    attr_content_type = _der_seq(
        _der_utf8("content-type"),
        _der_utf8(content_type),
    )
    attr_message_digest = _der_seq(
        _der_utf8("message-digest"),
        _der_octet(body_digest),
    )
    attr_signing_time = _der_seq(
        _der_utf8("signing-time"),
        _der_utf8(signing_time),
    )

    if headers:
        _cms_log.debug("[CMS] Headers diterima (belum di-sort) — %d header:", len(headers))
        for k, v in headers.items():
            v_str   = v if isinstance(v, str) else str(v)
            preview = v_str[:80] + "..." if len(v_str) > 80 else v_str
            _cms_log.debug("[CMS]   %-32s : %s", k, preview)

        hdr_canonical = canonical_headers(headers)

        _cms_log.debug("[CMS] Headers setelah di-sort & normalisasi (canonical form):")
        for line in hdr_canonical.decode("utf-8").splitlines():
            _cms_log.debug("[CMS]   %s", line)

        hdr_digest = hashlib.sha256(hdr_canonical).digest()
        _cms_log.debug(
            "[CMS] headers-digest = SHA-256(canonical) = %s...%s  (%d bytes)",
            hdr_digest.hex()[:16], hdr_digest.hex()[-8:], len(hdr_digest),
        )

        attr_headers_digest = _der_seq(
            _der_utf8("headers-digest"),
            _der_octet(hdr_digest),
        )
        signed_attrs_der = _der_set(
            attr_content_type,
            attr_headers_digest,
            attr_message_digest,
            attr_signing_time,
        )
        _cms_log.debug("[CMS] SignedAttributes SET :")
        _cms_log.debug("[CMS]   1. content-type   = %s", content_type)
        _cms_log.debug("[CMS]   2. headers-digest  = SHA-256(canonical_headers)  <- header integrity")
        _cms_log.debug("[CMS]   3. message-digest  = SHA-256(payload_bytes)")
        _cms_log.debug("[CMS]   4. signing-time    = %s", signing_time)
        _cms_log.debug("[CMS]   DER total          = %d bytes", len(signed_attrs_der))
    else:
        signed_attrs_der = _der_set(
            attr_content_type,
            attr_message_digest,
            attr_signing_time,
        )
        _cms_log.debug("[CMS] SignedAttributes SET :")
        _cms_log.debug("[CMS]   1. content-type   = %s", content_type)
        _cms_log.debug("[CMS]   2. message-digest  = SHA-256(payload_bytes)")
        _cms_log.debug("[CMS]   3. signing-time    = %s", signing_time)
        _cms_log.debug("[CMS]   DER total          = %d bytes", len(signed_attrs_der))

    return signed_attrs_der

def _parse_signed_attributes(signed_attrs_der: bytes) -> dict:
    result = {}

    pos = 0
    raw = signed_attrs_der
    if len(raw) < 2:
        return result

    if raw[0] != 0x31:
        return result
    pos = 1

    if raw[pos] < 0x80:
        inner_len = raw[pos]
        pos += 1
    elif raw[pos] == 0x81:
        inner_len = raw[pos + 1]
        pos += 2
    elif raw[pos] == 0x82:
        inner_len = (raw[pos + 1] << 8) | raw[pos + 2]
        pos += 3
    else:
        return result

    inner = raw[pos: pos + inner_len]

    i = 0
    while i < len(inner):
        if inner[i] != 0x30:
            break
        i += 1
        if inner[i] < 0x80:
            seq_len = inner[i]
            i += 1
        elif inner[i] == 0x81:
            seq_len = inner[i + 1]
            i += 2
        elif inner[i] == 0x82:
            seq_len = (inner[i + 1] << 8) | inner[i + 2]
            i += 3
        else:
            break

        seq_body = inner[i: i + seq_len]
        i += seq_len

        j = 0
        if len(seq_body) < 2 or seq_body[j] != 0x0C:
            continue
        j += 1
        name_len = seq_body[j]
        j += 1
        name = seq_body[j: j + name_len].decode("utf-8")
        j += name_len

        if j >= len(seq_body):
            continue

        val_tag = seq_body[j]
        j += 1
        val_len_b = seq_body[j]
        if val_len_b < 0x80:
            val_len = val_len_b
            j += 1
        elif val_len_b == 0x81:
            val_len = seq_body[j + 1]
            j += 2
        elif val_len_b == 0x82:
            val_len = (seq_body[j + 1] << 8) | seq_body[j + 2]
            j += 3
        else:
            continue
        val_bytes = seq_body[j: j + val_len]

        if val_tag == 0x0C:
            result[name] = val_bytes.decode("utf-8")
        elif val_tag == 0x04:
            result[name] = val_bytes

    return result

def compute_content_digest(body: bytes) -> str:
    raw = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(raw).decode('ascii')}:"

def _pss_padding() -> asym_padding.PSS:
    return asym_padding.PSS(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        salt_length=asym_padding.PSS.DIGEST_LENGTH,
    )

def _oaep_padding() -> asym_padding.OAEP:
    return asym_padding.OAEP(
        mgf=asym_padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )

def cms_pack(
    body:             bytes,
    signer_key:       RSAPrivateKey,
    signer_cert:      Certificate,
    recipient_pubkey: RSAPublicKey,
    content_type:     str  = "application/json",
    headers:          dict | None = None,
) -> bytes:
    signed_attrs_der = _build_signed_attributes(body, content_type, headers)

    digest = hashlib.sha256(signed_attrs_der).digest()

    _cms_log.debug("[CMS] -- Digital Signature Process (RSA-PSS-SHA256) --")
    _cms_log.debug(
        "[CMS]   Input  : DER(SignedAttributes SET) = %d bytes", len(signed_attrs_der)
    )
    _cms_log.debug(
        "[CMS]   Step 1 : SHA-256(DER) = %s...%s",
        digest.hex()[:16], digest.hex()[-8:],
    )
    _cms_log.debug("[CMS]   Step 2 : RSA-PSS-SHA256.sign(digest, client_private_key)")

    signature = signer_key.sign(digest, _pss_padding(), hashes.SHA256())

    _cms_log.debug(
        "[CMS]   Output : signature = %s...%s  (%d bytes)",
        signature.hex()[:16], signature.hex()[-8:], len(signature),
    )
    _cms_log.debug("[CMS] -- Signature selesai --")

    aes_key = os.urandom(32)
    iv      = os.urandom(12)

    aesgcm         = AESGCM(aes_key)
    encrypted_body = aesgcm.encrypt(iv, body, None)

    signer_cert_der = signer_cert.public_bytes(serialization.Encoding.DER)
    encrypted_key   = recipient_pubkey.encrypt(aes_key, _oaep_padding())

    signer_info = _der_seq(
        _der_octet(signer_cert_der),
        _der_utf8(_DIGEST_ALG),
        _der_utf8(_SIG_ALG),
        _der_octet(signed_attrs_der),
        _der_octet(signature),
    )
    recipient_info = _der_seq(
        _der_utf8(_KEY_ENC_ALG),
        _der_octet(encrypted_key),
    )
    encrypted_content_info = _der_seq(
        _der_utf8(_CONTENT_ENC_ALG),
        _der_octet(iv),
        _der_octet(encrypted_body),
    )
    cms_der = _der_seq(
        _der_int(CMS_VERSION),
        signer_info,
        recipient_info,
        encrypted_content_info,
    )
    return cms_der

def cms_unpack(
    cms_der:       bytes,
    recipient_key: RSAPrivateKey,
) -> tuple[bytes, bool]:
    pkg = _CMSPackageSeq.load(cms_der)

    signer_cert_der     = bytes(pkg["signer_info"]["signer_certificate"].native)
    signed_attrs_der    = bytes(pkg["signer_info"]["signed_attributes"].native)
    signature           = bytes(pkg["signer_info"]["signature"].native)

    encrypted_key_bytes  = bytes(pkg["recipient_info"]["encrypted_key"].native)
    iv                   = bytes(pkg["encrypted_content_info"]["iv"].native)
    encrypted_body_bytes = bytes(pkg["encrypted_content_info"]["encrypted_content"].native)

    aes_key = recipient_key.decrypt(encrypted_key_bytes, _oaep_padding())

    aesgcm = AESGCM(aes_key)
    body   = aesgcm.decrypt(iv, encrypted_body_bytes, None)

    sig_attrs = _parse_signed_attributes(signed_attrs_der)
    embedded_digest = sig_attrs.get("message-digest")

    if isinstance(embedded_digest, bytes):
        actual_digest = hashlib.sha256(body).digest()
        if actual_digest != embedded_digest:
            return body, False
    else:
        return body, False

    sig_valid = False
    try:
        signer_cert   = x509.load_der_x509_certificate(signer_cert_der)
        signer_pubkey = signer_cert.public_key()
        signing_digest = hashlib.sha256(signed_attrs_der).digest()
        signer_pubkey.verify(signature, signing_digest, _pss_padding(), hashes.SHA256())
        sig_valid = True
    except InvalidSignature:
        sig_valid = False
    except Exception:
        sig_valid = False

    return body, sig_valid

def cms_verify_signature(
    cms_der:      bytes,
    trusted_cert: Certificate,
) -> bool:
    try:
        pkg = _CMSPackageSeq.load(cms_der)
        signer_cert_der  = bytes(pkg["signer_info"]["signer_certificate"].native)
        signed_attrs_der = bytes(pkg["signer_info"]["signed_attributes"].native)
        signature        = bytes(pkg["signer_info"]["signature"].native)
    except Exception:
        return False

    trusted_der = trusted_cert.public_bytes(serialization.Encoding.DER)
    if signer_cert_der != trusted_der:
        return False

    try:
        signer_cert    = x509.load_der_x509_certificate(signer_cert_der)
        signing_digest = hashlib.sha256(signed_attrs_der).digest()
        signer_cert.public_key().verify(
            signature, signing_digest, _pss_padding(), hashes.SHA256()
        )
        return True
    except (InvalidSignature, Exception):
        return False
