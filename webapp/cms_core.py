import base64
import hashlib
import logging
import os
import sys
from pathlib import Path
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


for _shared_candidate in (
    Path("/shared"),
    Path(__file__).resolve().parent.parent / "shared",
):
    if _shared_candidate.is_dir() and str(_shared_candidate) not in sys.path:
        sys.path.insert(0, str(_shared_candidate))
        break

from cms_lib.canonical import canonical_headers, IGNORED_HEADERS

_cms_log = logging.getLogger("webapp")
CMS_VERSION: int = 1
_DIGEST_ALG      = "sha256"
_SIG_ALG         = "rsa_pss_sha256"
_KEY_ENC_ALG     = "rsa_oaep_sha256"
_CONTENT_ENC_ALG = "aes256_gcm"
_SIGNING_TIME_WINDOW_SECS: int = 300


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
        raise ValueError(f"DER value too large: {n} bytes")


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


def _build_signed_attributes(
    body:         bytes,
    content_type: str  = "application/json",
    headers:      dict | None = None,
) -> bytes:
    body_digest  = hashlib.sha256(body).digest()
    signing_time = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _cms_log.debug(
        "[CMS] message-digest = SHA-256(response_body) = %s...%s  (%d bytes)",
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
        _cms_log.debug("[CMS] Response headers diterima (belum di-sort) — %d header:", len(headers))
        for k, v in headers.items():
            v_str   = v if isinstance(v, str) else str(v)
            _cms_log.debug("[CMS]   %-32s : %s", k, v_str)
        hdr_canonical = canonical_headers(headers)
        _cms_log.debug("[CMS] Response headers setelah di-sort & normalisasi:")
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
        result = _der_set(
            attr_content_type,
            attr_headers_digest,
            attr_message_digest,
            attr_signing_time,
        )
        _cms_log.debug("[CMS] SignedAttributes SET (response):")
        _cms_log.debug("[CMS]   1. content-type   = %s", content_type)
        _cms_log.debug("[CMS]   2. headers-digest  = SHA-256(canonical_headers)  <- header integrity")
        _cms_log.debug("[CMS]   3. message-digest  = SHA-256(response_bytes)")
        _cms_log.debug("[CMS]   4. signing-time    = %s", signing_time)
        _cms_log.debug("[CMS]   DER total          = %d bytes", len(result))
        return result
    result = _der_set(
        attr_content_type,
        attr_message_digest,
        attr_signing_time,
    )
    _cms_log.debug("[CMS] SignedAttributes SET (response):")
    _cms_log.debug("[CMS]   1. content-type   = %s", content_type)
    _cms_log.debug("[CMS]   2. message-digest  = SHA-256(response_bytes)")
    _cms_log.debug("[CMS]   3. signing-time    = %s", signing_time)
    _cms_log.debug("[CMS]   DER total          = %d bytes", len(result))
    return result


def _parse_signed_attributes(signed_attrs_der: bytes) -> dict:
    result = {}
    raw = signed_attrs_der
    if len(raw) < 2 or raw[0] != 0x31:
        return result
    pos = 1
    if raw[pos] < 0x80:
        inner_len = raw[pos]; pos += 1
    elif raw[pos] == 0x81:
        inner_len = raw[pos + 1]; pos += 2
    elif raw[pos] == 0x82:
        inner_len = (raw[pos + 1] << 8) | raw[pos + 2]; pos += 3
    else:
        return result
    inner = raw[pos: pos + inner_len]
    i = 0
    while i < len(inner):
        if inner[i] != 0x30:
            break
        i += 1
        if inner[i] < 0x80:
            seq_len = inner[i]; i += 1
        elif inner[i] == 0x81:
            seq_len = inner[i + 1]; i += 2
        elif inner[i] == 0x82:
            seq_len = (inner[i + 1] << 8) | inner[i + 2]; i += 3
        else:
            break
        seq_body = inner[i: i + seq_len]
        i += seq_len
        j = 0
        if len(seq_body) < 2 or seq_body[j] != 0x0C:
            continue
        j += 1
        name_len = seq_body[j]; j += 1
        name = seq_body[j: j + name_len].decode("utf-8"); j += name_len
        if j >= len(seq_body):
            continue
        val_tag = seq_body[j]; j += 1
        val_len_b = seq_body[j]
        if val_len_b < 0x80:
            val_len = val_len_b; j += 1
        elif val_len_b == 0x81:
            val_len = seq_body[j + 1]; j += 2
        elif val_len_b == 0x82:
            val_len = (seq_body[j + 1] << 8) | seq_body[j + 2]; j += 3
        else:
            continue
        val_bytes = seq_body[j: j + val_len]
        if val_tag == 0x0C:
            result[name] = val_bytes.decode("utf-8")
        elif val_tag == 0x04:
            result[name] = val_bytes
    return result


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


def cms_decrypt_request(
    cms_der:         bytes,
    webapp_priv_key: RSAPrivateKey,
    client_cert:     Certificate,
) -> tuple[bytes, bool]:
    """Decrypt dan verify CMS request dari Proxy.
    Returns:
        (plaintext_body, sig_valid)
        sig_valid=False jika signer cert tidak cocok, digest invalid,
        signing-time di luar window, atau RSA-PSS signature gagal.
    """
    pkg = _CMSPackageSeq.load(cms_der)
    signer_cert_der     = bytes(pkg["signer_info"]["signer_certificate"].native)
    signed_attrs_der    = bytes(pkg["signer_info"]["signed_attributes"].native)
    signature           = bytes(pkg["signer_info"]["signature"].native)
    encrypted_key_bytes = bytes(pkg["recipient_info"]["encrypted_key"].native)
    iv                  = bytes(pkg["encrypted_content_info"]["iv"].native)
    encrypted_body_bytes = bytes(pkg["encrypted_content_info"]["encrypted_content"].native)
    expected_der = client_cert.public_bytes(serialization.Encoding.DER)
    if signer_cert_der != expected_der:
        _cms_log.warning(
            "[CMS] [SECURITY] Signer cert TIDAK COCOK dengan client cert yang diharapkan — "
            "request ditolak tanpa dekripsi."
        )
        return b"", False
    aes_key = webapp_priv_key.decrypt(encrypted_key_bytes, _oaep_padding())
    body    = AESGCM(aes_key).decrypt(iv, encrypted_body_bytes, None)
    sig_attrs = _parse_signed_attributes(signed_attrs_der)
    embedded_digest = sig_attrs.get("message-digest")
    if not isinstance(embedded_digest, bytes):
        _cms_log.warning("[CMS] message-digest tidak ditemukan di signed_attributes.")
        return body, False
    if hashlib.sha256(body).digest() != embedded_digest:
        _cms_log.warning(
            "[CMS] message-digest TIDAK COCOK — body mungkin dimanipulasi."
        )
        return body, False
    signing_time_str = sig_attrs.get("signing-time")
    if not isinstance(signing_time_str, str):
        _cms_log.warning("[CMS] signing-time tidak ditemukan di signed_attributes.")
        return body, False
    try:
        signing_dt = datetime.strptime(signing_time_str, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        now_dt = datetime.now(tz=timezone.utc)
        skew   = abs((now_dt - signing_dt).total_seconds())
        if skew > _SIGNING_TIME_WINDOW_SECS:
            _cms_log.warning(
                "[CMS] [SECURITY] signing-time di luar window (%ds > %ds) — "
                "kemungkinan replay attack. signing-time=%s, now=%s",
                int(skew), _SIGNING_TIME_WINDOW_SECS,
                signing_time_str, now_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            return body, False
        _cms_log.debug(
            "[CMS] signing-time OK — skew=%ds (window=%ds)",
            int(skew), _SIGNING_TIME_WINDOW_SECS,
        )
    except (ValueError, TypeError) as exc:
        _cms_log.warning("[CMS] Gagal parse signing-time '%s': %s", signing_time_str, exc)
        return body, False
    try:
        signer_cert    = x509.load_der_x509_certificate(signer_cert_der)
        signing_digest = hashlib.sha256(signed_attrs_der).digest()
        signer_cert.public_key().verify(
            signature, signing_digest, _pss_padding(), hashes.SHA256()
        )
        return body, True
    except InvalidSignature:
        _cms_log.warning("[CMS] RSA-PSS signature TIDAK VALID.")
        return body, False
    except Exception as exc:
        _cms_log.warning("[CMS] Error saat verifikasi signature: %s", exc)
        return body, False


def cms_pack_response(
    body:             bytes,
    signer_key:       RSAPrivateKey,
    signer_cert:      Certificate,
    recipient_pubkey: RSAPublicKey,
    content_type:     str  = "application/json",
    headers:          dict | None = None,
) -> bytes:
    signed_attrs_der = _build_signed_attributes(body, content_type, headers)
    signing_digest = hashlib.sha256(signed_attrs_der).digest()
    _cms_log.debug("[CMS] -- Digital Signature Process / Response (RSA-PSS-SHA256) --")
    _cms_log.debug(
        "[CMS]   Input  : DER(SignedAttributes SET) = %d bytes", len(signed_attrs_der)
    )
    _cms_log.debug(
        "[CMS]   Step 1 : SHA-256(DER) = %s...%s",
        signing_digest.hex()[:16], signing_digest.hex()[-8:],
    )
    _cms_log.debug("[CMS]   Step 2 : RSA-PSS-SHA256.sign(digest, webapp_private_key)")
    signature = signer_key.sign(signing_digest, _pss_padding(), hashes.SHA256())
    _cms_log.debug(
        "[CMS]   Output : signature = %s...%s  (%d bytes)",
        signature.hex()[:16], signature.hex()[-8:], len(signature),
    )
    _cms_log.debug("[CMS] -- Signature response selesai --")
    aes_key        = os.urandom(32)
    iv             = os.urandom(12)
    encrypted_body = AESGCM(aes_key).encrypt(iv, body, None)
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