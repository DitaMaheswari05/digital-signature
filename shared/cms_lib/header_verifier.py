import base64
import hashlib
import logging
from typing import Optional, Tuple
from asn1crypto import core as asn1_core
_log = logging.getLogger("cms_lib.header_verifier")
from .canonical import canonical_headers, IGNORED_HEADERS

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


def _parse_signed_attributes(signed_attrs_der: bytes) -> dict:
    result: dict = {}
    raw = signed_attrs_der
    if len(raw) < 2:
        return result
    if raw[0] != 0x31:
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
        name = seq_body[j: j + name_len].decode("utf-8")
        j += name_len
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

def verify_cms_headers(
    request_headers: dict,
    cms_b64: str,
    *,
    context: str = "",
) -> Tuple[bool, str]:
    ctx = f"[{context}] " if context else ""
    try:
        cms_der = base64.b64decode(cms_b64)
    except Exception as exc:
        msg = f"{ctx}Gagal decode base64 CMS: {exc}"
        _log.warning(msg)
        return False, msg
    try:
        pkg              = _CMSPackageSeq.load(cms_der)
        signed_attrs_der = bytes(pkg["signer_info"]["signed_attributes"].native)
    except Exception as exc:
        msg = f"{ctx}Gagal parse CMS package: {exc}"
        _log.warning(msg)
        return False, msg
    try:
        sig_attrs = _parse_signed_attributes(signed_attrs_der)
    except Exception as exc:
        msg = f"{ctx}Gagal parse signed_attributes: {exc}"
        _log.warning(msg)
        return False, msg
    embedded_digest: Optional[bytes] = sig_attrs.get("headers-digest")  
    if embedded_digest is None:
        _log.debug("%sHeaders-digest tidak ditemukan di signed_attributes — skip verifikasi.", ctx)
        return True, "no-headers-digest"
    if not isinstance(embedded_digest, bytes):
        msg = f"{ctx}headers-digest bukan bytes: {type(embedded_digest)}"
        _log.warning(msg)
        return False, msg
    try:
        canonical = canonical_headers(dict(request_headers))
    except Exception as exc:
        msg = f"{ctx}Gagal bangun canonical headers: {exc}"
        _log.warning(msg)
        return False, msg
    actual_digest = hashlib.sha256(canonical).digest()
    _log.debug(
        "%sHeaders-digest check — embedded=%s... actual=%s...",
        ctx,
        embedded_digest.hex()[:16],
        actual_digest.hex()[:16],
    )
    if actual_digest != embedded_digest:
        msg = (
            f"{ctx}Header digest TIDAK COCOK — "
            f"embedded={embedded_digest.hex()[:32]}... "
            f"actual={actual_digest.hex()[:32]}... "
            "Kemungkinan header dimanipulasi setelah signing."
        )
        _log.warning(msg)
        return False, msg
    _log.debug("%sHeader digest verified OK.", ctx)
    return True, "ok"
