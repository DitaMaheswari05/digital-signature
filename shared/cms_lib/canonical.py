IGNORED_HEADERS = {
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "x-original-method",
    "x-original-path",
    "x-original-authority",
    "x-ssl-client-verify",
    "x-ssl-client-s-dn",
    "x-ssl-client-cert",
    "x-cms-payload",
    "x-cms-response",
}
def canonical_headers(headers: dict) -> bytes:
    import logging
    _log = logging.getLogger("cms_lib.canonical")
    included = []
    excluded = []
    for k, v in headers.items():
        key = k.lower().strip()
        if k and key not in IGNORED_HEADERS:
            included.append((key, v.strip() if isinstance(v, str) else str(v).strip()))
        else:
            excluded.append(key)
    included.sort(key=lambda kv: kv[0])
    canonical = "".join(f"{k}: {v}\n" for k, v in included)
    _log.debug("[canonical] Included headers (%d):", len(included))
    for k, v in included:
        _log.debug("[canonical]   + %-32s : %s", k, v[:60])
    _log.debug("[canonical] Excluded headers (%d): %s", len(excluded), excluded)
    return canonical.encode("utf-8")
