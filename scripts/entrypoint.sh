set -e

SRC_DIR=/etc/pki/key_cert
OUT_DIR=/etc/pki/runtime

mkdir -p "$OUT_DIR"

extract_key() {
    local SRC="$SRC_DIR/$1"
    local DST="$OUT_DIR/$2.key"
    openssl pkey -in "$SRC" -out "$DST" 2>/dev/null \
        || openssl rsa -in "$SRC" -out "$DST" 2>/dev/null
}

extract_nth_cert() {
    local SRC="$SRC_DIR/$1"
    local DST="$OUT_DIR/$2.crt"
    local N="${3:-1}"
    awk -v n="$N" '
        /-----BEGIN CERTIFICATE-----/ { count++; if (count==n) { print; in_block=1; next } }
        in_block { print; if (/-----END CERTIFICATE-----/) { in_block=0 } }
    ' "$SRC" > "$DST"
}

extract_all_certs() {
    local SRC="$SRC_DIR/$1"
    local DST="$OUT_DIR/$2.crt"
    awk '
        /-----BEGIN CERTIFICATE-----/ { in_block=1; print; next }
        in_block { print; if (/-----END CERTIFICATE-----/) { in_block=0 } }
    ' "$SRC" > "$DST"
}

echo "Mengekstrak sertifikat dari bundle PEM..."

extract_key servercert_serverca_.pem servercert

extract_all_certs servercert_serverca_.pem server-fullchain

extract_nth_cert  servercert_serverca_.pem servercert 1

extract_nth_cert  rootca.pem rootca 1

extract_nth_cert  clientca_rootca_.pem clientca 1

cat "$OUT_DIR/clientca.crt" "$OUT_DIR/rootca.crt" > "$OUT_DIR/client-ca-bundle.crt"

echo "=== File dihasilkan di $OUT_DIR ==="
ls -la "$OUT_DIR/"

echo ""
echo "Verifikasi key <-> cert match:"
KEY_MOD=$(openssl rsa -in "$OUT_DIR/servercert.key" -noout -modulus 2>/dev/null | md5sum 2>/dev/null || echo "err")
CRT_MOD=$(openssl x509 -in "$OUT_DIR/servercert.crt" -noout -modulus 2>/dev/null | md5sum 2>/dev/null || echo "err2")
if [ "$KEY_MOD" = "$CRT_MOD" ]; then
    echo "  OK: servercert.key dan servercert.crt cocok"
else
    echo "  WARNING: key/cert mismatch (mungkin format berbeda)"
fi