
SRC_DIR=/etc/pki/key_cert
OUT_DIR=/etc/pki/runtime

mkdir -p "$OUT_DIR"

echo "Menyiapkan sertifikat runtime dari $SRC_DIR ..."

cp "$SRC_DIR/servercert.key" "$OUT_DIR/servercert.key"
chmod 640 "$OUT_DIR/servercert.key"

cat "$SRC_DIR/servercert.crt" "$SRC_DIR/serverca.crt" \
  > "$OUT_DIR/server-fullchain.crt"

cat "$SRC_DIR/clientca.crt" "$SRC_DIR/rootca.crt" \
  > "$OUT_DIR/client-ca-bundle.crt"

echo "=== File dihasilkan di $OUT_DIR ==="
ls -la "$OUT_DIR/"

echo ""
echo "Verifikasi key <-> cert match:"
KEY_MOD=$(openssl rsa -in "$OUT_DIR/servercert.key" -noout -modulus 2>/dev/null | md5sum 2>/dev/null || echo "err")
CRT_MOD=$(openssl x509 -in "$SRC_DIR/servercert.crt" -noout -modulus 2>/dev/null | md5sum 2>/dev/null || echo "err2")
if [ "$KEY_MOD" = "$CRT_MOD" ]; then
    echo "  OK: servercert.key dan servercert.crt cocok"
else
    echo "  WARNING: key/cert mismatch â€” cek apakah servercert.key sesuai dengan servercert.crt"
fi

echo ""
echo "Verifikasi client-ca-bundle:"
openssl verify -CAfile "$OUT_DIR/client-ca-bundle.crt" \
               "$SRC_DIR/clientcert.crt" 2>/dev/null \
    && echo "  OK: clientcert.crt valid terhadap client-ca-bundle.crt" \
    || echo "  INFO: clientcert.crt tidak terverifikasi CA bundle (nginx pakai optional_no_ca)"