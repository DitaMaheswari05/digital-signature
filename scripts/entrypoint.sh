#!/bin/sh
set -e

SRC_DIR=/etc/pki/key_cert       # read-only, hasil mount volume
OUT_DIR=/etc/pki/runtime        # writable, di-generate tiap start container

mkdir -p "$OUT_DIR"

split_pem() {
    # $1 = nama file sumber, $2 = nama basis output
    openssl x509 -in "$SRC_DIR/$1" -out "$OUT_DIR/$2.crt"
    openssl pkey -in "$SRC_DIR/$1" -out "$OUT_DIR/$2.key" 2>/dev/null \
        || openssl rsa -in "$SRC_DIR/$1" -out "$OUT_DIR/$2.key"
}

split_pem rootca.pem                 rootca
split_pem clientca_rootca_.pem       clientca
split_pem clientcert_clientca_.pem   clientcert
split_pem serverca_rootca_.pem       serverca
split_pem servercert_serverca_.pem   servercert
split_pem webca_rootca_.pem          webca
split_pem webappcert_webca_.pem      webappcert

# Bundle trust anchor: Sub-CA + RootCA (dipakai directive ssl_client_certificate / ssl_trusted_certificate)
cat "$OUT_DIR/clientca.crt" "$OUT_DIR/rootca.crt" > "$OUT_DIR/client-ca-bundle.crt"
cat "$OUT_DIR/serverca.crt" "$OUT_DIR/rootca.crt" > "$OUT_DIR/server-ca-bundle.crt"
cat "$OUT_DIR/webca.crt"    "$OUT_DIR/rootca.crt" > "$OUT_DIR/webapp-ca-bundle.crt"

# Fullchain leaf cert (leaf + sub-CA) buat ssl_certificate, biar peer bisa validasi chain lengkap
cat "$OUT_DIR/clientcert.crt" "$OUT_DIR/clientca.crt" > "$OUT_DIR/client-fullchain.crt"
cat "$OUT_DIR/servercert.crt" "$OUT_DIR/serverca.crt" > "$OUT_DIR/server-fullchain.crt"
cat "$OUT_DIR/webappcert.crt" "$OUT_DIR/webca.crt"    > "$OUT_DIR/webapp-fullchain.crt"

exec "$@"