#!/bin/sh
set -eu

private_dir=/var/lib/postgresql/tls-private
public_dir=/var/lib/postgresql/tls-public
tls_hostname=${PG_TLS_HOSTNAME:-db}
mkdir -p "$private_dir" "$public_dir"

if [ ! -s "$private_dir/ca.key" ] || [ ! -s "$private_dir/server.key" ] || \
  [ ! -s "$private_dir/server.crt" ] || ! openssl x509 -in "$private_dir/server.crt" -noout -checkhost "$tls_hostname" >/dev/null 2>&1; then
  umask 077
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$private_dir/ca.key"
  openssl req -x509 -new -sha256 -days 3650 -key "$private_dir/ca.key" \
    -subj '/CN=Mastodon local PostgreSQL development CA' -out "$private_dir/ca.crt"

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$private_dir/server.key"
  openssl req -new -sha256 -key "$private_dir/server.key" \
    -subj "/CN=$tls_hostname" -out "$private_dir/server.csr"
  printf '%s\n' \
    "subjectAltName=DNS:$tls_hostname" \
    'keyUsage=digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' > "$private_dir/server.ext"
  openssl x509 -req -sha256 -days 825 -in "$private_dir/server.csr" \
    -CA "$private_dir/ca.crt" -CAkey "$private_dir/ca.key" \
    -CAcreateserial -extfile "$private_dir/server.ext" \
    -out "$private_dir/server.crt"
  rm -f "$private_dir/server.csr" "$private_dir/server.ext" "$private_dir/ca.srl"
fi

chown -R postgres:postgres "$private_dir"
chmod 700 "$private_dir"
chmod 600 "$private_dir/ca.key" "$private_dir/server.key"
chmod 644 "$private_dir/ca.crt" "$private_dir/server.crt"
install -m 0644 -o root -g root "$private_dir/ca.crt" "$public_dir/ca.crt"

exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$private_dir/server.crt" \
  -c ssl_key_file="$private_dir/server.key"
