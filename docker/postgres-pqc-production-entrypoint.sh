#!/bin/sh
set -eu

source_dir=${PG_TLS_SOURCE_DIR:-/run/postgres-tls-source}
private_dir=${PG_TLS_PRIVATE_DIR:-/var/lib/postgresql/tls-private}
hostname=${PG_TLS_HOSTNAME:-db}
certificate="$source_dir/server.crt"
private_key="$source_dir/server.key"
ca_certificate="$source_dir/ca.crt"

for file in "$certificate" "$private_key" "$ca_certificate"; do
  if [ ! -s "$file" ] || [ ! -r "$file" ]; then
    echo "Required readable PostgreSQL TLS file is missing or empty: $file" >&2
    exit 1
  fi
done

openssl verify -CAfile "$ca_certificate" -verify_hostname "$hostname" "$certificate" >/dev/null
certificate_public_key=$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
private_public_key=$(openssl pkey -in "$private_key" -pubout -outform DER | sha256sum)
if [ "$certificate_public_key" != "$private_public_key" ]; then
  echo 'PostgreSQL TLS certificate and private key do not match' >&2
  exit 1
fi

mkdir -p "$private_dir"
install -m 0644 -o postgres -g postgres "$certificate" "$private_dir/server.crt"
install -m 0600 -o postgres -g postgres "$private_key" "$private_dir/server.key"
chown postgres:postgres "$private_dir"
chmod 0700 "$private_dir"

exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$private_dir/server.crt" \
  -c ssl_key_file="$private_dir/server.key" \
  -c ssl_groups=X25519MLKEM768 \
  -c hba_file=/etc/postgresql/pg_hba_hybrid.conf
