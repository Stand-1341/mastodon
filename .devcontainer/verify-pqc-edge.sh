#!/bin/sh
set -eu

output=$(openssl s_client -brief \
  -connect 127.0.0.1:443 \
  -servername localhost \
  -groups X25519MLKEM768 \
  -CAfile /etc/nginx/tls/server.crt \
  -verify_hostname localhost \
  -verify_return_error </dev/null 2>&1) || {
  printf '%s\n' "$output"
  exit 1
}

printf '%s\n' "$output" | grep -Fq 'Verification: OK'
printf '%s\n' "$output" | grep -Fq 'Verified peername: localhost'
printf '%s\n' "$output" | grep -Fq 'Negotiated TLS1.3 group: X25519MLKEM768'
