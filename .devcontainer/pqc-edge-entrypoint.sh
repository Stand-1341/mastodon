#!/bin/sh
set -eu

mkdir -p /etc/nginx/tls
if [ ! -s /etc/nginx/tls/server.crt ] || [ ! -s /etc/nginx/tls/server.key ]; then
  umask 077
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
    -keyout /etc/nginx/tls/server.key \
    -out /etc/nginx/tls/server.crt \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
fi

nginx -t
exec nginx -g 'daemon off;'
