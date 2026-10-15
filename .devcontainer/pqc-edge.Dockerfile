FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends nginx openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY pqc-edge.conf /etc/nginx/conf.d/default.conf
COPY pqc-edge-entrypoint.sh /usr/local/bin/pqc-edge-entrypoint.sh
COPY verify-pqc-edge.sh /usr/local/bin/verify-pqc-edge.sh
RUN chmod 0755 /usr/local/bin/pqc-edge-entrypoint.sh /usr/local/bin/verify-pqc-edge.sh

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/pqc-edge-entrypoint.sh"]
