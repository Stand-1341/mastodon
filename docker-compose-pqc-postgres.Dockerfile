FROM postgres:18-alpine

RUN apk add --no-cache openssl

COPY docker/postgres-pqc-production-entrypoint.sh /usr/local/bin/postgres-pqc-production-entrypoint.sh
COPY docker/postgres-pqc-hba.conf /etc/postgresql/pg_hba_hybrid.conf
RUN chmod 0755 /usr/local/bin/postgres-pqc-production-entrypoint.sh \
  && chmod 0644 /etc/postgresql/pg_hba_hybrid.conf

ENTRYPOINT ["/usr/local/bin/postgres-pqc-production-entrypoint.sh"]
