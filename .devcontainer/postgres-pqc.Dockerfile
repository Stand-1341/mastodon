FROM postgres:18-alpine

RUN apk add --no-cache openssl

COPY postgres-pqc-hba.conf /etc/postgresql/pg_hba_hybrid.conf
