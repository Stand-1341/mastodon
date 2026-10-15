# PostgreSQL TLS certificate configuration

Rails and streaming continue to require TLS by default for TCP database
connections. The production default is **not** changed to `verify-full`: doing so
without provisioning a trusted CA could break existing deployments. Conventional
RSA/ECDSA certificates and existing public-CA deployments remain supported; no
post-quantum signing certificate is required.

## Private CA / verified database connections

Mount a readable PEM CA certificate or CA bundle into **each** Rails/Sidekiq and
streaming container, then configure:

```dotenv
DB_SSLMODE=verify-full
DB_SSLROOTCERT=/run/certs/postgres-ca.pem
DB_HOST=database.example.internal
```

The server certificate must be issued by a trusted CA and its subject alternative
name must match `DB_HOST` (or the hostname in `DATABASE_URL`). Use the database CA,
not an unrelated web-server certificate. Paths are resolved inside the process's
container, not on the Docker host. Relative paths use its working directory.
Setting `DB_SSLROOTCERT` is optional; leaving it unset preserves each client's
existing trust-store behavior. It does not disable certificate verification in
streaming.

`DB_SSLROOTCERT` becomes libpq's `sslrootcert` path in Rails (including replicas)
and the file's PEM contents become Node's `ssl.ca` in streaming. Streaming also
keeps URL-provided `sslrootcert`, `sslcert`, and `sslkey` material when an explicit
`DB_SSLMODE=require` or `verify-full` overrides the URL's mode, including a URL
that explicitly says `sslmode=disable`.

For example, percent-encode certificate paths in a connection URL (use `%20`
for spaces, not `+`, since Active Record treats `+` literally):

```dotenv
DATABASE_URL=postgresql://mastodon@database.example.internal/mastodon?sslmode=verify-full&sslrootcert=%2Frun%2Fcerts%2Fpostgres-ca.pem
```

Client certificates (`sslcert` / `sslkey`) are optional and only needed if the
PostgreSQL server requires mutual TLS. These URL options are preserved, not
replaced when applying the streaming TLS policy.

Explicit missing, unreadable, empty-path, empty-file, or directory CA paths fail during
configuration with the variable name/path; they do not downgrade to an
unverified connection. Rails also preflights file paths in `DATABASE_URL`,
`PRIMARY_DATABASE_URL`, and `REPLICA_DATABASE_URL`, because libpq `require` can
otherwise ignore a missing CA. Certificate validity, issuer trust, and hostname
matching are checked at connection time. Rails leaves libpq's special URL
`sslrootcert=system` value to libpq (support depends on its version).

### Client semantics and precedence

- **Rails/libpq:** `require` requires encryption. With a root CA configured it
  also verifies the issuer, but it does **not** verify the hostname. Select
  `verify-full` for issuer **and** hostname verification. Existing libpq modes
  (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`) remain
  available. `allow` and `prefer` can use plaintext; they are not safe production
  hardening modes.
- **Streaming/Node:** `require` and `verify-full` both keep strict certificate
  and hostname verification (`rejectUnauthorized: true` plus Node's standard
  hostname checker). The legacy `allow`, `prefer`, and `verify-ca` mode names
  retain this same stronger behavior; streaming does not implement libpq's
  plaintext fallback or hostname opt-out. This policy also applies to URL modes;
  `uselibpqcompat=true` does not implicitly weaken verification.
- **Streaming precedence:** `DB_SSLMODE` overrides the URL mode, and
  `DB_SSLROOTCERT` overrides the URL CA without removing URL client certificates.
- **Rails precedence:** Active Record's existing URL merge rules are unchanged;
  explicitly supplied URL options take precedence over matching YAML/environment
  options. Avoid conflicting TLS options between the URL and `DB_*` variables.
  Named primary/replica URLs follow Active Record's existing rules.
- Unknown modes fail instead of silently selecting another verification policy.
  Explicit CA paths are checked even when TLS is disabled, so a bad path cannot
  become a latent trust configuration error.

## Local development and unsafe compatibility

The `.devcontainer` PostgreSQL service provisions a conventional local CA and
`db` hostname certificate in persistent Docker volumes. Rails and streaming use
`DB_SSLMODE=verify-full`; only the CA certificate is mounted read-only into the
app container. This is for local TLS behavior and does not provide PQC TLS.
The root production `docker-compose.yml` database still has no TLS configured;
provision server-side TLS before using the production defaults. Other local
PostgreSQL services without TLS may use `DB_SSLMODE=disable` in their local
environment only. Streaming retains its explicit empty `DB_SSLMODE` plaintext
opt-out. Rails rejects an empty mode; use `disable`.

**`DB_SSLMODE=no-verify` is unsafe, streaming-only compatibility.** It encrypts
traffic but disables certificate/hostname authentication, making the connection
vulnerable to an active man-in-the-middle attack. The equivalent explicit URL
`sslmode=no-verify` / `ssl=no-verify` remains available in streaming. Do not use
these settings as a fix for a missing CA or hostname mismatch. Rails/libpq does
not support the `no-verify` mode name.

## Validation and post-quantum scope

### Local PostgreSQL hybrid TLS

The optional `.devcontainer` `pqc-edge` service has a Docker health check that
performs a verified TLS 1.3 handshake against its own Nginx listener while
forcing `X25519MLKEM768`. It checks the generated certificate and hostname as
well as the negotiated group. Inspect it with:

```sh
docker compose --profile pqc ps pqc-edge
docker compose --profile pqc exec pqc-edge /usr/local/bin/verify-pqc-edge.sh
```

The optional local edge permits only TLS 1.3 and `X25519MLKEM768`; clients
without hybrid-group support will fail to connect. Its certificate still uses
conventional RSA authentication.

The `.devcontainer` primary `db` service now runs PostgreSQL 18 and forces
`ssl_groups=X25519MLKEM768`; its HBA rules reject unencrypted TCP connections,
and TLS connections fail if the client cannot negotiate that hybrid group. It
uses `DB_SSLMODE=verify-full`. A local RSA CA and server
certificate authenticate the `db` hostname; the CA and server private key stay
in separate Docker volumes, and the app receives only the CA certificate.
PostgreSQL data uses a separate volume. The previous PostgreSQL 14 data volume
is retained by the opt-in `db-legacy` service under the `legacy-db` profile.

### Production Compose PostgreSQL hybrid TLS overlay

The root `docker-compose.yml` stays compatible with its existing PostgreSQL 14
data. For a planned migration, `docker-compose.pqc.yml` provides an explicit
PostgreSQL 18 overlay. It uses a separate `./postgres18-pqc` data directory,
requires externally provisioned `./secrets/postgres-tls/ca.crt`, `server.crt`,
and `server.key`, plus `./secrets/postgres-superuser-password`. Generate and
protect the superuser secret before starting the overlay:

```sh
mkdir -p ./secrets
openssl rand -hex 32 | tr -d '\n' > ./secrets/postgres-superuser-password
chmod 600 ./secrets/postgres-superuser-password
```

Keep a secure backup of this secret; it is needed to administer the restored
database. The secret file is excluded from Git and mounted into PostgreSQL as a
Docker secret. The overlay requires SCRAM password authentication for TCP
connections, in addition to TLS. It refuses to start if the certificate chain,
`db` hostname, or certificate/private-key match is invalid. The server enforces
only `X25519MLKEM768`, and dedicated `pg_hba.conf` rules reject plaintext TCP
connections. Web, streaming, and Sidekiq use `DB_HOST=db`,
`DB_SSLMODE=verify-full`, and the mounted CA.

Do not point PostgreSQL 18 at `./postgres14` or start this overlay on an
unmigrated production database. Use a maintenance window and perform a logical
dump/restore into the new directory. First synchronize the existing Mastodon
database role password with `DB_PASS` in `.env.production` and store SCRAM
hashes, then set the `postgres` role password to the exact superuser secret.
The overlay builds the fork's Rails and streaming images from this checkout,
replacing the upstream images selected in the base Compose file. Build all
images and validate the merged configuration before the maintenance window:

```sh
docker compose -f docker-compose.yml -f docker-compose.pqc.yml config -q
docker compose -f docker-compose.yml -f docker-compose.pqc.yml build db web streaming
```

Use a password prompt so plaintext passwords are not written into shell history
or SQL logs:

```sh
docker compose stop web streaming sidekiq
docker compose exec -it db psql -U postgres -d postgres
```

In that `psql` session:

```sql
SET password_encryption = 'scram-sha-256';
\password mastodon
\password postgres
```

For `mastodon`, enter the existing `DB_PASS` value. For `postgres`, enter the
value from `./secrets/postgres-superuser-password`. Exit `psql`, then dump and
restore:

```sh
docker compose exec -T db pg_dumpall -U postgres > ./postgres14-pre-pqc.sql
test -s ./postgres14-pre-pqc.sql
docker compose stop db
docker compose -f docker-compose.yml -f docker-compose.pqc.yml up -d db
docker compose -f docker-compose.yml -f docker-compose.pqc.yml exec -T db \
  psql -U postgres -d postgres -v ON_ERROR_STOP=1 < ./postgres14-pre-pqc.sql
docker compose -f docker-compose.yml -f docker-compose.pqc.yml exec -T db \
  psql -U postgres -d postgres -c 'SELECT datname FROM pg_database ORDER BY datname'
```

`pg_dumpall` includes role password hashes and all databases. Store the dump on
protected storage and delete it securely after the restored backup is verified.
Treat it and the superuser secret as credentials. The dump path and secret are
gitignored. Keep `./postgres14` untouched during validation.
Only after checking the restored roles, schema, and data, start web, streaming,
and Sidekiq with the overlay. Set ActivityPub signing and messaging feature
flags explicitly in `.env.production`; building these fork images does not
enable them. Rolling back after the PostgreSQL 18 instance has
accepted writes requires another data migration; simply starting PostgreSQL 14
would lose those writes.

A `PQC_REQUIRE_HYBRID_DB_TLS` startup guard checks
the Rails and streaming database configurations and rejects conflicting DB URL
hosts or TLS options. Keep the CA certificate public;
protect the server private key as a deployment secret. The entrypoint copies
the key into a private volume with PostgreSQL-required ownership and mode.

The merged configuration can be checked independently:

```sh
docker compose -f docker-compose.yml -f docker-compose.pqc.yml config -q
```

After restoring data, start web, streaming, and Sidekiq with the same two-file
Compose command and confirm the database TLS group on live connections. The
certificate remains conventionally signed; the post-quantum property here is
hybrid key exchange.

The streaming TLS configuration guard can be exercised with:

```sh
docker compose -f docker-compose.yml -f docker-compose.pqc.yml exec -T streaming node streaming/test/db-hybrid-config.mjs
```

Check the actual app connection:

```sh
docker compose exec -T app bin/rails runner 'p ActiveRecord::Base.connection.select_one("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")'
```

This must report `ssl: true` and `TLSv1.3`. Since the server allows only the
hybrid group, a successful verified Rails connection also confirms libpq
negotiated it. Independently force and display the group from the app container:

```sh
docker compose exec -T app openssl s_client -brief -starttls postgres \
  -connect db:5432 -groups X25519MLKEM768 \
  -CAfile /run/pqc-postgres-tls/ca.crt -verify_hostname db -verify_return_error
```

The handshake must show `Negotiated TLS1.3 group: X25519MLKEM768`,
`Verification: OK`, and `Verified peername: db`. The live local deployment was
verified with PostgreSQL 18.6 and OpenSSL 3.5.9. The existing PostgreSQL 14
data was dumped, restored into the new volume, and checked through Rails; the
development database retained its account records and all 639 migration rows.

Verify Node streaming's `pg` client against the same hybrid-only server with:

```sh
docker compose exec -T app node streaming/test/db-hybrid-postgres.mjs
```

The check requires TLS 1.3 and `ssl_groups=X25519MLKEM768` and reports the
negotiated TLS version and cipher. It uses the same CA and `verify-full` policy
as the running streaming service.

For rollback, stop the app, start `db-legacy` with
`docker compose --profile legacy-db up -d db-legacy`, then set `DB_HOST=db-legacy`
and `DB_SSLROOTCERT=/run/postgres-tls/ca.crt` in the Compose environment and
recreate the app. The old PostgreSQL 14 volume is kept intact. Do not attach a
PostgreSQL 14 data directory to PostgreSQL 18; use a logical dump/restore when
migrating another existing installation.

Run the streaming suite in the existing app container:

```sh
docker compose exec -T app node test/streaming/db-tls-default.mjs
```

It generates a temporary conventional RSA certificate and tests TLS options and
real, finite-time **loopback** handshakes, including trusted success, untrusted
rejection, and hostname-mismatch rejection. It cleans up sockets and temporary
certificate/key files. It requires the existing `openssl` executable, not a new
Node dependency. It does not connect to PostgreSQL or verify a public endpoint.

The Rails regression suite is `spec/lib/pqc_db_ssl_defaults_spec.rb`. Use
`RAILS_ENV=test`, `DB_NAME=mastodon_local_validation` (Rails adds `_test`), and
isolated Redis database 15 when running it in the local container.

Hybrid key exchange and certificate signing are separate concerns: the local
PostgreSQL connection negotiates `X25519MLKEM768` while authenticating the
server with a conventional RSA certificate. This verifies the local Rails/libpq
path. It does not prove hybrid negotiation for Node streaming or a production
database deployment. The production `docker-compose.yml` and public CA/TLS
deployment still need their own configuration and endpoint tests; ML-DSA
signing does not require replacing public web certificates.
