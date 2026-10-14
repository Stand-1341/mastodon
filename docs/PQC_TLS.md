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

Keep `DB_SSLMODE=disable` for the existing isolated local PostgreSQL service that
has no TLS configured. Nothing here provisions PostgreSQL server-side TLS or
changes the local Compose opt-out. Streaming also retains its explicit empty
`DB_SSLMODE` plaintext opt-out. Rails rejects an empty mode; use `disable`.

**`DB_SSLMODE=no-verify` is unsafe, streaming-only compatibility.** It encrypts
traffic but disables certificate/hostname authentication, making the connection
vulnerable to an active man-in-the-middle attack. The equivalent explicit URL
`sslmode=no-verify` / `ssl=no-verify` remains available in streaming. Do not use
these settings as a fix for a missing CA or hostname mismatch. Rails/libpq does
not support the `no-verify` mode name.

## Validation and post-quantum scope

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

Hybrid key exchange and certificate signing are separate concerns: an
`X25519MLKEM768` handshake may authenticate with a conventional RSA/ECDSA
certificate. OpenSSL 3.5 runtime capabilities do not prove PostgreSQL or Node
negotiated that group, and ML-DSA signing support does not require replacing
public web certificates. This configuration makes no claim of public endpoint
verification or negotiated hybrid PostgreSQL TLS. It does not change nginx,
startup configuration, or the local HTTP-only topology.
