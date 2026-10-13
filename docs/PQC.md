# PQC Phase 0 and 1 deployment notes

## Phase 0: inventory and at-rest hardening

### Inventory

Run `bin/rails pqc:inventory` in the deployed Mastodon runtime. The task writes one JSON object to stdout and does not print encryption-key values or connect to the database. Optional operator-supplied fields are:

- `PQC_AR_ENCRYPTION_CUSTODY_POINTER`: a non-secret reference to the secret-manager entry and protected-backup/escrow record for the Active Record Encryption keys. Never put key material in this variable.
- `PQC_BACKUP_AGE`: age of the latest successful backup, such as `6h` or `3d`.

The deployed SHA comes from the image's `SOURCE_COMMIT` value. It is `null` when the image was not built with that value; the task does not substitute the SHA of a source checkout for deployed evidence. The Ruby/OpenSSL versions are those of the running Rails process, not the Nginx TLS terminator.

### TOTP secret migration

`devise-two-factor` declares `encrypts :otp_secret` for `User`; TOTP verification continues through Devise's existing accessor. The post-deployment migration `EncryptUserOtpSecrets` rewrites every non-null `users.otp_secret` through Active Record Encryption, including rows already encrypted. It temporarily enables legacy plaintext reads only in the migration process, restores that setting afterward, and is irreversible. There is no schema change and no OTP reset.

Run `bin/rails db:migrate` with the existing Active Record Encryption keys configured and unchanged. Ensure this migration completes before new application processes serve users with legacy plaintext secrets. Do not regenerate or rotate encryption keys to perform the migration; retain tested key custody and backup/restore procedures.

### PostgreSQL TLS

`config/database.yml` now defaults `DB_SSLMODE` to `require`, and the streaming server also defaults its PostgreSQL connection to TLS. PostgreSQL TLS must therefore be enabled for TCP-connected production databases. `require` encrypts the Rails connection but does not authenticate the server certificate or hostname; where the deployment has CA and hostname configuration, prefer a verified mode such as `verify-full`.

The development container, Vagrant environment, and CI PostgreSQL services explicitly set `DB_SSLMODE=disable` because their local/test PostgreSQL instances do not configure TLS. For other local development databases without TLS, set `DB_SSLMODE=disable` in that local environment only. Do not carry that opt-out into a production deployment. The root `docker-compose.yml` includes a PostgreSQL service without TLS configuration; deployments using that service over TCP must provision PostgreSQL TLS before using the new default.

## Phase 1: hybrid TLS at the edge

The sample `dist/nginx.conf` configures TLS groups as `X25519MLKEM768:X25519:P-256:P-384`: the standardized hybrid group is preferred while classical groups remain available for older clients and federation peers. This is a TLS 1.3 key-exchange change at the TLS terminator. It does not change Mastodon application code, ActivityPub signatures, certificate signatures, stored content, or DM confidentiality.

The Nginx process must be built and linked at runtime against OpenSSL 3.5 or newer. The repository does not ship an Nginx container, so the sample does not establish that any separately deployed Nginx/CDN/ingress supports the group. Inspect the actual terminator with `nginx -V`, `ldd "$(command -v nginx)"`, `openssl version -a`, and `openssl list -tls1_3 -tls-groups`. Then run `nginx -t` and test the public endpoint using the command commented beside the directive in `dist/nginx.conf`; its output should identify `X25519MLKEM768` as the negotiated group.

For container base images, Debian 13/Trixie supplies OpenSSL 3.5 (the current `openssl` package is listed at [packages.debian.org/trixie/openssl](https://packages.debian.org/trixie/openssl)). The repository's app and streaming Dockerfiles select `ruby:4.0.7-slim-trixie` and `node:24-trixie-slim`, respectively, so Trixie is the supported base-image family to use when OpenSSL 3.5 is required. Those images are not the public Nginx terminator; an Nginx image must independently use the Trixie OpenSSL 3.5 library, and its actual linkage must be checked. Do not infer support from an image tag alone, from Ruby's OpenSSL gem version, or from an unrelated `openssl` executable on the host.

The explicit group list can make Nginx fail to load on an older OpenSSL build that does not recognize `X25519MLKEM768`. Validate the exact binary and runtime library before rollout, and monitor handshake failures while retaining the classical fallback groups.
