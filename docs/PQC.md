# Post-quantum readiness and experimental signing

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

For PostgreSQL CA configuration and certificate-verification semantics in Rails
and streaming, see [PQC_TLS.md](PQC_TLS.md). Conventional public web certificates
remain unchanged. Hybrid key exchange does not make their signatures
post-quantum-resistant.

## Phase 2: experimental additive ActivityPub signing

### Security and compatibility boundary

`PQC_ACTIVITYPUB_SIGNING` is **disabled by default**. Only the literal value
`true` enables it. Enabling it does not generate keys or replace account keys.
Accounts without an explicitly provisioned, usable ML-DSA-44 key continue to use
RSA. Account creation and HTTP federation authentication remain RSA-compatible.

For provisioned accounts, the normal object-signing path adds a
`mldsa44-jcs-2024` Object Integrity Proof, then signs the entire resulting document
with the existing `RsaSignature2017` implementation. RSA HTTP signatures and the
legacy actor `publicKey` remain intact. Existing authorized-fetch signing rules
are respected. The native OpenSSL implementation and the upstream JCS verifier
are reused; no alternate cryptographic library or custom algorithm is introduced.

This is **additive compatibility**, not a policy requiring every federation peer
to verify a post-quantum signature. RSA-only authentication is still accepted,
and non-provisioned/expired/revoked-key accounts remain RSA-only. Do not describe
this mode as downgrade-resistant, post-quantum-only federation or end-to-end
encryption. Peer compatibility, especially older relay implementations, must be
validated before broad rollout. Keep the flag off outside controlled tests until
those tests pass.

### Provision one account explicitly

Back up the database and existing Active Record Encryption secrets first. Run in
an OpenSSL 3.5+ runtime whose provider supports ML-DSA-44 generation, export and
signing:

```sh
bin/rails 'pqc:generate_key[alice]'
```

For the local Docker setup, replace `alice` with the chosen local username:

```sh
docker compose exec -T app bin/rails 'pqc:generate_key[alice]'
```

The operation locks that account and is idempotent: repeated calls reuse its
oldest usable ML-DSA-44 key. It never changes RSA/legacy key material, provisions
remote accounts, deletes older keys, or prints private keys. Private material is
stored with the existing `Keypair` Active Record Encryption. RSA rotation now
preserves keys of other algorithms. No bulk migration is run.

The actor publishes usable ML-DSA public keys as embedded `Multikey` entries in
`assertionMethod`, alongside the unchanged RSA `publicKey`. Stable key fragments,
controller URIs and optional expiration timestamps are persisted/published. Key
publication remains available even when outbound signing is disabled so queued
proofs can still be verified. Newly added keys can be discovered despite a fresh
profile cache. On authoritative actor refresh, missing, malformed or revoked
keys lose their authorization; proof verification refreshes stale remote actor
key authorization instead of trusting it indefinitely. Proof-authenticated
Updates always revalidate the signing key against the authoritative actor, even
with a fresh profile cache, so in-band Updates cannot keep a withdrawn proof key
authorized indefinitely. Other activities use the existing actor-staleness bound,
not instantaneous revocation propagation.

### Enable only on controlled instances

Set this in the selected deployment's environment and restart web/background
processes:

```dotenv
PQC_ACTIVITYPUB_SIGNING=true
```

For local development, the assignment belongs in the gitignored
`.env.development.local`; then run `docker compose restart app`. The local site
is still HTTP-only and is not suitable for testing public TLS or real Internet
federation.

Proofs bind the canonical document, final JSON-LD context and proof options. They
expire after two days or earlier when the signing key expires. The standard Data
Integrity v2 context is pinned locally to avoid a context download while signing.
Proof-aware compaction and forwarding preserve the checked original dual-signed
JSON rather than rewriting a JCS-signed document. Malformed proof fields are
rejected rather than retried as ingress errors.

If a provisioned usable key cannot sign, delivery raises an actionable error;
it does not silently fall back to RSA after an OpenSSL/provider failure.
Check the linked runtime and key custody, or explicitly turn off the feature.

### Validation and rollback

Before enabling outside test instances:

1. Test a Create, Update, Delete, reply and boost between two controlled HTTPS
   instances, including relay/forwarding paths.
2. Verify that both signatures independently validate, and tampered content,
   context, proof values, expired proofs and unauthorized keys are rejected.
3. Test RSA-only receiving/relaying peers, authorized-fetch mode, queued updates
   signed with an old RSA key, and RSA rotation without PQC key loss.
4. Test key publication/discovery, expiration, revocation refresh, missing
   providers, worker retries, and database/key backup restoration.
5. Confirm hybrid key exchange at the actual public endpoint separately.

Repository regression coverage includes native ML-DSA signing and the upstream
W3C verification vector, dual-signature receive/forwarding, serializer integration,
public-key encoding, lifecycle refresh, provisioning and RSA rotation. Native tests
skip explicitly only when the provider lacks ML-DSA support; a skipped test is not
evidence of post-quantum capability. Tests must use a separate Rails test database
and Redis logical database, never the running instance's data.

Rollback by setting `PQC_ACTIVITYPUB_SIGNING=false` and restarting the processes.
Do not delete keys, change the account domain, regenerate account/encryption
secrets, or rewrite queued signed payloads. Keep public verification keys and the
matching encrypted private-key backups.

## Deferred: private-media encryption and encrypted messaging

Existing media and direct messages are **not changed or claimed to be encrypted**
by this work. Implementing those safely requires separate feature designs:

- Private media: separate storage/authorization, AES-256-GCM envelope encryption
  with one random data key per object and a real KMS; processing, thumbnails,
  authenticated retrieval, CDN caching, federation access and backup recovery
  must all be covered. Never encrypt public media indiscriminately or treat
  ML-KEM as a file-encryption cipher.
- Messaging: an independent opt-in E2EE protocol and client experience with
  authenticated hybrid key establishment, device keys, an established ratchet,
  recovery and downgrade resistance. Do not convert existing restricted-visibility
  ActivityPub posts or call ordinary Mastodon DMs end-to-end encrypted.

These are substantial security products, not extra configuration switches.
