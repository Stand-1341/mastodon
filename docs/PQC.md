# Post-quantum readiness and experimental signing

## Phase 0: inventory and at-rest hardening

### Inventory

Run `bin/rails pqc:inventory` in the deployed Mastodon runtime. The task writes one JSON object to stdout, reads local-account and usable ML-DSA key counts from the database, and never prints encryption-key values. Optional operator-supplied fields are:

- `PQC_AR_ENCRYPTION_CUSTODY_POINTER`: a non-secret reference to the secret-manager entry and protected-backup/escrow record for the Active Record Encryption keys. Never put key material in this variable.
- `PQC_BACKUP_AGE`: age of the latest successful backup, such as `6h` or `3d`.

The deployed SHA comes from the image's `SOURCE_COMMIT` value. It is `null` when the image was not built with that value; the task does not substitute the SHA of a source checkout for deployed evidence. The Ruby/OpenSSL versions are those of the running Rails process, not the Nginx TLS terminator.
The inventory reports live database TLS state and configured server groups,
outbound ML-DSA signing, strict inbound proof policy, and encrypted-messaging
capability flags; it never prints key material.

### TOTP secret migration

`devise-two-factor` declares `encrypts :otp_secret` for `User`; TOTP verification continues through Devise's existing accessor. The post-deployment migration `EncryptUserOtpSecrets` rewrites every non-null `users.otp_secret` through Active Record Encryption, including rows already encrypted. It temporarily enables legacy plaintext reads only in the migration process, restores that setting afterward, and is irreversible. There is no schema change and no OTP reset.

Run `bin/rails db:migrate` with the existing Active Record Encryption keys configured and unchanged. Ensure this migration completes before new application processes serve users with legacy plaintext secrets. Do not regenerate or rotate encryption keys to perform the migration; retain tested key custody and backup/restore procedures.

### PostgreSQL TLS

`config/database.yml` now defaults `DB_SSLMODE` to `require`, and the streaming server also defaults its PostgreSQL connection to TLS. PostgreSQL TLS must therefore be enabled for TCP-connected production databases. `require` encrypts the Rails connection but does not authenticate the server certificate or hostname; where the deployment has CA and hostname configuration, prefer a verified mode such as `verify-full`.

The devcontainer's primary PostgreSQL 18 service forces
`ssl_groups=X25519MLKEM768`; Rails and streaming use `DB_SSLMODE=verify-full` and
the mounted CA. The TLS key exchange is hybrid while the local server
certificate remains conventionally RSA-signed. Vagrant, CI, and other local
databases without TLS may set `DB_SSLMODE=disable` in their own development/test
environment only. Do not carry that opt-out into production. The root
`docker-compose.yml` includes a PostgreSQL service without TLS configuration;
deployments using that service over TCP must provision and verify TLS
separately.

## Phase 1: hybrid TLS at the edge

The sample `dist/nginx.conf` configures TLS groups as `X25519MLKEM768:X25519:P-256:P-384`: the standardized hybrid group is preferred while classical groups remain available for older clients and federation peers. This is a TLS 1.3 key-exchange change at the TLS terminator. It does not change Mastodon application code, ActivityPub signatures, certificate signatures, stored content, or DM confidentiality.

The Nginx process must be built and linked at runtime against OpenSSL 3.5 or newer. The optional local devcontainer profile now builds Debian Trixie's Nginx/OpenSSL stack, generates a self-signed localhost certificate, proxies to the running app, and exposes it only on `127.0.0.1:8443`. A local forced-group TLS 1.3 handshake was verified to negotiate `X25519MLKEM768`; the `/health` request through that proxy returned HTTP 200. This validates the local terminator, not a deployed public Nginx/CDN/ingress. For deployment, inspect the actual terminator with `nginx -V`, `ldd "$(command -v nginx)"`, `openssl version -a`, and `openssl list -tls1_3 -tls-groups`. Then run `nginx -t` and test the public endpoint using the command commented beside the directive in `dist/nginx.conf`; its output should identify `X25519MLKEM768` as the negotiated group.

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
Account creation
and HTTP federation authentication remain RSA-compatible. Accounts without a
usable ML-DSA-44 key continue signing with RSA only, so federation remains
available during staged per-account provisioning. The inventory reports how
many local accounts still lack a usable key; do not describe their outbound
activities as PQC-signed.

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

### Optional strict inbound policy for controlled peers

`PQC_ACTIVITYPUB_REQUIRE_PROOF=true` rejects inbound ActivityPub activities
unless their original document carries a valid `mldsa44-jcs-2024` Object Integrity Proof
whose authorized key belongs to the activity actor. It applies after HTTP
signature authentication and also rejects otherwise valid RSA Linked Data
Signatures without that proof. Leave it unset or `false` for ordinary mixed
federation; enabling it on a public instance will reject legacy peers. Use it
only where every expected sender has been provisioned and tested. This is a
local receiver policy; it does not negotiate a guarantee with remote servers.
Regardless of this flag, if an activity advertises the supported ML-DSA
cryptosuite, Mastodon verifies that proof and rejects the activity if the proof
is invalid. The default permits legacy activities that omit an ML-DSA proof.

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

For recovery evidence, take a protected database backup and preserve the exact
Active Record Encryption primary/deterministic keys and key derivation salt in
the same secret-management recovery plan. Restore both into an isolated
environment and run `bin/rails 'pqc:verify_key[alice]'` for a provisioned local
account. This decrypts the stored ML-DSA private key, signs a fresh random
challenge, and verifies it against the stored public key without printing
either key or the signature. Record
the backup identifier, restore date, application revision, and verification
result without recording secret values. A database backup without the matching
encryption secrets cannot restore usable private keys.
This recovery path was exercised locally with a disposable source PostgreSQL
database: a real ML-DSA-44 key was generated and encrypted, the database was
dumped and restored into a separate database, and `pqc:verify_key` successfully
decrypted the restored key and verified a fresh signature. The test used the
same configured Active Record Encryption secrets on both sides; it did not
export or print those secrets.

### Signing performance baseline

After provisioning an account key, run `bin/rails 'pqc:benchmark[alice,20]'`.
The task compares warmed RSA-only signing with the normal dual-signing path and
reports mean, median, p95, maximum, and the median incremental cost as JSON. It
includes key lookup, private-key decryption, JSON-LD canonicalization, and
signing, but excludes Rails boot and does not model server concurrency or full
request latency. Repeat the measurement on the target deployment hardware; do
not treat a development-container result as a production capacity estimate.

On this local development container (Ruby 4.0.7, OpenSSL 3.5.7), a 20-iteration
run on 2026-10-14 measured RSA-only median signing at 7.59 ms and
RSA-plus-ML-DSA-44 median at 15.23 ms, a 7.64 ms median increment. The observed
p95 values were 11.37 ms and 49.18 ms respectively, showing substantial run-to-
run variance in this environment. This warm signing-path measurement does not
explain browser startup or full page-load delays.

## Private media encryption

An opt-in owner-only private-media API is available separately from regular
ActivityPub attachments. It uses AES-256-GCM with a fresh 256-bit data key per
object, authenticated object/account context, and a wrapped data key. Only the
owning account can download or delete an object through the authenticated API;
downloads are `application/octet-stream` with `no-store` and `nosniff`. Objects
are limited to 32 MB. Public media, thumbnails, federation, and ordinary status
attachments are unchanged. The application server and authorized owner account
can decrypt this content, so this is at-rest encryption rather than E2EE.

The local Docker setup enables `PQC_PRIVATE_MEDIA_ENCRYPTION=true` and creates a
random development-only wrapping key in the ignored `.env.development.local`.
Local wrapping uses AES-GCM and is rejected outside development/test. Production
must set `PQC_MEDIA_KMS_KEY_ID` and provide AWS KMS credentials with
`GenerateDataKey` and `Decrypt` permissions; the request encryption context
binds each wrapped key to its object token and owner account. Do not use the
local development key in production. Persist `PQC_PRIVATE_MEDIA_ROOT` on
filesystem deployments; S3 deployments store ciphertext objects in the
configured bucket. Keep storage backups and KMS key policy/recovery procedures
with the database backup plan. A cleanup task reports untracked blobs older than
24 hours by default without deleting them; inspect the report, then pass the
explicit `delete` argument to remove confirmed orphans:

```sh
bin/rails 'pqc:cleanup_media_orphans[24,dry-run]'
bin/rails 'pqc:cleanup_media_orphans[24,delete]'
```

The task refuses ages below 24 hours and leaves every blob referenced by a
database record untouched. It supports local filesystem storage and the
configured S3 bucket.

For repeatable development/test integration, start the internal-only LocalStack
KMS service and run its verifier:

```sh
docker compose --profile pqc-kms up -d local-kms
docker compose exec -T \
  -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_REGION=us-east-1 \
  -e PQC_MEDIA_KMS_ENDPOINT=http://local-kms:4566 \
  app bin/rails pqc:verify_local_media_kms
```

The verifier is restricted to development/test and local endpoint hostnames. It
creates a temporary KMS key, exercises `GenerateDataKey` and `Decrypt`, checks
that a different owner context is rejected, then schedules the key for deletion.
The KMS SDK provider was verified against LocalStack 4.6.0 using these real API
calls. This emulator check does not verify AWS IAM policies or production key
custody. To test the configured provider before private uploads, use
`bin/rails pqc:verify_media_key` under the same environment and IAM identity as
the web/background processes; it prints only the provider name and result.

Verify the configured provider before accepting private uploads with
`bin/rails pqc:verify_media_key`. It generates and unwraps an ephemeral data key
using the configured local KEK or AWS KMS, compares the values, wipes the
in-process buffers, and prints only the provider name and result. Run it under
the same environment and IAM identity as the web/background processes.

Use an OAuth token with the `write:media` scope:

```sh
curl -H "Authorization: Bearer $TOKEN" -F file=@private.bin \
  http://localhost:3000/api/v1/private_media
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/v1/private_media/OBJECT_ID -o private.bin
```

The record is not a normal status attachment and is not shared with followers
or other recipients. The uploader's device does not perform client-side
encryption. ML-KEM is not used as a file cipher; recipient key distribution is
part of the deferred messaging design.

## Experimental MLS client prototype

Existing Mastodon direct messages remain ordinary restricted-visibility
ActivityPub posts. A separate client-side MLS primitive now demonstrates
two-device group setup and encrypted message exchange using
`MLS_256_XWING_AES256GCM_SHA512_MLDSA87` from the pinned `ts-mls` release
candidate. This suite combines X-Wing hybrid key establishment with ML-DSA-87
signatures, but its cipher-suite identifiers are experimental and the library
has not had a formal security audit.

The selected `ts-mls` suite uses private-use ID `0xf011`; it is not an IANA
assigned MLS cipher suite, so clients must use this exact private suite to
interoperate. As of 2026-10-14, the active [MLS post-quantum cipher-suite
draft](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/) has
different proposed combinations: its X-Wing hybrid suite uses ML-DSA-44,
ChaCha20-Poly1305, and SHA-384, while its ML-DSA-87 suite uses pure ML-KEM-1024,
AES-256-GCM, and SHA-384. This prototype's X-Wing/AES-256-GCM/SHA-512/ML-DSA-87
combination is not one of those draft suites. The deployment inventory reports
the private-use ID and marks cross-client interoperability unavailable; do not
claim compatibility with other MLS implementations until the suite is
standardized and an independent client passes a wire-level test.

A separate implementation in `draft_ciphersuite.ts` supports the draft's
hybrid ML-KEM-768/X25519, ChaCha20-Poly1305, SHA-384, and ML-DSA-44 suite using
provisional codepoint `0x0052`. Device registration now offers this suite as an
explicit experimental option. Existing private-use-suite devices remain the
default for compatibility. Group state records its suite, recovery restores
that suite, device-key rotation preserves it, and the client rejects a member
KeyPackage that uses a different suite. Every device in a group must therefore
be registered with the same suite. An opt-in wire test exchanges a KeyPackage,
Welcome, and encrypted application messages in both directions with OpenMLS
0.9.1 and its RustCrypto provider. The reproducible procedure is in
`spec/pqc_mls_interop/README.md`.

That result establishes interoperability for this draft suite between these
two implementations; it does not make the suite a registered or finalized MLS
suite, or establish security review of either implementation. The `0xf011`
suite remains available for existing devices and groups. New groups can use
`0x0052` only when all participating devices have matching KeyPackages. No
automatic migration of groups, devices, or recovery files occurs. Broader
migration and multi-device testing remains necessary before changing the
default, as does integration testing of the draft suite's ML-DSA-44 group
signatures alongside the separate ML-DSA-87 device request-authentication keys.

The prototype binds MLS basic credentials to explicitly confirmed SHA-256
fingerprints and includes a passing local two-device round-trip test. Group-state
exports and browser recovery data use AES-256-GCM with a passphrase-derived
PBKDF2 key (310,000 SHA-256 iterations). The prototype now has an experimental
authenticated relay API, enabled in the local Docker override with
`PQC_E2EE_EXPERIMENTAL=true`. Tokens need `write:statuses`.
Every messaging state change, including invitation, acceptance, decline,
departure, setup, membership and relay operations, requires a fresh ML-DSA-87
proof signed by the registered device key, bound to the HTTP method, full request path,
timestamp, one-use nonce, and SHA-256 of the raw request body. Devices created
before this proof was added have no server-side authentication key and cannot
use the protected endpoints; register a new device and re-enroll it in the MLS
groups. No automatic key backfill is performed.
Clients can register devices, fetch one-time KeyPackages for accounts already in
the same relay conversation, create conversations with up to ten local accounts,
and exchange base64-encoded opaque MLS messages up to 1 MiB. The relay enforces
membership and does not parse or decrypt payloads; it still sees membership,
message timing, and payload sizes. Only the group creator can claim KeyPackages;
claims are private/no-store, one-time, and tied to a stable request ID. Device
additions bind their idempotent operation to that KeyPackage request. After group creation or join, the UI rotates the
one-time KeyPackage while retaining the device signing identity and fingerprint.
The API also permits publishing a replacement with
`PATCH /api/v1/pqc_devices/:id/key_package`.

Rack::Attack limits relay writes to 120 per authenticated account per five
minutes, private-media uploads to 10 per 30 minutes, and private-media reads to
30 per five minutes. Private media also enforces a 1 GiB per-account stored-byte
quota, serialized under the account row lock so concurrent uploads cannot
overbook it. These application limits do not replace deployment-level capacity
monitoring, retention, backup, or orphaned-blob cleanup.

An opt-in Mastodon UI is available at `/pqc` when the relay flag is enabled. It
registers and revokes browser devices, creates local-account conversations,
lets the creator add local accounts to an active group, shows member fingerprints
for out-of-band verification, and sends/receives MLS messages. Existing members
must review changed device fingerprints before the client processes more group
messages. The browser saves the device's private KeyPackage material and active
MLS conversation states plus the latest 100 visible messages per conversation
in an encrypted localStorage record; after reload, the user can unlock it with
the recovery passphrase. It can export and import a
passphrase-protected recovery file for browser replacement. While unlocked,
users can change the passphrase on this browser's encrypted recovery record
after confirming the current passphrase; previously exported files retain their
original passphrase and must be exported again. A forgotten passphrase cannot
be reset. A restored file represents the same logical MLS device, so the old
copy must not be used concurrently or the group ratchet can fork. The UI now
holds an account-scoped Web Lock for the duration of an unlocked session,
preventing a second tab at the same browser origin from opening or creating a
competing device state. Browsers without the Web Locks API fail closed. Web
Locks are origin-scoped, so alternate schemes, hostnames, or ports do not share
the guard. Separate browser profiles or machines also require
single-use-at-a-time handling for recovery copies.
Outbound application messages, initial group setup messages, and member-add
commits/Welcome messages are persisted in the encrypted browser recovery record
before relay delivery. Each queued payload has a stable client message ID; the
relay deduplicates retries and rejects reuse of an ID for different ciphertext
or a different target. The encrypted record also retains unprocessed public
KeyPackages and group setup progress, so retries can continue at the correct
group epoch. KeyPackage retrieval and local persistence are separate operations,
so the browser saves a fetch request ID before requesting a KeyPackage; the relay
returns the same claimed package for that request after a retry and will not let
a stale request consume a subsequently rotated package. Member addition stages
the MLS commits and Welcome messages in encrypted browser recovery, then commits
relay membership and all deliveries in one idempotent server transaction. For an
already active group, the creator first sends a separate invitation. The invitee
must accept before the creator can fetch its KeyPackages; acceptance alone does
not grant message access or add the account to the MLS roster. The account becomes
a member only after the creator stores the MLS Welcome and commit deliveries
atomically. Relay message access and group rosters are restricted to joined
accounts. Declined invitations can be reissued by the creator. On recovery, the
UI fetches and saves missing prospective KeyPackages, displays
their fingerprints, and requires a fresh confirmation before advancing MLS
state. Initial group setup stages all MLS Welcome/commit messages in encrypted
recovery. Invitees can see pending invitation metadata and accept or decline;
they cannot read group messages or consume KeyPackages before acceptance. The
creator cannot activate setup while any invitation is unanswered. Only accepted
accounts are included in the MLS group, and declined accounts are excluded.
The client then activates the group and stores all setup deliveries in one
idempotent server transaction. The creator's registered device is bound to that
setup attempt. Every accepted participant must have an available registered
device package, and the server checks that every accepted active device receives
at least one Welcome or commit before marking the group active. An interrupted setup still depends on
the creator's encrypted recovery state to resume.
The creator can remove a member with an MLS Remove proposal; the relay removes
membership and stores the commit for every remaining active device atomically.
Individual devices can also be removed with an MLS Remove proposal. Starting
revocation immediately blocks the target device from relay and KeyPackage
operations while retaining its group roster entries for cleanup. A different
group device signs an MLS Remove commit for each group; any group member may
help once revocation is pending. The UI saves each new MLS epoch before delivery
and supports retrying the server transaction. The server finalizes revocation
when the last group removal commits. Revoking the currently active device from
a group therefore requires another registered device to perform that removal.
After activation, a participant can request departure; another active member must create the MLS
Remove commit, which the relay applies atomically. The group creator cannot
leave this prototype group. A client that loses its encrypted recovery record
may still require manual group recovery. There is no message retention or
abuse-control policy.
Existing Mastodon DMs are not encrypted. For a device move, register a fresh
device and keep the old device available. In each group, its creator adds the
new device using the account's local ID; verify the new device fingerprint out
of band, then let the new device process its MLS Welcome. Remove the old device
from every group only after the new device has joined and received the current
group state. The old device remains necessary if setup or recovery fails. Do not
clone one recovery file into two concurrently active browsers. This is a manual
group-by-group move, not automatic recovery of a lost device.

Do not present this experimental prototype as production ready; it still needs
operational retention and abuse decisions, independent protocol review, and
cross-client interoperability testing.
