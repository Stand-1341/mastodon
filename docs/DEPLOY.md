# Deploying a small PQC Mastodon instance

This is the deployment path for **one VPS serving a handful of friends**: Docker
Compose, a single PostgreSQL 18 instance with hybrid TLS, and per-account
ML-DSA-87 ActivityPub signing keys. It is not a hardened production deployment
and does not pretend to be one. See [What this is not](#what-this-is-not) at the
end before you invite anyone.

**Start here: this fork needs OpenSSL 3.5 or newer inside the Rails container.**
ML-DSA-87 comes from OpenSSL's default provider in 3.5+, and Ruby's `openssl`
binding must be linked against that library. The host's OpenSSL version is
irrelevant. If the runtime is older, account creation still succeeds: the
provisioning callback rescues the error, logs
`Could not provision ML-DSA-87 signing key ...` at `warn` level, and moves on.
The account is created, the site looks healthy, and it has no signing key. Do
not create accounts until the check in [§2](#2-verify-the-runtime-openssl-35)
passes.

Commands below use:

```sh
export COMPOSE="docker compose -f docker-compose.yml -f docker-compose.pqc.yml"
```

Both `-f` flags matter. `docker-compose.pqc.yml` is an overlay; running
`docker compose up` without it silently starts the upstream PostgreSQL 14
service with no TLS and none of the PQC wiring.

## 1. Prerequisites

- **VPS:** 2 vCPU, 4 GB RAM, 40 GB disk minimum. Mastodon is memory-hungry;
  2 GB will thrash. Add 2 GB of swap if the provider does not.
- **OS:** Debian 13 (Trixie) or Ubuntu 24.04. Trixie matters because its
  `openssl` package is 3.5.x, but you will still verify the container in §2
  rather than trusting the OS.
- **DNS:** an `A` (and `AAAA` if you have IPv6) record for the hostname in
  `LOCAL_DOMAIN`, pointing at the VPS. Federation finds you by this name.
- **Ports:** 80 and 443 reachable from the internet. PostgreSQL and Redis are
  never published; the app ports bind to `127.0.0.1` only.
- **Docker Engine 27+** with the Compose v2 plugin, and a non-root user in the
  `docker` group.
- **A mail relay.** The image has no MTA. Confirmation e-mails, password
  resets, and reports all need SMTP.

```sh
sudo apt update && sudo apt install -y ca-certificates curl git ufw
# install Docker Engine + compose plugin from Docker's repository, then:
sudo ufw allow 22/tcp && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
git clone <your-fork-url> mastodon && cd mastodon
git switch pqc/verification-badge
cp .env.pqc.sample .env.production
chmod 600 .env.production
```

The copied file is full of `REPLACE_ME` placeholders. That is fine for building;
you will fill it in after the runtime check.

## 2. Verify the runtime OpenSSL 3.5+

Build the image and ask the same Ruby that will run the app to generate one key.
Building directly, rather than through Compose, keeps this probe independent of
`.env.production`, the database secret, and the TLS files that do not exist yet.
The tag is exactly what the overlay expects, so the later Compose build reuses
the cache:

```sh
docker build -f Dockerfile -t mastodon-pqc:local .
docker run --rm mastodon-pqc:local ruby -e '
  require "openssl"
  puts OpenSSL::OPENSSL_VERSION
  puts OpenSSL::OPENSSL_LIBRARY_VERSION
  OpenSSL::PKey.generate_key("ML-DSA-87")
  puts "ML-DSA-87 key generation OK"
'
```

This bypasses Rails boot, the database, and every application initializer, so it
is a clean capability probe.

Expected output is two 3.5-or-newer version strings followed by
`ML-DSA-87 key generation OK`. The first (`OPENSSL_VERSION`) is what Ruby was
built against; the second (`OPENSSL_LIBRARY_VERSION`) is the library actually
loaded. The loaded one is what matters — a build against 3.5 with an old runtime
library still cannot generate ML-DSA-87 keys, and the key-generation line will
fail.

If it raises `OpenSSL::PKey::PKeyError` or `NotImplementedError`, stop. The
image is not built on a 3.5 runtime, most likely because
`--build-arg DEBIAN_VERSION` was overridden or a cached image was reused. Fix
the base image (`ARG DEBIAN_VERSION="trixie"` in the `Dockerfile`) and rebuild
with `--no-cache`; do not install an `openssl` CLI from an older distribution
and assume Ruby picked it up.

`bin/pqc-doctor` is the canonical version of this check: same runtime probe,
plus PEM export, a sign/verify round-trip, every PQC switch, and database
reachability. Section 8 runs it once the stack is up. This focused probe is
worth keeping because it needs neither Rails nor a database.

Confirm again from inside the running app later:

```sh
$COMPOSE exec -T web bin/rails runner 'puts OpenSSL::OPENSSL_VERSION'
```

## 3. Generate the PostgreSQL TLS material

```sh
bin/pqc-tls-init
```

One command writes exactly what `docker-compose.pqc.yml` mounts:

| Path | Mode | Contents |
| --- | --- | --- |
| `secrets/postgres-tls/ca.crt` | 0644 | CA certificate |
| `secrets/postgres-tls/ca.key` | 0600 | CA private key; back it up, never serve it |
| `secrets/postgres-tls/server.crt` | 0644 | server certificate, `subjectAltName=DNS:db`, signed by the CA |
| `secrets/postgres-tls/server.key` | 0600 | server private key, matching `server.crt` |
| `secrets/postgres-superuser-password` | 0600 | random 32-byte hex password for the `postgres` role |

The script uses only `openssl`, needs no Ruby or Docker, and verifies the chain,
the `db` hostname, and the certificate/key match before reporting success. It is
idempotent: an existing CA and server certificate are reused, and an existing
superuser password is never rewritten, because changing that file would silently
desynchronise it from the role password already stored in PostgreSQL.

Useful variants:

```sh
bin/pqc-tls-init --rotate-server   # re-issue the leaf cert from the same CA
bin/pqc-tls-init --force           # new CA + leaf; recreate db, web, streaming, sidekiq
```

`--force` invalidates the old CA. Every service that mounts `ca.crt` must be
recreated (`$COMPOSE up -d --force-recreate`), and any client using the old CA
will fail verification until it is updated. Keep `ca.key` somewhere safe: it is
what lets you re-issue the server certificate without touching the app.

The `db` SAN is not decorative. `DB_SSLMODE=verify-full` checks the hostname,
and the Compose service is named `db`. If you change the service name, pass
`--san <name>` and update `DB_HOST` and the `PQC_REQUIRE_HYBRID_DB_TLS` guard
together.

## 4. Fill in `.env.production`

Generate the Rails secrets with the app image so the formats match what Rails
expects:

```sh
# Session/cookie signing key
openssl rand -hex 64

# Active Record Encryption keys: paste all three output lines
$COMPOSE run --rm --no-deps -e SECRET_KEY_BASE_DUMMY=1 web bin/rails db:encryption:init

# Web Push keys: paste both output lines
$COMPOSE run --rm --no-deps web bin/rails mastodon:webpush:generate_vapid_key
```

Then edit `.env.production` and replace every remaining `REPLACE_ME`:

- `LOCAL_DOMAIN` — the DNS name from §1. This cannot be changed later without
  breaking federation and account identity.
- `SECRET_KEY_BASE` — the 128-character hex string.
- The three `ACTIVE_RECORD_ENCRYPTION_*` values — exactly as printed. These
  encrypt every account's ML-DSA-87 private key. Back them up before the first
  boot and never rotate them.
- `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY`.
- `DB_PASS` — generate with `openssl rand -hex 24` (hex avoids quoting problems
  in Compose env files). You will type the same value at the `\password` prompt
  in §5.
- SMTP settings.
- `PQC_AR_ENCRYPTION_CUSTODY_POINTER` — a non-secret pointer to where the AR
  keys are escrowed. `pqc:inventory` reports it; do not put key material here.

`PQC_ACTIVITYPUB_SIGNING=true` is already set explicitly. Keep it explicit: the
signing code treats an unset value as enabled, but `pqc:inventory` reports only
the literal string `true`, so an unset variable produces a misleading `false`
in your monitoring output. Setting it to `false` is the RSA-only escape hatch
described in [§10](#10-rollback).

Validate the merged Compose configuration before starting anything:

```sh
$COMPOSE config -q
```

## 5. Bring the stack up

```sh
$COMPOSE build db web streaming
$COMPOSE up -d --wait db redis
```

Create the application role. The `postgres` superuser is reachable over the
container's local socket (`local all all trust` in the overlay's HBA), so no
password prompt is needed to get in:

```sh
$COMPOSE exec db psql -U postgres -d postgres
```

```sql
CREATE ROLE mastodon LOGIN CREATEDB;
\password mastodon
\q
```

Enter the `DB_PASS` value at the prompt. `CREATEDB` lets the next command create
`mastodon_production` itself; you can revoke it afterwards with
`ALTER ROLE mastodon NOCREATEDB;`.

```sh
$COMPOSE run --rm web bin/rails db:prepare
$COMPOSE run --rm web bin/rails db:seed      # idempotent; ensures roles exist
```

`db:prepare` is also the first real end-to-end test of the database TLS chain:
it connects over TCP as `mastodon`, with `verify-full`, to `db:5432`. A
certificate, SAN, CA, or password mistake fails here rather than at first login.

Now start the app processes:

```sh
$COMPOSE up -d
$COMPOSE ps
```

All five services should be `running`/`healthy`. If `web` restarts in a loop,
read `$COMPOSE logs web`; the most common causes are a missing AR key (the app
aborts with a clear message) or a database TLS mismatch.

### Terminate TLS at the edge

Compose publishes `127.0.0.1:3000` (Rails) and `127.0.0.1:4000` (streaming).
Put Nginx or Caddy in front with a public certificate. A minimal Nginx server
block:

```nginx
map $http_upgrade $connection_upgrade { default upgrade; '' close; }

server {
  listen 443 ssl;
  server_name mastodon.example.invalid;

  ssl_certificate     /etc/letsencrypt/live/mastodon.example.invalid/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/mastodon.example.invalid/privkey.pem;
  client_max_body_size 99m;

  location /api/v1/streaming {
    proxy_pass http://127.0.0.1:4000;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 90s;
  }

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_read_timeout 90s;
  }
}
```

Obtain the certificate with certbot (`certbot --nginx -d mastodon.example.invalid`).
Do not point `LOCAL_DOMAIN` at an IP address and do not serve the instance over
plain HTTP.

## 6. Create the first admin and choose registration mode

```sh
$COMPOSE exec web bin/tootctl accounts create alice \
  --email alice@example.invalid --confirmed --role Owner
```

The command prints a generated password. Save it, sign in, and change it. The
account is created through the normal model callback, so it receives an
ML-DSA-87 key immediately — this is the first account that proves §2 was not a
lie:

```sh
$COMPOSE exec -T web bin/rails 'pqc:verify_key[alice]'
```

A fresh database has `Setting.registrations_mode = 'none'`: there is no signup
form at all, just a login page. Pick deliberately:

```sh
# Public form, you approve each account (recommended for friends)
$COMPOSE exec web bin/tootctl settings registrations approved

# Public form, anyone can sign up
$COMPOSE exec web bin/tootctl settings registrations open

# No public form; invite links only
$COMPOSE exec web bin/tootctl settings registrations close
```

`close` restores `none`. Invite links created from the admin UI still work in
that mode, which is the right choice for a small closed group: keep the front
door shut and hand out invites. Whatever you choose, do not leave a
friends-only instance on `open` by accident.

## 7. Provision keys for existing accounts

New local accounts provision themselves. Accounts that predate this branch, or
that were created while the runtime was broken, need the backfill:

```sh
$COMPOSE exec -T web bin/rails pqc:backfill
```

It walks every local account, skips ones with a usable ML-DSA-87 key, prints a
JSON report, and exits non-zero if anything failed. It runs inside the container
from §2, so the OpenSSL requirement is already satisfied; if the runtime is
still wrong it fails loudly instead of pretending.

One account at a time:

```sh
$COMPOSE exec -T web bin/rails 'pqc:generate_key[alice]'   # idempotent
$COMPOSE exec -T web bin/rails 'pqc:verify_key[alice]'     # decrypt + sign + verify
```

`pqc:generate_key` reuses the oldest usable key; it does not rotate or delete
anything. `pqc:verify_key` is the recovery check: it decrypts the stored private
key, signs a random challenge, and verifies it without printing key material.

## 8. Verify the deployment

Five checks, in increasing order of user-visible confidence.

**Runtime doctor.** `bin/pqc-doctor` is the repository's canonical preflight. It
checks Ruby, the loaded OpenSSL, real ML-DSA-87 generation plus PEM export and a
sign/verify round-trip, prints every PQC switch, and confirms the database is
reachable from the app container:

```sh
$COMPOSE exec -T web bin/pqc-doctor
```

Every line should be `PASS` or `INFO`; the summary ends with
`RESULT: ready for ML-DSA-87`. A `FAIL` on an ML-DSA line means accounts are
being created without keys even though signup succeeds.

**Status report and health endpoints.** `pqc:status` is the human-readable
report; `/health/pqc` is the same data for uptime checks. `/health` stays the
shallow liveness endpoint:

```sh
$COMPOSE exec -T web bin/rails pqc:status
curl -fsS http://127.0.0.1:3000/health
curl -fsS https://mastodon.example.invalid/health/pqc
```

```json
{"status":"ok","capability":true,"signing_enabled":true,"accounts_with_key":3,"accounts_missing_key":0}
```

`degraded` means signing is enabled but either the runtime cannot generate
ML-DSA-87 keys or at least one local account has no usable key. Treat it as a
ticket, not an outage: RSA signing still works. `docs/MONITORING.md` covers the
Prometheus gauges and the difference between degraded and down.

**Deployment inventory.** `pqc:inventory` is the machine-readable evidence
record: Ruby and OpenSSL versions, live database TLS state, signing policy,
Active Record Encryption configuration, and the count of accounts missing keys:

```sh
$COMPOSE exec -T web bin/rails pqc:inventory | tee /tmp/pqc-inventory.json
```

The fields to read:

- `openssl_version` — must be 3.5+.
- `database_tls.encrypted` — `true`.
- `database_tls.tls_version` — `TLSv1.3`.
- `database_tls.server_tls_groups` — `["X25519MLKEM768"]`, and
  `hybrid_group_enforced` — `true`.
- `activitypub.pqc_signing_enabled` — `true`.
- `activitypub.accounts_missing_usable_ml_dsa_key` — `0` on a healthy instance.
- `active_record_encryption.required_key_environment_variables` — all
  `configured: true`.

Run this or `pqc:status` on a schedule and alert when accounts are missing keys.
A deploy that "works" but issues no keys looks identical to a healthy one from
the outside.

**Database TLS in the live connection.**

```sh
$COMPOSE exec -T web bin/rails runner \
  'p ActiveRecord::Base.connection.select_one("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")'
```

Expect `ssl: true` and `version: "TLSv1.3"`. Because the server permits only
`X25519MLKEM768`, a successful verified connection also means libpq negotiated
the hybrid group.

**The badge itself.** The REST serializer exposes `pqc_signed`:

```sh
curl -fsS 'https://mastodon.example.invalid/api/v1/accounts/lookup?acct=alice' | jq '.pqc_signed'
# no jq? pipe through python3 -c 'import json,sys; print(json.load(sys.stdin)["pqc_signed"])'
```

`true` means the account has a usable ML-DSA-87 key row. It does not prove the
key can sign — run `pqc:verify_key` for that. In the web UI the badge appears in
the account header on the profile; it is not attached to individual posts.

## 9. Backups and restore

Back up five things, together, on the same schedule:

1. **The database** — every account's encrypted ML-DSA-87 private key lives in
   `keypairs`.
2. **The three `ACTIVE_RECORD_ENCRYPTION_*` keys** — without them the private
   keys in that dump are ciphertext forever.
3. **`.env.production`** — `SECRET_KEY_BASE`, VAPID keys, `DB_PASS`.
4. **`secrets/`** — the superuser password file and the CA key, so you can
   re-issue the database certificate.
5. **`public/system`** — uploaded media, unless you use S3.

```sh
sudo install -d -m 700 /var/backups/mastodon
$COMPOSE exec -T db pg_dumpall -U postgres \
  > /var/backups/mastodon/db-$(date +%F).sql
sudo tar -C "$PWD" -czf /var/backups/mastodon/secrets-$(date +%F).tgz \
  .env.production secrets
sudo chmod 600 /var/backups/mastodon/*
```

`pg_dumpall` includes role password hashes and all databases. Treat the dump as
a credential, not as a text file: it contains the encrypted signing keys and
everything else on the instance. Uploaded media lives in `./public/system`
unless you use S3; put it on the same backup schedule with `tar` or `restic`.

> **Losing the Active Record Encryption keys loses every account's badge.**
> The `keypairs` rows survive a restore, so the UI may still show a badge, but
> no process can decrypt the private key, signing raises instead of falling back
> to RSA, and the badge is meaningless. There is no recovery path and no
> re-derivation. Re-provisioning gives each account a *new* key identity, which
> invalidates existing proofs and MLS device certificates. Test a restore before
> you need one.

Restore drill on a fresh host:

```sh
# Same checkout. Restore .env.production and secrets/ from the backup first:
# the superuser password file must match the hash stored in the dump, and
# pqc-tls-init will keep whatever already exists.
sudo tar -xzf /var/backups/mastodon/secrets-YYYY-MM-DD.tgz -C .
sudo chown -R "$(id -u):$(id -g)" .env.production secrets
bin/pqc-tls-init                     # verifies the restored set, fills gaps
$COMPOSE up -d db redis
$COMPOSE exec -T db psql -U postgres -d postgres \
  < /var/backups/mastodon/db-YYYY-MM-DD.sql
$COMPOSE up -d
$COMPOSE exec -T web bin/rails db:migrate   # only if the dump predates the code
$COMPOSE exec -T web bin/rails 'pqc:verify_key[alice]'
$COMPOSE exec -T web bin/rails pqc:inventory
```

A full-cluster dump starts with `CREATE ROLE postgres`, which already exists on
a freshly initialised cluster. That one `role "postgres" already exists` error
is expected; do not use `-v ON_ERROR_STOP=1` with `pg_dumpall` output, and stop
on any other error. If you generated a new superuser password instead of
restoring the old one, reset it inside the new cluster with
`\password postgres` so it matches `secrets/postgres-superuser-password`.

A `pqc:verify_key` success on the restored database is the only proof that the
backup is actually usable. Do it on a disposable host, not in place.

## 10. Rollback

**Turn signing off.** Set `PQC_ACTIVITYPUB_SIGNING=false` in `.env.production`
and recreate the app processes:

```sh
$COMPOSE up -d --force-recreate web sidekiq
```

Outbound activities fall back to RSA-only. Keys, public key publication, and
stored private keys are untouched; setting the flag back to `true` resumes
signing. This does **not** hide the badge: `pqc_signed` is derived from the key
row, not from the signing flag. If you need badges gone, that is a code change,
not an environment switch.

**Roll back the database overlay.** This is the hard one. PostgreSQL 18 has
already written to `./postgres18-pqc`; starting PostgreSQL 14 against that
directory corrupts it. To go back to the base Compose file you must dump from 18
and restore into 14:

```sh
$COMPOSE exec -T db pg_dumpall -U postgres > /tmp/pre-rollback.sql
$COMPOSE down
# start the base (PostgreSQL 14) db on the untouched ./postgres14 volume
docker compose up -d db
docker compose exec -T db psql -U postgres < /tmp/pre-rollback.sql
```

The same `role "postgres" already exists` line from a full-cluster dump applies
here; ignore that one and stop on anything else. A newer `pg_dump` can also emit
session `SET`s that an older server does not recognise; with `ON_ERROR_STOP`
off those are non-fatal, but confirm the restore ends with your tables and that
`pqc:status` reports the expected account count. The dump restores the
`mastodon` role and its password hash, so the `DB_PASS` in `.env.production`
still matches.

Only do this if you kept `./postgres14` intact (the migration path in
`docs/PQC_TLS.md`). A fresh deployment has no old 14 volume, so the first
`docker compose up -d db` initialises an empty PostgreSQL 14 cluster and the
dump becomes the restore source rather than a rollback. Either way, the old database has no
TLS, so the base stack needs `DB_SSLMODE=disable` for the app services (the
`database.yml` default is `require`, which fails against a server with `ssl=off`).
Add it to `.env.production` for the rollback, and remove `DB_SSLROOTCERT`/
`PQC_REQUIRE_HYBRID_DB_TLS` if you copied them anywhere. This is a plaintext
database connection; keep the rollback window short.

**Roll back the code.** Check out the previous revision, rebuild `web` and
`streaming`, and recreate the services. The ML-DSA key rows are additive; older
code ignores them. The account encryption keys must stay the same.

## What this is not

- **Not hardened.** One host, no failover, no WAF, no audit logging, no
  intrusion detection. Secrets sit in a file readable by the deploy user on the
  same machine as the database. There is no HSM or KMS behind the signing keys.
- **Not audited.** The ML-DSA-87 profile (`mldsa87-jcs-2024`) is not a W3C
  standard; the current Quantum-Resistant Cryptosuites specification lists only
  ML-DSA-44. Peers are not required to understand it. The badge reflects a proof
  this instance published, not a globally trusted identity.
- **Not post-quantum authentication for the database.** The PostgreSQL
  connection uses hybrid `X25519MLKEM768` key exchange but a conventional RSA
  server certificate. Hybrid key exchange and PQ signatures are separate
  concerns.
- **Not highly available.** Backups are manual, restores are manual, and a disk
  failure loses everything since the last dump. Monitoring is `pqc:status`, the
  inventory, and the two health endpoints; there is no alerting stack.
- **Not a public-instance design.** `PQC_ACTIVITYPUB_REQUIRE_PROOF` stays
  `false`; turning it on rejects every RSA-only peer. Private media needs AWS
  KMS and is off. The encrypted messaging UI is experimental and has no
  cross-client interoperability test.

## The three most likely ways this still fails

1. **The running image is not the image you checked.** A stale
   `mastodon-pqc:local`, a forgotten `-f docker-compose.pqc.yml`, or a rebuild
   that reused a cached layer puts an older OpenSSL back in production. The
   preflight in §2 only proves the image you just built. Check
   `openssl_version` in `pqc:inventory` from the running container, and read
   `web` logs for `Could not provision ML-DSA-87 signing key` after the first
   signup.
2. **Certificate drift after rotation.** `bin/pqc-tls-init --force` mints a new
   CA, but a still-running `web`/`streaming` container keeps the old `ca.crt`
   bind-mount and fails `verify-full`; or the leaf is re-issued for the wrong
   `--san` and the server hostname check fails. Recreate every service after
   rotation, and keep the SAN at `db`.
3. **A backup that omits the encryption keys.** The database dump restores
   cleanly and the site boots, but every `keypairs.private_key` is undecryptable
   because `ACTIVE_RECORD_ENCRYPTION_*` was not in the backup. The failure shows
   up only when someone posts and signing raises. Restore the keys with the
   dump and run `pqc:verify_key` as part of every restore drill.
