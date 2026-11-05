# PQC local quickstart

This is the short path from a fresh clone to a running Mastodon instance where
one local account shows the **Post-quantum signed** badge on another local
account's profile. It uses ML-DSA-87 keys and needs no certificate files, no
`./secrets` directory and no `.env` file.

The ten minutes are your attention, not wall-clock time: the first `make up`
builds the production image (including libvips and ffmpeg) and can take
10–25 minutes depending on the laptop. Every later start takes seconds.

## What you need

- Docker Desktop, or Docker Engine with the Compose v2 plugin
  (`docker compose version` must work).
- About 4 GB of RAM free for the stack and 10 GB of disk for images.
- Port 3000 free on `127.0.0.1`.
- Nothing else: no Ruby, no OpenSSL tooling, no PostgreSQL client.

The stack runs Mastodon's production environment because that is what the
image is built for. Production forces HTTPS (`config.force_ssl = true`), so the
compose file includes a small Caddy container that terminates TLS with a local,
self-signed certificate. Your browser will warn once; that is expected.

## 1. Start the stack

```sh
git clone <this-repository> mastodon-pqc
cd mastodon-pqc
make up
```

`make up` does all of the following, in order:

1. Builds the `web`/`sidekiq` image and the `streaming` image.
2. Starts PostgreSQL and Redis and waits for them to be healthy.
3. Runs `rails db:prepare` and `rails db:seed` in a one-shot `migrate`
   container, which creates the schema and the default Owner/Admin roles.
4. Starts `web`, `sidekiq`, `streaming` and the Caddy TLS proxy.
5. Creates the admin account and sets `registrations_mode=open`.
6. Runs `bin/pqc-doctor` inside the web container.

The last step matters. If the runtime cannot generate ML-DSA-87 keys, `make up`
exits non-zero and says so instead of leaving you with a quietly broken demo.

A healthy run ends approximately like this:

```
PASS  Ruby 4.0.7 satisfies the Gemfile requirement (>= 3.3.0, < 4.1.0)
PASS  OpenSSL runtime OpenSSL 3.5.x ... is 3.5.0 or newer
PASS  ML-DSA-87 key generation, PEM export and sign/verify round-trip all work
...
RESULT: ready for ML-DSA-87 (...).
Next: sign in and open a local profile; its header should show the "Post-quantum signed" badge.
```

If any line says `FAIL`, stop and read [When it goes wrong](#when-it-goes-wrong)
before creating accounts.

## 2. Open the site

Go to:

<https://localhost:3000>

The certificate is signed by Caddy's local CA, which your browser does not
trust yet. Click **Advanced → Proceed to localhost** (Chrome/Edge) or accept
the exception (Firefox/Safari). The connection is still encrypted; only the
certificate authority is local.

Optional, if you want to stop the warning: copy Caddy's root certificate out
and add it to your OS/browser trust store.

```sh
docker compose -f docker-compose.pqc-local.yml cp \
  proxy:/data/caddy/pki/authorities/local/root.crt ./pqc-local-ca.crt
```

The file is safe to delete. If you later run `down -v`, Caddy generates a new
CA and you would need to repeat this.

## 3. Sign in as the admin

`make up` created this account:

| Field    | Value                 |
| -------- | --------------------- |
| Email    | `admin@example.test`  |
| Password | `pqc-demo-password`   |
| Username | `@pqcadmin`           |

Sign in at <https://localhost:3000/auth/sign_in>. No confirmation email is
sent or needed.

You can change the defaults before the first run:

```sh
make up ADMIN_EMAIL=me@example.test ADMIN_PASSWORD='something-longer'
```

`*@example.test` addresses never leave the machine, and this demo has no SMTP
server configured.

## 4. Create the second account

```sh
make demo
```

This creates `demo@example.test` / `pqc-demo-password` (`@demo`), makes sure it
has an ML-DSA-87 key, and prints the exact click path. It looks like this:

```
Demo account: demo@example.test / pqc-demo-password (@demo)

What to click:
  1. Open https://localhost:3000 and accept the local certificate warning (Advanced -> Proceed).
  2. Sign in as demo@example.test / pqc-demo-password.
  3. Open https://localhost:3000/@pqcadmin - the profile header should show a "Post-quantum signed" badge.
  4. Open https://localhost:3000/@demo - your own profile carries the same badge.

ML-DSA-87 key: present. Everything the badge needs is in place.
```

## 5. See the badge

Use a private/incognito window for `@demo` so it does not replace the admin
session:

1. Sign in as `demo@example.test` / `pqc-demo-password`.
3. Open <https://localhost:3000/@pqcadmin>.
3. Under the display name, in the badge row, look for **Post-quantum signed**.

That badge is rendered from `Account#pqc_signed?`: it means the account has an
ML-DSA-87 keypair stored in the database. Remote accounts do not get the badge
from this local demo.

## 6. Check it from the command line

```sh
make doctor    # Ruby, OpenSSL, real ML-DSA-87 generation, switches, database
make status    # pqc:status report (if the monitoring task exists in this checkout)
```

Per-account key checks:

```sh
docker compose -f docker-compose.pqc-local.yml exec web \
  bin/rails 'pqc:verify_key[pqcadmin]'

docker compose -f docker-compose.pqc-local.yml exec web \
  bin/rails 'pqc:benchmark[pqcadmin,3]'
```

`pqc:verify_key` signs and verifies a challenge with the stored private key, so
it proves the encrypted key material is usable, not merely present.

If `make status` prints that `pqc:status` is not defined, this checkout
predates the monitoring change; `make doctor` is the supported fallback.

## 7. Stop and restart

```sh
make down      # stop everything, keep accounts, keys and database
make up        # start again; no rebuild unless code changed
make logs      # follow all logs
make logs SERVICE=web
```

PostgreSQL, Redis, uploaded media and Caddy's CA live in named Docker volumes,
so `make down` does not destroy accounts or their ML-DSA keys.

To start over from zero:

```sh
docker compose -f docker-compose.pqc-local.yml down -v
```

That deletes the database, all accounts and all keys. The next `make up` will
recreate them with fresh demo accounts.

## When it goes wrong

### OpenSSL is too old: no keys, no badges, no visible error

This is the failure mode the doctor exists for. `ActivityPub::GeneratePqcKeyService`
raises `UnsupportedRuntimeError` when `OpenSSL::PKey.generate_key('ML-DSA-87')`
is unavailable. Account creation deliberately rescues that error and continues
so signups never fail; the only trace is a log line such as:

```
Could not provision ML-DSA-87 signing key for @pqcadmin: ActivityPub::GeneratePqcKeyService::UnsupportedRuntimeError: ...
```

The UI shows nothing. Accounts work, profiles render, and the badge is simply
missing. Do not treat "the site loads" as proof that PQC works.

Diagnose:

```sh
make doctor
docker compose -f docker-compose.pqc-local.yml logs web | grep -i 'Could not provision ML-DSA-87'
docker compose -f docker-compose.pqc-local.yml exec web \
  ruby -ropenssl -e 'puts OpenSSL::OPENSSL_VERSION; puts OpenSSL::OPENSSL_LIBRARY_VERSION'
```

`make doctor` reports the loaded library version and the real exception from
`OpenSSL::PKey.generate_key`. If the runtime is below OpenSSL 3.5, ML-DSA does
not exist in the default provider, no matter what the Ruby version is.

Fix: build on a base whose **runtime** OpenSSL is 3.5 or newer. This
repository's `Dockerfile` defaults to `ruby:4.0.7-slim-trixie` (Debian trixie,
OpenSSL 3.5). If you changed `RUBY_VERSION` or `DEBIAN_VERSION` to an older
Debian release, or are reusing an image built elsewhere, rebuild without the
stale layer:

```sh
docker compose -f docker-compose.pqc-local.yml build --no-cache web sidekiq
make up
```

Then backfill keys for accounts created while the runtime was broken:

```sh
docker compose -f docker-compose.pqc-local.yml exec web bin/rails pqc:backfill
```

`pqc:backfill` is idempotent and reports how many accounts it provisioned. If
it still fails with `UnsupportedRuntimeError`, you are still on an old
OpenSSL; the doctor will say so.

### Signups are disabled

Symptom: there is no "Sign up" link, or `/auth/sign_up` redirects to the sign-in
page with "Registrations are closed".

`Setting.registrations_mode` defaults to `none` in `config/settings.yml`, which
means the signup form does not exist at all. `make up` sets it to `open`, but a
skipped or failed seed leaves it closed. Fix:

```sh
make seed
```

Or set it in the admin UI at <https://localhost:3000/admin/settings/registrations>.

Verify:

```sh
docker compose -f docker-compose.pqc-local.yml exec web \
  bin/rails runner 'puts Setting.registrations_mode'
```

It must print `open`. You do not need open signups for the demo accounts
themselves; `make seed` and `make demo` create confirmed users directly. Open
registrations are for signing up in the browser.

### The accounts exist but no badge appears

Work through these in order:

1. **Confirm the account actually has a key.**

   ```sh
   docker compose -f docker-compose.pqc-local.yml exec web \
     bin/rails runner 'puts Account.find_local("pqcadmin").pqc_signed?'
   ```

   `true` means the key is stored; the problem is display or caching. `false`
   means provisioning failed: run `make doctor`, then
   `bin/rails pqc:backfill`.

2. **Confirm you are looking at the local profile.** Open
   <https://localhost:3000/@pqcadmin>, not a cached copy or a remote account with
   the same name. The badge is in the profile header, next to the display name
   and other role badges.

3. **Hard-reload the page.** The account JSON is cached by the web client. Use
   Ctrl+Shift+R (Cmd+Shift+R on macOS), or sign out and back in.

4. **Confirm the browser is on the new session.** If you created the key after
   the page was loaded, the serializer result is stale until reload.

5. **Check the serializer output directly:**

   ```sh
   curl -sk 'https://localhost:3000/api/v1/accounts/lookup?acct=pqcadmin' | grep -o '"pqc_signed":[a-z]*'
   ```

   It should print `"pqc_signed":true`. If it does and the UI still hides the
   badge, the frontend bundle is stale: rebuild the image and restart.

### The certificate warning is blocking the page

Click through it once (Advanced → Proceed). If your browser refuses, import the
CA as shown in step 2. Safari can be stricter about locally signed
certificates; Chrome or Firefox are easier for this demo.

### Port 3000 is already in use

Edit `docker-compose.pqc-local.yml`: change the `proxy` port mapping and the
Caddy site address from `3000` to another port, and set `LOCAL_DOMAIN` to the
same host and port, for example `LOCAL_DOMAIN=localhost:3001`. Generated links
and the Caddy certificate hostname must match what is in the address bar.

### `make up` stops with "web did not become healthy"

Inspect the logs:

```sh
make logs SERVICE=web
make logs SERVICE=migrate
```

The usual causes are a failed migration (look at `migrate`), a port conflict,
or the Docker daemon running out of memory. `make down` then `make up` is safe;
named volumes keep the data.

### `make status` says `pqc:status` is not defined

That rake task is added by a separate monitoring change. Until it lands, use
`make doctor` for runtime capability and the `bin/rails runner` commands above
for per-account checks. This is expected on older checkouts, not a broken
stack.

## What is deliberately not production-ready here

- Fixed, public `SECRET_KEY_BASE` and Active Record encryption keys.
- PostgreSQL trust authentication with no TLS.
- An HTTPS proxy with a self-signed local certificate, bound only to `127.0.0.1`.
- No SMTP, no object storage, no Elasticsearch.

The production PostgreSQL hybrid-TLS path lives in `docker-compose.pqc.yml` and
is unchanged. Do not mix the two files; this one is for a laptop demo only.
