# Monitoring the PQC signing layer

Three read-only surfaces cover the same facts: a one-screen report for humans,
a JSON endpoint for uptime checks, and Prometheus gauges for dashboards and
alerts. None of them write to the database, and none of them print account
names or key material.

The facts they report are: whether this process's OpenSSL can generate
ML-DSA-87 keys, whether ML-DSA-87 signing is switched on, how many local
accounts have a usable key, and how many do not.

## Status report

```sh
bin/rails pqc:status
```

```text
PQC status at 2026-11-05 00:14:02 UTC

Runtime
  OpenSSL                          OpenSSL 3.5.0 8 Apr 2025
  ML-DSA-87 key generation         supported

Signing
  PQC_ACTIVITYPUB_SIGNING          enabled (default; set PQC_ACTIVITYPUB_SIGNING=false to opt out)

Accounts
  Local                            1,204
  Remote                           58,332
  Total                            59,536

ML-DSA-87 keys (local accounts)
  Accounts with a usable key       1,198
  Accounts missing a usable key    6
  Revoked keys                     2
  Expiring within 7 days           0

Status: DEGRADED (6 local accounts without a usable ML-DSA-87 key)
Next step: bin/rails pqc:backfill
```

The task reads three count queries (one of them a single aggregate over
`keypairs`), so it stays fast on large instances and does not raise on an empty
database; every number is simply `0`. It always exits `0`, even when the status
is `degraded`, so it can run from cron without paging on a backfill that is
still in progress. A usable key is one that is neither revoked nor expired.

## Health endpoint

```sh
curl -fsS https://social.example.com/health/pqc
```

```json
{"status":"degraded","capability":true,"signing_enabled":true,"accounts_with_key":1198,"accounts_missing_key":6}
```

The endpoint is unauthenticated by design (it is a health check), accepts only
`GET`, and returns `200` with the same five keys whenever the database is
reachable, including when it is empty. `capability` matches
`pqc_runtime_supported`, and `accounts_with_key`/`accounts_missing_key` match
the gauges of the same names. Each request runs the same three count queries as
the rake task, one of which is a single aggregate scan of `keypairs`, so poll
at the interval your uptime check already uses rather than every few seconds.
It deliberately does not replace `GET /health`: that endpoint's plain-text `OK`
contract is unchanged for existing uptime checks.

## Prometheus

The exporter is off unless it is explicitly enabled. In the application
environment:

```sh
MASTODON_PROMETHEUS_EXPORTER_ENABLED=true
```

Run the exporter process (it listens on `localhost:9394` by default) and push
the PQC gauges once a minute:

```sh
bin/prometheus_exporter
```

```cron
* * * * * cd /home/mastodon/live && RAILS_ENV=production bin/rails pqc:metrics >> log/pqc_metrics.log 2>&1
```

`pqc:metrics` is a no-op that exits cleanly when
`MASTODON_PROMETHEUS_EXPORTER_ENABLED` is not `true`. It sends to
`PROMETHEUS_EXPORTER_HOST`/`PROMETHEUS_EXPORTER_PORT` if those are set.

| Metric | Type | Meaning |
| --- | --- | --- |
| `pqc_runtime_supported` | gauge | `1` when the Ruby/OpenSSL runtime can generate ML-DSA-87 keys |
| `pqc_signing_enabled` | gauge | `1` when ML-DSA-87 signing is not explicitly disabled |
| `pqc_local_accounts` | gauge | Local accounts |
| `pqc_accounts_with_usable_key` | gauge | Local accounts with an unexpired, unrevoked ML-DSA-87 key |
| `pqc_accounts_missing_key` | gauge | Local accounts with no usable ML-DSA-87 key |
| `pqc_ml_dsa_keys_revoked` | gauge | Revoked ML-DSA-87 keys belonging to local accounts |
| `pqc_ml_dsa_keys_expiring_7d` | gauge | Usable ML-DSA-87 keys expiring within seven days |

All seven are gauges because each value is a point-in-time count. Names use a
`pqc_` subsystem prefix, the same convention as the `sidekiq_`, `puma_` and
`http_` names the bundled instrumentation emits. The standalone
`bin/prometheus_exporter` process applies its own global `--prefix`, which
defaults to `ruby_`, so there the gauges appear as
`ruby_pqc_accounts_with_usable_key`; the in-process local server applies no
prefix, so it exposes `pqc_accounts_with_usable_key`. Pass `--prefix ''` only
if you also want to rename the existing `ruby_*` metrics.

A `pqc_ml_dsa_keys_expiring_7d` above zero is an early warning rather than a
fault: those keys still work, and `bin/rails pqc:backfill` provisions
replacements once the expired ones stop being usable.

Two operational notes:

- The exporter keeps the last value it received, so a stopped cron job freezes
  the gauges instead of clearing them. Alert on the job itself, not only on
  these values.
- `pqc:metrics` reaches the exporter over TCP at
  `PROMETHEUS_EXPORTER_HOST`/`PROMETHEUS_EXPORTER_PORT` (`localhost:9394` by
  default). `MASTODON_PROMETHEUS_EXPORTER_LOCAL=true` serves `/metrics` on that
  same address, so the cron entry does not change between modes.

## What `degraded` means

`degraded` says the PQC layer cannot do what it is configured to do: either
signing is enabled while the runtime cannot generate ML-DSA-87 keys, so no
proofs can be attached at all, or some local accounts have no usable key and
silently fall back to RSA-only signing. `ok` means the layer matches its
configuration, including the case where signing is explicitly disabled with
`PQC_ACTIVITYPUB_SIGNING=false`.

Neither state is an outage. The instance still serves requests, and RSA signing
still works, so `degraded` should open a ticket rather than page anyone. An
outage looks different: `/health` stops returning `OK`, `/health/pqc` stops
answering or returns `500`, or the database or exporter is down. Alert on both,
but only page for the outage.
