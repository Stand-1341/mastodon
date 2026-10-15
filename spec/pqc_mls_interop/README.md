# Experimental MLS wire interoperability check

This opt-in development harness checks the draft suite
`MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44` (provisional MLS ID
`0x0052`) between the TypeScript `ts-mls` implementation and OpenMLS 0.9.1's
RustCrypto provider. It verifies a TypeScript KeyPackage in OpenMLS, adds the
TypeScript client to an OpenMLS group, sends the Welcome to TypeScript, and
exchanges encrypted application messages in both directions.

The listener is test-only. It creates an ephemeral group, accepts one client,
uses a permissive credential-validation callback, and has no HTTP authentication.
Run it only for a local test. It does not connect to Mastodon's database or
modify the running app's groups.

## Run locally with the devcontainer

Start the isolated OpenMLS peer on the internal Docker network:

```powershell
docker compose -p mastodon-local `
  -f .devcontainer/compose.yaml `
  -f .devcontainer/compose.local.yaml `
  --profile pqc-interop up -d pqc-openmls-interop
```

After the peer prints `OpenMLS interop listener ready`, run the TypeScript side
inside the app container:

```powershell
docker compose -p mastodon-local `
  -f .devcontainer/compose.yaml `
  -f .devcontainer/compose.local.yaml `
  exec -e PQC_OPENMLS_INTEROP_URL=tcp://pqc-openmls-interop:45554 app `
  'yarn test:js run app/javascript/mastodon/features/pqc_messaging/openmls_interop.test.ts'
```

The test process completes after a successful exchange, and the one-shot Rust
peer exits. The initial Rust compilation can take about a minute; the named
Cargo target volume retains compiled dependencies for later runs. The service
is attached only to the internal network and does not publish a host port.
Without `PQC_OPENMLS_INTEROP_URL`, Vitest skips only this integration test.
