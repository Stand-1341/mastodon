# Tanya's bot message authentication demonstration

Owner: Tanyaradzwa Mangundhla.
Topic: Trustworthy AI with PQC-Based Authentication.

## What this does

A simulated bot writes a message. A private ML-DSA-87 key signs it. A verifier uses the bot's trusted public key to check it. Changing the text, identity, message ID, timestamp, signature, or key makes verification fail. Signing proves origin and unchanged content, assuming the public key is trusted and the private key is protected. It does not prove the message is true or that an AI actually wrote it.

## Run it

Use Node.js 24.6 or later with ML-DSA support. Tested with Node 24.22.1 and OpenSSL 3.5.9. Older Node 22 installations may run Mastodon but cannot run this demo. No package installation is required. From the repository root:

```sh
node tools/bot-auth-demo/demo.mjs
node --test tools/bot-auth-demo/auth.test.mjs
node tools/bot-auth-demo/benchmark.mjs tools/bot-auth-demo/results
```

Expected demo: original true, changed message false, wrong key false. There are 14 automated tests.

## Why it stays separate

All new files are under `tools/bot-auth-demo/`. No existing files, shared dependencies, database tables, routes, environment settings, or application behavior are changed. No network request, posting, AI API call, or Mastodon credentials are used. This is a repository-contained prototype, not a deployed Mastodon feature or a replacement for the team's federation signatures. The folder can be removed without reverting application changes. It does not overlap with `tools/crypto-analyzer/`.

Base repository commit: ddbb0de326112289b75849ddfed15c5fc32fceae.

## Files

- `auth.mjs`: reusable key generation, signing, and verification functions.
- `demo.mjs`: short readable demonstration.
- `auth.test.mjs`: acceptance and rejection tests, including Unicode and a documented replay limitation.
- `benchmark.mjs`: records actual local measurements and raw timings.
- `results/`: recorded benchmark evidence; no private keys.

## Important boundaries

Keys are generated in memory for each run and are not written to disk. The verifier receives its trusted public key separately; it never trusts a public key supplied by the message sender. A future deployment needs authenticated account-to-key registration, protected persistent keys, rotation, revocation, and replay controls. Signing an ID and timestamp prevents undetected modification of them; it does not reject an old or repeated message. Repeated original signatures are intentionally accepted by this cryptographic-only prototype. JavaScript memory management is not a guarantee of secret-key zeroization.

The wire format signs a fixed ordered array of four nonempty strings with a versioned domain prefix. It rejects additional message fields. It is not RFC 8785 JCS, JSON-LD, an ActivityPub object proof, or an interoperable federation extension.


## Reading the benchmark

The benchmark compares ML-DSA-87 with RSA-3072 using SHA-256 and PKCS#1 v1.5 signatures. These are distinct security choices, not equivalent security levels. It tests 128, 1,024, and 10,240 byte synthetic inputs with 20 warmups and 200 measured calls per operation/size. It measures crypto calls, excluding JSON formatting, key lookup, Base64, network, Rails, and AI inference. Key generation has 20 separate trials. Verification timings reuse one valid signature per payload. A single host/process/run in fixed order is exploratory evidence only. The correctness repetitions reuse one envelope and show behavior, not an attack-resistance probability. RSA is a comparison baseline, not a deployment recommendation.

## Optional future connection

A separately reviewed Mastodon integration could fetch actual bot output, register the public key to an authorized account, sign the final immutable text, and verify before publishing or showing a verification result. That work is outside this prototype and would need coordination with the group's existing object-proof design.
