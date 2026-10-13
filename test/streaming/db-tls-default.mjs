// Phase 0 verification: the Node streaming server's Postgres client must
// default to TLS (ssl object = TLS on, verified) with explicit env opt-outs,
// matching the Rails-side hardening. Runnable standalone:
//   node test/streaming/db-tls-default.mjs
import { readFileSync } from 'node:fs';

let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? 'PASS' : 'FAIL'} - ${name}`);
  if (!cond) failures++;
};

const src = readFileSync(new URL('../../streaming/database.js', import.meta.url), 'utf8');

// Contract 1: when DB_SSLMODE is unset and the connection URL carries no ssl
// setting, the client defaults to TLS (an ssl object, i.e. TLS + verification).
check(
  'default path enables TLS when ssl is otherwise undefined (ssl = {})',
  /else\s+if\s*\(\s*baseConfig\.ssl\s*===\s*undefined\s*\)\s*\{[^}]*baseConfig\.ssl\s*=\s*\{\}/s.test(src)
);

// Contract 2: DB_SSLMODE=disable (or empty) is an explicit opt-out to plaintext.
check(
  "DB_SSLMODE 'disable' or '' explicitly turns ssl off (ssl = false)",
  /case\s+'disable':\s*\n\s*case\s+'':\s*\n\s*baseConfig\.ssl\s*=\s*false/.test(src)
);

// Contract 3: DB_SSLMODE=no-verify keeps TLS but relaxes verification.
check(
  "DB_SSLMODE 'no-verify' sets rejectUnauthorized: false (TLS kept, relaxed)",
  /case\s+'no-verify':\s*\n\s*baseConfig\.ssl\s*=\s*\{\s*rejectUnauthorized:\s*false\s*\}/.test(src)
);

process.exit(failures === 0 ? 0 : 1);
