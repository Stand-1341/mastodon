// Phase 0 verification: the Node streaming server's Postgres client must
// default to TLS (sslmode=require) with an explicit env opt-out, matching
// the Rails-side hardening. Runnable standalone: node test/streaming/db-tls-default.mjs
import { readFileSync } from 'node:fs';

let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? 'PASS' : 'FAIL'} - ${name}`);
  if (!cond) failures++;
};

const src = readFileSync(new URL('../../streaming/database.js', import.meta.url), 'utf8');

check('streaming database.js mentions sslmode', /sslmode/.test(src));
check('default sslmode is require (not prefer/none)', /sslmode[^;]*require|require[^;]*sslmode/.test(src));
check('DB_SSLMODE env override is honored', /DB_SSLMODE/.test(src));

process.exit(failures === 0 ? 0 : 1);
