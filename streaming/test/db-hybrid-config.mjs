import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

// Native ESM requires the extension for this in-package import.
// eslint-disable-next-line import/extensions
import { configFromEnv } from '../database.js';

const directory = mkdtempSync(path.join(os.tmpdir(), 'mastodon-hybrid-db-config-'));
const caPath = path.join(directory, 'ca.pem');
writeFileSync(caPath, 'test CA');

const env = {
  NODE_ENV: 'production',
  DB_HOST: 'db',
  DB_SSLMODE: 'verify-full',
  DB_SSLROOTCERT: caPath,
  PQC_HYBRID_DB_TLS_CA_PATH: caPath,
  PQC_REQUIRE_HYBRID_DB_TLS: 'true',
  DATABASE_URL: 'postgresql://mastodon:secret@db/mastodon_production',
};

try {
  const config = configFromEnv(env, 'production');
  assert.equal(config.host, 'db');
  assert.equal(config.ssl.rejectUnauthorized, true);
  assert.equal(config.ssl.ca, 'test CA');

  assert.throws(
    () => configFromEnv({ ...env, DATABASE_URL: 'postgresql://mastodon@other-db/mastodon' }, 'production'),
    /PQC_REQUIRE_HYBRID_DB_TLS requires DATABASE_URL to connect to db/,
  );
  assert.throws(
    () => configFromEnv({ ...env, DB_SSLMODE: 'require' }, 'production'),
    /PQC_REQUIRE_HYBRID_DB_TLS requires DB_HOST=db, DB_SSLMODE=verify-full/,
  );

  process.stdout.write('Streaming hybrid PostgreSQL URL guard passed\n');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
