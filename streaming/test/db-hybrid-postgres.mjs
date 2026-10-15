import assert from 'node:assert/strict';
import process from 'node:process';

// Native ESM requires the extension for this in-package import.
// eslint-disable-next-line import/extensions
import { configFromEnv, getPool } from '../database.js';

const environment = process.env.NODE_ENV || 'development';
const pool = getPool(configFromEnv(process.env, environment), environment, { debug() {} });

try {
  const { rows: [connection] } = await pool.query(`
    SELECT current_setting('ssl_groups') AS ssl_groups,
           ssl,
           version,
           cipher
      FROM pg_stat_ssl
     WHERE pid = pg_backend_pid()
  `);

  assert.ok(connection?.ssl, 'Node PostgreSQL connection must use TLS');
  assert.equal(connection.version, 'TLSv1.3');
  assert.equal(connection.ssl_groups, 'X25519MLKEM768');

  process.stdout.write(`${JSON.stringify(connection)}\n`);
} finally {
  await pool.end();
}
