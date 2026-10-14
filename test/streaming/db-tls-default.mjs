// Runnable without a database: node test/streaming/db-tls-default.mjs
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { checkServerIdentity, connect, createServer } from 'node:tls';

import { configFromEnv } from '../../streaming/database.js';

const directory = mkdtempSync(join(tmpdir(), 'mastodon-db-tls-'));
const caPath = join(directory, 'CA with spaces #1.pem');
const keyPath = join(directory, 'client.key');
const otherCaPath = join(directory, 'other-ca.pem');
const emptyCaPath = join(directory, 'empty-ca.pem');
let ca;
let key;

before(() => {
  // Conventional certificates remain supported; no PQ signing key is needed.
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=database.example',
      '-addext',
      'subjectAltName=DNS:database.example',
      '-keyout',
      keyPath,
      '-out',
      caPath,
    ],
    { timeout: 10000, stdio: 'pipe' },
  );
  ca = readFileSync(caPath, 'utf8');
  key = readFileSync(keyPath, 'utf8');
  writeFileSync(otherCaPath, `${ca}\n`);
  writeFileSync(emptyCaPath, '');
});

after(() => rmSync(directory, { recursive: true, force: true }));

function databaseUrl(params = {}) {
  return `postgres://mastodon:password@database.example/mastodon?${new URLSearchParams(params)}`;
}

function sslConfig(env = {}, environment = 'production') {
  return configFromEnv(env, environment).ssl;
}

for (const environment of ['development', 'production']) {
  test(`${environment} defaults to verified TLS without a custom CA`, () => {
    const ssl = sslConfig({}, environment);
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(ssl.checkServerIdentity, checkServerIdentity);
    assert.equal(ssl.ca, undefined);
  });
}

test('DATABASE_URL without SSL options still defaults to verified TLS', () => {
  assert.equal(
    sslConfig({ DATABASE_URL: databaseUrl() }).rejectUnauthorized,
    true,
  );
});

for (const mode of ['disable', '']) {
  test(`DB_SSLMODE=${JSON.stringify(mode)} preserves the local plaintext opt-out`, () => {
    assert.equal(
      sslConfig({ DB_SSLMODE: mode, DB_SSLROOTCERT: caPath }),
      false,
    );
    assert.equal(
      sslConfig({
        DB_SSLMODE: mode,
        DATABASE_URL: databaseUrl({
          sslmode: 'verify-full',
          sslrootcert: caPath,
        }),
      }),
      false,
    );
  });
}

for (const params of [{ sslmode: 'disable' }, { ssl: '0' }]) {
  test(`DATABASE_URL ${JSON.stringify(params)} explicitly disables TLS`, () => {
    assert.equal(sslConfig({ DATABASE_URL: databaseUrl(params) }), false);
  });
}

for (const mode of ['require', 'verify-full', 'allow', 'prefer', 'verify-ca']) {
  test(`DB_SSLMODE=${mode} keeps strict verification with an explicit CA`, () => {
    const ssl = sslConfig({ DB_SSLMODE: mode, DB_SSLROOTCERT: caPath });
    assert.equal(ssl.ca, ca);
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(ssl.checkServerIdentity, checkServerIdentity);
  });
}

for (const mode of [undefined, 'require', 'verify-full', 'no-verify']) {
  test(`URL CA and client certificates survive DB_SSLMODE=${mode}`, () => {
    const env = {
      DATABASE_URL: databaseUrl({
        sslmode: 'verify-full',
        sslrootcert: caPath,
        sslcert: caPath,
        sslkey: keyPath,
      }),
    };
    if (mode !== undefined) env.DB_SSLMODE = mode;
    const ssl = sslConfig(env);
    assert.equal(ssl.ca, ca);
    assert.equal(ssl.cert, ca);
    assert.equal(ssl.key, key);
    assert.equal(ssl.rejectUnauthorized, mode !== 'no-verify');
  });
}

for (const mode of ['require', 'verify-full', 'no-verify']) {
  test(`DB_SSLMODE=${mode} overrides URL disable without losing certificate material`, () => {
    const ssl = sslConfig({
      DB_SSLMODE: mode,
      DATABASE_URL: databaseUrl({
        sslmode: 'disable',
        sslrootcert: caPath,
        sslcert: caPath,
        sslkey: keyPath,
      }),
    });
    assert.equal(ssl.ca, ca);
    assert.equal(ssl.cert, ca);
    assert.equal(ssl.key, key);
    assert.equal(ssl.rejectUnauthorized, mode !== 'no-verify');
  });
}

test('a URL disable with certificates remains plaintext without an env mode override', () => {
  assert.equal(
    sslConfig({
      DATABASE_URL: databaseUrl({
        sslmode: 'disable',
        sslrootcert: caPath,
        sslcert: caPath,
        sslkey: keyPath,
      }),
    }),
    false,
  );
});

for (const mode of ['require', 'verify-full']) {
  test(`DB_SSLMODE=${mode} overrides a URL verification opt-out without losing its CA`, () => {
    const ssl = sslConfig({
      DB_SSLMODE: mode,
      DATABASE_URL: databaseUrl({ sslmode: 'no-verify', sslrootcert: caPath }),
    });
    assert.equal(ssl.ca, ca);
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(ssl.checkServerIdentity, checkServerIdentity);
  });

  test(`URL sslmode=${mode} remains strict even with libpq compatibility requested`, () => {
    const ssl = sslConfig({
      DATABASE_URL: databaseUrl({
        sslmode: mode,
        uselibpqcompat: 'true',
        sslrootcert: caPath,
      }),
    });
    assert.equal(ssl.ca, ca);
    assert.equal(ssl.rejectUnauthorized, true);
    assert.equal(ssl.checkServerIdentity, checkServerIdentity);
  });
}

test('DB_SSLROOTCERT overrides the URL CA without discarding client certificates', () => {
  const ssl = sslConfig({
    DB_SSLROOTCERT: otherCaPath,
    DATABASE_URL: databaseUrl({
      sslrootcert: caPath,
      sslcert: caPath,
      sslkey: keyPath,
    }),
  });
  assert.equal(ssl.ca, `${ca}\n`);
  assert.equal(ssl.cert, ca);
  assert.equal(ssl.key, key);
  assert.equal(ssl.rejectUnauthorized, true);
});

for (const env of [
  { DB_SSLMODE: 'no-verify', DB_SSLROOTCERT: caPath },
  { DATABASE_URL: databaseUrl({ sslmode: 'no-verify', sslrootcert: caPath }) },
  { DATABASE_URL: databaseUrl({ ssl: 'no-verify' }) },
]) {
  test(`explicit unsafe no-verify compatibility: ${Object.keys(env).join(', ')}`, () => {
    assert.equal(sslConfig(env).rejectUnauthorized, false);
  });
}

for (const mode of ['typo', 'VERIFY-FULL', 'require ']) {
  test(`rejects invalid DB_SSLMODE=${JSON.stringify(mode)}`, () => {
    assert.throws(() => sslConfig({ DB_SSLMODE: mode }), /Invalid DB_SSLMODE/);
  });
}

for (const mode of ['typo', '']) {
  test(`rejects invalid URL sslmode=${JSON.stringify(mode)} even with an env override`, () => {
    assert.throws(
      () =>
        sslConfig({
          DATABASE_URL: databaseUrl({ sslmode: mode }),
          DB_SSLMODE: 'require',
        }),
      /Invalid sslmode in DATABASE_URL/,
    );
  });
}

for (const path of [
  '',
  join(directory, 'missing.pem'),
  directory,
  emptyCaPath,
]) {
  test(`fails actionably for invalid DB_SSLROOTCERT=${JSON.stringify(path)}`, () => {
    assert.throws(
      () => sslConfig({ DB_SSLROOTCERT: path }),
      (error) => {
        assert.match(
          error.message,
          /Unable to read DB_SSLROOTCERT.*readable PEM CA file/,
        );
        assert.ok(error.cause);
        return true;
      },
    );
  });
}

test('a bad explicit CA fails even with DB_SSLMODE=disable', () => {
  assert.throws(
    () =>
      sslConfig({
        DB_SSLMODE: 'disable',
        DB_SSLROOTCERT: join(directory, 'missing.pem'),
      }),
    /DB_SSLROOTCERT/,
  );
});

test('an unreadable URL CA fails actionably without exposing URL credentials', () => {
  assert.throws(
    () =>
      sslConfig({
        DATABASE_URL: databaseUrl({
          sslrootcert: join(directory, 'missing.pem'),
        }),
      }),
    (error) => {
      assert.match(error.message, /DATABASE_URL.*sslrootcert/);
      assert.doesNotMatch(error.message, /password/);
      assert.equal(error.cause.code, 'ENOENT');
      return true;
    },
  );
});

for (const path of ['', emptyCaPath]) {
  test(`rejects an explicit empty URL CA path/file: ${JSON.stringify(path)}`, () => {
    assert.throws(
      () => sslConfig({ DATABASE_URL: databaseUrl({ sslrootcert: path }) }),
      /Invalid sslrootcert in DATABASE_URL/,
    );
  });
}

test(
  'an inaccessible CA fails actionably even when running the main suite as root',
  { skip: process.platform === 'win32' },
  () => {
    const inaccessiblePath = join(directory, 'inaccessible-ca.pem');
    writeFileSync(inaccessiblePath, ca, { mode: 0o000 });
    // A root process can read mode-000 files; a short-lived unprivileged child
    // exercises the actual EACCES path instead of mocking filesystem access.
    const options = process.getuid() === 0 ? { uid: 65534, gid: 65534 } : {};
    const moduleUrl = new URL('../../streaming/database.js', import.meta.url)
      .href;
    execFileSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `
    import assert from 'node:assert/strict';
    import { configFromEnv } from ${JSON.stringify(moduleUrl)};
    assert.throws(() => configFromEnv({ DB_SSLROOTCERT: ${JSON.stringify(inaccessiblePath)} }, 'production'), error => {
      assert.match(error.message, /Unable to read DB_SSLROOTCERT/);
      assert.equal(error.cause.code, 'EACCES');
      return true;
    });
  `,
      ],
      { ...options, timeout: 5000, stdio: 'pipe' },
    );
  },
);

test('verify-full checks the certificate hostname', () => {
  const ssl = sslConfig({ DB_SSLMODE: 'verify-full', DB_SSLROOTCERT: caPath });
  const certificate = new X509Certificate(ca).toLegacyObject();
  assert.equal(
    ssl.checkServerIdentity('database.example', certificate),
    undefined,
  );
  assert.equal(
    ssl.checkServerIdentity('wrong.example', certificate).code,
    'ERR_TLS_CERT_ALTNAME_INVALID',
  );
});

// Exercise the returned options against a real, temporary loopback TLS server.
// Every socket is tracked and closed; each client has a finite timeout.
async function handshake(env, servername = 'database.example') {
  const ssl = sslConfig(env);
  const sockets = new Set();
  const server = createServer({ cert: ca, key }, (socket) => socket.end());
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  server.on('tlsClientError', () => {});
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  let client;
  try {
    return await new Promise((resolve, reject) => {
      client = connect({
        ...ssl,
        host: '127.0.0.1',
        port: server.address().port,
        servername,
      });
      client.setTimeout(3000, () =>
        client.destroy(new Error('Loopback TLS handshake timed out')),
      );
      client.once('secureConnect', () => resolve(client.authorized));
      client.once('error', reject);
    });
  } finally {
    client?.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

for (const mode of ['require', 'verify-full']) {
  test(
    `${mode} accepts a trusted conventional RSA certificate on loopback`,
    { timeout: 5000 },
    async () => {
      assert.equal(
        await handshake({ DB_SSLMODE: mode, DB_SSLROOTCERT: caPath }),
        true,
      );
    },
  );
}

test(
  'verified TLS rejects an untrusted certificate on loopback',
  { timeout: 5000 },
  async () => {
    await assert.rejects(handshake({}), {
      code: 'DEPTH_ZERO_SELF_SIGNED_CERT',
    });
  },
);

test(
  'verify-full rejects a trusted certificate for the wrong hostname on loopback',
  { timeout: 5000 },
  async () => {
    await assert.rejects(
      handshake(
        { DB_SSLMODE: 'verify-full', DB_SSLROOTCERT: caPath },
        'wrong.example',
      ),
      {
        code: 'ERR_TLS_CERT_ALTNAME_INVALID',
      },
    );
  },
);

test(
  'only explicit no-verify accepts an untrusted, wrong-host certificate on loopback',
  { timeout: 5000 },
  async () => {
    assert.equal(
      await handshake({ DB_SSLMODE: 'no-verify' }, 'wrong.example'),
      false,
    );
  },
);
