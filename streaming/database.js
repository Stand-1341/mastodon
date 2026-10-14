import { readFileSync } from 'node:fs';
import { checkServerIdentity } from 'node:tls';

import pg from 'pg';
import pgConnectionString from 'pg-connection-string';

import { parseIntFromEnvValue } from './utils.js';

/**
 * @param {NodeJS.ProcessEnv} env the `process.env` value to read configuration from
 * @param {string} environment
 * @returns {pg.PoolConfig} the configuration for the PostgreSQL connection
 */
export function configFromEnv(env, environment) {
  /** @type {Record<string, pg.PoolConfig>} */
  const pgConfigs = {
    development: {
      user: env.DB_USER || pg.defaults.user,
      password: env.DB_PASS || pg.defaults.password,
      database: env.DB_NAME || 'mastodon_development',
      host: env.DB_HOST || pg.defaults.host,
      port: parseIntFromEnvValue(env.DB_PORT, pg.defaults.port ?? 5432, 'DB_PORT')
    },

    production: {
      user: env.DB_USER || 'mastodon',
      password: env.DB_PASS || '',
      database: env.DB_NAME || 'mastodon_production',
      host: env.DB_HOST || 'localhost',
      port: parseIntFromEnvValue(env.DB_PORT, 5432, 'DB_PORT')
    },
  };

  /**
   * @type {pg.PoolConfig}
   */
  let baseConfig = {};
  /** @type {string | undefined} */
  let urlSslMode;

  if (env.DATABASE_URL) {
    let parsedUrl;
    /** @type {import('node:tls').ConnectionOptions | undefined} */
    let urlCertificateOptions;
    try {
      parsedUrl = pgConnectionString.parse(env.DATABASE_URL);
      if (parsedUrl.ssl === false && (parsedUrl.sslcert || parsedUrl.sslkey || parsedUrl.sslrootcert)) {
        // The parser loads these files, then discards them for sslmode=disable.
        // Retain them in case DB_SSLMODE explicitly re-enables verified TLS.
        urlCertificateOptions = {
          cert: parsedUrl.sslcert ? readFileSync(parsedUrl.sslcert, 'utf8') : undefined,
          key: parsedUrl.sslkey ? readFileSync(parsedUrl.sslkey, 'utf8') : undefined,
          ca: parsedUrl.sslrootcert ? readFileSync(parsedUrl.sslrootcert, 'utf8') : undefined,
        };
      }
    } catch (error) {
      throw new Error('Unable to parse DATABASE_URL; check its format and sslrootcert/sslcert/sslkey file paths', { cause: error });
    }
    urlSslMode = parsedUrl.sslmode ?? (parsedUrl.ssl === false ? 'disable' : undefined);
    if (parsedUrl.sslrootcert === '') {
      throw new Error('Invalid sslrootcert in DATABASE_URL; provide a readable PEM CA file path');
    }

    // The result of dbUrlToConfig from pg-connection-string is not type
    // compatible with pg.PoolConfig, since parts of the connection URL may be
    // `null` when pg.PoolConfig expects `undefined`, as such we have to
    // manually create the baseConfig object from the properties of the
    // parsedUrl.
    //
    // For more information see:
    // https://github.com/brianc/node-postgres/issues/2280
    //
    // FIXME: clean up once brianc/node-postgres#3128 lands
    if (typeof parsedUrl.password === 'string') baseConfig.password = parsedUrl.password;
    if (typeof parsedUrl.host === 'string') baseConfig.host = parsedUrl.host;
    if (typeof parsedUrl.user === 'string') baseConfig.user = parsedUrl.user;
    if (typeof parsedUrl.port === 'string' && parsedUrl.port) {
      const parsedPort = parseInt(parsedUrl.port, 10);
      if (isNaN(parsedPort)) {
        throw new Error('Invalid port specified in DATABASE_URL environment variable');
      }
      baseConfig.port = parsedPort;
    }
    if (typeof parsedUrl.database === 'string') baseConfig.database = parsedUrl.database;
    if (typeof parsedUrl.options === 'string') baseConfig.options = parsedUrl.options;

    // The parser's types omit the TLS options object it returns for certificate
    // paths. Keep the certificate material, but apply our verification policy below.
    if (typeof parsedUrl.ssl === 'boolean') {
      baseConfig.ssl = parsedUrl.ssl;
    }
    if (urlCertificateOptions || (typeof parsedUrl.ssl === 'object' && !Array.isArray(parsedUrl.ssl) && parsedUrl.ssl !== null)) {
      const sslOptions = urlCertificateOptions ?? /** @type {import('node:tls').ConnectionOptions} */ (parsedUrl.ssl);
      if (typeof sslOptions.ca === 'string' && sslOptions.ca.trim() === '') {
        throw new Error('Invalid sslrootcert in DATABASE_URL; CA file is empty');
      }
      baseConfig.ssl = {
        cert: sslOptions.cert,
        key: sslOptions.key,
        ca: sslOptions.ca,
      };
    } else if (parsedUrl.ssl === 'no-verify') {
      urlSslMode ??= 'no-verify';
    }

    // Support overriding the database password in the connection URL
    if (!baseConfig.password && env.DB_PASS) {
      baseConfig.password = env.DB_PASS;
    }
  } else if (Object.hasOwn(pgConfigs, environment)) {
    baseConfig = pgConfigs[environment];
  } else {
    throw new Error('Unable to resolve postgresql database configuration.');
  }

  // Check explicit CA paths even when TLS is disabled: a typo must not silently
  // become a different trust configuration when TLS is subsequently enabled.
  let rootCert;
  if (env.DB_SSLROOTCERT !== undefined) {
    try {
      if (env.DB_SSLROOTCERT === '') throw new Error('expected a non-empty file path');
      rootCert = readFileSync(env.DB_SSLROOTCERT, 'utf8');
      if (rootCert.trim() === '') throw new Error('CA file is empty');
    } catch (error) {
      throw new Error(`Unable to read DB_SSLROOTCERT ${JSON.stringify(env.DB_SSLROOTCERT)}; provide a readable PEM CA file`, { cause: error });
    }
  }

  // Reject unknown URL modes even if DB_SSLMODE overrides them, so configuration
  // mistakes cannot silently change the verification policy.
  const validModes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full', 'no-verify'];
  if (urlSslMode !== undefined && !validModes.includes(urlSslMode)) {
    throw new Error(`Invalid sslmode in DATABASE_URL: ${JSON.stringify(urlSslMode)}`);
  }

  const sslMode = env.DB_SSLMODE ?? urlSslMode ?? (baseConfig.ssl === false ? 'disable' : 'require');
  const sslOptions = typeof baseConfig.ssl === 'object' ? baseConfig.ssl : {};
  switch (sslMode) {
  case 'disable':
  case '':
    baseConfig.ssl = false;
    break;
  case 'no-verify':
    baseConfig.ssl = { ...sslOptions, rejectUnauthorized: false };
    break;
  case 'allow':
  case 'prefer':
  case 'require':
  case 'verify-ca':
  case 'verify-full':
    // Preserve the existing verified-TLS behavior of these streaming modes;
    // unlike libpq, there is no plaintext fallback or hostname-verification opt-out.
    baseConfig.ssl = { ...sslOptions, rejectUnauthorized: true, checkServerIdentity };
    break;
  default:
    throw new Error(`Invalid DB_SSLMODE: ${JSON.stringify(sslMode)}; expected ${validModes.join(', ')}`);
  }

  if (rootCert !== undefined && typeof baseConfig.ssl === 'object') {
    baseConfig.ssl.ca = rootCert;
  }

  return {
    ...baseConfig,
    max: parseIntFromEnvValue(env.DB_POOL, 10, 'DB_POOL'),
    connectionTimeoutMillis: 15000,
    // Deliberately set application_name to an empty string to prevent excessive
    // CPU usage with PG Bouncer. See:
    // - https://github.com/mastodon/mastodon/pull/23958
    // - https://github.com/pgbouncer/pgbouncer/issues/349
    application_name: '',
  };
}

let pool;
/**
 *
 * @param {pg.PoolConfig} config
 * @param {string} environment
 * @param {import('pino').Logger} logger
 * @returns {pg.Pool}
 */
export function getPool(config, environment, logger) {
  if (pool) {
    return pool;
  }

  pool = new pg.Pool(config);

  // Setup logging on pool.query and client.query for checked out clients:
  // This is taken from: https://node-postgres.com/guides/project-structure
  if (environment === 'development') {
    const logQuery = (originalQuery) => {
      return async (queryTextOrConfig, values, ...rest) => {
        const start = process.hrtime();

        const result = await originalQuery.apply(pool, [queryTextOrConfig, values, ...rest]);

        const duration = process.hrtime(start);
        const durationInMs = (duration[0] * 1000000000 + duration[1]) / 1000000;

        logger.debug({
          query: queryTextOrConfig,
          values,
          duration: durationInMs
        }, 'Executed database query');

        return result;
      };
    };

    pool.on('connect', (client) => {
      const originalQuery = client.query.bind(client);
      client.query = logQuery(originalQuery);
    });
  }

  return pool;
}
