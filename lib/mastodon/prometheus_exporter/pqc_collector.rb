# frozen_string_literal: true

module Mastodon
  module PrometheusExporter
    # One read-only view of the PQC signing layer, shared by the `pqc:status`
    # rake task, the `/health/pqc` endpoint and the Prometheus reporter below.
    #
    # Every number comes from an aggregate SQL count rather than from loading
    # accounts or keypairs, because the endpoint is polled and the cost has to
    # stay flat no matter how large the server gets.
    class PqcCollector
      ML_DSA_TYPE = 'ml-dsa-87'
      EXPIRY_WINDOW = 7 * 24 * 60 * 60 # seven days, in seconds
      SIGNING_ENV = 'PQC_ACTIVITYPUB_SIGNING'
      EXPORTER_ENV = 'MASTODON_PROMETHEUS_EXPORTER_ENABLED'

      # Gauges only: every value is a point-in-time count, and the exporter
      # rejects a `_total` suffix on gauges. Names are namespaced per
      # subsystem, mirroring the sidekiq_/puma_/http_ names that the bundled
      # instrumentation already emits.
      METRICS = {
        'pqc_runtime_supported' => 'Whether this Ruby/OpenSSL runtime can generate ML-DSA-87 keys (1 = yes).',
        'pqc_signing_enabled' => 'Whether ML-DSA-87 ActivityPub signing is enabled (1 = yes).',
        'pqc_local_accounts' => 'Local accounts on this server.',
        'pqc_accounts_with_usable_key' => 'Local accounts with an unexpired, unrevoked ML-DSA-87 key.',
        'pqc_accounts_missing_key' => 'Local accounts with no usable ML-DSA-87 key.',
        'pqc_ml_dsa_keys_revoked' => 'Revoked ML-DSA-87 keys belonging to local accounts.',
        'pqc_ml_dsa_keys_expiring_7d' => 'Usable ML-DSA-87 keys expiring within seven days.',
      }.freeze

      METRICS_MUTEX = Mutex.new

      class << self
        # `include_remote` is off by default: the remote-account count costs
        # another table scan and only the human-readable report needs it.
        def snapshot(include_remote: false)
          local_accounts = Account.local.count
          keypairs = keypair_counts
          with_key = keypairs[:accounts_with_usable_key]

          values = {
            capability: capability?,
            signing_enabled: signing_enabled?,
            local_accounts: local_accounts,
            accounts_with_usable_key: with_key,
            accounts_missing_key: [local_accounts - with_key, 0].max,
            revoked_keys: keypairs[:revoked_keys],
            keys_expiring_7d: keypairs[:keys_expiring_7d],
          }

          if include_remote
            values[:remote_accounts] = Account.remote.count
            values[:total_accounts] = values[:local_accounts] + values[:remote_accounts]
          end

          values
        end

        # 'degraded' means "configured to attach ML-DSA-87 proofs but cannot
        # do so everywhere". An explicit opt-out is a deliberate configuration
        # and reports 'ok'; a real outage is /health failing, not this.
        def status(values = snapshot)
          degraded = values[:signing_enabled] &&
                     (!values[:capability] || values[:accounts_missing_key].positive?)

          degraded ? 'degraded' : 'ok'
        end

        def degraded_reason(values = snapshot)
          return unless values[:signing_enabled]
          return 'the OpenSSL runtime cannot generate ML-DSA-87 keys' unless values[:capability]

          missing = values[:accounts_missing_key]
          return if missing.zero?

          "#{missing} local #{'account'.pluralize(missing)} without a usable ML-DSA-87 key"
        end

        # Memoised per process: OpenSSL provider support cannot appear at
        # runtime, and the health endpoint must not generate a key per poll.
        def capability?
          return @capability unless @capability.nil?

          @capability = probe_capability
        end

        def signing_enabled?
          ENV[SIGNING_ENV] != 'false'
        end

        def exporter_enabled?
          ENV[EXPORTER_ENV] == 'true'
        end

        # Pushes the gauges through the exporter client, which is the same
        # mechanism the bundled instrumentation uses: Mastodon's exporter has
        # no hook for exporter-side collectors, and plain named gauges need no
        # change to the exporter process.
        def report!(client: nil, flush: false)
          return false unless exporter_enabled?

          require 'prometheus_exporter'
          require 'prometheus_exporter/client'

          client ||= ::PrometheusExporter::Client.default
          values = metric_values(snapshot)

          metrics_for(client).each do |name, metric|
            metric.observe(values.fetch(name))
          end

          # The client sends from a background thread; one-shot callers (the
          # rake task) have to stop it or the process will exit first.
          client.stop(wait_timeout_seconds: 5) if flush

          true
        end

        private

        def probe_capability
          return false unless OpenSSL::PKey.respond_to?(:generate_key)

          OpenSSL::PKey.generate_key(ML_DSA_TYPE)
          true
        rescue OpenSSL::OpenSSLError, NotImplementedError
          false
        end

        # One aggregate query for the whole key section: a single pass over
        # keypairs, no per-account work, and no rows loaded into Ruby. Values
        # are quoted through the connection, never taken from user input.
        def keypair_counts
          type = Keypair.types[ML_DSA_TYPE]
          return { accounts_with_usable_key: 0, revoked_keys: 0, keys_expiring_7d: 0 } if type.nil?

          connection = Keypair.connection
          now = Time.current
          quoted_type = connection.quote(type)
          quoted_now = connection.quote(now)
          quoted_limit = connection.quote(now + EXPIRY_WINDOW)

          sql = <<~SQL.squish
            SELECT
              COUNT(DISTINCT accounts.id) FILTER (
                WHERE keypairs.revoked = FALSE
                  AND (keypairs.expires_at IS NULL OR keypairs.expires_at > #{quoted_now})
              ) AS accounts_with_usable_key,
              COUNT(*) FILTER (WHERE keypairs.revoked = TRUE) AS revoked_keys,
              COUNT(*) FILTER (
                WHERE keypairs.revoked = FALSE
                  AND keypairs.expires_at > #{quoted_now}
                  AND keypairs.expires_at <= #{quoted_limit}
              ) AS keys_expiring_7d
            FROM keypairs
            INNER JOIN accounts ON accounts.id = keypairs.account_id
            WHERE keypairs.type = #{quoted_type} AND accounts.domain IS NULL
          SQL

          row = connection.select_one(sql)

          {
            accounts_with_usable_key: row['accounts_with_usable_key'].to_i,
            revoked_keys: row['revoked_keys'].to_i,
            keys_expiring_7d: row['keys_expiring_7d'].to_i,
          }
        end

        def metric_values(values)
          {
            'pqc_runtime_supported' => values[:capability] ? 1 : 0,
            'pqc_signing_enabled' => values[:signing_enabled] ? 1 : 0,
            'pqc_local_accounts' => values[:local_accounts],
            'pqc_accounts_with_usable_key' => values[:accounts_with_usable_key],
            'pqc_accounts_missing_key' => values[:accounts_missing_key],
            'pqc_ml_dsa_keys_revoked' => values[:revoked_keys],
            'pqc_ml_dsa_keys_expiring_7d' => values[:keys_expiring_7d],
          }
        end

        # Client#register appends to the client every time it is called, so
        # register once per client and reuse the returned remote metrics.
        def metrics_for(client)
          METRICS_MUTEX.synchronize do
            unless defined?(@metrics_client) && @metrics_client.equal?(client)
              @metrics_client = client
              @metrics = {}
            end

            METRICS.each_key.to_h do |name|
              [name, @metrics[name] ||= client.register('gauge', name, METRICS.fetch(name))]
            end
          end
        end
      end
    end
  end
end
