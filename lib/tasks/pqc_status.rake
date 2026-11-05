# frozen_string_literal: true

namespace :pqc do
  desc 'Report ML-DSA-87 signing status: runtime capability, signing switch and key coverage'
  task status: :environment do
    # Required here rather than at the top of the file: rake loads task files
    # before :environment, which is when Rails puts lib/ on the load path.
    require 'mastodon/prometheus_exporter/pqc_collector'

    collector = Mastodon::PrometheusExporter::PqcCollector
    values = collector.snapshot(include_remote: true)

    signing_state = if values[:signing_enabled]
                      'enabled (default; set PQC_ACTIVITYPUB_SIGNING=false to opt out)'
                    else
                      'disabled (PQC_ACTIVITYPUB_SIGNING=false)'
                    end

    section = lambda do |title, rows|
      puts title
      rows.each { |label, value| puts format('  %-32s %s', label, value) }
      puts
    end

    count = ->(number) { ActiveSupport::NumberHelper.number_to_delimited(number) }

    puts "PQC status at #{Time.current.utc.strftime('%Y-%m-%d %H:%M:%S UTC')}"
    puts

    section.call('Runtime', [
                   ['OpenSSL', OpenSSL::OPENSSL_VERSION],
                   ['ML-DSA-87 key generation', values[:capability] ? 'supported' : 'unsupported'],
                 ])

    section.call('Signing', [
                   ['PQC_ACTIVITYPUB_SIGNING', signing_state],
                 ])

    section.call('Accounts', [
                   ['Local', count.call(values[:local_accounts])],
                   ['Remote', count.call(values[:remote_accounts])],
                   ['Total', count.call(values[:total_accounts])],
                 ])

    section.call('ML-DSA-87 keys (local accounts)', [
                   ['Accounts with a usable key', count.call(values[:accounts_with_usable_key])],
                   ['Accounts missing a usable key', count.call(values[:accounts_missing_key])],
                   ['Revoked keys', count.call(values[:revoked_keys])],
                   ['Expiring within 7 days', count.call(values[:keys_expiring_7d])],
                 ])

    reason = collector.degraded_reason(values)
    puts "Status: #{collector.status(values).upcase}#{reason ? " (#{reason})" : ''}"

    if values[:signing_enabled] && !values[:capability]
      puts 'Next step: use OpenSSL 3.5 or newer with ML-DSA support, or set PQC_ACTIVITYPUB_SIGNING=false to fall back to RSA-only signing.'
    elsif values[:accounts_missing_key].positive? && values[:signing_enabled]
      puts 'Next step: bin/rails pqc:backfill'
    elsif !values[:signing_enabled]
      puts 'Note: PQC signing is explicitly disabled; ML-DSA-87 keys are still published but no proofs are attached.'
    end
  end

  desc 'Push PQC gauges to the Prometheus exporter (schedule every minute)'
  task metrics: :environment do
    require 'mastodon/prometheus_exporter/pqc_collector'

    collector = Mastodon::PrometheusExporter::PqcCollector

    unless collector.exporter_enabled?
      puts "Prometheus exporter is disabled (#{collector::EXPORTER_ENV} is not 'true'); nothing to push."
      next
    end

    collector.report!(flush: true)
    puts "Sent #{collector::METRICS.size} PQC gauges to the Prometheus exporter."
  end
end
