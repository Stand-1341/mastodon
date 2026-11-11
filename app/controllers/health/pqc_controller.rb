# frozen_string_literal: true

require 'mastodon/prometheus_exporter/pqc_collector'

module Health
  # Unauthenticated, read-only view of the PQC signing layer for uptime checks
  # and monitoring. Counts only: no account identifiers or key material.
  class PqcController < ActionController::Base # rubocop:disable Rails/ApplicationController
    def show
      collector = Mastodon::PrometheusExporter::PqcCollector
      values = collector.snapshot

      render json: {
        status: collector.status(values),
        capability: values[:capability],
        signing_enabled: values[:signing_enabled],
        accounts_with_key: values[:accounts_with_usable_key],
        accounts_missing_key: values[:accounts_missing_key],
      }
    end
  end
end
