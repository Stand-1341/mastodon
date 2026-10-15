# frozen_string_literal: true

require 'benchmark'

class Pqc::ActivityPubSigningBenchmark
  DEFAULT_ITERATIONS = 20
  MAX_ITERATIONS = 500

  def initialize(account, iterations: DEFAULT_ITERATIONS)
    @account = account
    @iterations = Integer(iterations)
  rescue ArgumentError, TypeError
    raise ArgumentError, 'Benchmark iterations must be an integer between 1 and 500'
  end

  def call
    raise ArgumentError, 'A persisted local account is required' unless @account&.persisted? && @account.local?
    raise ArgumentError, 'Benchmark iterations must be between 1 and 500' unless @iterations.between?(1, MAX_ITERATIONS)
    raise ArgumentError, 'A usable ML-DSA-44 key must be provisioned for this account' unless @account.keypair(type: :'ml-dsa-44')&.usable?
    raise ArgumentError, 'A usable RSA key must be available for this account' unless @account.keypair(type: :rsa)&.usable?

    rsa_signer = ->(payload) { ActivityPub::LinkedDataSignature.new(payload).sign!(@account) }
    dual_signer = ->(payload) { ActivityPub::PqcSigning.new(payload).sign!(@account) }

    previous_setting = ENV.fetch('PQC_ACTIVITYPUB_SIGNING', nil)
    ENV['PQC_ACTIVITYPUB_SIGNING'] = 'false'
    rsa_signer.call(payload(0))
    rsa = measure(rsa_signer)

    ENV['PQC_ACTIVITYPUB_SIGNING'] = 'true'
    dual_signer.call(payload(-1))
    dual = measure(dual_signer)

    {
      account: @account.username,
      iterations: @iterations,
      measurement: 'warm Rails signing path including key lookup, JSON-LD canonicalization, and cryptographic signing',
      rsa_only: rsa,
      rsa_plus_ml_dsa44: dual,
      incremental_median_ms: (dual[:median_ms] - rsa[:median_ms]).round(2),
      ml_dsa_proof_bytes: 2420,
    }
  ensure
    if defined?(previous_setting)
      previous_setting.nil? ? ENV.delete('PQC_ACTIVITYPUB_SIGNING') : ENV['PQC_ACTIVITYPUB_SIGNING'] = previous_setting
    end
  end

  private

  def measure(signer)
    samples = (1..@iterations).map do |index|
      (Benchmark.realtime { signer.call(payload(index)) } * 1000).round(4)
    end.sort
    middle = samples.length / 2
    median = if samples.length.odd?
               samples[middle]
             else
               (samples[middle - 1] + samples[middle]) / 2
             end

    {
      mean_ms: (samples.sum / samples.length).round(2),
      median_ms: median.round(2),
      p95_ms: samples[[(samples.length * 0.95).ceil - 1, 0].max].round(2),
      max_ms: samples.last.round(2),
    }
  end

  def payload(index)
    actor_uri = ActivityPub::TagManager.instance.uri_for(@account)
    base_uri = actor_uri.delete_suffix("/@#{@account.username}")
    {
      '@context' => ['https://www.w3.org/ns/activitystreams'],
      'id' => "#{base_uri}/activities/pqc-benchmark-#{index}",
      'type' => 'Create',
      'actor' => actor_uri,
      'object' => {
        'id' => "#{base_uri}/objects/pqc-benchmark-#{index}",
        'type' => 'Note',
        'content' => 'Representative benchmark ActivityPub content',
        'attributedTo' => actor_uri,
      },
    }
  end
end
