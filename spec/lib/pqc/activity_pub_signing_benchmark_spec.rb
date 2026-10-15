# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Pqc::ActivityPubSigningBenchmark do
  include PqcKeyProvisioningHelpers

  let(:account) { Fabricate(:account, username: 'pqc_benchmark') }

  before do
    generate_real_ml_dsa_44_key
    ActivityPub::GeneratePqcKeyService.new.call(account)
  end

  it 'compares both outbound paths and restores the signing feature flag' do
    ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: 'false' do
      report = described_class.new(account, iterations: 2).call

      expect(report).to include(
        account: 'pqc_benchmark',
        iterations: 2,
        ml_dsa_proof_bytes: 2420
      )
      expect(report[:rsa_only]).to include(:mean_ms, :median_ms, :p95_ms, :max_ms)
      expect(report[:rsa_plus_ml_dsa44]).to include(:mean_ms, :median_ms, :p95_ms, :max_ms)
      expect(ENV.fetch('PQC_ACTIVITYPUB_SIGNING', nil)).to eq('false')
    end
  end

  it 'rejects an out-of-range iteration count' do
    expect { described_class.new(account, iterations: 501).call }
      .to raise_error(ArgumentError, /between 1 and 500/)
  end
end
