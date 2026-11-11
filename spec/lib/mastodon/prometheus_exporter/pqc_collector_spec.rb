# frozen_string_literal: true

require 'rails_helper'
require 'prometheus_exporter'
require 'prometheus_exporter/client'
require 'mastodon/prometheus_exporter/pqc_collector'

RSpec.describe Mastodon::PrometheusExporter::PqcCollector do
  include PqcKeyProvisioningHelpers

  let(:ml_dsa_public_key) { synthetic_ml_dsa_87_public_key }

  # The full snapshot shape, so an example can vary a single field.
  def snapshot_values(overrides = {})
    {
      capability: true,
      signing_enabled: true,
      local_accounts: 2,
      accounts_with_usable_key: 2,
      accounts_missing_key: 0,
      revoked_keys: 0,
      keys_expiring_7d: 0,
    }.merge(overrides)
  end

  before do
    # `capability?` memoises for the life of the process, so a previous
    # example (or another spec file) must not decide what this one sees.
    described_class.instance_variable_set(:@capability, nil)

    # A local account provisions an ML-DSA-87 key after commit on a capable
    # runtime, which would make the expected counts depend on the host OpenSSL.
    allow(ActivityPub::GeneratePqcKeyService).to receive(:new)
      .and_return(instance_double(ActivityPub::GeneratePqcKeyService, call: nil))
  end

  after do
    described_class.instance_variable_set(:@capability, nil)
    described_class.instance_variable_set(:@metrics_client, nil)
    described_class.instance_variable_set(:@metrics, nil)
  end

  describe '.snapshot' do
    before do
      allow(described_class).to receive(:capability?).and_return(false)

      # The test database is seeded with the instance actor (a local account
      # with only an RSA key), so counts would otherwise start at one.
      Account.where(id: Account::INSTANCE_ACTOR_ID).delete_all
    end

    it 'returns the documented keys and zeroed counts on an empty database' do
      ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true') do
        values = described_class.snapshot

        expect(values.keys).to contain_exactly(
          :capability,
          :signing_enabled,
          :local_accounts,
          :accounts_with_usable_key,
          :accounts_missing_key,
          :revoked_keys,
          :keys_expiring_7d
        )
        expect(values).to include(
          capability: false,
          signing_enabled: true,
          local_accounts: 0,
          accounts_with_usable_key: 0,
          accounts_missing_key: 0,
          revoked_keys: 0,
          keys_expiring_7d: 0
        )
      end
    end

    it 'reflects the signing opt-out' do
      ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'false') do
        expect(described_class.snapshot[:signing_enabled]).to be(false)
      end
    end

    context 'with local and remote accounts' do
      before do
        Fabricate(:account)
        Fabricate(:account)
        Fabricate(:remote_account)
      end

      it 'omits the remote totals by default' do
        values = described_class.snapshot

        expect(values).to_not have_key(:remote_accounts)
        expect(values).to_not have_key(:total_accounts)
        expect(values[:local_accounts]).to eq 2
      end

      it 'includes and sums the remote totals when asked' do
        values = described_class.snapshot(include_remote: true)

        expect(values).to include(remote_accounts: 1, total_accounts: 3)
      end
    end

    context 'with ML-DSA-87 keypairs' do
      it 'counts a local account with a usable key once' do
        account = Fabricate(:account)
        Fabricate(:keypair, account: account, type: :'ml-dsa-87', public_key: ml_dsa_public_key)

        expect(described_class.snapshot).to include(
          local_accounts: 1,
          accounts_with_usable_key: 1,
          accounts_missing_key: 0,
          revoked_keys: 0
        )
      end

      it 'counts an account once even when it has rotated through several usable keys' do
        account = Fabricate(:account)
        2.times { Fabricate(:keypair, account: account, type: :'ml-dsa-87', public_key: ml_dsa_public_key) }

        expect(described_class.snapshot).to include(
          accounts_with_usable_key: 1,
          accounts_missing_key: 0
        )
      end

      it 'moves a revoked key out of the usable accounts and into revoked_keys' do
        account = Fabricate(:account)
        Fabricate(:keypair, account: account, type: :'ml-dsa-87', public_key: ml_dsa_public_key, revoked: true)

        expect(described_class.snapshot).to include(
          local_accounts: 1,
          accounts_with_usable_key: 0,
          accounts_missing_key: 1,
          revoked_keys: 1
        )
      end

      it 'does not treat an expired key as usable' do
        account = Fabricate(:account)
        Fabricate(:keypair, account: account, type: :'ml-dsa-87', public_key: ml_dsa_public_key, expires_at: 1.minute.ago)

        expect(described_class.snapshot).to include(
          accounts_with_usable_key: 0,
          accounts_missing_key: 1,
          revoked_keys: 0,
          keys_expiring_7d: 0
        )
      end

      it 'flags keys expiring within seven days but not later ones' do
        expiring_soon = Fabricate(:account)
        expiring_later = Fabricate(:account)
        Fabricate(:keypair, account: expiring_soon, type: :'ml-dsa-87', public_key: ml_dsa_public_key, expires_at: 6.days.from_now)
        Fabricate(:keypair, account: expiring_later, type: :'ml-dsa-87', public_key: ml_dsa_public_key, expires_at: 30.days.from_now)

        expect(described_class.snapshot).to include(
          local_accounts: 2,
          accounts_with_usable_key: 2,
          accounts_missing_key: 0,
          keys_expiring_7d: 1
        )
      end

      it 'ignores every key belonging to a remote account' do
        remote = Fabricate(:remote_account)
        Fabricate(:keypair, account: remote, type: :'ml-dsa-87', public_key: ml_dsa_public_key, expires_at: 1.day.from_now)
        Fabricate(:keypair, account: remote, type: :'ml-dsa-87', public_key: ml_dsa_public_key, revoked: true)

        expect(described_class.snapshot).to include(
          local_accounts: 0,
          accounts_with_usable_key: 0,
          accounts_missing_key: 0,
          revoked_keys: 0,
          keys_expiring_7d: 0
        )
      end

      it 'ignores keypairs of other types' do
        account = Fabricate(:account)

        expect(account.keypairs.pluck(:type)).to eq ['rsa']
        expect(described_class.snapshot).to include(
          accounts_with_usable_key: 0,
          accounts_missing_key: 1
        )
      end

      it 'never reports a negative missing count' do
        allow(described_class).to receive(:keypair_counts).and_return(
          accounts_with_usable_key: 5,
          revoked_keys: 0,
          keys_expiring_7d: 0
        )

        expect(described_class.snapshot[:accounts_missing_key]).to eq 0
      end
    end
  end

  describe '.status' do
    subject(:status) { described_class.status(values) }

    let(:values) { snapshot_values }

    context 'when signing is enabled and every local account has a usable key' do
      it { is_expected.to eq 'ok' }
    end

    context 'when signing is enabled and an account is missing a key' do
      let(:values) { snapshot_values(accounts_missing_key: 1) }

      it 'reports degraded' do
        expect(status).to eq 'degraded'
      end
    end

    context 'when signing is enabled but the runtime cannot generate keys' do
      let(:values) { snapshot_values(capability: false) }

      it 'reports degraded even with a fully keyed database' do
        expect(status).to eq 'degraded'
      end
    end

    context 'when signing is explicitly disabled and an account is missing a key' do
      let(:values) { snapshot_values(signing_enabled: false, accounts_missing_key: 4) }

      it 'reports ok, because an opt-out is a configuration and not a fault' do
        expect(status).to eq 'ok'
      end
    end

    context 'when signing is explicitly disabled and every account has a key' do
      let(:values) { snapshot_values(signing_enabled: false) }

      it 'stays ok' do
        expect(status).to eq 'ok'
      end
    end

    context 'with the live snapshot default' do
      before do
        Account.where(id: Account::INSTANCE_ACTOR_ID).delete_all
        Fabricate(:account)
        allow(described_class).to receive(:capability?).and_return(true)
      end

      it 'reports ok for an opt-out even though the account has no PQC key' do
        ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'false') do
          expect(described_class.status).to eq 'ok'
          expect(described_class.degraded_reason).to be_nil
        end
      end
    end
  end

  describe '.degraded_reason' do
    subject(:reason) { described_class.degraded_reason(values) }

    let(:values) { snapshot_values }

    it { is_expected.to be_nil }

    context 'when the runtime cannot generate ML-DSA-87 keys' do
      let(:values) { snapshot_values(capability: false) }

      it { is_expected.to eq 'the OpenSSL runtime cannot generate ML-DSA-87 keys' }
    end

    context 'when one local account is missing a key' do
      let(:values) { snapshot_values(accounts_missing_key: 1) }

      it { is_expected.to eq '1 local account without a usable ML-DSA-87 key' }
    end

    context 'when several local accounts are missing a key' do
      let(:values) { snapshot_values(accounts_missing_key: 3) }

      it { is_expected.to eq '3 local accounts without a usable ML-DSA-87 key' }
    end

    context 'when both the runtime and the accounts are at fault' do
      let(:values) { snapshot_values(capability: false, accounts_missing_key: 2) }

      it 'blames the runtime first' do
        expect(reason).to eq 'the OpenSSL runtime cannot generate ML-DSA-87 keys'
      end
    end

    context 'when signing is explicitly disabled' do
      let(:values) { snapshot_values(signing_enabled: false, capability: false, accounts_missing_key: 5) }

      it 'has no reason to report' do
        expect(reason).to be_nil
      end
    end
  end

  describe '.signing_enabled?' do
    it 'is enabled when the variable is unset' do
      ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: nil) do
        expect(described_class.signing_enabled?).to be(true)
      end
    end

    it 'only treats the exact string "false" as an opt-out' do
      expectations = {
        nil => true,
        '' => true,
        'true' => true,
        '0' => true,
        'FALSE' => true,
        'false' => false,
      }

      observed = expectations.keys.to_h do |raw|
        [raw, ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: raw) { described_class.signing_enabled? }]
      end

      expect(observed).to eq(expectations)
    end
  end

  describe '.report!' do
    let(:client) { instance_double(PrometheusExporter::Client, stop: nil) }
    let(:registrations) { [] }
    let(:observations) { {} }

    let(:metrics) do
      described_class::METRICS.each_key.to_h do |name|
        metric = instance_double(PrometheusExporter::Client::RemoteMetric)
        allow(metric).to receive(:observe) { |value| observations[name] = value }
        [name, metric]
      end
    end

    before do
      allow(client).to receive(:register) do |type, name, help|
        registrations << [type, name, help]
        metrics.fetch(name)
      end

      allow(described_class).to receive(:snapshot).and_return(
        snapshot_values(
          local_accounts: 5,
          accounts_with_usable_key: 3,
          accounts_missing_key: 2,
          revoked_keys: 1,
          keys_expiring_7d: 4
        )
      )
    end

    context 'when the exporter is disabled' do
      it 'returns false without touching the client' do
        ClimateControl.modify(MASTODON_PROMETHEUS_EXPORTER_ENABLED: nil) do
          expect(described_class.report!(client: client)).to be(false)
        end

        expect(client).to_not have_received(:register)
        expect(client).to_not have_received(:stop)
      end
    end

    context 'when the exporter is enabled' do
      around do |example|
        ClimateControl.modify(MASTODON_PROMETHEUS_EXPORTER_ENABLED: 'true') { example.run }
      end

      it 'returns true' do
        expect(described_class.report!(client: client)).to be(true)
      end

      it 'registers every metric as a gauge with its description' do
        described_class.report!(client: client)

        expect(registrations).to eq(described_class::METRICS.map { |name, help| ['gauge', name, help] })
      end

      it 'observes each gauge once with the snapshot value' do
        described_class.report!(client: client)

        expect(metrics.values).to all(have_received(:observe).once)
        expect(observations).to eq(
          'pqc_runtime_supported' => 1,
          'pqc_signing_enabled' => 1,
          'pqc_local_accounts' => 5,
          'pqc_accounts_with_usable_key' => 3,
          'pqc_accounts_missing_key' => 2,
          'pqc_ml_dsa_keys_revoked' => 1,
          'pqc_ml_dsa_keys_expiring_7d' => 4
        )
      end

      it 'coerces a false capability and a disabled signing flag to 0' do
        allow(described_class).to receive(:snapshot)
          .and_return(snapshot_values(capability: false, signing_enabled: false))

        described_class.report!(client: client)

        expect(observations).to include('pqc_runtime_supported' => 0, 'pqc_signing_enabled' => 0)
      end

      it 'does not stop the client unless asked to flush' do
        described_class.report!(client: client)

        expect(client).to_not have_received(:stop)
      end

      it 'stops the client after flushing' do
        described_class.report!(client: client, flush: true)

        expect(client).to have_received(:stop).with(wait_timeout_seconds: 5)
      end

      it 'reuses the registered gauges across repeated calls' do
        2.times { described_class.report!(client: client) }

        expect(client).to have_received(:register).exactly(7).times
        expect(metrics.values).to all(have_received(:observe).twice)
      end
    end
  end

  describe '.capability?' do
    it 'probes once and memoises a supported runtime' do
      allow(described_class).to receive(:probe_capability).and_return(true)

      expect(described_class.capability?).to be(true)
      expect(described_class.capability?).to be(true)
      expect(described_class).to have_received(:probe_capability).once
    end

    it 'memoises an unsupported runtime instead of probing again' do
      allow(described_class).to receive(:probe_capability).and_return(false)

      expect(described_class.capability?).to be(false)
      expect(described_class.capability?).to be(false)
      expect(described_class).to have_received(:probe_capability).once
    end

    it 'reports false when the runtime raises while generating a key' do
      allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-87').and_raise(OpenSSL::OpenSSLError)

      expect(described_class.capability?).to be(false)
    end
  end
end
