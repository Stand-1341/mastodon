# frozen_string_literal: true

require 'rails_helper'
require 'rake'
require 'stringio'

# The tasks require the collector themselves, inside their bodies, because
# rake loads task files before :environment puts lib/ on the load path. This
# harness replaces :environment with a no-op task, so the collaborator is
# loaded up front to let examples stub it before the task runs; the tasks'
# own require still has to resolve it when invoked.
require 'mastodon/prometheus_exporter/pqc_collector'

RSpec.describe Rake::Task do
  include PqcKeyProvisioningHelpers

  let(:collector) { Mastodon::PrometheusExporter::PqcCollector }

  def capture_stdout
    original_stdout = $stdout
    $stdout = StringIO.new
    yield
    $stdout.string
  ensure
    $stdout = original_stdout
  end

  # The task prints rows with `format('  %-32s %s', label, value)`; split on
  # the run of spaces so assertions do not depend on the column width.
  def report_rows(stdout)
    stdout.lines.filter_map do |line|
      next unless line.start_with?('  ')

      label, value = line.strip.split(/\s{2,}/, 2)
      [label, value]
    end.to_h
  end

  describe 'pqc:status' do
    subject(:task) { described_class['pqc:status'] }

    let(:public_key) { synthetic_ml_dsa_87_public_key }
    let(:private_key) { SigningKeysHelpers::PRIVATE_RSA_TEST_KEY }
    let(:native_key) { instance_double(OpenSSL::PKey::PKey, private_to_pem: private_key, public_to_pem: public_key) }

    around do |example|
      # `capability?` memoises per process: clear it so the OpenSSL stub
      # decides the value here, then restore whatever the rest of the suite had.
      previous_capability = collector.instance_variable_get(:@capability)

      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc_status.rake')
        collector.instance_variable_set(:@capability, nil)
        example.run
      ensure
        collector.instance_variable_set(:@capability, previous_capability)
      end
    end

    before do
      # Two call sites with different casing: the collector's capability probe
      # uses ML_DSA_TYPE ('ml-dsa-87'), the provisioning service uses
      # 'ML-DSA-87' (which account creation triggers through the callback).
      allow(OpenSSL::PKey).to receive(:generate_key).with(collector::ML_DSA_TYPE).and_return(native_key)
      allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-87').and_return(native_key)
    end

    def run_status(signing: 'true')
      stdout = ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: signing) do
        capture_stdout { task.invoke }
      end

      [report_rows(stdout), stdout]
    end

    it 'reports OK and prints every section when there are no accounts' do
      rows, stdout = run_status

      expect(rows).to include(
        'ML-DSA-87 key generation' => 'supported',
        'Local' => '0',
        'Remote' => '0',
        'Total' => '0',
        'Accounts with a usable key' => '0',
        'Accounts missing a usable key' => '0',
        'Revoked keys' => '0',
        'Expiring within 7 days' => '0'
      )
      expect(stdout).to include('PQC status at', OpenSSL::OPENSSL_VERSION)
      expect(stdout).to match(/^Status: OK$/)
      expect(stdout).to_not include('Next step', 'Note:')
    end

    it 'reports DEGRADED and the backfill next step when a local account lacks a usable key' do
      account = Fabricate(:account, username: 'status_missing')
      account.keypairs.where(type: :'ml-dsa-87').delete_all

      rows, stdout = run_status

      expect(rows).to include(
        'Local' => '1',
        'Accounts with a usable key' => '0',
        'Accounts missing a usable key' => '1'
      )
      expect(stdout).to include('Status: DEGRADED (1 local account without a usable ML-DSA-87 key)')
      expect(stdout).to include('Next step: bin/rails pqc:backfill')
    end

    it 'reports OK when every local account already has a usable key' do
      account = Fabricate(:account, username: 'status_provisioned')

      rows, stdout = run_status

      expect(account.pqc_signed?).to be true
      expect(rows).to include('Accounts with a usable key' => '1', 'Accounts missing a usable key' => '0')
      expect(stdout).to match(/^Status: OK$/)
      expect(stdout).to_not include('Next step')
    end

    it 'counts remote accounts separately from local ones' do
      Fabricate(:account, username: 'status_local_only')
      2.times { |index| Fabricate(:remote_account, username: "status_remote_#{index}") }

      rows, = run_status

      expect(rows).to include('Local' => '1', 'Remote' => '2', 'Total' => '3')
    end

    it 'reports OK and explains the explicit opt-out when signing is disabled' do
      rows, stdout = run_status(signing: 'false')

      expect(rows).to include('PQC_ACTIVITYPUB_SIGNING' => 'disabled (PQC_ACTIVITYPUB_SIGNING=false)')
      expect(stdout).to match(/^Status: OK$/)
      expect(stdout).to include('Note: PQC signing is explicitly disabled; ML-DSA-87 keys are still published but no proofs are attached.')
      expect(stdout).to_not include('Next step')
    end

    it 'reports DEGRADED and the OpenSSL hint when the runtime cannot generate ML-DSA-87 keys' do
      allow(OpenSSL::PKey).to receive(:generate_key).with(collector::ML_DSA_TYPE).and_raise(OpenSSL::PKey::PKeyError, 'unsupported')

      rows, stdout = run_status

      expect(rows).to include('ML-DSA-87 key generation' => 'unsupported')
      expect(stdout).to include('Status: DEGRADED (the OpenSSL runtime cannot generate ML-DSA-87 keys)')
      expect(stdout).to include('Next step: use OpenSSL 3.5 or newer with ML-DSA support, or set PQC_ACTIVITYPUB_SIGNING=false to fall back to RSA-only signing.')
    end
  end

  describe 'pqc:metrics' do
    subject(:task) { described_class['pqc:metrics'] }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc_status.rake')
        example.run
      end
    end

    before do
      # Pushing would open a socket to the exporter process; the task's
      # contract is "push once, flush, and say how many gauges went out".
      allow(collector).to receive(:report!).and_return(true)
    end

    it 'refuses to push and says why when the exporter is disabled' do
      stdout = ClimateControl.modify(MASTODON_PROMETHEUS_EXPORTER_ENABLED: nil) do
        capture_stdout { task.invoke }
      end

      expect(stdout).to include("Prometheus exporter is disabled (MASTODON_PROMETHEUS_EXPORTER_ENABLED is not 'true'); nothing to push.")
      expect(collector).to_not have_received(:report!)
    end

    it 'pushes every gauge with a flush when the exporter is enabled' do
      stdout = ClimateControl.modify(MASTODON_PROMETHEUS_EXPORTER_ENABLED: 'true') do
        capture_stdout { task.invoke }
      end

      expect(stdout).to include("Sent #{collector::METRICS.size} PQC gauges to the Prometheus exporter.")
      expect(collector).to have_received(:report!).with(flush: true).once
    end
  end
end
