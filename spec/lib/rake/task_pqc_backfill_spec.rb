# frozen_string_literal: true

require 'rails_helper'
require 'rake'
require 'stringio'

RSpec.describe Rake::Task do
  include PqcKeyProvisioningHelpers

  describe 'pqc:backfill' do
    subject(:task) { described_class['pqc:backfill'] }

    let(:public_key) { synthetic_ml_dsa_87_public_key }
    let(:private_key) { SigningKeysHelpers::PRIVATE_RSA_TEST_KEY }
    let(:native_key) { instance_double(OpenSSL::PKey::PKey, private_to_pem: private_key, public_to_pem: public_key) }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc.rake')
        example.run
      end
    end

    before do
      allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-87').and_return(native_key)
    end

    # Auto-provisioning on account creation makes every new local account start
    # with a key, so tests that need a bare account remove it explicitly.
    def without_pqc_key(account)
      account.keypairs.where(type: :'ml-dsa-87').delete_all
      account
    end

    def run_backfill
      original_stdout = $stdout
      original_stderr = $stderr
      $stdout = StringIO.new
      $stderr = StringIO.new
      task.invoke
      [$stdout.string, $stderr.string]
    rescue SystemExit
      [$stdout.string, $stderr.string]
    ensure
      $stdout = original_stdout
      $stderr = original_stderr
    end

    def report_from(stdout)
      JSON.parse(stdout[stdout.index('{')..])
    end

    it 'provisions usable keys for local accounts that lack one' do
      alice = without_pqc_key(Fabricate(:account, username: 'backfill_alice'))
      bob = without_pqc_key(Fabricate(:account, username: 'backfill_bob'))

      stdout, = run_backfill
      report = report_from(stdout)

      expect(report).to include(
        'local_accounts' => 2,
        'provisioned' => 2,
        'already_present' => 0,
        'failed' => 0,
        'failures' => []
      )

      [alice, bob].each do |account|
        keypair = account.keypairs.reload.find_by(type: :'ml-dsa-87')
        expect(keypair).to be_present
        expect(keypair).to be_usable
        expect(keypair.public_key).to eq(public_key)
      end
    end

    it 'leaves local accounts that already have a usable key untouched' do
      account = without_pqc_key(Fabricate(:account, username: 'backfill_existing'))
      existing_key = Fabricate(:keypair, account: account, type: :'ml-dsa-87', public_key: public_key)
      existing_attributes = existing_key.attributes
      key_count = Keypair.count

      stdout, = run_backfill
      report = report_from(stdout)

      expect(report).to include('provisioned' => 0, 'already_present' => 1, 'failed' => 0)
      expect(existing_key.reload.attributes).to eq(existing_attributes)
      expect(Keypair.count).to eq(key_count)
    end

    it 'is idempotent across runs' do
      account = without_pqc_key(Fabricate(:account, username: 'backfill_twice'))

      run_backfill
      task.reenable
      key_attributes = account.keypairs.reload.find_by!(type: :'ml-dsa-87').attributes

      stdout, = run_backfill
      report = report_from(stdout)

      expect(report).to include('provisioned' => 0, 'already_present' => 1, 'failed' => 0)
      expect(account.keypairs.reload.find_by!(type: :'ml-dsa-87').attributes).to eq(key_attributes)
    end

    it 'counts a failing account and keeps provisioning the rest of the run' do
      failing = without_pqc_key(Fabricate(:account, username: 'backfill_failing'))
      healthy = without_pqc_key(Fabricate(:account, username: 'backfill_healthy'))
      service = ActivityPub::GeneratePqcKeyService.new
      allow(ActivityPub::GeneratePqcKeyService).to receive(:new).and_return(service)
      allow(service).to receive(:call).and_wrap_original do |original, account|
        raise StandardError, 'simulated provider failure' if account.id == failing.id

        original.call(account)
      end

      stdout, _stderr = run_backfill
      report = report_from(stdout)

      expect(report).to include('provisioned' => 1, 'already_present' => 0, 'failed' => 1)
      expect(report['failures'].first).to include(
        'acct' => failing.acct,
        'error' => a_string_including('simulated provider failure')
      )
      expect(healthy.keypairs.reload.where(type: :'ml-dsa-87')).to be_present
      expect(failing.keypairs.reload.where(type: :'ml-dsa-87')).to be_empty
    end

    it 'ignores remote accounts' do
      remote = Fabricate(:remote_account, username: 'backfill_remote')

      stdout, = run_backfill
      report = report_from(stdout)

      expect(report).to include('local_accounts' => 0, 'provisioned' => 0, 'already_present' => 0, 'failed' => 0)
      expect(remote.keypairs.where(type: :'ml-dsa-87')).to be_empty
    end
  end
end
