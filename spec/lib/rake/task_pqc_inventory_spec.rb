# frozen_string_literal: true

require 'rails_helper'
require 'rake'
require 'json'

RSpec.describe Rake::Task do
  describe 'pqc:inventory' do
    subject(:task) { described_class['pqc:inventory'] }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc.rake')
        example.run
      end
    end

    it 'remains read-only and does not probe capability by generating keys' do
      allow(OpenSSL::PKey).to receive(:generate_key).and_raise('Inventory must not generate keys')

      expect do
        expect { task.invoke }.to output(/"activitypub"/).to_stdout
      end.to not_change(Keypair, :count).and not_change(Account, :count)
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'emits a JSON inventory without exposing encryption key material' do
      key_values = %w(
        ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
        ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
        ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT
      ).filter_map { |key| ENV[key].presence }
      json = nil
      expect { task.invoke }.to output(satisfy { |value| json = value }).to_stdout
      inventory = JSON.parse(json)

      expect(inventory).to include(
        'schema_version' => 1,
        'deployed_sha' => Mastodon::Version.source_commit.presence
      )
      expect(inventory).to include(
        'ruby_version',
        'openssl_version',
        'openssl_library_version',
        'database_sslmode',
        'activitypub',
        'media_backend',
        'active_record_encryption',
        'backup_age'
      )
      expect(inventory.fetch('activitypub')).to eq(
        'pqc_signing_enabled' => (ENV['PQC_ACTIVITYPUB_SIGNING'] == 'true'),
        'key_provisioning' => 'explicit_per_account',
        'public_key_publication' => 'usable_keys_regardless_of_signing'
      )
      expect(inventory.dig('backup_age', 'operator_input_required')).to be_in([true, false])
      expect(inventory.dig('active_record_encryption', 'required_key_environment_variables')).to all(include('name', 'configured'))
      key_values.each { |value| expect(json).to_not include(value) }
    end
  end
end
