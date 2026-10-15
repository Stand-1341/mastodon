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
        'schema_version' => 4,
        'deployed_sha' => Mastodon::Version.source_commit.presence
      )
      expect(inventory).to include(
        'ruby_version',
        'openssl_version',
        'openssl_library_version',
        'database_sslmode',
        'database_tls',
        'activitypub',
        'media_backend',
        'private_media',
        'encrypted_messaging',
        'active_record_encryption',
        'backup_age'
      )
      expect(inventory.fetch('database_tls')).to include(
        'server_version',
        'encrypted',
        'tls_version',
        'cipher',
        'server_tls_groups',
        'hybrid_group_enforced'
      )
      expect(inventory.fetch('activitypub')).to include(
        'pqc_signing_enabled' => (ENV['PQC_ACTIVITYPUB_SIGNING'] == 'true'),
        'pqc_inbound_proof_required' => (ENV['PQC_ACTIVITYPUB_REQUIRE_PROOF'] == 'true'),
        'key_provisioning' => 'explicit_per_account',
        'local_account_count' => Account.local.count,
        'accounts_with_usable_ml_dsa_key' => a_kind_of(Integer),
        'accounts_missing_usable_ml_dsa_key' => a_kind_of(Integer),
        'public_key_publication' => 'usable_keys_regardless_of_signing'
      )
      expect(inventory.fetch('private_media')).to include(
        'encryption_enabled' => (ENV['PQC_PRIVATE_MEDIA_ENCRYPTION'] == 'true'),
        'cipher' => 'AES-256-GCM',
        'access_policy' => 'owner_only',
        'max_upload_bytes' => Pqc::PrivateMedia::CreateService::MAX_FILE_SIZE,
        'account_quota_bytes' => Pqc::PrivateMedia::CreateService::MAX_ACCOUNT_STORAGE
      )
      expect(inventory.fetch('encrypted_messaging')).to include(
        'experimental_relay_enabled' => (ENV['PQC_E2EE_EXPERIMENTAL'] == 'true'),
        'protocol' => 'MLS_256_XWING_AES256GCM_SHA512_MLDSA87',
        'cipher_suite_id' => '0xf011',
        'cipher_suite_registry_status' => 'ts-mls private-use; not IANA assigned',
        'cross_client_interoperability' => false,
        'relay_payloads' => 'opaque_ciphertext',
        'user_interface_available' => true,
        'local_private_state_persisted' => true,
        'recovery_storage' => 'passphrase_encrypted_localstorage',
        'portable_recovery_available' => true,
        'creator_can_add_local_members' => true,
        'durable_outbound_queue' => true,
        'idempotent_message_delivery' => true,
        'idempotent_key_package_claims' => true,
        'recoverable_group_setup' => true,
        'atomic_initial_group_setup' => true,
        'atomic_member_addition' => true,
        'atomic_member_removal' => true,
        'member_departure_requests' => true,
        'pre_setup_invitation_acceptance' => true,
        'active_member_invitation_acceptance' => true,
        'production_ready' => false
      )
      expect(inventory.dig('backup_age', 'operator_input_required')).to be_in([true, false])
      expect(inventory.dig('active_record_encryption', 'required_key_environment_variables')).to all(include('name', 'configured'))
      key_values.each { |value| expect(json).to_not include(value) }
    end
  end
end
