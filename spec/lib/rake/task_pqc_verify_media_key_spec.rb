# frozen_string_literal: true

require 'rails_helper'
require 'rake'
require 'aws-sdk-kms'

RSpec.describe Rake::Task do
  describe 'pqc:verify_media_key' do
    subject(:task) { described_class['pqc:verify_media_key'] }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc.rake')
        example.run
      end
    end

    it 'verifies the local provider without printing key material' do
      ClimateControl.modify PQC_MEDIA_KMS_KEY_ID: nil, PQC_MEDIA_LOCAL_KEK: Base64.strict_encode64('m' * 32) do
        expect { task.invoke }.to output("Private-media local-aes-gcm-v1 data-key round-trip verified\n").to_stdout
      end
    end

    it 'reports a missing local wrapping key without revealing key material' do
      ClimateControl.modify PQC_MEDIA_KMS_KEY_ID: nil, PQC_MEDIA_LOCAL_KEK: nil do
        expect do
          expect { task.invoke }.to raise_error(SystemExit)
        end.to output(/Unable to use the configured private-media key provider: Set PQC_MEDIA_LOCAL_KEK/).to_stderr
      end
    end
  end

  describe 'pqc:verify_local_media_kms' do
    subject(:task) { described_class['pqc:verify_local_media_kms'] }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc.rake')
        example.run
      end
    end

    it 'checks KMS wrapping and context binding, then schedules the temporary key for deletion' do
      data_key = 'k' * 32
      kms_client = instance_double(Aws::KMS::Client)
      allow(Aws::KMS::Client).to receive(:new).and_return(kms_client)
      allow(kms_client).to receive(:create_key)
        .and_return(double(key_metadata: double(key_id: 'local-test-key')))
      allow(kms_client).to receive(:schedule_key_deletion)
      allow(Pqc::PrivateMedia::DataKey).to receive(:generate)
        .and_return([data_key.dup, 'encrypted-data-key', Pqc::PrivateMedia::DataKey::AWS_KMS_PROVIDER])
      allow(Pqc::PrivateMedia::DataKey).to receive(:decrypt) do |_wrapped, _provider, context|
        raise Pqc::PrivateMedia::DataKey::ConfigurationError if context['account_id'] == 'different-owner'

        data_key.dup
      end

      ClimateControl.modify(
        PQC_MEDIA_KMS_ENDPOINT: 'http://local-kms:4566',
        AWS_ACCESS_KEY_ID: 'test',
        AWS_SECRET_ACCESS_KEY: 'test',
        AWS_REGION: 'us-east-1',
        PQC_MEDIA_KMS_KEY_ID: nil
      ) do
        expect { task.invoke }.to output("Local KMS private-media round-trip and encryption-context binding verified\n").to_stdout
      end

      expect(kms_client).to have_received(:schedule_key_deletion).with(key_id: 'local-test-key', pending_window_in_days: 7)
    end

    it 'rejects a nonlocal endpoint' do
      ClimateControl.modify(
        PQC_MEDIA_KMS_ENDPOINT: 'https://kms.example.com',
        AWS_ACCESS_KEY_ID: 'test',
        AWS_SECRET_ACCESS_KEY: 'test'
      ) do
        expect do
          expect { task.invoke }.to raise_error(SystemExit)
        end.to output(/Set PQC_MEDIA_KMS_ENDPOINT to a local KMS-compatible endpoint/).to_stderr
      end
    end
  end
end
