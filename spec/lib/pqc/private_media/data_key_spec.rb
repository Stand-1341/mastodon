# frozen_string_literal: true

require 'rails_helper'
require 'aws-sdk-kms'

RSpec.describe Pqc::PrivateMedia::DataKey do
  let(:context) { { 'object_token' => SecureRandom.uuid, 'account_id' => '123' } }
  let(:local_key) { Base64.strict_encode64('k' * 32) }

  around do |example|
    ClimateControl.modify(PQC_MEDIA_LOCAL_KEK: local_key) { example.run }
  end

  describe '.generate and .decrypt' do
    it 'wraps a fresh 256-bit data key and decrypts it for the matching object context' do
      data_key, wrapped_key, provider = described_class.generate(context)

      expect(data_key.bytesize).to eq(32)
      expect(provider).to eq(described_class::LOCAL_PROVIDER)
      expect(described_class.decrypt(wrapped_key, provider, context)).to eq(data_key)
    end

    it 'rejects a wrapped key used with another owner or object' do
      _data_key, wrapped_key, provider = described_class.generate(context)

      expect do
        described_class.decrypt(wrapped_key, provider, context.merge('account_id' => '456'))
      end.to raise_error(described_class::ConfigurationError, /authenticate/)
    end

    it 'rejects a modified wrapped key' do
      _data_key, wrapped_key, provider = described_class.generate(context)
      prefix, encoded = wrapped_key.split(':', 2)
      bytes = Base64.strict_decode64(encoded)
      bytes.setbyte(-1, bytes.getbyte(-1) ^ 1)

      expect do
        described_class.decrypt("#{prefix}:#{Base64.strict_encode64(bytes)}", provider, context)
      end.to raise_error(described_class::ConfigurationError, /authenticate/)
    end

    it 'rejects a missing local key' do
      ClimateControl.modify(PQC_MEDIA_LOCAL_KEK: nil) do
        expect { described_class.generate(context) }
          .to raise_error(described_class::ConfigurationError, /PQC_MEDIA_LOCAL_KEK/)
      end
    end

    it 'uses the configured KMS key and object context to wrap and unwrap the data key' do
      kms_client = instance_spy(Aws::KMS::Client)
      kms_key = 'wrapped-data-key'.b
      data_key = 'd' * 32
      allow(Aws::KMS::Client).to receive(:new).with(region: 'us-east-1', endpoint: nil).and_return(kms_client)
      allow(kms_client).to receive(:generate_data_key).with(
        key_id: 'alias/mastodon-private-media',
        key_spec: 'AES_256',
        encryption_context: context
      ).and_return(double(plaintext: data_key, ciphertext_blob: kms_key))
      allow(kms_client).to receive(:decrypt).with(
        ciphertext_blob: kms_key,
        encryption_context: context
      ).and_return(double(plaintext: data_key))

      ClimateControl.modify(PQC_MEDIA_KMS_KEY_ID: 'alias/mastodon-private-media') do
        _key, wrapped_key, provider = described_class.generate(context)

        expect(provider).to eq(described_class::AWS_KMS_PROVIDER)
        expect(Base64.strict_decode64(wrapped_key)).to eq(kms_key)
        expect(described_class.decrypt(wrapped_key, provider, context)).to eq(data_key)
      end

      expect(kms_client).to have_received(:generate_data_key).with(
        key_id: 'alias/mastodon-private-media',
        key_spec: 'AES_256',
        encryption_context: context
      )
    end

    it 'allows a local KMS-compatible endpoint in development and test' do
      client = instance_spy(Aws::KMS::Client)
      allow(Aws::KMS::Client).to receive(:new).with(
        region: 'us-east-1', endpoint: 'http://local-kms:4566'
      ).and_return(client)

      ClimateControl.modify(PQC_MEDIA_KMS_ENDPOINT: 'http://local-kms:4566') do
        expect(described_class.send(:kms_client)).to eq(client)
      end
    end

    it 'rejects a custom KMS endpoint outside development and test' do
      allow(Rails).to receive(:env).and_return(ActiveSupport::StringInquirer.new('production'))

      ClimateControl.modify(
        PQC_MEDIA_KMS_KEY_ID: 'alias/mastodon-private-media',
        PQC_MEDIA_KMS_ENDPOINT: 'http://untrusted.invalid'
      ) do
        expect { described_class.generate(context) }
          .to raise_error(described_class::ConfigurationError, /restricted to development and test/)
      end
    end
  end
end
