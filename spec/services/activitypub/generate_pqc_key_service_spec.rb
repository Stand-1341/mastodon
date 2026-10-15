# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ActivityPub::GeneratePqcKeyService do
  include PqcKeyProvisioningHelpers

  subject(:service) { described_class.new }

  let(:account) { Fabricate(:account) }
  let(:native_key) { instance_double(OpenSSL::PKey::PKey, private_to_pem: private_key, public_to_pem: public_key) }
  let(:private_key) { SigningKeysHelpers::PRIVATE_RSA_TEST_KEY }
  let(:public_key) { synthetic_ml_dsa_44_public_key }

  before do
    generated_key = native_key
    allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-44').and_return(generated_key)
  end

  describe 'native key test requirements' do
    let(:optional_modes) { [nil, 'false'] }

    [OpenSSL::PKey::PKeyError, NotImplementedError].each do |error_class|
      context "when generation raises #{error_class}" do
        before do
          allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-44').and_raise(error_class, 'provider unavailable')
          allow(self).to receive(:skip)
        end

        it 'fails with actionable guidance when native ML-DSA is required' do
          ClimateControl.modify PQC_REQUIRE_ML_DSA: 'true' do
            expect { generate_real_ml_dsa_44_key }.to raise_error(OpenSSL::PKey::PKeyError, /PQC_REQUIRE_ML_DSA=true.*OpenSSL 3\.5.*provider unavailable/)
          end

          expect(self).to_not have_received(:skip)
        end

        it 'keeps skipping when strict mode is unset or false' do
          optional_modes.each do |value|
            ClimateControl.modify PQC_REQUIRE_ML_DSA: value do
              generate_real_ml_dsa_44_key
            end
          end

          expect(self).to have_received(:skip).with(/require a supported OpenSSL provider: provider unavailable/).twice
        end
      end
    end
  end

  describe '#call' do
    it 'adds an encrypted key with a persistent, unique fragment without changing RSA or legacy keys' do
      rsa_key = account.keypair(type: :rsa)
      original_account = account.reload.attributes
      original_rsa = rsa_key.reload.attributes

      expect { service.call(account) }.to change(Keypair, :count).by(1)

      key = account.keypairs.find_by!(type: :'ml-dsa-44')
      expect(key).to have_attributes(public_key: public_key, private_key: private_key, revoked: false, expires_at: nil)
      expect(key.local_fragment).to match(/\A#ml-dsa-44-[a-f0-9]{32}\z/)
      expect(key.full_uri).to eq(ActivityPub::TagManager.instance.uri_for(account) + key.local_fragment)
      expect(key.reload.read_attribute_before_type_cast(:private_key)).to_not include(private_key)
      expect(key.private_key).to eq(private_key)
      expect(account.reload.attributes).to eq(original_account)
      expect(rsa_key.reload.attributes).to eq(original_rsa)
    end

    it 'preserves legacy account keys without creating or replacing an RSA keypair' do
      legacy_account = Fabricate(:account, legacy_keypair: true)
      original_attributes = legacy_account.reload.attributes

      expect { service.call(legacy_account) }.to change(Keypair, :count).by(1)
      expect(legacy_account.reload.attributes).to eq(original_attributes)
      expect(legacy_account.keypairs.pluck(:type)).to eq(['ml-dsa-44'])
    end

    it 'returns the same stored key and fragment on repeated calls' do
      key = service.call(account)

      expect { expect(service.call(Account.find(account.id))).to eq(key) }.to_not change(Keypair, :count)
      expect(service.call(account).full_uri).to eq(key.full_uri)
      expect(OpenSSL::PKey).to have_received(:generate_key).with('ML-DSA-44').once
    end

    it 'reuses the oldest usable key even when generation is unsupported' do
      first_key = Fabricate(:keypair, account: account, type: :'ml-dsa-44', public_key: public_key)
      Fabricate(:keypair, account: account, type: :'ml-dsa-44', public_key: public_key)
      allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-44').and_raise(OpenSSL::PKey::PKeyError, 'unsupported')

      expect(service.call(account)).to eq(first_key)
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'does not reuse or delete revoked or expired keys' do
      revoked = Fabricate(:keypair, account: account, type: :'ml-dsa-44', public_key: public_key, revoked: true)
      expired = Fabricate(:keypair, account: account, type: :'ml-dsa-44', public_key: public_key, expires_at: 1.minute.ago)

      expect { service.call(account) }.to change(Keypair, :count).by(1)
      expect(service.call(account)).to be_usable
      expect(service.call(account).id).to_not be_in([revoked.id, expired.id])
      expect(revoked.reload).to be_revoked
      expect(expired.reload).to be_expired
    end

    it 'reuses a key whose expiry is in the future' do
      key = Fabricate(:keypair, account: account, type: :'ml-dsa-44', public_key: public_key, expires_at: 1.day.from_now)

      expect(service.call(account)).to eq(key)
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'rejects an unpersisted local account without generating a key' do
      expect { service.call(Account.new(username: 'alice')) }.to raise_error(ArgumentError, /persisted local accounts/)
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'rejects a remote account without generating a key or changing its records' do
      remote_account = Fabricate(:account, domain: 'remote.example')
      original_attributes = remote_account.reload.attributes

      expect { service.call(remote_account) }.to raise_error(ArgumentError, /persisted local accounts/)
      expect(remote_account.reload.attributes).to eq(original_attributes)
      expect(remote_account.keypairs.pluck(:type)).to eq(['rsa'])
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    context 'when the runtime does not support ML-DSA-44' do
      before do
        allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-44').and_raise(OpenSSL::PKey::PKeyError, 'unsupported algorithm')
      end

      it 'raises an actionable error without database changes' do
        original_attributes = account.reload.attributes

        expect { service.call(account) }.to raise_error(described_class::UnsupportedRuntimeError, /OpenSSL 3\.5/)
        expect(account.reload.attributes).to eq(original_attributes)
        expect(account.keypairs.pluck(:type)).to eq(['rsa'])
      end
    end

    context 'when the runtime cannot export the generated key' do
      before do
        allow(native_key).to receive(:public_to_pem).and_raise(OpenSSL::PKey::PKeyError, 'export unsupported')
      end

      it 'raises an actionable error without a partially stored key' do
        account

        expect { service.call(account) }.to raise_error(described_class::UnsupportedRuntimeError, /generate or export/)
        expect(account.keypairs.pluck(:type)).to eq(['rsa'])
      end
    end

    context 'with concurrent provisioning', use_transactional_tests: false do
      after do
        account.destroy!
      end

      it 'creates only one key for callers using separate account instances' do
        account_id = account.id
        key_ids = Concurrent::Array.new

        expect do
          multi_threaded_execution(2) do
            ActiveRecord::Base.connection_pool.with_connection do
              key_ids << described_class.new.call(Account.find(account_id)).id
            end
          end
        end.to change(Keypair, :count).by(1)

        expect(key_ids.size).to eq(2)
        expect(key_ids.uniq.size).to eq(1)
      end
    end

    context 'with native ML-DSA-44 support' do
      before do
        allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-44').and_call_original
        generate_real_ml_dsa_44_key
      end

      it 'stores and reloads a real matching keypair with encrypted private material' do
        key = service.call(account)
        private_pem = key.private_key
        public_pem = key.public_key

        expect(key.reload.read_attribute_before_type_cast(:private_key)).to_not include(private_pem)
        expect(key).to have_attributes(private_key: private_pem, public_key: public_pem)

        public_key = OpenSSL::PKey.read(key.public_key)
        algorithm = OpenSSL::ASN1.decode(public_key.public_to_der).value.first
        expect(algorithm.value.first.oid).to eq('2.16.840.1.101.3.4.3.17')
        expect(OpenSSL::PKey.read(key.private_key).public_to_der).to eq(public_key.public_to_der)
      end

      it 'reuses the persisted native key and fragment without generating another key' do
        key = service.call(account)
        fragment = key.local_fragment
        uri = key.full_uri

        expect { expect(service.call(Account.find(account.id))).to eq(key) }.to_not change(Keypair, :count)
        expect(service.call(account)).to have_attributes(local_fragment: fragment, full_uri: uri, private_key: key.private_key, public_key: key.public_key)
        # One capability probe in setup and one key generated by the service.
        expect(OpenSSL::PKey).to have_received(:generate_key).with('ML-DSA-44').twice
      end

      it 'signs with the reloaded private key and verifies using only the public key' do
        key = service.call(account).reload
        public_key = OpenSSL::PKey.read(key.public_key)
        message = 'ML-DSA-44 native provisioning round-trip'
        signature = key.keypair.sign(nil, message)

        expect(signature.bytesize).to eq(2420)
        expect(public_key.verify(nil, signature, message)).to be true
        expect(public_key.verify(nil, signature, "#{message} tampered")).to be false
        expect { public_key.private_to_pem }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end
  end
end
