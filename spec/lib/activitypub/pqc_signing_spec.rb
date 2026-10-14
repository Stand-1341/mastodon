# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ActivityPub::PqcSigning do
  include PqcKeyProvisioningHelpers

  subject(:signed) { described_class.new(document).sign!(account) }

  let(:account) { Fabricate(:account) }
  let(:document) do
    {
      '@context' => 'https://www.w3.org/ns/activitystreams',
      'id' => 'https://example.org/activities/1',
      'type' => 'Create',
      'actor' => ActivityPub::TagManager.instance.uri_for(account),
      'object' => { 'type' => 'Note', 'content' => 'Hello world' },
    }
  end

  context 'when disabled' do
    it 'preserves RSA-only signing without querying or generating PQC keys' do
      rsa_key = account.keypair(type: :rsa)
      allow(account).to receive(:keypair).and_call_original
      allow(account).to receive(:keypair).with(type: :'ml-dsa-44').and_raise('Unexpected PQC key lookup')

      ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: nil do
        expect(signed['signature']).to include('type' => 'RsaSignature2017', 'creator' => rsa_key.full_uri)
        expect(signed).to_not have_key('proof')
      end
    end

    it 'does not enable signing for other truthy-looking strings' do
      ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: 'false' do
        expect(signed).to_not have_key('proof')
      end
    end
  end

  context 'when enabled' do
    around do |example|
      ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true') { example.run }
    end

    it 'keeps RSA-only behavior for accounts not explicitly provisioned' do
      account

      expect { signed }.to_not change(Keypair, :count)
      expect(signed).to_not have_key('proof')
      expect(signed['signature']['type']).to eq('RsaSignature2017')
    end

    context 'with a native ML-DSA-44 key' do
      let!(:pqc_key) do
        generate_real_ml_dsa_44_key
        ActivityPub::GeneratePqcKeyService.new.call(account)
      end
      let(:receiver_actor) { Fabricate(:remote_account, uri: ActivityPub::TagManager.instance.uri_for(account)) }

      before do
        generate_real_ml_dsa_44_key
        rsa_key = account.keypair(type: :rsa)
        Fabricate(:keypair, account: receiver_actor, type: :rsa, uri: rsa_key.full_uri, public_key: rsa_key.public_key)
        Fabricate(:keypair, account: receiver_actor, type: :'ml-dsa-44', uri: pqc_key.full_uri, public_key: pqc_key.public_key)
      end

      it 'produces a document independently verifiable by both RSA and ML-DSA verifiers' do
        original_rsa = account.keypair(type: :rsa).attributes
        original_document = document.deep_dup

        expect(signed['signature']['type']).to eq('RsaSignature2017')
        expect(signed['proof']['cryptosuite']).to eq('mldsa44-jcs-2024')
        expect(ActivityPub::LinkedDataSignature.new(signed).verify_actor!).to eq(receiver_actor)
        expect(ActivityPub::ObjectIntegrityProof.new(signed.without('signature')).verify_actor!).to eq(receiver_actor)
        expect(account.keypair(type: :rsa).reload.attributes).to eq(original_rsa)
        expect(document).to eq(original_document)
      end

      it 'preserves caller-supplied RSA signing keys' do
        rsa_key = account.keypair(type: :rsa)
        secured = described_class.new(document).sign!(account, sign_with: rsa_key)

        expect(secured['signature']['creator']).to eq(rsa_key.full_uri)
        expect(secured['proof']['verificationMethod']).to eq(pqc_key.full_uri)
        expect(ActivityPub::LinkedDataSignature.new(secured).verify_actor!).to eq(receiver_actor)
      end

      it 'binds the ML-DSA proof into the RSA signature' do
        secured = signed.deep_dup
        secured['proof']['proofValue'] = "u#{Base64.urlsafe_encode64('tampered', padding: false)}"

        expect(ActivityPub::LinkedDataSignature.new(secured).verify_actor!).to be_nil
        expect(ActivityPub::ObjectIntegrityProof.new(secured.without('signature')).verify_actor!).to be_nil
        expect(ActivityPub::LinkedDataSignature.new(signed.without('proof')).verify_actor!).to be_nil
      end

      it 'rejects tampered document contents with both signatures' do
        secured = signed.deep_dup
        secured['object']['content'] = 'Tampered'

        expect(ActivityPub::LinkedDataSignature.new(secured).verify_actor!).to be_nil
        expect(ActivityPub::ObjectIntegrityProof.new(secured.without('signature')).verify_actor!).to be_nil
      end

      it 'rejects an expired proof and a revoked verification key' do
        secured = signed
        travel_to 3.days.from_now do
          expect(ActivityPub::ObjectIntegrityProof.new(secured.without('signature')).verify_actor!).to be_nil
        end
        receiver_actor.keypairs.where(type: :'ml-dsa-44').update_all(revoked: true)

        expect(ActivityPub::ObjectIntegrityProof.new(secured.without('signature')).verify_actor!).to be_nil
      end

      it 'does not sign with expired or revoked local keys' do
        pqc_key.update!(revoked: true)
        expired = ActivityPub::GeneratePqcKeyService.new.call(account)
        expired.update!(expires_at: 1.minute.ago)

        expect(signed).to_not have_key('proof')
        expect(signed['signature']['type']).to eq('RsaSignature2017')
      end

      it 'does not silently downgrade when a provisioned key cannot sign' do
        native_key = instance_double(OpenSSL::PKey::PKey)
        allow(native_key).to receive(:sign).and_raise(OpenSSL::PKey::PKeyError, 'provider unavailable')
        allow(pqc_key).to receive(:keypair).and_return(native_key)
        allow(account).to receive(:keypair).with(type: :'ml-dsa-44').and_return(pqc_key)

        expect { signed }.to raise_error(described_class::SigningError, /Disable PQC_ACTIVITYPUB_SIGNING explicitly/)
      end

      it 'rejects malformed proof fields without raising errors' do
        secured = signed
        malformed = [
          ['proofValue', 'u!'],
          ['proofValue', []],
          ['verificationMethod', 42],
          ['created', 'not-a-date'],
          ['expires', 'not-a-date'],
          ['expires', []],
        ]

        malformed.each do |field, value|
          tampered = secured.without('signature').deep_dup
          tampered['proof'][field] = value
          expect(ActivityPub::ObjectIntegrityProof.new(tampered).verify_actor!).to be_falsey
        end
      end

      it 'requires authoritative key refresh when remote authorization is stale' do
        secured = signed
        receiver_actor.update!(last_webfingered_at: 10.days.ago)
        fetcher = instance_double(ActivityPub::FetchRemoteKeyService)
        allow(fetcher).to receive(:call).with(pqc_key.full_uri, force_refresh: true).and_return(nil)
        allow(ActivityPub::FetchRemoteKeyService).to receive(:new).and_return(fetcher)

        expect(ActivityPub::ObjectIntegrityProof.new(secured.without('signature')).verify_actor!).to be_nil
        expect(fetcher).to have_received(:call).with(pqc_key.full_uri, force_refresh: true)
      end

      it 'supports explicit rollback to RSA without deleting verification keys' do
        ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: 'false' do
          expect(signed).to_not have_key('proof')
          expect(signed['signature']['type']).to eq('RsaSignature2017')
          expect(pqc_key.reload).to be_usable
        end
      end
    end
  end
end
