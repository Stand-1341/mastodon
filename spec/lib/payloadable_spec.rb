# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Payloadable do
  include PqcKeyProvisioningHelpers

  subject(:serializer) { Class.new { include Payloadable }.new }

  let(:account) { Fabricate(:account) }
  let(:options) { { signer: account } }

  def payload
    serializer.serialize_payload(account, ActivityPub::UpdateActorSerializer, options.dup)
  end

  around do |example|
    ClimateControl.modify(AUTHORIZED_FETCH: 'false') { example.run }
  end

  it 'keeps existing RSA signing by default' do
    ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: nil do
      expect(payload['signature']['type']).to eq('RsaSignature2017')
      expect(payload).to_not have_key('proof')
    end
  end

  context 'when PQC signing is enabled' do
    around do |example|
      ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true') { example.run }
    end

    before do
      generate_real_ml_dsa_44_key
      ActivityPub::GeneratePqcKeyService.new.call(account)
    end

    it 'adds a verifiable proof alongside the RSA signature to actual serializer output' do
      secured = payload
      key = account.keypair(type: :'ml-dsa-44')

      expect(secured['signature']['type']).to eq('RsaSignature2017')
      expect(ActivityPub::ObjectIntegrityProof.verify_mldsa44_jcs_2024(secured.without('signature'), OpenSSL::PKey.read(key.public_key))).to be true
    end

    it 'does not bypass authorized-fetch mode' do
      ClimateControl.modify AUTHORIZED_FETCH: 'true' do
        expect(payload).to_not have_key('signature')
        expect(payload).to_not have_key('proof')
      end
    end

    it 'respects the existing always_sign override' do
      options[:always_sign] = true

      ClimateControl.modify AUTHORIZED_FETCH: 'true' do
        expect(payload).to have_key('signature')
        expect(payload).to have_key('proof')
      end
    end

    it 'does not sign objects that disallow signing' do
      allow(account).to receive(:sign?).and_return(false)

      expect(payload).to_not have_key('signature')
      expect(payload).to_not have_key('proof')
    end

    it 'does not add a proof without an explicit signer' do
      options.delete(:signer)

      expect(payload).to_not have_key('signature')
      expect(payload).to_not have_key('proof')
    end
  end
end
