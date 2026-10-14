# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ActivityPub::MultikeySerializer do
  include PqcKeyProvisioningHelpers

  subject(:json) { serialized_record_json(record, described_class, adapter: ActivityPub::Adapter) }

  let(:record) { Fabricate(:keypair, type: :'ml-dsa-44', public_key: synthetic_ml_dsa_44_public_key) }

  it 'publishes an interoperable Multikey with only public key material' do
    expect(json).to include(
      'id' => record.full_uri,
      'type' => 'Multikey',
      'controller' => ActivityPub::TagManager.instance.uri_for(record.account),
      'publicKeyMultibase' => Multibase.encode_key_from_pem(record.public_key, type: record.type)
    )
    expect(json['@context']).to include('https://www.w3.org/ns/cid/v1')
    expect(json).to_not include('privateKey', 'privateKeyPem', 'publicKeyPem')
    expect(json.to_json).to_not include(record.private_key)
  end

  it 'omits expiration and revocation metadata for a non-expiring usable key' do
    expect(json).to_not include('expires', 'expiresAt', 'revoked')
  end

  it 'does not publish a revoked key through the actor document' do
    record.update!(revoked: true)
    actor_json = serialized_record_json(record.account, ActivityPub::ActorSerializer, adapter: ActivityPub::Adapter)

    expect(actor_json).to_not have_key('assertionMethod')
  end

  context 'with an expiring usable key' do
    let(:expiration) { Time.utc(2030, 1, 2, 3, 4, 5) }
    let(:record) { Fabricate(:keypair, type: :'ml-dsa-44', public_key: synthetic_ml_dsa_44_public_key, expires_at: expiration) }

    it 'publishes expiration as an ISO8601 expires value' do
      expect(json['expires']).to eq('2030-01-02T03:04:05Z')
      expect(json).to_not include('expiresAt', 'revoked')
    end

    it 'includes expiration in the embedded actor Multikey' do
      actor_json = serialized_record_json(record.account, ActivityPub::ActorSerializer, adapter: ActivityPub::Adapter)

      expect(actor_json['assertionMethod']).to contain_exactly(a_hash_including('id' => record.full_uri, 'expires' => expiration.iso8601))
    end
  end

  it 'never reads or decrypts the private key' do
    allow(record).to receive(:private_key).and_raise('Private key must not be read')
    allow(record).to receive(:keypair).and_raise('Native key must not be read')

    expect(json['publicKeyMultibase']).to start_with('u')
    expect(record).to_not have_received(:private_key)
    expect(record).to_not have_received(:keypair)
  end

  context 'with a real ML-DSA-44 key' do
    let(:native_key) { generate_real_ml_dsa_44_key }
    let(:record) { Fabricate(:keypair, type: :'ml-dsa-44', public_key: native_key.public_to_pem, private_key: native_key.private_to_pem) }

    it 'publishes the exact public bitstring of the generated key' do
      _type, pem = Multibase.decode_key_to_pem(json['publicKeyMultibase'])

      expect(OpenSSL::PKey.read(pem).public_to_der).to eq(native_key.public_to_der)
      expect(json.to_json).to_not include(native_key.private_to_pem)
    end
  end
end
