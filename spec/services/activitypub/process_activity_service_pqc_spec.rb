# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ActivityPub::ProcessActivityService do
  include PqcKeyProvisioningHelpers

  let(:signer) { Fabricate(:account) }
  let(:relay) { Fabricate(:remote_account) }
  let(:pqc_key) { ActivityPub::GeneratePqcKeyService.new.call(signer) }
  let(:actor) { Fabricate(:remote_account, uri: ActivityPub::TagManager.instance.uri_for(signer)) }
  let(:document) do
    {
      '@context' => 'https://www.w3.org/ns/activitystreams',
      'id' => 'https://example.org/activities/1',
      'type' => 'Create',
      'actor' => actor.uri,
      'object' => { 'id' => 'https://example.org/notes/1', 'type' => 'Note', 'content' => 'Hello world' },
    }
  end
  let(:secured) { ActivityPub::PqcSigning.new(document).sign!(signer) }

  around do |example|
    ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true') { example.run }
  end

  before do
    generate_real_ml_dsa_44_key
    rsa_key = signer.keypair(type: :rsa)
    Fabricate(:keypair, account: actor, type: :rsa, uri: rsa_key.full_uri, public_key: rsa_key.public_key)
    Fabricate(:keypair, account: actor, type: :'ml-dsa-44', uri: pqc_key.full_uri, public_key: pqc_key.public_key)
    allow(ActivityPub::Activity).to receive(:factory).and_return(nil)
  end

  it 'processes relayed dual-signed activities through the real RSA verification path' do
    secured
    allow(ActivityPub::ObjectIntegrityProof).to receive(:new).and_raise('Unexpected PQC fallback')

    described_class.new.call(secured.to_json, relay)

    expect(ActivityPub::Activity).to have_received(:factory).with(secured, actor, hash_including(relayed_through_actor: relay))
  end

  it 'preserves the original dual-signed document for forwarding without rewriting its context' do
    described_class.new.call(secured.to_json, actor)

    expect(ActivityPub::Activity).to have_received(:factory) do |forwarded, _actor, _options|
      expect(forwarded).to eq(secured)
      expect(ActivityPub::LinkedDataSignature.new(forwarded).verify_actor!).to eq(actor)
      expect(ActivityPub::ObjectIntegrityProof.new(forwarded.without('signature')).verify_actor!).to eq(actor)
    end
  end

  it 'verifies ML-DSA relayed activities when RSA verification is unavailable' do
    secured
    rsa_verifier = instance_double(ActivityPub::LinkedDataSignature, verify_actor!: nil)
    allow(ActivityPub::LinkedDataSignature).to receive(:new).and_return(rsa_verifier)

    described_class.new.call(secured.to_json, relay)

    expect(ActivityPub::Activity).to have_received(:factory).with(instance_of(Hash), actor, hash_including(relayed_through_actor: relay))
  end

  it 'rejects tampering when the activity is relayed' do
    tampered = secured.deep_dup
    tampered['object']['content'] = 'Tampered'

    described_class.new.call(tampered.to_json, relay)

    expect(ActivityPub::Activity).to_not have_received(:factory)
  end

  it 'does not let a withdrawn proof key install actor keys or extend freshness through an Update' do
    update = document.merge(
      'type' => 'Update',
      'object' => {
        'id' => actor.uri,
        'type' => 'Person',
        'preferredUsername' => actor.username,
        'publicKey' => {
          'id' => "#{actor.uri}#attacker-rsa",
          'owner' => actor.uri,
          'publicKeyPem' => signer.keypair(type: :rsa).public_key,
        },
      }
    )
    proof_only = ActivityPub::ObjectIntegrityProof.new(update).sign!(signer, sign_with: pqc_key)
    original_actor = actor.reload.attributes
    original_keys = actor.keypairs.map(&:attributes)
    expect(actor).to_not be_possibly_stale
    fetcher = instance_double(ActivityPub::FetchRemoteKeyService)
    allow(fetcher).to receive(:call).with(pqc_key.full_uri, force_refresh: true).and_return(nil)
    allow(ActivityPub::FetchRemoteKeyService).to receive(:new).and_return(fetcher)
    allow(ActivityPub::Activity).to receive(:factory).and_call_original

    described_class.new.call(proof_only.to_json, relay)

    expect(fetcher).to have_received(:call).with(pqc_key.full_uri, force_refresh: true)
    expect(ActivityPub::Activity).to_not have_received(:factory)
    expect(actor.reload.attributes).to eq(original_actor)
    expect(actor.keypairs.map(&:attributes)).to eq(original_keys)
  end

  it 'rejects malformed proofs without raising ingress errors' do
    [[], ['invalid'], 'invalid', { 'verificationMethod' => [] }, { 'verificationMethod' => 42 }].each do |proof|
      expect { described_class.new.call(document.merge('proof' => proof).to_json, relay) }.to_not raise_error
    end

    expect(ActivityPub::Activity).to_not have_received(:factory)
  end
end
