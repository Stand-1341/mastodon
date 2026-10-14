# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ActivityPub::ActorSerializer do
  include PqcKeyProvisioningHelpers

  subject(:json) { serialized_record_json(record, described_class, adapter: ActivityPub::Adapter) }

  describe 'public keys' do
    let(:record) { Fabricate(:account) }
    let(:public_key) { synthetic_ml_dsa_44_public_key }

    it 'preserves RSA-only publication without adding a CID context or generating keys' do
      rsa_key = record.keypair(type: :rsa)

      expect { json }.to_not change(Keypair, :count)
      expect(json['publicKey']).to eq(
        'id' => rsa_key.full_uri,
        'owner' => ActivityPub::TagManager.instance.uri_for(record),
        'publicKeyPem' => rsa_key.public_key
      )
      expect(json).to_not have_key('assertionMethod')
      expect(json['@context']).to_not include('https://www.w3.org/ns/cid/v1')
    end

    context 'with usable ML-DSA-44 keys' do
      let!(:pqc_key) { Fabricate(:keypair, account: record, type: :'ml-dsa-44', public_key: public_key) }

      it 'publishes embedded Multikey entries alongside the unchanged RSA key' do
        rsa_key = record.keypair(type: :rsa)
        second_key = Fabricate(:keypair, account: record, type: :'ml-dsa-44', public_key: public_key, expires_at: 1.day.from_now)

        expect(json['publicKey']['publicKeyPem']).to eq(rsa_key.public_key)
        expect(json['assertionMethod']).to eq([pqc_key, second_key].map do |key|
          {
            'id' => key.full_uri,
            'type' => 'Multikey',
            'controller' => ActivityPub::TagManager.instance.uri_for(record),
            'publicKeyMultibase' => Multibase.encode_key_from_pem(key.public_key, type: key.type),
          }.tap do |attributes|
            attributes['expires'] = key.expires_at.utc.iso8601 if key.expires_at.present?
          end
        end)
        expect(json['@context']).to include('https://www.w3.org/ns/cid/v1')
        expect(json.to_json).to_not include(pqc_key.private_key)
      end

      it 'continues publishing after outbound signing is disabled' do
        ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: 'false' do
          expect(json['assertionMethod'].pluck('id')).to include(pqc_key.full_uri)
          expect(json['@context']).to include('https://www.w3.org/ns/cid/v1')
        end
      end

      it 'publishes when the signing flag is absent' do
        ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: nil do
          expect(json['assertionMethod'].pluck('id')).to include(pqc_key.full_uri)
        end
      end

      it 'never substitutes an ML-DSA key for a missing RSA key' do
        record.keypairs.where(type: :rsa).delete_all
        record.update!(public_key: SigningKeysHelpers::PUBLIC_RSA_TEST_KEY, private_key: SigningKeysHelpers::PRIVATE_RSA_TEST_KEY)

        expect(json['publicKey']['id']).to eq(ActivityPub::TagManager.instance.key_uri_for(record))
        expect(json['publicKey']['publicKeyPem']).to eq(record.public_key)
        expect(json['assertionMethod'].pluck('id')).to include(pqc_key.full_uri)
      end

      context 'with real native key material' do
        let(:native_key) { generate_real_ml_dsa_44_key }
        let(:public_key) { native_key.public_to_pem }

        it 'publishes a public key that round-trips to native DER' do
          _type, pem = Multibase.decode_key_to_pem(json['assertionMethod'].first['publicKeyMultibase'])

          expect(OpenSSL::PKey.read(pem).public_to_der).to eq(native_key.public_to_der)
          expect(json['publicKey']['publicKeyPem']).to eq(record.keypair(type: :rsa).public_key)
        end
      end
    end

    it 'omits revoked, expired, and other key types' do
      Fabricate(:keypair, account: record, type: :'ml-dsa-44', public_key: public_key, revoked: true)
      Fabricate(:keypair, account: record, type: :'ml-dsa-44', public_key: public_key, expires_at: 1.minute.ago)
      Fabricate(:keypair, account: record, type: :ed25519)

      expect(json).to_not have_key('assertionMethod')
      expect(json['@context']).to_not include('https://www.w3.org/ns/cid/v1')
    end
  end

  describe '#type' do
    context 'with the instance actor' do
      let(:record) { Account.find(Account::INSTANCE_ACTOR_ID) }

      it { is_expected.to include('type' => 'Application') }
    end

    context 'with an application actor' do
      let(:record) { Fabricate :account, actor_type: 'Application' }

      it { is_expected.to include('type' => 'Service') }
    end

    context 'with a service actor' do
      let(:record) { Fabricate :account, actor_type: 'Service' }

      it { is_expected.to include('type' => 'Service') }
    end

    context 'with a Group actor' do
      let(:record) { Fabricate :account, actor_type: 'Group' }

      it { is_expected.to include('type' => 'Group') }
    end

    context 'with a Person actor' do
      let(:record) { Fabricate :account, actor_type: 'Person' }

      it { is_expected.to include('type' => 'Person') }
    end
  end

  describe '#interactionPolicy' do
    let(:record) { Fabricate(:account) }

    context 'when actor is discoverable' do
      it 'includes an automatic policy allowing everyone' do
        expect(json).to include('interactionPolicy' => {
          'canFeature' => {
            'automaticApproval' => ['https://www.w3.org/ns/activitystreams#Public'],
          },
        })
      end

      context 'when actor is locked' do
        let(:record) { Fabricate(:account, locked: true) }

        it 'includes an automatic policy allowing followers' do
          expect(json).to include('interactionPolicy' => {
            'canFeature' => {
              'automaticApproval' => [ActivityPub::TagManager.instance.followers_uri_for(record)],
            },
          })
        end
      end
    end

    context 'when actor is not discoverable' do
      let(:record) { Fabricate(:account, discoverable: false) }

      it 'includes an automatic policy limited to the actor itself' do
        expect(json).to include('interactionPolicy' => {
          'canFeature' => {
            'automaticApproval' => [ActivityPub::TagManager.instance.uri_for(record)],
          },
        })
      end
    end
  end

  describe 'avatar description' do
    let(:record) { Fabricate(:account, avatar: attachment_fixture('avatar.gif'), avatar_description: 'test') }

    it 'includes an `icon` with the appropraite `summary`' do
      expect(json).to include('icon' => a_hash_including(
        'summary' => 'test'
      ))
    end
  end
end
