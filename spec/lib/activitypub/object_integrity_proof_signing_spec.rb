# frozen_string_literal: true

require 'rails_helper'

RSpec.describe ActivityPub::ObjectIntegrityProof, '#sign!' do
  include PqcKeyProvisioningHelpers

  let(:account) { Fabricate(:account) }
  let(:key) { ActivityPub::GeneratePqcKeyService.new.call(account) }
  let(:document) do
    {
      '@context' => 'https://www.w3.org/ns/activitystreams',
      'id' => 'https://example.org/activities/1',
      'type' => 'Create',
      'actor' => ActivityPub::TagManager.instance.uri_for(account),
      'object' => { 'type' => 'Note', 'content' => 'Hello world' },
    }
  end

  before do
    generate_real_ml_dsa_44_key
  end

  it 'creates a verifiable ML-DSA proof without mutating the input' do
    original = document.deep_dup
    secured = described_class.new(document).sign!(account, sign_with: key)

    expect(document).to eq(original)
    expect(secured['proof']).to include(
      'type' => 'DataIntegrityProof',
      'cryptosuite' => 'mldsa44-jcs-2024',
      'verificationMethod' => key.full_uri,
      'proofPurpose' => 'assertionMethod'
    )
    expect(Multibase.decode(secured['proof']['proofValue']).bytesize).to eq(2420)
    expect(described_class.verify_mldsa44_jcs_2024(secured, OpenSSL::PKey.read(key.public_key))).to be true
  end

  it 'binds the document content, proof options, and final context' do
    secured = described_class.new(document).sign!(account, sign_with: key)
    public_key = OpenSSL::PKey.read(key.public_key)
    changed_content = secured.deep_dup
    changed_content['object']['content'] = 'Tampered'
    changed_key = secured.deep_dup
    changed_key['proof']['verificationMethod'] = 'https://attacker.example/key'
    changed_context = secured.deep_dup
    changed_context['@context'] << 'https://attacker.example/context'

    [changed_content, changed_key, changed_context].each do |tampered|
      expect(described_class.verify_mldsa44_jcs_2024(tampered, public_key)).to be false
    end
  end

  it 'rejects signatures made with a different key' do
    secured = described_class.new(document).sign!(account, sign_with: key)

    expect(described_class.verify_mldsa44_jcs_2024(secured, generate_real_ml_dsa_44_key)).to be false
  end

  it 'sets signed creation and expiration timestamps' do
    freeze_time do
      secured = described_class.new(document).sign!(account, sign_with: key, expires_in: 1.hour)

      expect(secured['proof']).to include('created' => Time.now.utc.iso8601, 'expires' => 1.hour.from_now.utc.iso8601)
    end
  end

  it 'caps proof expiration at the key expiration time' do
    freeze_time do
      key.update!(expires_at: 10.minutes.from_now)
      secured = described_class.new(document).sign!(account, sign_with: key)

      expect(secured['proof']['expires']).to eq(key.expires_at.utc.iso8601)
    end
  end

  it 'rejects an already expired proof lifetime' do
    expect { described_class.new(document).sign!(account, sign_with: key, expires_in: -1.minute) }.to raise_error(ArgumentError, /expiration must be in the future/)
  end

  it 'does not replace existing signatures or proofs' do
    key

    %w(proof signature).each do |field|
      expect { described_class.new(document.merge(field => {})).sign!(account) }.to raise_error(ArgumentError, /Refusing to replace/)
    end
  end

  it 'rejects a key owned by a different account' do
    other = Fabricate(:account)

    expect { described_class.new(document).sign!(other, sign_with: key) }.to raise_error(ArgumentError, /owned by the signer/)
  end

  it 'rejects a missing key without automatically provisioning one' do
    account

    expect { described_class.new(document).sign!(account) }.to raise_error(ArgumentError, /usable local ML-DSA/)
    expect(account.keypairs.pluck(:type)).to eq(['rsa'])
  end

  it 'rejects RSA, revoked, and expired keys' do
    rsa = account.keypair(type: :rsa)
    revoked = key
    revoked.update!(revoked: true)
    expired = ActivityPub::GeneratePqcKeyService.new.call(account)
    expired.update!(expires_at: 1.minute.ago)

    [rsa, revoked, expired].each do |unusable|
      expect { described_class.new(document).sign!(account, sign_with: unusable) }.to raise_error(ArgumentError, /usable local ML-DSA/)
    end
  end
end
