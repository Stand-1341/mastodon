# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Pqc::Messaging::DeviceBindingCertificate do
  include PqcKeyProvisioningHelpers

  let(:account) { Fabricate(:account) }
  let(:device_id) { 'browser-device-123' }
  let(:fingerprint) { 'ab' * 32 }

  it 'binds an ML-DSA-87 device identity to the account assertion key' do
    generate_real_ml_dsa_87_key

    certificate = described_class.issue(account:, device_id:, fingerprint:)
    key = account.keypairs.find { |candidate| candidate.full_uri == certificate[:key_uri] }
    message = described_class.signing_message(
      actor_uri: ActivityPub::TagManager.instance.uri_for(account),
      device_id:,
      fingerprint:,
      verification_method: certificate[:key_uri],
      issued_at: certificate[:issued_at]
    )

    expect(key.type).to eq('ml-dsa-87')
    expect(key.keypair.verify(nil, certificate[:signature], message)).to be true
    expect(key.keypair.verify(nil, certificate[:signature], message.sub(fingerprint, 'cd' * 32))).to be false
  end
end
