# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Pqc::Messaging::DeviceRequestAuthenticator do
  let(:account) { Fabricate(:account) }
  let(:now) { Time.zone.parse('2026-10-14 12:00:00') }
  let(:nonce) { SecureRandom.uuid }
  let(:timestamp) { now.to_i.to_s }
  let(:raw_post) { '{"ciphertext":"abc"}' }
  let(:request) { instance_double(ActionDispatch::Request, method: 'POST', fullpath: '/api/v1/pqc_messages?x=1', raw_post:, headers:) }
  let(:private_key) { OpenSSL::PKey.generate_key('ML-DSA-87') }
  let(:raw_public_key) { OpenSSL::ASN1.decode(private_key.public_to_der).value.last.value }
  let!(:device) do
    PqcDevice.create!(account:, device_id: 'device-1', fingerprint: Digest::SHA256.hexdigest(raw_public_key), key_package: 'package', auth_public_key: raw_public_key)
  end
  let(:headers) { build_headers }

  before do
    begin
      private_key
    rescue OpenSSL::PKey::PKeyError, NotImplementedError => e
      skip "ML-DSA-87 OpenSSL provider unavailable: #{e.message}"
    end
  end

  it 'authenticates a valid device signature and records its nonce' do
    expect(described_class.call(request:, account:, now:)).to eq(device)
    expect(PqcDeviceRequestNonce.where(pqc_device: device, nonce:).count).to eq(1)
  end

  it 'rejects a changed request body' do
    allow(request).to receive(:raw_post).and_return('tampered')

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a changed request path' do
    allow(request).to receive(:fullpath).and_return('/different')

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a stale timestamp' do
    headers['X-PQC-Device-Timestamp'] = (now.to_i - 301).to_s

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects reuse of a nonce' do
    described_class.call(request:, account:, now:)

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects malformed strict base64' do
    headers['X-PQC-Device-Signature'] += ' '

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a well-formed but invalid signature' do
    signature = Base64.strict_decode64(headers.fetch('X-PQC-Device-Signature'))
    signature.setbyte(0, signature.getbyte(0) ^ 1)
    headers['X-PQC-Device-Signature'] = Base64.strict_encode64(signature)

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a malformed nonce' do
    headers['X-PQC-Device-Nonce'] = 'not-a-uuid'

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a device without an authentication key' do
    device.update!(auth_public_key: nil)

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects an authentication key whose fingerprint does not match' do
    device.update!(auth_fingerprint: '0' * 64)

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a revoked device' do
    device.revoke!

    expect { described_class.call(request:, account:, now:) }.to raise_error(described_class::AuthenticationError)
  end

  it 'rejects a device belonging to another account' do
    expect { described_class.call(request:, account: Fabricate(:account), now:) }.to raise_error(described_class::AuthenticationError)
  end

  private

  def build_headers
    signature = private_key.sign(nil, signed_bytes)
    {
      'X-PQC-Device-ID' => 'device-1',
      'X-PQC-Device-Timestamp' => timestamp,
      'X-PQC-Device-Nonce' => nonce,
      'X-PQC-Device-Signature' => Base64.strict_encode64(signature),
    }
  end

  def signed_bytes
    "Mastodon-PQC-Device-Auth-v1\nPOST\n/api/v1/pqc_messages?x=1\n#{timestamp}\n#{nonce}\n#{Digest::SHA256.hexdigest(raw_post)}"
  end
end
