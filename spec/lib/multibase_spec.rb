# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Multibase do
  include PqcKeyProvisioningHelpers

  describe '.decode' do
    it 'rejects invalid input with a domain error rather than an ingress exception' do
      [nil, '', [], 42, 'u!'].each do |input|
        expect { described_class.decode(input) }.to raise_error(described_class::Error)
      end
    end
  end

  describe '.encode_key_from_pem' do
    subject(:encoded_key) { described_class.encode_key_from_pem(public_key, type: :'ml-dsa-44') }

    let(:public_key) { synthetic_ml_dsa_44_public_key }

    it 'encodes the public bitstring with the ML-DSA multicodec and unpadded base64url multibase' do
      expect(encoded_key).to start_with('u')
      expect(encoded_key).to_not include('=', '+', '/')
      expect(described_class.decode_multicodec(encoded_key)).to eq([:'mldsa-44-pub', "\x42" * 1312])
      expect(described_class.decode_key_to_pem(encoded_key)).to eq([:'ml-dsa-44', public_key])
    end

    it 'does not require the runtime to parse ML-DSA keys' do
      allow(OpenSSL::PKey).to receive(:read).and_raise(OpenSSL::PKey::PKeyError, 'unsupported')

      expect(encoded_key).to start_with('u')
      expect(OpenSSL::PKey).to_not have_received(:read)
    end

    it 'rejects another algorithm labelled as ML-DSA-44' do
      expect do
        described_class.encode_key_from_pem(SigningKeysHelpers::PUBLIC_RSA_TEST_KEY, type: :'ml-dsa-44')
      end.to raise_error(described_class::Error, /Invalid ML-DSA-44/)
    end

    it 'rejects private key PEM rather than publishing it' do
      expect do
        described_class.encode_key_from_pem(SigningKeysHelpers::PRIVATE_RSA_TEST_KEY, type: :'ml-dsa-44')
      end.to raise_error(described_class::Error, /Invalid public key PEM/)
    end

    it 'rejects unsupported key types' do
      expect { described_class.encode_key_from_pem(public_key, type: :rsa) }.to raise_error(described_class::Error, /Unsupported key type/)
    end

    it 'rejects malformed DER' do
      pem = "-----BEGIN PUBLIC KEY-----\nYmFk\n-----END PUBLIC KEY-----\n"

      expect { described_class.encode_key_from_pem(pem, type: :'ml-dsa-44') }.to raise_error(described_class::Error)
    end

    it 'rejects a non-sequence DER structure' do
      pem = "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(OpenSSL::ASN1::Integer.new(1).to_der)}\n-----END PUBLIC KEY-----\n"

      expect { described_class.encode_key_from_pem(pem, type: :'ml-dsa-44') }.to raise_error(described_class::Error, /Invalid public key DER/)
    end

    it 'rejects an invalid public bitstring length' do
      der = OpenSSL::ASN1.decode(Base64.decode64(public_key.lines[1...-1].join))
      der.value.last.value = 'short'
      pem = "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(der.to_der)}\n-----END PUBLIC KEY-----\n"

      expect { described_class.encode_key_from_pem(pem, type: :'ml-dsa-44') }.to raise_error(described_class::Error, /Invalid ML-DSA-44/)
    end

    context 'with a real ML-DSA-44 key' do
      let(:key) { generate_real_ml_dsa_44_key }
      let(:public_key) { key.public_to_pem }

      it 'round-trips to the same native public key' do
        type, pem = described_class.decode_key_to_pem(encoded_key)

        expect(type).to eq(:'ml-dsa-44')
        expect(OpenSSL::PKey.read(pem).public_to_der).to eq(key.public_to_der)
        expect(described_class.decode_multicodec(encoded_key).last.bytesize).to eq(1312)
      end
    end
  end

  describe '.decode_key_to_pem' do
    it 'rejects a truncated ML-DSA-44 multicodec payload' do
      binary = "#{described_class::MULTICODEC_PREFIXES[:'mldsa-44-pub']}short"
      encoded_key = "u#{Base64.urlsafe_encode64(binary, padding: false)}"

      expect { described_class.decode_key_to_pem(encoded_key) }.to raise_error(described_class::Error, /Invalid data size/)
    end
  end
end
