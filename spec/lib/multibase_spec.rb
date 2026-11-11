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

    it 'rejects non-canonical base64url encodings' do
      expect { described_class.decode('uAB==') }.to raise_error(described_class::Error, /Non-canonical/)
    end
  end

  describe '.decode_multicodec' do
    it 'rejects a varint prefix truncated before the second byte' do
      encoded = "u#{Base64.urlsafe_encode64("\x92".b, padding: false)}"

      expect { described_class.decode_multicodec(encoded) }
        .to raise_error(described_class::Error, /Truncated Multicodec prefix/)
    end
  end

  describe '.encode_key_from_pem' do
    subject(:encoded_key) { described_class.encode_key_from_pem(public_key, type: :'ml-dsa-87') }

    let(:public_key) { synthetic_ml_dsa_87_public_key }

    it 'encodes the public bitstring with the ML-DSA multicodec and unpadded base64url multibase' do
      expect(encoded_key).to start_with('u')
      expect(encoded_key).to_not include('=', '+', '/')
      expect(described_class.decode_multicodec(encoded_key)).to eq([:'mldsa-87-pub', "\x42" * 2592])
      expect(described_class.decode_key_to_pem(encoded_key)).to eq([:'ml-dsa-87', public_key])
    end

    it 'does not require the runtime to parse ML-DSA keys' do
      allow(OpenSSL::PKey).to receive(:read).and_raise(OpenSSL::PKey::PKeyError, 'unsupported')

      expect(encoded_key).to start_with('u')
      expect(OpenSSL::PKey).to_not have_received(:read)
    end

    it 'rejects another algorithm labelled as ML-DSA-87' do
      expect do
        described_class.encode_key_from_pem(SigningKeysHelpers::PUBLIC_RSA_TEST_KEY, type: :'ml-dsa-87')
      end.to raise_error(described_class::Error, /Invalid ML-DSA-87/)
    end

    it 'rejects private key PEM rather than publishing it' do
      expect do
        described_class.encode_key_from_pem(SigningKeysHelpers::PRIVATE_RSA_TEST_KEY, type: :'ml-dsa-87')
      end.to raise_error(described_class::Error, /Invalid public key PEM/)
    end

    it 'rejects unsupported key types' do
      expect { described_class.encode_key_from_pem(public_key, type: :rsa) }.to raise_error(described_class::Error, /Unsupported key type/)
    end

    it 'rejects retired ML-DSA-44 keys instead of publishing a second signature algorithm' do
      expect do
        described_class.encode_key_from_pem(public_key, type: :'ml-dsa-44')
      end.to raise_error(described_class::Error, /Unsupported key type/)
    end

    it 'rejects malformed DER' do
      pem = "-----BEGIN PUBLIC KEY-----\nYmFk\n-----END PUBLIC KEY-----\n"

      expect { described_class.encode_key_from_pem(pem, type: :'ml-dsa-87') }.to raise_error(described_class::Error)
    end

    it 'rejects a non-sequence DER structure' do
      pem = "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(OpenSSL::ASN1::Integer.new(1).to_der)}\n-----END PUBLIC KEY-----\n"

      expect { described_class.encode_key_from_pem(pem, type: :'ml-dsa-87') }.to raise_error(described_class::Error, /Invalid public key DER/)
    end

    it 'rejects an invalid public bitstring length' do
      der = OpenSSL::ASN1.decode(Base64.decode64(public_key.lines[1...-1].join))
      der.value.last.value = 'short'
      pem = "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(der.to_der)}\n-----END PUBLIC KEY-----\n"

      expect { described_class.encode_key_from_pem(pem, type: :'ml-dsa-87') }.to raise_error(described_class::Error, /Invalid ML-DSA-87/)
    end

    context 'with a real ML-DSA-87 key' do
      let(:key) { generate_real_ml_dsa_87_key }
      let(:public_key) { key.public_to_pem }

      it 'round-trips to the same native public key' do
        type, pem = described_class.decode_key_to_pem(encoded_key)

        expect(type).to eq(:'ml-dsa-87')
        expect(OpenSSL::PKey.read(pem).public_to_der).to eq(key.public_to_der)
        expect(described_class.decode_multicodec(encoded_key).last.bytesize).to eq(2592)
      end
    end
  end

  describe 'ML-DSA-87 SubjectPublicKeyInfo' do
    it 'round-trips a public key with valid DER lengths' do
      public_bytes = "\x42" * 2592
      der = described_class::ML_DSA_87_PUB_DER_HEADER + public_bytes
      pem = "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(der).scan(/.{1,64}/).join("\n")}\n-----END PUBLIC KEY-----\n"

      encoded = described_class.encode_key_from_pem(pem, type: :'ml-dsa-87')
      expect(described_class.decode_multicodec(encoded)).to eq([:'mldsa-87-pub', public_bytes])

      type, decoded_pem = described_class.decode_key_to_pem(encoded)
      expect(type).to eq(:'ml-dsa-87')
      decoded_der = Base64.strict_decode64(decoded_pem.lines[1...-1].map(&:strip).join)
      expect(OpenSSL::ASN1.decode(decoded_der).to_der).to eq(decoded_der)
    end
  end

  describe '.decode_key_to_pem' do
    it 'rejects a truncated ML-DSA-87 multicodec payload' do
      binary = "#{described_class::MULTICODEC_PREFIXES[:'mldsa-87-pub']}short"
      encoded_key = "u#{Base64.urlsafe_encode64(binary, padding: false)}"

      expect { described_class.decode_key_to_pem(encoded_key) }.to raise_error(described_class::Error, /Invalid data size/)
    end
  end
end
