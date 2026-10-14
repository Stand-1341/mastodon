# frozen_string_literal: true

class Multibase
  # Multicodec uses a variable-length unsigned integer to tag
  # data. We precompute here the types we are interested about.
  # Registered types are available at https://github.com/multiformats/multicodec/blob/master/table.csv
  MULTICODEC_PREFIXES = {
    'rsa-pub': 0x1205,
    'ed25519-pub': 0xED,
    'mldsa-44-pub': 0x1210,
  }.transform_values do |code|
    bytes = []

    while code > 127
      bytes << ((code & 0x7F) | 128)
      code >>= 7
    end

    bytes << code
    bytes.pack('C*')
  end.freeze

  ED25519_PUB_DER_HEADER = ['302a300506032b6570032100'].pack('H*').freeze
  ML_DSA_44_PUB_DER_HEADER = ['30820532300b06096086480165030403110382052100'].pack('H*').freeze

  class Error < StandardError; end

  def self.decode(string)
    raise Error, 'Multibase input must be a non-empty string' unless string.is_a?(String) && string.present?

    case string[0]
    when 'u'
      Base64.urlsafe_decode64(string[1...])
    when 'z'
      Base58.base58_to_binary(string[1...], :bitcoin)
    else
      raise Error, 'Invalid Multibase base'
    end
  rescue ArgumentError => e
    raise Error, e
  end

  def self.decode_multicodec(string)
    binary = decode(string)

    MULTICODEC_PREFIXES.each do |tag, prefix|
      return [tag, binary[prefix.length..]] if binary.starts_with?(prefix)
    end

    raise Error, 'Unknown Multicodec tag'
  end

  def self.encode_key_from_pem(pem, type:)
    raise Error, 'Unsupported key type' unless type.to_s == 'ml-dsa-44'

    match = pem.match(%r{\A-----BEGIN PUBLIC KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*\z})
    raise Error, 'Invalid public key PEM' if match.nil?

    der = Base64.strict_decode64(match[1].gsub(/\s+/, ''))
    sequence = OpenSSL::ASN1.decode(der)
    raise Error, 'Invalid public key DER' unless sequence.is_a?(OpenSSL::ASN1::Sequence) && sequence.value.size == 2

    algorithm, public_key = sequence.value
    unless algorithm.is_a?(OpenSSL::ASN1::Sequence) && algorithm.value.size == 1 &&
           algorithm.value.first.is_a?(OpenSSL::ASN1::ObjectId) && algorithm.value.first.oid == '2.16.840.1.101.3.4.3.17' &&
           public_key.is_a?(OpenSSL::ASN1::BitString) && public_key.unused_bits.zero? && public_key.value.bytesize == 1312
      raise Error, 'Invalid ML-DSA-44 public key'
    end

    "u#{Base64.urlsafe_encode64(MULTICODEC_PREFIXES[:'mldsa-44-pub'] + public_key.value, padding: false)}"
  rescue OpenSSL::ASN1::ASN1Error, ArgumentError => e
    raise Error, e
  end

  def self.decode_key_to_pem(string)
    tag, binary = decode_multicodec(string)

    case tag
    when :'rsa-pub'
      [:rsa, OpenSSL::PKey::RSA.new(binary).to_pem]
    when :'ed25519-pub'
      raise Error, 'Invalid data size for ed25519-pub' unless binary.size == 32

      der = ED25519_PUB_DER_HEADER + binary
      [:ed25519, "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(der)}\n-----END PUBLIC KEY-----\n"]
    when :'mldsa-44-pub'
      raise Error, 'Invalid data size for mldsa-44-pub' unless binary.size == 1312

      der = ML_DSA_44_PUB_DER_HEADER + binary
      [:'ml-dsa-44', "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(der).scan(/.{,64}/).join("\n")}-----END PUBLIC KEY-----\n"]
    else
      raise Error, 'Unsupported key type'
    end
  rescue OpenSSL::PKey::PKeyError => e
    raise Error, e
  end
end
