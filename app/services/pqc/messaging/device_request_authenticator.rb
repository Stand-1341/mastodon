# frozen_string_literal: true

require 'digest'
require 'base64'
require 'openssl'

class Pqc::Messaging::DeviceRequestAuthenticator
  PUBLIC_KEY_BYTES = 2592
  ML_DSA_87_OID = '2.16.840.1.101.3.4.3.19'
  TIMESTAMP_TOLERANCE = 5.minutes
  NONCE_FORMAT = /\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i

  class AuthenticationError < StandardError; end

  def self.call(request:, account:, now: Time.current)
    new(request:, account:, now:).call
  end

  def initialize(request:, account:, now:)
    @request = request
    @account = account
    @now = now
  end

  def call
    device_id = header('X-PQC-Device-ID')
    timestamp = header('X-PQC-Device-Timestamp')
    nonce = header('X-PQC-Device-Nonce')
    encoded_signature = header('X-PQC-Device-Signature')

    reject! unless device_id.present? && timestamp&.match?(/\A[0-9]{1,12}\z/) && nonce&.match?(NONCE_FORMAT) && encoded_signature.present?

    timestamp_time = Time.at(Integer(timestamp, 10)).utc
    reject! if (timestamp_time - @now).abs > TIMESTAMP_TOLERANCE

    device = PqcDevice.active.find_by(account_id: @account.id, device_id:)
    reject! unless device

    raw_key = device[:auth_public_key]
    reject! unless raw_key.is_a?(String) && raw_key.bytesize == PUBLIC_KEY_BYTES

    auth_fingerprint = Digest::SHA256.hexdigest(raw_key)
    reject! unless device.auth_fingerprint.present? && secure_compare(auth_fingerprint, device.auth_fingerprint)

    signature = strict_base64(encoded_signature)
    public_key = import_public_key(raw_key)
    signed_bytes = "Mastodon-PQC-Device-Auth-v1\n#{@request.method.upcase}\n#{@request.fullpath}\n#{timestamp}\n#{nonce}\n#{Digest::SHA256.hexdigest(@request.raw_post)}"
    reject! unless public_key.verify(nil, signature, signed_bytes.encode(Encoding::UTF_8))

    PqcDeviceRequestNonce.create!(pqc_device: device, nonce:)
    device
  rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
    reject!('Device request nonce has already been used')
  rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error, ArgumentError, RangeError, TypeError
    reject!
  end

  private

  def header(name)
    @request.headers[name]
  end

  def strict_base64(value)
    decoded = Base64.strict_decode64(value)
    reject! unless Base64.strict_encode64(decoded) == value
    decoded
  rescue ArgumentError
    reject!
  end

  def import_public_key(raw_key)
    algorithm = OpenSSL::ASN1::Sequence.new([
                                              OpenSSL::ASN1::ObjectId.new(ML_DSA_87_OID),
                                            ])
    subject_public_key_info = OpenSSL::ASN1::Sequence.new([
                                                            algorithm,
                                                            OpenSSL::ASN1::BitString.new(raw_key),
                                                          ])
    OpenSSL::PKey.read(subject_public_key_info.to_der)
  end

  def secure_compare(left, right)
    left.bytesize == right.bytesize && ActiveSupport::SecurityUtils.secure_compare(left, right)
  end

  def reject!(message = 'Invalid PQC device authentication')
    raise AuthenticationError, message
  end
end
