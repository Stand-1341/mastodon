# frozen_string_literal: true

class ActivityPub::PqcSigning
  class SigningError < StandardError; end

  def initialize(json)
    @json = json.deep_stringify_keys
  end

  def sign!(creator, sign_with: nil)
    document = @json
    key = creator.keypair(type: :'ml-dsa-44') if ENV['PQC_ACTIVITYPUB_SIGNING'] == 'true' && creator.local?
    document = add_proof(creator, key) if key.present?

    ActivityPub::LinkedDataSignature.new(document).sign!(creator, sign_with: sign_with)
  end

  private

  def add_proof(creator, key)
    # RSA signing adds this context. Include it before JCS signing so both
    # signatures bind the same document context on the receiving server.
    context = (Array(@json['@context']) + ['https://w3id.org/security/v1']).uniq
    document = @json.merge('@context' => context)
    ActivityPub::ObjectIntegrityProof.new(document).sign!(creator, sign_with: key)
  rescue OpenSSL::PKey::PKeyError, NotImplementedError
    raise SigningError, 'Cannot sign with the configured ML-DSA-44 key; check OpenSSL/provider support. Disable PQC_ACTIVITYPUB_SIGNING explicitly to resume RSA-only signing'
  end
end
