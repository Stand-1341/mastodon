# frozen_string_literal: true

class ActivityPub::PqcSigning
  class SigningError < StandardError; end

  def initialize(json)
    @json = json.deep_stringify_keys
  end

  def sign!(creator, sign_with: nil)
    document = @json
    key = pqc_key_for(creator)

    document = add_proof(creator, key) if key.present?

    ActivityPub::LinkedDataSignature.new(document).sign!(creator, sign_with: sign_with)
  end

  private

  # ML-DSA-87 keys are provisioned automatically for every local account, so
  # signing with them is on by default. Setting PQC_ACTIVITYPUB_SIGNING=false is
  # only an escape hatch for deployments whose OpenSSL cannot handle ML-DSA-87;
  # an absent or empty value means signing is enabled.
  def pqc_key_for(creator)
    return nil unless pqc_signing_enabled? && creator.local?

    key = creator.keypair(type: :'ml-dsa-87')
    return key if key&.usable? && key.private_key.present?

    Rails.logger.debug { "Skipping ML-DSA ActivityPub proof for #{creator.acct}: no usable signing key is provisioned" }
    nil
  end

  def pqc_signing_enabled?
    ENV['PQC_ACTIVITYPUB_SIGNING'] != 'false'
  end

  def add_proof(creator, key)
    # RSA signing adds this context. Include it before JCS signing so both
    # signatures bind the same document context on the receiving server.
    context = (ActivityPub::ObjectIntegrityProof.context_list(@json['@context']) + ['https://w3id.org/security/v1']).uniq
    document = @json.merge('@context' => context)
    ActivityPub::ObjectIntegrityProof.new(document).sign!(creator, sign_with: key)
  rescue OpenSSL::PKey::PKeyError, NotImplementedError
    raise SigningError, 'Cannot sign with the configured ML-DSA-87 key; check OpenSSL/provider support. Disable PQC_ACTIVITYPUB_SIGNING explicitly (set it to false) to resume RSA-only signing'
  end
end
