# frozen_string_literal: true

# This is an implementation of https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md
class ActivityPub::ObjectIntegrityProof
  include JsonLdHelper

  SUPPORTED_CRYPTOSUITES = %w(eddsa-jcs-2022 mldsa44-jcs-2024).freeze
  CONTEXT = 'https://w3id.org/security/data-integrity/v2'

  def initialize(json)
    @json = json.is_a?(Hash) ? json.deep_stringify_keys : json
  end

  def self.context_list(context)
    case context
    when Array then context
    when nil then []
    else [context]
    end
  end

  def verify_actor!(proof_purpose: 'assertionMethod', force_key_refresh: false)
    return unless @json.is_a?(Hash) && @json['proof'].is_a?(Hash)

    proof = @json['proof']
    return unless proof['type'] == 'DataIntegrityProof' && proof['verificationMethod'].present? && proof['proofPurpose'] == proof_purpose

    return unless %w(type cryptosuite verificationMethod proofPurpose proofValue).all? { |field| proof[field].is_a?(String) && proof[field].present? }
    return if proof.key?('created') && (!proof['created'].is_a?(String) || !Time.iso8601(proof['created']))
    return if proof.key?('expires') && (!proof['expires'].is_a?(String) || Time.iso8601(proof['expires']).past?)

    cryptosuite = proof['cryptosuite']
    key_uri = proof['verificationMethod']

    return unless SUPPORTED_CRYPTOSUITES.include?(cryptosuite) && proof['proofValue'].present?

    keypair = Keypair.from_keyid(key_uri)
    if keypair&.public_key.blank?
      keypair = ActivityPub::FetchRemoteKeyService.new.call(key_uri)
    elsif keypair.actor.remote? && (force_key_refresh || @json['type'] == 'Update' || keypair.actor.possibly_stale?)
      keypair = ActivityPub::FetchRemoteKeyService.new.call(key_uri, force_refresh: true)
    end
    return if keypair.nil? || !keypair.usable?

    case cryptosuite
    when 'eddsa-jcs-2022'
      return if keypair.type != 'ed25519'

      keypair.actor if ActivityPub::ObjectIntegrityProof.verify_eddsa_jcs_2022(@json, keypair.keypair)
    when 'mldsa44-jcs-2024'
      return if keypair.type != 'ml-dsa-44'

      keypair.actor if ActivityPub::ObjectIntegrityProof.verify_mldsa44_jcs_2024(@json, keypair.keypair)
    end
  rescue Multibase::Error, OpenSSL::PKey::PKeyError, ArgumentError, NotImplementedError
    false
  end

  def sign!(creator, sign_with: nil, expires_in: 2.days)
    key = sign_with || creator.keypair(type: :'ml-dsa-44')
    raise ArgumentError, 'A usable local ML-DSA-44 private key owned by the signer is required' unless creator.local? && key&.account == creator && key.type == 'ml-dsa-44' && key.usable? && key.private_key.present?
    raise ArgumentError, 'Refusing to replace an existing proof or signature' if @json.key?('proof') || @json.key?('signature')

    document = @json.deep_dup
    document['@context'] = (self.class.context_list(document['@context']) + [CONTEXT]).uniq
    expires_at = expires_in.from_now.utc
    expires_at = [expires_at, key.expires_at].min if key.expires_at.present?
    raise ArgumentError, 'Proof expiration must be in the future' unless expires_at.future?

    options = {
      'type' => 'DataIntegrityProof',
      'cryptosuite' => 'mldsa44-jcs-2024',
      'created' => Time.now.utc.iso8601,
      'expires' => expires_at.iso8601,
      'verificationMethod' => key.full_uri,
      'proofPurpose' => 'assertionMethod',
    }

    # The ML-DSA suite binds the document's final context in the proof configuration.
    proof_config = options.merge('@context' => document['@context']).to_json_c14n
    to_be_signed = Digest::SHA256.digest(proof_config) + Digest::SHA256.digest(document.to_json_c14n)
    signature = key.keypair.sign(nil, to_be_signed)

    document.merge('proof' => options.merge('proofValue' => "u#{Base64.urlsafe_encode64(signature, padding: false)}"))
  end

  # https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-jcs-2022
  def self.verify_eddsa_jcs_2022(document, keypair) # rubocop:disable Naming/VariableNumber
    unsecured_document = document.without('proof')
    proof_options = document['proof'].without('proofValue')
    proof_bytes = Multibase.decode(document['proof']['proofValue'])

    if proof_options['@context'].present?
      return unless unsecured_document['@context'].is_a?(Array)
      return unless unsecured_document['@context'][...proof_options['@context'].length] == proof_options['@context']

      # Step 4.2. from the aforementioned algorithm, it's useful when vocabulary necessary to the cryptosuite had to be added on top of the to-be-signed document
      unsecured_document['@context'] = proof_options['@context']
    end

    transformed_data = unsecured_document.to_json_c14n
    proof_config = proof_options.to_json_c14n

    to_be_verified = Digest::SHA256.digest(proof_config) + Digest::SHA256.digest(transformed_data)

    keypair.verify(nil, proof_bytes, to_be_verified)
  end

  # https://www.w3.org/TR/2026/WD-vc-di-quantum-resistant-1.0-20260616/#verify-proof-ml-dsa
  def self.verify_mldsa44_jcs_2024(document, keypair) # rubocop:disable Naming/VariableNumber
    unsecured_document = document.without('proof')
    proof_options = document['proof'].without('proofValue')
    proof_bytes = Multibase.decode(document['proof']['proofValue'])

    # This is inconsistent with eddsa-jcs-2022 but described in https://www.w3.org/TR/2026/WD-vc-di-quantum-resistant-1.0-20260616/#ProofConfigurationAlg
    proof_options['@context'] = unsecured_document['@context']

    transformed_data = unsecured_document.to_json_c14n
    proof_config = proof_options.to_json_c14n

    to_be_verified = Digest::SHA256.digest(proof_config) + Digest::SHA256.digest(transformed_data)

    keypair.verify(nil, proof_bytes, to_be_verified)
  end
end
