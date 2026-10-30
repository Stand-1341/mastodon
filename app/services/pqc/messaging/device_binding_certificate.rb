# frozen_string_literal: true

class Pqc::Messaging::DeviceBindingCertificate
  CIPHERSUITE_ID = '0xf011'
  DOMAIN = 'Mastodon-PQC-Device-Binding-v1'

  def self.issue(account:, device_id:, fingerprint:)
    key = ActivityPub::GeneratePqcKeyService.new.call(account)
    issued_at = Time.now.to_i
    actor_uri = ActivityPub::TagManager.instance.uri_for(account)
    message = signing_message(actor_uri:, device_id:, fingerprint:, verification_method: key.full_uri, issued_at:)

    certificate = {
      key_uri: key.full_uri,
      issued_at:,
      signature: key.keypair.sign(nil, message),
    }
    account.touch
    certificate
  end

  def self.signing_message(actor_uri:, device_id:, fingerprint:, verification_method:, issued_at:)
    [DOMAIN, actor_uri, device_id, fingerprint, CIPHERSUITE_ID, verification_method, issued_at].join("\n")
  end
end
