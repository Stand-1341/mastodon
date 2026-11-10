# frozen_string_literal: true

require 'digest'
require 'base64'

# == Schema Information
#
# Table name: pqc_devices
#
#  id                                :bigint(8)        not null, primary key
#  auth_fingerprint                  :string
#  auth_public_key                   :binary
#  account_binding_issued_at         :bigint
#  account_binding_key_uri           :string
#  account_binding_signature         :binary
#  fingerprint                       :string           not null
#  key_package                       :binary           not null
#  key_package_consumed_at           :datetime
#  revocation_pending_at             :datetime
#  revoked_at                        :datetime
#  created_at                        :datetime         not null
#  updated_at                        :datetime         not null
#  account_id                        :bigint(8)        not null
#  device_id                         :string           not null
#  key_package_claim_conversation_id :bigint(8)
#  key_package_claim_id              :uuid
#
class PqcDevice < ApplicationRecord
  class EnrolledInMlsGroupError < StandardError; end

  belongs_to :account
  belongs_to :key_package_claim_conversation, class_name: 'PqcConversation', optional: true
  has_many :pqc_conversation_devices, dependent: :delete_all

  validates :device_id, presence: true, length: { maximum: 128 }, format: { without: /[\r\n\0]/ }
  validates :fingerprint, presence: true, format: { with: /\A[0-9a-f]{64}\z/ }
  validates :auth_fingerprint, format: { with: /\A[0-9a-f]{64}\z/ }, allow_nil: true
  validates :key_package, presence: true, length: { maximum: 512.kilobytes }
  validates :media_kem_public_key, length: { is: 1568 }, allow_nil: true
  validates :device_id, uniqueness: true

  scope :active, -> { where(revoked_at: nil, revocation_pending_at: nil) }
  scope :unrevoked, -> { where(revoked_at: nil) }
  scope :with_unused_key_package, -> { active.where(key_package_consumed_at: nil) }

  before_validation :derive_auth_fingerprint, if: -> { auth_public_key.present? && (auth_fingerprint.blank? || will_save_change_to_auth_public_key?) }

  def revoke!
    with_lock do
      raise EnrolledInMlsGroupError, 'Remove this device from every active MLS group before revoking it' if pqc_conversation_devices.exists?

      update!(revoked_at: Time.current, key_package_consumed_at: Time.current)
    end
  end

  def account_binding_certificate
    return unless account_binding_key_uri.present? && account_binding_issued_at.present? && account_binding_signature.present?

    {
      version: 1,
      actor_uri: ActivityPub::TagManager.instance.uri_for(account),
      device_id:,
      fingerprint:,
      ciphersuite_id: Pqc::Messaging::DeviceBindingCertificate::CIPHERSUITE_ID,
      verification_method: account_binding_key_uri,
      issued_at: account_binding_issued_at,
      signature: "u#{Base64.urlsafe_encode64(account_binding_signature, padding: false)}",
    }
  end

  def ensure_account_binding!
    return unless auth_public_key&.bytesize == 2592
    return unless ActiveSupport::SecurityUtils.secure_compare(Digest::SHA256.hexdigest(auth_public_key), fingerprint)

    with_lock do
      current_actor_uri = ActivityPub::TagManager.instance.uri_for(account)
      existing_key = account.keypairs.usable.where(type: :'ml-dsa-87').find do |key|
        key.full_uri == account_binding_key_uri
      end
      if existing_key && account_binding_certificate.present? && account_binding_key_uri.start_with?("#{current_actor_uri}#")
        message = Pqc::Messaging::DeviceBindingCertificate.signing_message(
          actor_uri: current_actor_uri,
          device_id:,
          fingerprint:,
          verification_method: account_binding_key_uri,
          issued_at: account_binding_issued_at
        )
        public_key = OpenSSL::PKey.read(existing_key.public_key)
        return account_binding_certificate if public_key.verify(nil, account_binding_signature, message)
      end

      binding = Pqc::Messaging::DeviceBindingCertificate.issue(account:, device_id:, fingerprint:)
      update!(
        account_binding_key_uri: binding[:key_uri],
        account_binding_issued_at: binding[:issued_at],
        account_binding_signature: binding[:signature]
      )
    end

    account_binding_certificate
  end

  private

  def derive_auth_fingerprint
    self.auth_fingerprint = Digest::SHA256.hexdigest(self[:auth_public_key])
  end
end
