# frozen_string_literal: true

require 'digest'

# == Schema Information
#
# Table name: pqc_devices
#
#  id                                :bigint(8)        not null, primary key
#  auth_fingerprint                  :string
#  auth_public_key                   :binary
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

  private

  def derive_auth_fingerprint
    self.auth_fingerprint = Digest::SHA256.hexdigest(self[:auth_public_key])
  end
end
