# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_conversation_devices
#
#  id                  :bigint(8)        not null, primary key
#  created_at          :datetime         not null
#  updated_at          :datetime         not null
#  pqc_conversation_id :bigint(8)        not null
#  pqc_device_id       :bigint(8)        not null
#
class PqcConversationDevice < ApplicationRecord
  belongs_to :pqc_conversation
  belongs_to :pqc_device

  validates :pqc_device_id, uniqueness: { scope: :pqc_conversation_id }
  validate :pqc_device_must_remain_active

  scope :active, -> { joins(:pqc_device).merge(PqcDevice.active) }

  private

  def pqc_device_must_remain_active
    return unless pqc_device

    pqc_device.with_lock do
      errors.add(:pqc_device, 'must be active') if pqc_device.revoked_at? || pqc_device.revocation_pending_at?
    end
  end
end
