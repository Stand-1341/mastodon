# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_messages
#
#  id                  :bigint(8)        not null, primary key
#  ciphertext          :binary           not null
#  created_at          :datetime         not null
#  updated_at          :datetime         not null
#  account_id          :bigint(8)        not null
#  client_message_id   :uuid
#  pqc_conversation_id :bigint(8)        not null
#  recipient_device_id :string
#  sender_device_id    :string
#
class PqcMessage < ApplicationRecord
  belongs_to :pqc_conversation
  belongs_to :account
  belongs_to :sender_device, class_name: 'PqcDevice', primary_key: :device_id, optional: true, inverse_of: false
  belongs_to :recipient_device, class_name: 'PqcDevice', primary_key: :device_id, optional: true, inverse_of: false

  validates :ciphertext, presence: true, length: { maximum: 1.megabyte }
  validates :client_message_id, uniqueness: { scope: [:pqc_conversation_id, :account_id, :sender_device_id] }, allow_nil: true
  validate :sender_must_be_a_member

  private

  def sender_must_be_a_member
    unless pqc_conversation&.pqc_conversation_devices&.exists?(pqc_device_id: sender_device&.id)
      errors.add(:sender_device, 'must be enrolled in the encrypted conversation')
      return
    end

    errors.add(:sender_device, 'must belong to the sending account') unless sender_device_id.present? && sender_device&.account_id == account_id

    return if recipient_device.blank? || pqc_conversation.pqc_conversation_devices.exists?(pqc_device_id: recipient_device.id)

    errors.add(:recipient_device, 'must belong to an encrypted conversation member')
  end
end
