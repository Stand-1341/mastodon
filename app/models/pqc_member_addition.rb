# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_member_additions
#
#  id                     :bigint(8)        not null, primary key
#  added_device_ids       :jsonb            not null
#  client_message_ids     :jsonb            not null
#  created_at             :datetime         not null
#  updated_at             :datetime         not null
#  actor_account_id       :bigint(8)        not null
#  key_package_request_id :uuid
#  operation_id           :uuid             not null
#  pqc_conversation_id    :bigint(8)        not null
#  sender_device_id       :string           not null
#  target_account_id      :bigint(8)        not null
#
class PqcMemberAddition < ApplicationRecord
  belongs_to :pqc_conversation
  belongs_to :actor_account, class_name: 'Account'
  belongs_to :target_account, class_name: 'Account'

  validates :operation_id, presence: true, uniqueness: { scope: :pqc_conversation_id }
  validates :sender_device_id, presence: true
end
