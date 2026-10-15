# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_member_removals
#
#  id                  :bigint(8)        not null, primary key
#  client_message_ids  :jsonb            not null
#  created_at          :datetime         not null
#  updated_at          :datetime         not null
#  actor_account_id    :bigint(8)        not null
#  operation_id        :uuid             not null
#  pqc_conversation_id :bigint(8)        not null
#  sender_device_id    :string           not null
#  target_account_id   :bigint(8)        not null
#  target_device_id    :string
#
class PqcMemberRemoval < ApplicationRecord
  belongs_to :pqc_conversation
  belongs_to :actor_account, class_name: 'Account'
  belongs_to :target_account, class_name: 'Account'

  validates :operation_id, presence: true, uniqueness: { scope: :pqc_conversation_id }
end
