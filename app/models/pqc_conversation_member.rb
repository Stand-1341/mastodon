# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_conversation_members
#
#  id                  :bigint(8)        not null, primary key
#  invitation_status   :string           default("accepted"), not null
#  joined_at           :datetime
#  leave_requested_at  :datetime
#  created_at          :datetime         not null
#  updated_at          :datetime         not null
#  account_id          :bigint(8)        not null
#  pqc_conversation_id :bigint(8)        not null
#
class PqcConversationMember < ApplicationRecord
  enum :invitation_status, { invited: 'invited', accepted: 'accepted', declined: 'declined' }, default: :accepted

  scope :joined, -> { where.not(joined_at: nil) }

  belongs_to :pqc_conversation
  belongs_to :account

  validates :account_id, uniqueness: { scope: :pqc_conversation_id }
  validates :invitation_status, inclusion: { in: invitation_statuses.keys }
end
