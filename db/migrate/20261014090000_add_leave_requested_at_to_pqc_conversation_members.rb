# frozen_string_literal: true

class AddLeaveRequestedAtToPqcConversationMembers < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_conversation_members, :leave_requested_at, :datetime
  end
end
