# frozen_string_literal: true

class AddInvitationStatusToPqcConversationMembers < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_conversation_members, :invitation_status, :string, null: false, default: 'accepted'

    reversible do |direction|
      direction.up do
        safety_assured do
          execute <<~SQL.squish
            UPDATE pqc_conversation_members
            SET invitation_status = 'invited'
            FROM pqc_conversations
            WHERE pqc_conversation_members.pqc_conversation_id = pqc_conversations.id
              AND pqc_conversations.ready_at IS NULL
              AND pqc_conversation_members.account_id <> pqc_conversations.creator_account_id
          SQL
        end
      end
    end
  end
end
