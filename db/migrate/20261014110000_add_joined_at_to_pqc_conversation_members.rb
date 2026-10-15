# frozen_string_literal: true

class AddJoinedAtToPqcConversationMembers < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_conversation_members, :joined_at, :datetime

    reversible do |direction|
      direction.up do
        safety_assured do
          execute <<~SQL.squish
            UPDATE pqc_conversation_members
            SET joined_at = pqc_conversation_members.updated_at
            FROM pqc_conversations
            WHERE pqc_conversation_members.pqc_conversation_id = pqc_conversations.id
              AND pqc_conversations.ready_at IS NOT NULL
              AND pqc_conversation_members.invitation_status = 'accepted'
          SQL
        end
      end
    end
  end
end
