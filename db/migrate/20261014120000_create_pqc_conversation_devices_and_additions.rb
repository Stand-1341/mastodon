# frozen_string_literal: true

class CreatePqcConversationDevicesAndAdditions < ActiveRecord::Migration[8.1]
  def change
    create_table :pqc_conversation_devices do |t|
      t.references :pqc_conversation, null: false, foreign_key: true
      t.references :pqc_device, null: false, foreign_key: true
      t.timestamps
    end

    add_index :pqc_conversation_devices, [:pqc_conversation_id, :pqc_device_id], unique: true, name: 'index_pqc_conversation_devices_on_conversation_and_device'

    create_table :pqc_member_additions do |t|
      t.references :pqc_conversation, null: false, foreign_key: true
      t.references :actor_account, null: false, foreign_key: { to_table: :accounts }
      t.references :target_account, null: false, foreign_key: { to_table: :accounts }
      t.uuid :operation_id, null: false
      t.string :sender_device_id, null: false
      t.jsonb :added_device_ids, null: false, default: []
      t.jsonb :client_message_ids, null: false, default: []
      t.timestamps
    end

    add_index :pqc_member_additions, [:pqc_conversation_id, :operation_id], unique: true, name: 'index_pqc_member_additions_on_conversation_and_operation'

    reversible do |direction|
      direction.up do
        safety_assured do
          execute <<~SQL.squish
            INSERT INTO pqc_conversation_devices (pqc_conversation_id, pqc_device_id, created_at, updated_at)
            SELECT pqc_conversation_members.pqc_conversation_id, pqc_devices.id, NOW(), NOW()
            FROM pqc_conversation_members
            INNER JOIN pqc_conversations ON pqc_conversations.id = pqc_conversation_members.pqc_conversation_id
            INNER JOIN pqc_devices ON pqc_devices.account_id = pqc_conversation_members.account_id AND pqc_devices.revoked_at IS NULL
            WHERE pqc_conversations.ready_at IS NOT NULL
              AND pqc_conversation_members.invitation_status = 'accepted'
              AND pqc_conversation_members.joined_at IS NOT NULL
            ON CONFLICT DO NOTHING
          SQL
        end
      end
    end
  end
end
