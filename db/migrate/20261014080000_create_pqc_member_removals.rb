# frozen_string_literal: true

class CreatePqcMemberRemovals < ActiveRecord::Migration[8.1]
  def change
    create_table :pqc_member_removals do |t|
      t.references :pqc_conversation, null: false, foreign_key: true
      t.references :actor_account, null: false, foreign_key: { to_table: :accounts }
      t.references :target_account, null: false, foreign_key: { to_table: :accounts }
      t.uuid :operation_id, null: false
      t.string :sender_device_id, null: false
      t.jsonb :client_message_ids, null: false, default: []

      t.timestamps
    end

    add_index :pqc_member_removals, [:pqc_conversation_id, :operation_id], unique: true
  end
end
