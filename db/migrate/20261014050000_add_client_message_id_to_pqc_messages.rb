# frozen_string_literal: true

class AddClientMessageIdToPqcMessages < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :pqc_messages, :client_message_id, :uuid
    add_index :pqc_messages, [:pqc_conversation_id, :account_id, :sender_device_id, :client_message_id],
              unique: true,
              where: 'client_message_id IS NOT NULL',
              name: 'index_pqc_messages_on_client_idempotency',
              algorithm: :concurrently
  end
end
