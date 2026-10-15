# frozen_string_literal: true

class AddRecipientDeviceToPqcMessages < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :pqc_messages, :recipient_device_id, :string
    add_index :pqc_messages, [:pqc_conversation_id, :recipient_device_id, :id], name: 'index_pqc_messages_on_conversation_recipient_and_id', algorithm: :concurrently
  end
end
