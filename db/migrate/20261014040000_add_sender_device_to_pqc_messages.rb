# frozen_string_literal: true

class AddSenderDeviceToPqcMessages < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :pqc_messages, :sender_device_id, :string
    add_index :pqc_messages, [:pqc_conversation_id, :sender_device_id, :id], name: 'index_pqc_messages_on_conversation_sender_and_id', algorithm: :concurrently
  end
end
