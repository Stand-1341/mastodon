# frozen_string_literal: true

class AddPqcConversationDepartureIndex < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :pqc_conversation_members, [:pqc_conversation_id, :leave_requested_at], algorithm: :concurrently
  end
end
