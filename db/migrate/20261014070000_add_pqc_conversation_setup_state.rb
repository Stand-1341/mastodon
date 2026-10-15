# frozen_string_literal: true

class AddPqcConversationSetupState < ActiveRecord::Migration[8.1]
  def up
    add_column :pqc_conversations, :ready_at, :datetime
    add_column :pqc_conversations, :setup_device_id, :string
    safety_assured do
      execute 'UPDATE pqc_conversations SET ready_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)'
    end
  end

  def down
    remove_column :pqc_conversations, :setup_device_id
    remove_column :pqc_conversations, :ready_at
  end
end
