# frozen_string_literal: true

class AddTargetDeviceToPqcMemberRemovals < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :pqc_member_removals, :target_device_id, :string
    add_index :pqc_member_removals, [:pqc_conversation_id, :target_device_id], name: 'index_pqc_member_removals_on_conversation_target_device', algorithm: :concurrently
  end
end
