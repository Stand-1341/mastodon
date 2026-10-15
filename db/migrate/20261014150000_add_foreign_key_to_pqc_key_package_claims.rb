# frozen_string_literal: true

class AddForeignKeyToPqcKeyPackageClaims < ActiveRecord::Migration[8.1]
  def change
    add_foreign_key :pqc_devices, :pqc_conversations, column: :key_package_claim_conversation_id, validate: false
  end
end
