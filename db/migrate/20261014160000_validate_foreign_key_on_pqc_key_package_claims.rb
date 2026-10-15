# frozen_string_literal: true

class ValidateForeignKeyOnPqcKeyPackageClaims < ActiveRecord::Migration[8.1]
  def change
    validate_foreign_key :pqc_devices, :pqc_conversations, column: :key_package_claim_conversation_id
  end
end
