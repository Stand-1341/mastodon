# frozen_string_literal: true

class AddConversationToPqcKeyPackageClaims < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_reference :pqc_devices, :key_package_claim_conversation, index: { algorithm: :concurrently }, foreign_key: false
  end
end
