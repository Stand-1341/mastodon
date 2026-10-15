# frozen_string_literal: true

class AddKeyPackageClaimIdToPqcDevices < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :pqc_devices, :key_package_claim_id, :uuid
    add_index :pqc_devices, [:account_id, :key_package_claim_id],
              where: 'key_package_claim_id IS NOT NULL',
              name: 'index_pqc_devices_on_account_and_key_package_claim',
              algorithm: :concurrently
  end
end
