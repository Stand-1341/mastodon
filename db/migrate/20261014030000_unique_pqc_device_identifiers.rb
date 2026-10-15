# frozen_string_literal: true

class UniquePqcDeviceIdentifiers < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :pqc_devices, :device_id, unique: true, algorithm: :concurrently
  end
end
