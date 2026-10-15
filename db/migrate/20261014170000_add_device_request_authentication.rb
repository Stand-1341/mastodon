# frozen_string_literal: true

class AddDeviceRequestAuthentication < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_devices, :auth_public_key, :binary

    create_table :pqc_device_request_nonces do |t|
      t.references :pqc_device, null: false, foreign_key: true
      t.uuid :nonce, null: false
      t.timestamps
    end

    add_index :pqc_device_request_nonces, [:pqc_device_id, :nonce], unique: true, name: 'index_pqc_device_request_nonces_unique_nonce'
    add_index :pqc_device_request_nonces, :created_at
  end
end
