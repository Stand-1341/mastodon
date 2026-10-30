# frozen_string_literal: true

class AddAccountBindingToPqcDevices < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_devices, :account_binding_key_uri, :string
    add_column :pqc_devices, :account_binding_issued_at, :bigint
    add_column :pqc_devices, :account_binding_signature, :binary
  end
end
