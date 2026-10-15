# frozen_string_literal: true

class AddAuthFingerprintToPqcDevices < ActiveRecord::Migration[8.1]
  def up
    add_column :pqc_devices, :auth_fingerprint, :string

    PqcDevice.reset_column_information
    PqcDevice.where.not(auth_public_key: nil).find_each do |device|
      device.update_columns(auth_fingerprint: Digest::SHA256.hexdigest(device[:auth_public_key]))
    end
  end

  def down
    remove_column :pqc_devices, :auth_fingerprint
  end
end
