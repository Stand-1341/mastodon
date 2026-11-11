# frozen_string_literal: true

class AddMediaKemPublicKeyToPqcDevices < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_devices, :media_kem_public_key, :binary
  end
end
