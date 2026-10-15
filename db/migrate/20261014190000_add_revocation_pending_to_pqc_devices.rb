# frozen_string_literal: true

class AddRevocationPendingToPqcDevices < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_devices, :revocation_pending_at, :datetime
  end
end
