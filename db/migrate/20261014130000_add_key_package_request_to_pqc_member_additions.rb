# frozen_string_literal: true

class AddKeyPackageRequestToPqcMemberAdditions < ActiveRecord::Migration[8.1]
  def change
    add_column :pqc_member_additions, :key_package_request_id, :uuid
  end
end
