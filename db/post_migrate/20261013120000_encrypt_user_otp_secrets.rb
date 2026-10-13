# frozen_string_literal: true

class EncryptUserOtpSecrets < ActiveRecord::Migration[7.1]
  disable_ddl_transaction!

  class MigrationUser < ActiveRecord::Base
    self.table_name = :users

    encrypts :otp_secret, support_unencrypted_data: true
  end

  def up
    encryption_config = ActiveRecord::Encryption.config
    previous_support = encryption_config.support_unencrypted_data

    begin
      encryption_config.support_unencrypted_data = true
      MigrationUser.reset_column_information

      MigrationUser.where.not(otp_secret: nil).find_each do |user|
        # Rewriting through the encrypted attribute type encrypts legacy plaintext
        # while preserving values that were already stored in encrypted form.
        user.update_columns(otp_secret: user.otp_secret)
      end
    ensure
      encryption_config.support_unencrypted_data = previous_support
    end
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
