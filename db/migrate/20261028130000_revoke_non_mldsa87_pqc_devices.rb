# frozen_string_literal: true

class RevokeNonMldsa87PqcDevices < ActiveRecord::Migration[8.1]
  def up
    now = Time.current
    safety_assured do
      execute <<~SQL.squish
        UPDATE pqc_devices
        SET revoked_at = #{connection.quote(now)},
            key_package_consumed_at = COALESCE(key_package_consumed_at, #{connection.quote(now)}),
            updated_at = #{connection.quote(now)}
        WHERE revoked_at IS NULL
          AND (
            auth_public_key IS NULL
            OR octet_length(auth_public_key) <> 2592
            OR auth_fingerprint IS DISTINCT FROM fingerprint
          )
      SQL
    end
  end

  def down
    raise ActiveRecord::IrreversibleMigration, 'Revoked device records cannot be safely restored to active status'
  end
end
