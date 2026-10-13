# frozen_string_literal: true

require 'rails_helper'
require Rails.root.join('db/post_migrate/20261013120000_encrypt_user_otp_secrets').to_s

RSpec.describe EncryptUserOtpSecrets do
  describe '#up' do
    it 'encrypts legacy OTP secrets and preserves TOTP verification' do
      legacy_secret = User.generate_otp_secret
      encrypted_secret = User.generate_otp_secret
      legacy_user = Fabricate(:user, otp_secret: nil)
      encrypted_user = Fabricate(:user, otp_secret: encrypted_secret)

      connection = ActiveRecord::Base.connection
      connection.execute(<<~SQL.squish)
        UPDATE users
        SET otp_secret = #{connection.quote(legacy_secret)}
        WHERE id = #{legacy_user.id}
      SQL

      expect(connection.select_value("SELECT otp_secret FROM users WHERE id = #{legacy_user.id}")).to eq(legacy_secret)

      described_class.new('EncryptUserOtpSecrets', 20261013120000).up

      legacy_user.reload
      encrypted_user.reload

      expect(legacy_user.otp_secret).to eq(legacy_secret)
      expect(legacy_user.attributes_before_type_cast[:otp_secret]).to_not eq(legacy_secret)
      expect(encrypted_user.otp_secret).to eq(encrypted_secret)

      code = ROTP::TOTP.new(legacy_secret).at(Time.current.utc)
      expect(legacy_user.validate_and_consume_otp!(code)).to be true
    end
  end
end
