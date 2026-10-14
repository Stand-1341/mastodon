# frozen_string_literal: true

class ActivityPub::GeneratePqcKeyService < BaseService
  class UnsupportedRuntimeError < StandardError; end

  def call(account)
    raise ArgumentError, 'ML-DSA-44 keys can only be provisioned for persisted local accounts' unless account&.persisted? && account.local?

    account.with_lock do
      raise ArgumentError, 'ML-DSA-44 keys can only be provisioned for local accounts' unless account.local?

      existing_key = account.keypairs.usable.where(type: :'ml-dsa-44').order(id: :asc).first
      next existing_key if existing_key.present?

      private_key, public_key = generate_key

      account.keypairs.create!(
        type: :'ml-dsa-44',
        local_fragment: "#ml-dsa-44-#{SecureRandom.hex(16)}",
        private_key:,
        public_key:
      )
    end
  end

  private

  def generate_key
    key = OpenSSL::PKey.generate_key('ML-DSA-44')
    [key.private_to_pem, key.public_to_pem]
  rescue OpenSSL::PKey::PKeyError, NotImplementedError
    raise UnsupportedRuntimeError, 'Cannot generate or export ML-DSA-44 keys; use OpenSSL 3.5 or newer with an ML-DSA-capable provider'
  end
end
