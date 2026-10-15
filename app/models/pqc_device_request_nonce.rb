# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_device_request_nonces
#
#  id            :bigint(8)        not null, primary key
#  nonce         :uuid             not null
#  created_at    :datetime         not null
#  updated_at    :datetime         not null
#  pqc_device_id :bigint(8)        not null
#
class PqcDeviceRequestNonce < ApplicationRecord
  belongs_to :pqc_device

  after_create :cleanup_expired_records, if: -> { (id % 256).zero? }

  validates :nonce, presence: true, format: { with: /\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i }, uniqueness: { scope: :pqc_device_id }

  # Keep replay records beyond the full accepted timestamp window.
  def self.cleanup_expired!(now: Time.current)
    where(created_at: ...(now - 15.minutes)).delete_all
  end

  private

  def cleanup_expired_records
    self.class.cleanup_expired!
  end
end
