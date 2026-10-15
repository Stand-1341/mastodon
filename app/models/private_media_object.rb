# frozen_string_literal: true

# == Schema Information
#
# Table name: private_media_objects
#
#  id                      :bigint(8)        not null, primary key
#  auth_tag                :string           not null
#  byte_size               :bigint(8)        not null
#  content_type            :string           default("application/octet-stream"), not null
#  key_encryption_provider :string           not null
#  nonce                   :string           not null
#  storage_key             :string           not null
#  token                   :uuid             not null
#  wrapped_key             :text             not null
#  created_at              :datetime         not null
#  updated_at              :datetime         not null
#  account_id              :bigint(8)        not null
#
class PrivateMediaObject < ApplicationRecord
  belongs_to :account

  validates :token, :storage_key, :wrapped_key, :key_encryption_provider, :nonce, :auth_tag, presence: true
  validates :token, uniqueness: true, format: { with: /\A[0-9a-f-]{36}\z/i }
  validates :storage_key, uniqueness: true
  validates :byte_size, numericality: { only_integer: true, greater_than: 0 }

  after_destroy_commit :delete_encrypted_blob

  private

  def delete_encrypted_blob
    Pqc::PrivateMedia::Storage.new.delete(storage_key)
  rescue => e
    Rails.logger.error("Unable to remove encrypted private media object (#{e.class})")
  end
end
