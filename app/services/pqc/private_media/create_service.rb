# frozen_string_literal: true

class Pqc::PrivateMedia::CreateService < BaseService
  MAX_FILE_SIZE = 32.megabytes
  MAX_ACCOUNT_STORAGE = 1.gigabyte

  class InvalidUploadError < StandardError; end
  class QuotaExceededError < InvalidUploadError; end

  def call(account, upload)
    plaintext = data_key = ciphertext = storage = object = nil

    raise InvalidUploadError, 'A file is required' if upload.blank? || !upload.respond_to?(:read)
    raise InvalidUploadError, "Private media files must be at most #{MAX_FILE_SIZE / 1.megabyte} MB" if upload.size.to_i <= 0 || upload.size.to_i > MAX_FILE_SIZE

    upload.rewind if upload.respond_to?(:rewind)
    # Do not trust the upload's reported size alone. UploadedFile is backed by
    # a local tempfile, but callers and alternate upload adapters can report a
    # smaller size than the bytes they return.
    plaintext = upload.read(MAX_FILE_SIZE + 1)
    raise InvalidUploadError, "Private media files must be at most #{MAX_FILE_SIZE / 1.megabyte} MB" if plaintext.bytesize > MAX_FILE_SIZE
    raise InvalidUploadError, 'A file is required' if plaintext.empty?

    storage = Pqc::PrivateMedia::Storage.new
    account.with_lock do
      used_storage = account.private_media_objects.sum(:byte_size)
      raise QuotaExceededError, "Private media storage is limited to #{MAX_ACCOUNT_STORAGE / 1.gigabyte} GB per account" if used_storage + plaintext.bytesize > MAX_ACCOUNT_STORAGE

      token = SecureRandom.uuid
      context = { 'object_token' => token, 'account_id' => account.id.to_s }
      data_key, wrapped_key, provider = Pqc::PrivateMedia::DataKey.generate(context)
      cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
      nonce = OpenSSL::Random.random_bytes(12)
      cipher.key = data_key
      cipher.iv = nonce
      cipher.auth_data = canonical_context(context)
      ciphertext = cipher.update(plaintext) + cipher.final

      object = PrivateMediaObject.create!(
        account: account,
        token: token,
        storage_key: "pqc-private-media/#{token}",
        content_type: 'application/octet-stream',
        byte_size: plaintext.bytesize,
        wrapped_key: wrapped_key,
        key_encryption_provider: provider,
        nonce: Base64.strict_encode64(nonce),
        auth_tag: Base64.strict_encode64(cipher.auth_tag)
      )
      storage.write(object.storage_key, ciphertext)
      object
    end
  rescue
    if object
      begin
        storage.delete(object.storage_key)
      rescue Pqc::PrivateMedia::Storage::StorageError => e
        Rails.logger.error("Private media cleanup failed (#{e.class})")
      end
    end
    raise
  ensure
    wipe(plaintext)
    wipe(data_key)
    wipe(ciphertext)
  end

  private

  def canonical_context(context)
    context.sort.to_h.to_json
  end

  def wipe(secret)
    secret&.replace("\0" * secret.bytesize)
  end
end
