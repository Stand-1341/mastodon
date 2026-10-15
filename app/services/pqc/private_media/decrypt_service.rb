# frozen_string_literal: true

class Pqc::PrivateMedia::DecryptService < BaseService
  class DecryptionError < StandardError; end

  def call(object)
    context = { 'object_token' => object.token, 'account_id' => object.account_id.to_s }
    data_key = Pqc::PrivateMedia::DataKey.decrypt(object.wrapped_key, object.key_encryption_provider, context)
    cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
    cipher.key = data_key
    cipher.iv = Base64.strict_decode64(object.nonce)
    cipher.auth_tag = Base64.strict_decode64(object.auth_tag)
    cipher.auth_data = canonical_context(context)
    plaintext = cipher.update(Pqc::PrivateMedia::Storage.new.read(object.storage_key))
    plaintext << cipher.final

    raise DecryptionError, 'Private media byte size did not match its authenticated record' unless plaintext.bytesize == object.byte_size

    plaintext
  rescue OpenSSL::Cipher::CipherError, ArgumentError, Pqc::PrivateMedia::DataKey::ConfigurationError, Pqc::PrivateMedia::Storage::StorageError
    wipe(plaintext)
    raise DecryptionError, 'Private media could not be authenticated or decrypted'
  ensure
    data_key&.replace("\0" * data_key.bytesize)
  end

  private

  def canonical_context(context)
    context.sort.to_h.to_json
  end

  def wipe(secret)
    secret&.replace("\0" * secret.bytesize)
  end
end
