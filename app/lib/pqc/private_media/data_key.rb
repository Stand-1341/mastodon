# frozen_string_literal: true

module Pqc
  module PrivateMedia
    module DataKey
      class ConfigurationError < StandardError; end

      LOCAL_PROVIDER = 'local-aes-gcm-v1'
      AWS_KMS_PROVIDER = 'aws-kms-v1'

      module_function

      def generate(context)
        return generate_with_kms(context) if ENV['PQC_MEDIA_KMS_KEY_ID'].present?

        raise ConfigurationError, 'Local media key wrapping is restricted to development and test' unless Rails.env.local?

        kek = local_key_encryption_key
        data_key = OpenSSL::Random.random_bytes(32)
        cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
        cipher.key = kek
        nonce = OpenSSL::Random.random_bytes(12)
        cipher.iv = nonce
        cipher.auth_data = canonical_context(context)
        wrapped = cipher.update(data_key) + cipher.final

        [data_key, "#{LOCAL_PROVIDER}:#{Base64.strict_encode64(nonce + cipher.auth_tag + wrapped)}", LOCAL_PROVIDER]
      ensure
        wipe(kek)
      end

      def decrypt(wrapped_key, provider, context)
        case provider
        when LOCAL_PROVIDER
          decrypt_local(wrapped_key, context)
        when AWS_KMS_PROVIDER
          decrypt_with_kms(wrapped_key, context)
        else
          raise ConfigurationError, 'Unknown private media key encryption provider'
        end
      end

      def generate_with_kms(context)
        response = kms_client.generate_data_key(
          key_id: ENV.fetch('PQC_MEDIA_KMS_KEY_ID'),
          key_spec: 'AES_256',
          encryption_context: kms_context(context)
        )

        unless response.plaintext.is_a?(String) && response.plaintext.bytesize == 32 && response.ciphertext_blob.present?
          wipe(response.plaintext)
          raise ConfigurationError, 'AWS KMS returned an invalid private media data key'
        end

        [response.plaintext, Base64.strict_encode64(response.ciphertext_blob), AWS_KMS_PROVIDER]
      rescue ConfigurationError
        raise
      rescue => e
        raise ConfigurationError, "AWS KMS data-key generation failed (#{e.class})"
      end
      private_class_method :generate_with_kms

      def decrypt_with_kms(wrapped_key, context)
        response = kms_client.decrypt(
          ciphertext_blob: Base64.strict_decode64(wrapped_key),
          encryption_context: kms_context(context)
        )
        unless response.plaintext.is_a?(String) && response.plaintext.bytesize == 32
          wipe(response.plaintext)
          raise ConfigurationError, 'AWS KMS returned an invalid private media data key'
        end

        response.plaintext
      rescue ConfigurationError
        raise
      rescue => e
        raise ConfigurationError, "AWS KMS data-key decryption failed (#{e.class})"
      end
      private_class_method :decrypt_with_kms

      def decrypt_local(wrapped_key, context)
        raise ConfigurationError, 'Local media key wrapping is restricted to development and test' unless Rails.env.local?

        prefix, encoded = wrapped_key.split(':', 2)
        raise ConfigurationError, 'Invalid wrapped media key format' unless prefix == LOCAL_PROVIDER && encoded.present?

        bytes = Base64.strict_decode64(encoded)
        raise ConfigurationError, 'Invalid wrapped media key length' unless bytes.bytesize == 60

        kek = local_key_encryption_key
        cipher = OpenSSL::Cipher.new('aes-256-gcm').decrypt
        cipher.key = kek
        cipher.iv = bytes.byteslice(0, 12)
        cipher.auth_tag = bytes.byteslice(12, 16)
        cipher.auth_data = canonical_context(context)
        cipher.update(bytes.byteslice(28, 32)) + cipher.final
      rescue OpenSSL::Cipher::CipherError, ArgumentError
        raise ConfigurationError, 'Unable to authenticate the wrapped private media key'
      ensure
        wipe(kek)
      end
      private_class_method :decrypt_local

      def local_key_encryption_key
        encoded = ENV.fetch('PQC_MEDIA_LOCAL_KEK', nil)
        raise ConfigurationError, 'Set PQC_MEDIA_LOCAL_KEK to a base64 encoded 32-byte key for local development' if encoded.blank?

        key = Base64.strict_decode64(encoded)
        raise ConfigurationError, 'PQC_MEDIA_LOCAL_KEK must decode to exactly 32 bytes' unless key.bytesize == 32

        key
      rescue ArgumentError
        raise ConfigurationError, 'PQC_MEDIA_LOCAL_KEK must be valid base64 for exactly 32 bytes'
      end
      private_class_method :local_key_encryption_key

      def kms_client
        require 'aws-sdk-kms'

        endpoint = ENV['PQC_MEDIA_KMS_ENDPOINT'].presence
        raise ConfigurationError, 'PQC_MEDIA_KMS_ENDPOINT is restricted to development and test' if endpoint && !Rails.env.local?

        Aws::KMS::Client.new(
          region: ENV['AWS_REGION'].presence || ENV.fetch('S3_REGION', 'us-east-1'),
          endpoint:
        )
      end
      private_class_method :kms_client

      def kms_context(context)
        context.transform_values(&:to_s)
      end
      private_class_method :kms_context

      def canonical_context(context)
        context.transform_values(&:to_s).sort.to_h.to_json
      end
      private_class_method :canonical_context

      def wipe(secret)
        secret&.replace("\0" * secret.bytesize)
      end
      private_class_method :wipe
    end
  end
end
