# frozen_string_literal: true

require 'base64'

module Pqc
  module PrivateMedia
    module DeviceKeyEnvelope
      class EnvelopeError < StandardError; end

      CIPHERTEXT_BYTES = 1568
      WRAPPED_KEY_BYTES = 60
      NONCE_BYTES = 12
      TAG_BYTES = 16

      module_function

      def validate_envelope!(envelope, device_id:)
        unless envelope.is_a?(Hash) &&
               envelope.keys.sort == %w(device_id kem_ciphertext wrapped_key) &&
               envelope['device_id'].is_a?(String) &&
               envelope['device_id'].bytesize.between?(1, 128) &&
               envelope['device_id'] == device_id &&
               envelope['kem_ciphertext'].is_a?(String) &&
               envelope['wrapped_key'].is_a?(String)
          raise EnvelopeError, 'Invalid ML-KEM-1024 envelope'
        end

        ciphertext = Base64.strict_decode64(envelope.fetch('kem_ciphertext'))
        wrapped_key = Base64.strict_decode64(envelope.fetch('wrapped_key'))
        raise EnvelopeError, 'Invalid ML-KEM-1024 ciphertext size' unless ciphertext.bytesize == CIPHERTEXT_BYTES
        raise EnvelopeError, 'Invalid wrapped file key size' unless wrapped_key.bytesize == WRAPPED_KEY_BYTES
        raise EnvelopeError, 'Non-canonical ML-KEM-1024 envelope encoding' unless Base64.strict_encode64(ciphertext) == envelope['kem_ciphertext'] && Base64.strict_encode64(wrapped_key) == envelope['wrapped_key']

        envelope
      rescue ArgumentError, KeyError
        raise EnvelopeError, 'Invalid ML-KEM-1024 envelope'
      end

      def validate_metadata!(nonce:, auth_tag:)
        raise EnvelopeError, 'Invalid private media encryption metadata' unless nonce.is_a?(String) && auth_tag.is_a?(String)

        decoded_nonce = Base64.strict_decode64(nonce)
        decoded_tag = Base64.strict_decode64(auth_tag)
        raise EnvelopeError, 'Invalid private media nonce' unless decoded_nonce.bytesize == NONCE_BYTES
        raise EnvelopeError, 'Invalid private media authentication tag' unless decoded_tag.bytesize == TAG_BYTES
        raise EnvelopeError, 'Non-canonical private media metadata' unless Base64.strict_encode64(decoded_nonce) == nonce && Base64.strict_encode64(decoded_tag) == auth_tag

        true
      rescue ArgumentError
        raise EnvelopeError, 'Invalid private media encryption metadata'
      end

      def serialize_envelopes(envelopes)
        validate_recipient_envelopes!(envelopes)
        JSON.generate(envelopes)
      end

      def parse_envelopes(value)
        raise EnvelopeError, 'Invalid recipient key envelopes' unless value.is_a?(String)

        envelopes = JSON.parse(value)
        raise EnvelopeError, 'Private media has no device key envelopes' unless envelopes.is_a?(Array) && envelopes.any?

        validate_recipient_envelopes!(envelopes)
      rescue JSON::ParserError, NoMethodError
        raise EnvelopeError, 'Invalid recipient key envelopes'
      end

      def validate_recipient_envelopes!(envelopes)
        raise EnvelopeError, 'Invalid recipient key envelopes' unless envelopes.is_a?(Array) && envelopes.any? && envelopes.size <= 64

        device_ids = []
        envelopes.each do |envelope|
          raise EnvelopeError, 'Invalid recipient key envelope fields' unless envelope.is_a?(Hash) && envelope.keys.sort == %w(device_id kem_ciphertext wrapped_key)

          validate_envelope!(envelope, device_id: envelope['device_id'])
          device_ids << envelope['device_id']
        end
        raise EnvelopeError, 'Duplicate recipient device envelopes' unless device_ids.uniq == device_ids

        envelopes
      end
      private_class_method :validate_recipient_envelopes!

      def canonical_context(context)
        raise EnvelopeError, 'Invalid private media context' unless context.is_a?(Hash) && context.keys.sort == %w(account_id object_token) && context.values.all?(String)

        JSON.generate('account_id' => context.fetch('account_id'), 'object_token' => context.fetch('object_token'))
      end
      private_class_method :canonical_context
    end
  end
end
