# frozen_string_literal: true

class Pqc::Messaging::CommitMemberAdditionService < BaseService
  MAX_DELIVERIES = 256
  MAX_CIPHERTEXT_BYTES = 1.megabyte

  class InvalidAdditionError < StandardError; end
  class IdempotencyConflict < StandardError; end

  def call(conversation:, creator:, account_id:, sender_device_id:, operation_id:, key_package_request_id:, target_device_ids:, deliveries:)
    raise InvalidAdditionError, 'Only the conversation creator can add a device to an active group' unless conversation.creator_account_id == creator.id
    raise InvalidAdditionError, 'Encrypted member-add deliveries must be an array' unless deliveries.is_a?(Array)
    raise InvalidAdditionError, 'A device addition must include 1 to 256 encrypted deliveries' unless deliveries.length.between?(1, MAX_DELIVERIES)
    raise InvalidAdditionError, 'operation_id must be a UUID' unless uuid?(operation_id)
    raise InvalidAdditionError, 'key_package_request_id must be a UUID' unless uuid?(key_package_request_id)

    target_device_ids = Array(target_device_ids).map(&:to_s)
    raise InvalidAdditionError, 'A device addition must include unique target devices' if target_device_ids.empty? || target_device_ids.uniq != target_device_ids

    created = false
    message_ids = []
    PqcConversation.transaction do
      conversation.lock!
      raise InvalidAdditionError, 'Initial encrypted group setup is not complete' unless conversation.ready_at?

      account = Account.find_by(id: account_id, domain: nil)
      raise InvalidAdditionError, 'The participant must be a local account' if account.nil?

      membership = conversation.pqc_conversation_members.find_by(account_id: account.id)
      raise InvalidAdditionError, 'The account must accept its invitation before a device can be added' unless membership&.accepted?

      seen_message_ids = Set.new
      seen_recipient_ids = Set.new
      decoded_deliveries = deliveries.map do |delivery|
        delivery = delivery.to_h.symbolize_keys
        message_id = delivery[:client_message_id].to_s
        raise InvalidAdditionError, 'Each delivery needs a unique UUID client_message_id' unless uuid?(message_id) && seen_message_ids.add?(message_id)

        recipient_device_id = delivery[:recipient_device_id].to_s
        raise InvalidAdditionError, 'Each delivery must target a unique group or target device' if recipient_device_id.blank? || !seen_recipient_ids.add?(recipient_device_id)

        ciphertext = Base64.strict_decode64(delivery[:ciphertext].to_s)
        raise InvalidAdditionError, 'Encrypted MLS payload must be between 1 byte and 1 MiB' unless ciphertext.bytesize.between?(1, MAX_CIPHERTEXT_BYTES)

        [message_id, recipient_device_id, ciphertext]
      end

      addition = conversation.pqc_member_additions.find_by(operation_id:)
      target_devices = PqcDevice.active.where(
        account_id: account.id,
        device_id: target_device_ids,
        key_package_consumed_at: ..Time.current,
        key_package_claim_id: key_package_request_id,
        key_package_claim_conversation_id: conversation.id
      ).index_by(&:device_id)
      unless target_devices.keys.to_set == target_device_ids.to_set
        raise IdempotencyConflict, 'operation_id was already used for another device addition' if addition

        raise InvalidAdditionError, 'Each target device must have a KeyPackage claimed for this operation in this conversation'
      end

      if addition
        request_matches = addition.key_package_request_id.nil? || addition.key_package_request_id == key_package_request_id
        operation_matches = addition.actor_account_id == creator.id &&
                            addition.target_account_id == account.id &&
                            addition.sender_device_id == sender_device_id &&
                            request_matches &&
                            addition.added_device_ids.sort == target_device_ids.sort &&
                            addition.client_message_ids.sort == decoded_deliveries.map(&:first).sort
        raise IdempotencyConflict, 'operation_id was already used for another device addition' unless operation_matches

        sender_device = PqcDevice.active.find_by!(device_id: sender_device_id, account_id: creator.id)
        decoded_deliveries.each do |message_id, recipient_device_id, ciphertext|
          message = conversation.pqc_messages.find_by(account: creator, sender_device:, client_message_id: message_id)
          raise IdempotencyConflict, 'A retry does not match the committed device-addition messages' unless message&.ciphertext == ciphertext && message.recipient_device_id == recipient_device_id

          message_ids << message.id
        end
        next
      end

      existing_device_ids = conversation.pqc_conversation_devices.joins(:pqc_device).merge(PqcDevice.active).pluck('pqc_devices.device_id').to_set
      raise InvalidAdditionError, 'A target device is already enrolled in this MLS group' if (target_device_ids.to_set & existing_device_ids).any?

      sender_device = PqcDevice.active.find_by!(device_id: sender_device_id, account_id: creator.id)
      raise InvalidAdditionError, 'The sending device is not enrolled in this MLS group' unless existing_device_ids.include?(sender_device.device_id)

      expected_recipient_ids = (existing_device_ids - [sender_device.device_id]) | target_device_ids.to_set
      recipient_devices = PqcDevice.active.where(device_id: expected_recipient_ids).index_by(&:device_id)
      raise InvalidAdditionError, 'An active MLS device is no longer available' unless recipient_devices.keys.to_set == expected_recipient_ids

      target_devices.each_value do |target_device|
        conversation.pqc_conversation_devices.create!(pqc_device: target_device)
      end

      delivered_device_ids = Set.new
      decoded_deliveries.each do |message_id, recipient_device_id, ciphertext|
        recipient_device = recipient_devices[recipient_device_id]
        raise InvalidAdditionError, 'Each delivery must target an enrolled group or target device' if recipient_device.nil?

        delivered_device_ids << recipient_device_id
        message = conversation.pqc_messages.create!(
          account: creator,
          sender_device:,
          recipient_device:,
          client_message_id: message_id,
          ciphertext:
        )
        message_ids << message.id
      end

      missing_recipient_ids = expected_recipient_ids - delivered_device_ids
      raise InvalidAdditionError, 'Member-add deliveries must reach every enrolled group and target device' if missing_recipient_ids.any?

      membership.update!(joined_at: Time.current) unless membership.joined_at?
      conversation.pqc_member_additions.create!(
        actor_account: creator,
        target_account: account,
        operation_id:,
        sender_device_id:,
        key_package_request_id:,
        added_device_ids: target_device_ids,
        client_message_ids: decoded_deliveries.map(&:first)
      )
      conversation.touch
      created = true
    end

    { conversation:, created:, message_ids: }
  rescue ArgumentError => e
    raise InvalidAdditionError, e.message
  end

  private

  def uuid?(value)
    value.to_s.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i)
  end
end
