# frozen_string_literal: true

class Pqc::Messaging::RemoveDeviceService < BaseService
  MAX_DELIVERIES = 256
  MAX_CIPHERTEXT_BYTES = 1.megabyte

  class InvalidRemovalError < StandardError; end
  class IdempotencyConflict < StandardError; end

  def call(conversation:, actor:, target_device_id:, sender_device_id:, operation_id:, deliveries:)
    raise InvalidRemovalError, 'Encrypted device-removal commits must be an array' unless deliveries.is_a?(Array)
    raise InvalidRemovalError, 'A device removal may include at most 256 deliveries' if deliveries.length > MAX_DELIVERIES
    raise InvalidRemovalError, 'operation_id must be a UUID' unless operation_id.to_s.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i)

    removed = false
    message_ids = []
    PqcConversation.transaction do
      conversation.lock!
      raise InvalidRemovalError, 'Initial encrypted group setup is not complete' unless conversation.ready_at?

      target = PqcDevice.find_by!(device_id: target_device_id)
      raise InvalidRemovalError, 'A device cannot remove itself from its MLS groups' if target.device_id == sender_device_id
      raise InvalidRemovalError, 'Only the device owner or conversation creator can remove this device' unless target.account_id == actor.id || conversation.creator_account_id == actor.id || target.revocation_pending_at?

      target_link = conversation.pqc_conversation_devices.find_by(pqc_device_id: target.id)
      decoded_deliveries = decode_deliveries(deliveries)
      removal = conversation.pqc_member_removals.find_by(operation_id:)
      if removal
        unless removal.actor_account_id == actor.id && removal.target_account_id == target.account_id && removal.target_device_id == target.device_id && removal.sender_device_id == sender_device_id && removal.client_message_ids.sort == decoded_deliveries.map(&:first).sort
          raise IdempotencyConflict, 'operation_id was already used for another removal'
        end

        decoded_deliveries.each do |message_id, recipient_device_id, ciphertext|
          message = conversation.pqc_messages.find_by(account: actor, sender_device_id:, client_message_id: message_id)
          raise IdempotencyConflict, 'A retry does not match the committed device-removal messages' unless message&.ciphertext == ciphertext && message.recipient_device_id == recipient_device_id

          message_ids << message.id
        end
        next
      end

      raise InvalidRemovalError, 'The target device is not in this MLS group' unless target_link
      raise InvalidRemovalError, 'The target device is already revoked' if target.revoked_at?

      sender_device = actor.pqc_devices.active.find_by!(device_id: sender_device_id)
      raise InvalidRemovalError, 'The sending device is not enrolled in this MLS group' unless conversation.pqc_conversation_devices.exists?(pqc_device_id: sender_device.id)

      recipient_devices = PqcDevice.active.joins(:pqc_conversation_devices)
        .where(pqc_conversation_devices: { pqc_conversation_id: conversation.id })
        .where.not(device_id: [target.device_id, sender_device_id]).index_by(&:device_id)
      raise InvalidRemovalError, 'Deliveries must target every remaining active group device' unless decoded_deliveries.to_set { |delivery| delivery.fetch(1) } == recipient_devices.keys.to_set

      decoded_deliveries.each do |message_id, recipient_device_id, ciphertext|
        message = conversation.pqc_messages.create!(
          account: actor,
          sender_device: sender_device,
          recipient_device: recipient_devices.fetch(recipient_device_id),
          client_message_id: message_id,
          ciphertext: ciphertext
        )
        message_ids << message.id
      end

      target_link.destroy!
      target.with_lock do
        target.update!(revoked_at: Time.current, key_package_consumed_at: Time.current) if target.revocation_pending_at? && !target.pqc_conversation_devices.exists?
      end
      conversation.pqc_member_removals.create!(
        actor_account: actor,
        target_account: target.account,
        target_device_id: target.device_id,
        operation_id:,
        sender_device_id:,
        client_message_ids: decoded_deliveries.map(&:first)
      )
      conversation.touch
      removed = true
    end

    { conversation:, removed:, message_ids: }
  rescue ArgumentError => e
    raise InvalidRemovalError, e.message
  rescue ActiveRecord::RecordNotFound
    raise InvalidRemovalError, 'The target, sender, or recipient device is not available'
  end

  private

  def decode_deliveries(deliveries)
    message_ids = Set.new
    recipient_ids = Set.new
    deliveries.map do |delivery|
      delivery = delivery.to_h.symbolize_keys
      message_id = delivery[:client_message_id].to_s
      raise InvalidRemovalError, 'Each delivery needs a unique UUID client_message_id' unless message_id.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i) && message_ids.add?(message_id)

      recipient_id = delivery[:recipient_device_id].to_s
      raise InvalidRemovalError, 'Each delivery needs a unique recipient device' if recipient_id.blank? || !recipient_ids.add?(recipient_id)

      ciphertext = Base64.strict_decode64(delivery[:ciphertext].to_s)
      raise InvalidRemovalError, 'Encrypted MLS payload must be between 1 byte and 1 MiB' unless ciphertext.bytesize.between?(1, MAX_CIPHERTEXT_BYTES)

      [message_id, recipient_id, ciphertext]
    end
  end
end
