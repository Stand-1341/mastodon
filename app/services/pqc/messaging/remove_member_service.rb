# frozen_string_literal: true

class Pqc::Messaging::RemoveMemberService < BaseService
  MAX_DELIVERIES = 256
  MAX_CIPHERTEXT_BYTES = 1.megabyte

  class InvalidRemovalError < StandardError; end
  class IdempotencyConflict < StandardError; end

  def call(conversation:, creator:, account_id:, sender_device_id:, operation_id:, deliveries:)
    creator_can_remove_others = conversation.creator_account_id == creator.id
    raise InvalidRemovalError, 'Encrypted removal commits must be an array' unless deliveries.is_a?(Array)
    raise InvalidRemovalError, 'A removal may include at most 256 encrypted deliveries' if deliveries.length > MAX_DELIVERIES
    raise InvalidRemovalError, 'operation_id must be a UUID' unless operation_id.to_s.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i)

    removed = false
    message_ids = []
    PqcConversation.transaction do
      conversation.lock!
      raise InvalidRemovalError, 'Initial encrypted group setup is not complete' unless conversation.ready_at?

      target = Account.find_by(id: account_id, domain: nil)
      raise InvalidRemovalError, 'The removed member must be a local account' if target.nil?
      raise InvalidRemovalError, 'A member cannot commit its own removal' if target.id == creator.id

      seen_message_ids = Set.new
      seen_recipient_ids = Set.new
      decoded_deliveries = deliveries.map do |delivery|
        delivery = delivery.to_h.symbolize_keys
        message_id = delivery[:client_message_id].to_s
        raise InvalidRemovalError, 'Each delivery needs a unique UUID client_message_id' unless message_id.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i) && seen_message_ids.add?(message_id)

        recipient_device_id = delivery[:recipient_device_id].to_s
        raise InvalidRemovalError, 'Each removal commit must target a remaining member device' if recipient_device_id.blank? || !seen_recipient_ids.add?(recipient_device_id)

        ciphertext = Base64.strict_decode64(delivery[:ciphertext].to_s)
        raise InvalidRemovalError, 'Encrypted MLS payload must be between 1 byte and 1 MiB' unless ciphertext.bytesize.between?(1, MAX_CIPHERTEXT_BYTES)

        [message_id, recipient_device_id, ciphertext]
      end

      removal = conversation.pqc_member_removals.find_by(operation_id:)
      if removal
        unless removal.target_device_id.nil? && removal.actor_account_id == creator.id && removal.target_account_id == target.id && removal.sender_device_id == sender_device_id && removal.client_message_ids.sort == decoded_deliveries.map(&:first).sort
          raise IdempotencyConflict, 'operation_id was already used for another member removal'
        end

        sender_device = creator.pqc_devices.find_by!(device_id: sender_device_id)
        decoded_deliveries.each do |message_id, recipient_device_id, ciphertext|
          message = conversation.pqc_messages.find_by(account: creator, sender_device:, client_message_id: message_id)
          raise IdempotencyConflict, 'A retry does not match the committed member-removal messages' unless message&.ciphertext == ciphertext && message.recipient_device_id == recipient_device_id

          message_ids << message.id
        end
        next
      end

      membership = conversation.pqc_conversation_members.find_by(account_id: target.id)
      raise InvalidRemovalError, 'The account is not an active member of this encrypted conversation' unless membership&.accepted? && membership.joined_at?
      raise InvalidRemovalError, 'Only the creator can remove members without an explicit departure request' unless creator_can_remove_others || membership.leave_requested_at?

      sender_device = creator.pqc_devices.active.find_by!(device_id: sender_device_id)
      raise InvalidRemovalError, 'The sending device is not enrolled in this MLS group' unless conversation.pqc_conversation_devices.exists?(pqc_device_id: sender_device.id)

      recipient_devices = PqcDevice.active.joins(:pqc_conversation_devices)
        .where(pqc_conversation_devices: { pqc_conversation_id: conversation.id })
        .where.not(account_id: target.id).where.not(device_id: sender_device_id).index_by(&:device_id)
      raise InvalidRemovalError, 'The removal commit must be delivered to every remaining active group device' unless seen_recipient_ids == recipient_devices.keys.to_set

      decoded_deliveries.each do |message_id, recipient_device_id, ciphertext|
        recipient_device = recipient_devices.fetch(recipient_device_id)
        message = conversation.pqc_messages.create!(
          account: creator,
          sender_device: sender_device,
          recipient_device: recipient_device,
          client_message_id: message_id,
          ciphertext: ciphertext
        )
        message_ids << message.id
      end

      membership.destroy!
      conversation.pqc_conversation_devices.joins(:pqc_device).where(pqc_devices: { account_id: target.id }).delete_all
      conversation.pqc_member_removals.create!(
        actor_account: creator,
        target_account: target,
        operation_id: operation_id,
        sender_device_id: sender_device_id,
        client_message_ids: decoded_deliveries.map(&:first)
      )
      conversation.touch
      removed = true
    end

    { conversation: conversation, removed: removed, message_ids: message_ids }
  rescue ArgumentError => e
    raise InvalidRemovalError, e.message
  end
end
