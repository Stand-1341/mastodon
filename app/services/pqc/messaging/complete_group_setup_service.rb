# frozen_string_literal: true

class Pqc::Messaging::CompleteGroupSetupService < BaseService
  MAX_DELIVERIES = 256
  MAX_CIPHERTEXT_BYTES = 1.megabyte

  class InvalidSetupError < StandardError; end
  class IdempotencyConflict < StandardError; end

  def call(conversation:, creator:, sender_device_id:, deliveries:)
    raise InvalidSetupError, 'Only the conversation creator can complete group setup' unless conversation.creator_account_id == creator.id
    raise InvalidSetupError, 'Encrypted setup deliveries must be an array' unless deliveries.is_a?(Array)
    raise InvalidSetupError, 'Group setup may include at most 256 encrypted deliveries' if deliveries.length > MAX_DELIVERIES

    activated = false
    message_ids = []
    PqcConversation.transaction do
      conversation.lock!
      raise InvalidSetupError, 'The setup device does not match the device that created this group' if conversation.setup_device_id.present? && conversation.setup_device_id != sender_device_id

      sender_devices = conversation.ready_at? ? creator.pqc_devices : creator.pqc_devices.active
      sender_device = sender_devices.find_by!(device_id: sender_device_id)
      conversation.update!(setup_device_id: sender_device_id) if conversation.setup_device_id.blank?
      pending_invitees = !conversation.ready_at? && conversation.pqc_conversation_members.invited.exists?
      raise InvalidSetupError, 'Every invitee must accept or decline before group setup can finish' if pending_invitees

      member_account_ids = conversation.pqc_conversation_members.accepted.select(:account_id)
      recipient_devices = PqcDevice.active.where(account_id: member_account_ids).index_by(&:device_id)
      seen_message_ids = Set.new
      delivered_recipient_device_ids = Set.new
      conversation.pqc_conversation_devices.find_or_create_by!(pqc_device: sender_device)

      deliveries.each do |delivery|
        delivery = delivery.to_h.symbolize_keys
        message_id = delivery[:client_message_id].to_s
        raise InvalidSetupError, 'Each delivery needs a unique UUID client_message_id' unless message_id.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i) && seen_message_ids.add?(message_id)

        recipient_device_id = delivery[:recipient_device_id].to_s
        raise InvalidSetupError, 'Each setup delivery must target a member device' if recipient_device_id.blank?

        # A previously added device must receive every later MLS commit while
        # the creator adds more devices. Multiple ordered deliveries to one
        # recipient are therefore valid; activation still requires coverage.
        delivered_recipient_device_ids.add(recipient_device_id)

        ciphertext = Base64.strict_decode64(delivery[:ciphertext].to_s)
        raise InvalidSetupError, 'Encrypted MLS payload must be between 1 byte and 1 MiB' unless ciphertext.bytesize.between?(1, MAX_CIPHERTEXT_BYTES)

        message = conversation.pqc_messages.find_by(account: creator, sender_device:, client_message_id: message_id)
        if message.present?
          raise IdempotencyConflict, 'client_message_id was already used for a different setup delivery' unless message.ciphertext == ciphertext && message.recipient_device_id == recipient_device_id

          message_ids << message.id
          next
        end

        raise InvalidSetupError, 'Group setup has already been completed' if conversation.ready_at?

        recipient_device = recipient_devices[recipient_device_id]
        raise InvalidSetupError, 'Each setup delivery must target an active member device' if recipient_device.nil?

        conversation.pqc_conversation_devices.find_or_create_by!(pqc_device: recipient_device)

        message = conversation.pqc_messages.create!(
          account: creator,
          sender_device: sender_device,
          recipient_device: recipient_device,
          client_message_id: message_id,
          ciphertext: ciphertext
        )
        message_ids << message.id
      end

      unless conversation.ready_at?
        # The setup sender already holds the resulting MLS state locally. Relaying
        # its own commit back to itself would be redundant and could be replayed
        # against the state that has already advanced.
        required_recipient_device_ids = recipient_devices.keys - [sender_device.device_id]
        missing_recipient_device_ids = required_recipient_device_ids - delivered_recipient_device_ids.to_a
        raise InvalidSetupError, 'Group setup must deliver the protocol commit or Welcome to every active member device' if missing_recipient_device_ids.any?

        ready_at = Time.current
        conversation.update!(ready_at:)
        conversation.pqc_conversation_members.accepted.update_all(joined_at: ready_at, updated_at: ready_at)
        activated = true
      end
    end

    { conversation: conversation, activated: activated, message_ids: message_ids }
  rescue ArgumentError => e
    raise InvalidSetupError, e.message
  end
end
