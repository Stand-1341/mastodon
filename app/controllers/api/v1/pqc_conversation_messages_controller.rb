# frozen_string_literal: true

class Api::V1::PqcConversationMessagesController < Api::BaseController
  include PqcDeviceRequestAuthenticationConcern

  MAX_CIPHERTEXT_BYTES = 1.megabyte

  before_action -> { doorkeeper_authorize! :write, :'write:statuses' }
  before_action :require_user!
  before_action :require_pqc_messaging_enabled!
  before_action :set_conversation
  before_action :authenticate_pqc_device_request!
  before_action :require_authenticated_message_device!

  def index
    device = current_account.pqc_devices.active.find_by!(device_id: params.require(:device_id))
    raise ActiveRecord::RecordNotFound unless @conversation.pqc_conversation_devices.exists?(pqc_device_id: device.id)

    messages = @conversation.pqc_messages.where(recipient_device_id: [nil, device.device_id]).order(:id)
    messages = messages.where('id > ?', params[:after_id].to_i) if params[:after_id].present?

    response.headers['Cache-Control'] = 'private, no-store, max-age=0'
    render json: messages.limit(limit).map { |message| serialize_message(message) }
  end

  def create
    ciphertext = Base64.strict_decode64(params.require(:ciphertext))
    raise ArgumentError, 'Encrypted MLS payload exceeds 1 MiB' if ciphertext.bytesize > MAX_CIPHERTEXT_BYTES

    sender_device = current_account.pqc_devices.active.find_by!(device_id: params.require(:sender_device_id))
    raise ActiveRecord::RecordNotFound unless @conversation.pqc_conversation_devices.exists?(pqc_device_id: sender_device.id)

    recipient_device = if params[:recipient_device_id].present?
                         recipient_device = PqcDevice.active.find_by!(device_id: params[:recipient_device_id])
                         raise ActiveRecord::RecordNotFound unless @conversation.pqc_conversation_devices.exists?(pqc_device_id: recipient_device.id)

                         recipient_device
                       end
    client_message_id = params[:client_message_id].presence
    if client_message_id && (existing = @conversation.pqc_messages.find_by(account: current_account, sender_device:, client_message_id:))
      return render_idempotent_result(existing, ciphertext, recipient_device)
    end

    message = @conversation.pqc_messages.create!(account: current_account, sender_device:, recipient_device:, ciphertext: ciphertext, client_message_id:)
    render json: serialize_message(message), status: 201
  rescue ArgumentError => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordInvalid => e
    if e.record.client_message_id.present? && (existing = @conversation.pqc_messages.find_by(account: current_account, sender_device_id: e.record.sender_device_id, client_message_id: e.record.client_message_id))
      return render_idempotent_result(existing, e.record.ciphertext, e.record.recipient_device)
    end

    render json: { error: e.record.errors.full_messages }, status: 422
  rescue ActiveRecord::RecordNotUnique
    existing = @conversation.pqc_messages.find_by!(account: current_account, sender_device_id: params[:sender_device_id], client_message_id: params[:client_message_id])
    render_idempotent_result(existing, ciphertext, recipient_device)
  end

  private

  def set_conversation
    @conversation = PqcConversation.joins(:pqc_conversation_members)
      .where.not(ready_at: nil)
      .merge(PqcConversationMember.joined)
      .find_by!(token: params[:pqc_conversation_token], pqc_conversation_members: { account_id: current_account.id, invitation_status: :accepted })
  end

  def require_authenticated_message_device!
    device_id = action_name == 'index' ? params[:device_id] : params[:sender_device_id]
    require_authenticated_pqc_device_id!(device_id)
  end

  def require_pqc_messaging_enabled!
    head 404 unless ENV['PQC_E2EE_EXPERIMENTAL'] == 'true'
  end

  def limit
    return 100 if params[:limit].blank?

    requested = params[:limit].to_i
    requested.clamp(1, 100)
  end

  def serialize_message(message)
    {
      id: message.id,
      sender_account_id: message.account_id.to_s,
      sender_device_id: message.sender_device_id,
      recipient_device_id: message.recipient_device_id,
      ciphertext: Base64.strict_encode64(message.ciphertext),
      created_at: message.created_at,
    }
  end

  def render_idempotent_result(existing, ciphertext, recipient_device)
    return render json: { error: 'client_message_id was already used for a different message' }, status: 409 unless existing.ciphertext == ciphertext && existing.recipient_device_id == recipient_device&.device_id

    render json: serialize_message(existing), status: 200
  end
end
