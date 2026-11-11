# frozen_string_literal: true

class Api::V1::PrivateMedia::EnvelopesController < Api::BaseController
  before_action -> { doorkeeper_authorize! :'write:media' }
  before_action :require_user!
  before_action :require_private_media_enabled!
  before_action :set_private_media_object

  def show
    response.headers['Cache-Control'] = 'private, no-store, max-age=0'
    render json: {
      id: @private_media_object.id.to_s,
      token: @private_media_object.token,
      nonce: @private_media_object.client_nonce,
      auth_tag: @private_media_object.client_auth_tag,
      envelopes: Pqc::PrivateMedia::DeviceKeyEnvelope.parse_envelopes(@private_media_object.device_key_envelopes),
    }
  rescue Pqc::PrivateMedia::DeviceKeyEnvelope::EnvelopeError => e
    Rails.logger.error("Private media envelope read failed (#{e.class})")
    render json: { error: 'Private media is temporarily unavailable' }, status: 503
  end

  def create
    token = params.require(:token)
    nonce = params.require(:nonce)
    auth_tag = params.require(:auth_tag)
    envelope_params = params.require(:envelope)
    raise Pqc::PrivateMedia::DeviceKeyEnvelope::EnvelopeError, 'Invalid ML-KEM-1024 envelope' unless envelope_params.is_a?(ActionController::Parameters)

    envelope = envelope_params.to_unsafe_h.stringify_keys
    raise Pqc::PrivateMedia::DeviceKeyEnvelope::EnvelopeError, 'Invalid private media token' unless token == @private_media_object.token

    Pqc::PrivateMedia::DeviceKeyEnvelope.validate_envelope!(envelope, device_id: envelope['device_id'])
    Pqc::PrivateMedia::DeviceKeyEnvelope.validate_metadata!(nonce:, auth_tag:)
    serialized_envelopes = Pqc::PrivateMedia::DeviceKeyEnvelope.serialize_envelopes([envelope])
    device = current_account.pqc_devices.active.find_by!(device_id: envelope.fetch('device_id'))
    raise Pqc::PrivateMedia::DeviceKeyEnvelope::EnvelopeError, 'No ML-KEM-1024 key is registered for this device' if device.media_kem_public_key.blank?

    @private_media_object.with_lock do
      raise Pqc::PrivateMedia::DeviceKeyEnvelope::EnvelopeError, 'Private media envelope is already attached' if @private_media_object.device_key_envelope_attached?

      @private_media_object.update!(client_nonce: nonce, client_auth_tag: auth_tag, device_key_envelopes: serialized_envelopes)
    end

    response.headers['Cache-Control'] = 'private, no-store, max-age=0'
    render json: { id: @private_media_object.id.to_s }, status: 201
  rescue Pqc::PrivateMedia::DeviceKeyEnvelope::EnvelopeError, ActionController::ParameterMissing, ArgumentError, ActiveRecord::RecordNotFound => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordInvalid => e
    render json: { error: e.record.errors.full_messages }, status: 422
  end

  private

  def require_private_media_enabled!
    head 404 unless ENV['PQC_PRIVATE_MEDIA_ENCRYPTION'] == 'true'
  end

  def set_private_media_object
    @private_media_object = current_account.private_media_objects.find(params[:private_media_id])
  end
end
