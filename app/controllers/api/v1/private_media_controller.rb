# frozen_string_literal: true

class Api::V1::PrivateMediaController < Api::BaseController
  before_action -> { doorkeeper_authorize! :'write:media' }
  before_action :require_user!
  before_action :require_private_media_enabled!
  before_action :set_private_media_object, only: [:show, :destroy]

  def show
    plaintext = Pqc::PrivateMedia::DecryptService.new.call(@private_media_object)
    response.headers['Cache-Control'] = 'private, no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    send_data plaintext, type: 'application/octet-stream', disposition: 'attachment', filename: "private-media-#{@private_media_object.token}"
  rescue Pqc::PrivateMedia::DecryptService::DecryptionError, Pqc::PrivateMedia::DataKey::ConfigurationError => e
    Rails.logger.error("Private media decryption failed (#{e.class})")
    render json: { error: 'Private media is temporarily unavailable' }, status: 503
  end

  def create
    object = Pqc::PrivateMedia::CreateService.new.call(current_account, params[:file])
    render json: {
      id: object.id.to_s,
      byte_size: object.byte_size,
      content_type: object.content_type,
      url: "/api/v1/private_media/#{object.id}",
    }, status: 201
  rescue Pqc::PrivateMedia::CreateService::QuotaExceededError => e
    render json: { error: e.message }, status: 413
  rescue Pqc::PrivateMedia::CreateService::InvalidUploadError => e
    render json: { error: e.message }, status: 422
  rescue Pqc::PrivateMedia::DataKey::ConfigurationError, Pqc::PrivateMedia::Storage::StorageError => e
    Rails.logger.error("Private media encryption/storage failed (#{e.class})")
    render json: { error: 'Private media is temporarily unavailable' }, status: 503
  end

  def destroy
    storage = Pqc::PrivateMedia::Storage.new
    ciphertext = storage.read(@private_media_object.storage_key)
    storage.delete(@private_media_object.storage_key)
    @private_media_object.destroy!
    render_empty
  rescue Pqc::PrivateMedia::Storage::StorageError => e
    Rails.logger.error("Private media deletion failed (#{e.class})")
    render json: { error: 'Private media is temporarily unavailable' }, status: 503
  rescue
    begin
      storage.write(@private_media_object.storage_key, ciphertext) if ciphertext
    rescue Pqc::PrivateMedia::Storage::StorageError => e
      Rails.logger.error("Private media deletion rollback failed (#{e.class})")
    end
    raise
  end

  private

  def require_private_media_enabled!
    head 404 unless ENV['PQC_PRIVATE_MEDIA_ENCRYPTION'] == 'true'
  end

  def set_private_media_object
    @private_media_object = current_account.private_media_objects.find(params[:id])
  end
end
