# frozen_string_literal: true

class Api::V1::PqcDevicesController < Api::BaseController
  include PqcDeviceRequestAuthenticationConcern

  before_action -> { doorkeeper_authorize! :write, :'write:statuses' }
  before_action :require_user!
  before_action :require_pqc_messaging_enabled!
  before_action :authenticate_pqc_device_request!, only: [:destroy, :update_key_package, :key_packages]
  before_action :require_authenticated_key_package_device!, only: [:update_key_package]
  before_action :require_authenticated_package_claim_device!, only: [:key_packages]

  def index
    render json: current_account.pqc_devices.unrevoked.order(:created_at).map { |device| serialize_device(device) }
  end

  def create
    key_package = Base64.strict_decode64(params.require(:key_package))
    raise ArgumentError, 'KeyPackage exceeds 512 KiB' if key_package.bytesize > 512.kilobytes

    device = current_account.pqc_devices.create!(
      device_id: params.require(:device_id),
      fingerprint: params.require(:fingerprint),
      auth_public_key: decode_auth_public_key(params.require(:device_auth_public_key)),
      key_package: key_package
    )

    render json: serialize_device(device), status: 201
  rescue ArgumentError => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordInvalid => e
    render json: { error: e.record.errors.full_messages }, status: 422
  end

  def destroy
    device = current_account.pqc_devices.find(params[:id])
    return render_empty if device.revoked_at?

    if device.pqc_conversation_devices.exists?
      device.with_lock do
        device.update!(revocation_pending_at: Time.current) unless device.revocation_pending_at?
      end
      return render json: { revocation_pending: true }, status: 202
    end

    device.revoke!
    render_empty
  rescue PqcDevice::EnrolledInMlsGroupError => e
    render json: { error: e.message }, status: 409
  end

  def update_key_package
    key_package = Base64.strict_decode64(params.require(:key_package))
    raise ArgumentError, 'KeyPackage exceeds 512 KiB' if key_package.bytesize > 512.kilobytes

    device = current_account.pqc_devices.active.find(params[:id])
    if params[:device_auth_public_key].present?
      auth_public_key = decode_auth_public_key(params[:device_auth_public_key])
      raise ArgumentError, 'Device authentication key cannot be changed' if device.auth_public_key.present? && device.auth_public_key != auth_public_key

      device.auth_public_key ||= auth_public_key
    end
    device.update!(key_package: key_package, key_package_consumed_at: nil)

    render json: serialize_device(device)
  rescue ArgumentError => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordInvalid => e
    render json: { error: e.record.errors.full_messages }, status: 422
  end

  def key_packages
    conversation = PqcConversation.joins(:pqc_conversation_members)
      .find_by!(token: params.require(:conversation_id), pqc_conversation_members: { account_id: current_account.id, invitation_status: :accepted })
    account = Account.find_by!(id: params.require(:account_id), domain: nil)
    membership = conversation.pqc_conversation_members.find_by(account_id: account.id)
    is_accepted_member = membership&.accepted?
    # KeyPackage claims are stateful: fetching consumes the package and binds
    # it to a single addition attempt. Restrict claims to the creator, who is
    # the only account allowed to commit member/device changes.
    raise ActiveRecord::RecordNotFound unless conversation.creator_account_id == current_account.id
    raise ActiveRecord::RecordNotFound unless is_accepted_member

    excluded_device = current_account.pqc_devices.active.find_by!(device_id: params[:exclude_device_id]) if params[:exclude_device_id].present?
    enrolled_device_ids = conversation.pqc_conversation_devices.pluck(:pqc_device_id)
    devices = account.pqc_devices.active.where.not(key_package: nil).where.not(id: enrolled_device_ids)
    devices = devices.where.not(id: excluded_device.id) if excluded_device
    request_id = params[:request_id].presence
    return render json: { error: 'request_id must be a UUID' }, status: 422 if request_id && !request_id.match?(/\A[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\z/i)

    packages = devices.order(:created_at).filter_map do |device|
      package = nil
      device.with_lock do
        next if device.revoked_at?

        if device.key_package_consumed_at?
          next unless request_id.present? && device.key_package_claim_id == request_id && device.key_package_claim_conversation_id == conversation.id

          package = serialize_key_package(device)
          next
        end

        # A retry token from a package already replaced must never consume its successor.
        # A request token is never allowed to claim a successor package, even
        # after rotation or when the retry is made in another conversation.
        next if request_id.present? && device.key_package_claim_id == request_id

        package = serialize_key_package(device)
        device.update!(key_package_consumed_at: Time.current, key_package_claim_id: request_id, key_package_claim_conversation: conversation)
      end
      package
    end

    response.headers['Cache-Control'] = 'private, no-store, max-age=0'
    render json: packages
  end

  private

  def require_authenticated_key_package_device!
    head 403 unless @authenticated_pqc_device&.id.to_s == params[:id].to_s
  end

  def require_authenticated_package_claim_device!
    head 403 if params[:exclude_device_id].present? && @authenticated_pqc_device&.device_id != params[:exclude_device_id].to_s
  end

  def decode_auth_public_key(encoded)
    key = Base64.strict_decode64(encoded)
    raise ArgumentError, 'ML-DSA-87 authentication key must be 2592 bytes' unless key.bytesize == Pqc::Messaging::DeviceRequestAuthenticator::PUBLIC_KEY_BYTES

    key
  end

  def require_pqc_messaging_enabled!
    head 404 unless ENV['PQC_E2EE_EXPERIMENTAL'] == 'true'
  end

  def serialize_device(device)
    {
      id: device.id,
      device_id: device.device_id,
      fingerprint: device.fingerprint,
      device_auth_ready: device.auth_public_key.present?,
      revocation_pending: device.revocation_pending_at.present?,
      created_at: device.created_at,
    }
  end

  def serialize_key_package(device)
    {
      id: device.id,
      account_id: device.account_id.to_s,
      actor_uri: ActivityPub::TagManager.instance.uri_for(device.account),
      device_id: device.device_id,
      fingerprint: device.fingerprint,
      key_package: Base64.strict_encode64(device.key_package),
    }
  end
end
