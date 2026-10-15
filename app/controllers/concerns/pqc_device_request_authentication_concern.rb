# frozen_string_literal: true

module PqcDeviceRequestAuthenticationConcern
  extend ActiveSupport::Concern

  private

  def authenticate_pqc_device_request!
    @authenticated_pqc_device = Pqc::Messaging::DeviceRequestAuthenticator.call(request:, account: current_account)
  rescue Pqc::Messaging::DeviceRequestAuthenticator::AuthenticationError
    head 401
  end

  def require_authenticated_pqc_device_id!(device_id)
    head 403 unless @authenticated_pqc_device&.device_id == device_id.to_s
  end
end
