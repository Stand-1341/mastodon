# frozen_string_literal: true

class Api::V1::PqcConversationsController < Api::BaseController
  include PqcDeviceRequestAuthenticationConcern

  before_action -> { doorkeeper_authorize! :write, :'write:statuses' }
  before_action :require_user!
  before_action :require_pqc_messaging_enabled!
  before_action :authenticate_pqc_device_request!, only: [
    :create, :complete_setup, :commit_member, :remove_member, :remove_device,
    :invite_member, :request_leave, :accept_invitation, :decline_invitation
  ]
  before_action :require_authenticated_sender_device!, only: [:complete_setup, :commit_member, :remove_member, :remove_device]
  before_action :require_authenticated_setup_device!, only: [:create]
  before_action :set_conversation, only: [:show, :complete_setup, :commit_member, :remove_member, :remove_device, :request_leave, :accept_invitation, :decline_invitation, :invite_member]

  def index
    conversations = PqcConversation.joins(:pqc_conversation_members)
      .where(pqc_conversation_members: { account_id: current_account.id })
      .where(pqc_conversation_members: { invitation_status: %w(invited accepted) })
      .includes(:pqc_conversation_members, pqc_conversation_devices: :pqc_device)
      .distinct
      .order(updated_at: :desc)
      .to_a

    member_account_ids = conversations.flat_map do |conversation|
      conversation.pqc_conversation_members.filter_map do |membership|
        membership.account_id if membership.accepted? && (!conversation.ready_at? || membership.joined_at?)
      end
    end.uniq

    @pqc_devices_by_account_id = PqcDevice.unrevoked.includes(:account)
      .where(account_id: member_account_ids).group_by(&:account_id)

    render json: conversations.map { |conversation| serialize_conversation(conversation) }
  end

  def show
    render json: serialize_conversation(@conversation)
  end

  def complete_setup
    raw_deliveries = params.require(:deliveries)
    return render json: { error: 'Encrypted setup deliveries must be an array' }, status: 422 unless raw_deliveries.is_a?(Array)
    return render json: { error: 'Each setup delivery must be an object' }, status: 422 unless raw_deliveries.all? { |delivery| delivery.respond_to?(:permit) || delivery == '' }

    result = Pqc::Messaging::CompleteGroupSetupService.new.call(
      conversation: @conversation,
      creator: current_account,
      sender_device_id: params.require(:sender_device_id),
      deliveries: raw_deliveries.filter_map do |delivery|
        delivery.permit(:client_message_id, :recipient_device_id, :ciphertext).to_h if delivery.respond_to?(:permit)
      end
    )

    render json: {
      conversation: serialize_conversation(result.fetch(:conversation)),
      message_ids: result.fetch(:message_ids),
    }, status: result.fetch(:activated) ? 201 : 200
  rescue Pqc::Messaging::CompleteGroupSetupService::IdempotencyConflict => e
    render json: { error: e.message }, status: 409
  rescue Pqc::Messaging::CompleteGroupSetupService::InvalidSetupError, ActiveRecord::RecordInvalid => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'The setup device or a recipient device is not available' }, status: 422
  end

  def commit_member
    raw_deliveries = params.require(:deliveries)
    return render json: { error: 'Encrypted member-add deliveries must be an array' }, status: 422 unless raw_deliveries.is_a?(Array)
    return render json: { error: 'Each member-add delivery must be an object' }, status: 422 unless raw_deliveries.all? { |delivery| delivery.respond_to?(:permit) || delivery == '' }

    result = Pqc::Messaging::CommitMemberAdditionService.new.call(
      conversation: @conversation,
      creator: current_account,
      account_id: params.require(:account_id),
      sender_device_id: params.require(:sender_device_id),
      operation_id: params.require(:operation_id),
      key_package_request_id: params.require(:key_package_request_id),
      target_device_ids: params.require(:target_device_ids),
      deliveries: raw_deliveries.filter_map do |delivery|
        delivery.permit(:client_message_id, :recipient_device_id, :ciphertext).to_h if delivery.respond_to?(:permit)
      end
    )

    render json: {
      conversation: serialize_conversation(result.fetch(:conversation)),
      message_ids: result.fetch(:message_ids),
    }, status: result.fetch(:created) ? 201 : 200
  rescue Pqc::Messaging::CommitMemberAdditionService::IdempotencyConflict => e
    render json: { error: e.message }, status: 409
  rescue Pqc::Messaging::CommitMemberAdditionService::InvalidAdditionError, ActiveRecord::RecordInvalid => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'A sender or recipient device is not available' }, status: 422
  end

  def invite_member
    result = Pqc::Messaging::InviteGroupMemberService.new.call(
      conversation: @conversation,
      creator: current_account,
      account_id: params.require(:account_id)
    )

    render json: serialize_conversation(result.fetch(:conversation)), status: result.fetch(:created) ? 201 : 200
  rescue Pqc::Messaging::InviteGroupMemberService::InvalidInvitationError, ActiveRecord::RecordInvalid => e
    render json: { error: e.message }, status: 422
  end

  def remove_member
    raw_deliveries = params.require(:deliveries)
    return render json: { error: 'Encrypted removal commits must be an array' }, status: 422 unless raw_deliveries.is_a?(Array)
    return render json: { error: 'Each removal delivery must be an object' }, status: 422 unless raw_deliveries.all? { |delivery| delivery.respond_to?(:permit) || delivery == '' }

    result = Pqc::Messaging::RemoveMemberService.new.call(
      conversation: @conversation,
      creator: current_account,
      account_id: params.require(:account_id),
      sender_device_id: params.require(:sender_device_id),
      operation_id: params.require(:operation_id),
      deliveries: raw_deliveries.filter_map do |delivery|
        delivery.permit(:client_message_id, :recipient_device_id, :ciphertext).to_h if delivery.respond_to?(:permit)
      end
    )

    render json: {
      conversation: serialize_conversation(result.fetch(:conversation)),
      message_ids: result.fetch(:message_ids),
    }, status: result.fetch(:removed) ? 201 : 200
  rescue Pqc::Messaging::RemoveMemberService::IdempotencyConflict => e
    render json: { error: e.message }, status: 409
  rescue Pqc::Messaging::RemoveMemberService::InvalidRemovalError, ActiveRecord::RecordInvalid => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'The sender or remaining recipient device is not available' }, status: 422
  end

  def request_leave
    raise Pqc::Messaging::RemoveMemberService::InvalidRemovalError, 'Accept the invitation and finish setup before requesting to leave' unless @conversation.ready_at?
    raise Pqc::Messaging::RemoveMemberService::InvalidRemovalError, 'The creator cannot leave this prototype group' if @conversation.creator_account_id == current_account.id

    membership = @conversation.pqc_conversation_members.find_by!(account_id: current_account.id)
    raise Pqc::Messaging::RemoveMemberService::InvalidRemovalError, 'Join the MLS group before requesting to leave' unless membership.joined_at?

    membership.update!(leave_requested_at: Time.current) unless membership.leave_requested_at?
    render json: serialize_conversation(@conversation)
  rescue Pqc::Messaging::RemoveMemberService::InvalidRemovalError => e
    render json: { error: e.message }, status: 422
  end

  def remove_device
    raw_deliveries = params.require(:deliveries)
    return render json: { error: 'Encrypted device-removal commits must be an array' }, status: 422 unless raw_deliveries.is_a?(Array)
    return render json: { error: 'Each device-removal delivery must be an object' }, status: 422 unless raw_deliveries.all? { |delivery| delivery.respond_to?(:permit) || delivery == '' }

    result = Pqc::Messaging::RemoveDeviceService.new.call(
      conversation: @conversation,
      actor: current_account,
      target_device_id: params.require(:target_device_id),
      sender_device_id: params.require(:sender_device_id),
      operation_id: params.require(:operation_id),
      deliveries: raw_deliveries.filter_map do |delivery|
        delivery.permit(:client_message_id, :recipient_device_id, :ciphertext).to_h if delivery.respond_to?(:permit)
      end
    )

    render json: {
      conversation: serialize_conversation(result.fetch(:conversation)),
      message_ids: result.fetch(:message_ids),
    }, status: result.fetch(:removed) ? 201 : 200
  rescue Pqc::Messaging::RemoveDeviceService::IdempotencyConflict => e
    render json: { error: e.message }, status: 409
  rescue Pqc::Messaging::RemoveDeviceService::InvalidRemovalError, ActiveRecord::RecordInvalid => e
    render json: { error: e.message }, status: 422
  end

  def accept_invitation
    update_invitation_status(:accepted)
  end

  def decline_invitation
    update_invitation_status(:declined)
  end

  def create
    requested_ids = Array(params[:account_ids]).map(&:to_s).uniq
    raise ArgumentError, 'A conversation can have at most 10 members' if requested_ids.length > 9

    accounts = Account.where(id: requested_ids, domain: nil).to_a
    raise ArgumentError, 'Every participant must be a local account' unless accounts.length == requested_ids.length

    setup_device = current_account.pqc_devices.active.find_by!(device_id: params.require(:setup_device_id))

    conversation = PqcConversation.transaction do
      record = PqcConversation.create!(creator_account: current_account, setup_device_id: setup_device.device_id)
      (accounts + [current_account]).uniq.each do |account|
        record.pqc_conversation_members.create!(account: account, invitation_status: account == current_account ? :accepted : :invited)
      end
      record
    end

    render json: serialize_conversation(conversation), status: 201
  rescue ArgumentError => e
    render json: { error: e.message }, status: 422
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'The setup device is not available' }, status: 422
  end

  private

  def set_conversation
    statuses = %w(invited accepted)
    statuses << 'declined' if action_name == 'decline_invitation'
    @conversation = PqcConversation.joins(:pqc_conversation_members)
      .find_by!(token: params[:token], pqc_conversation_members: { account_id: current_account.id, invitation_status: statuses })
  end

  def require_authenticated_sender_device!
    require_authenticated_pqc_device_id!(params[:sender_device_id])
  end

  def require_authenticated_setup_device!
    require_authenticated_pqc_device_id!(params[:setup_device_id])
  end

  def require_pqc_messaging_enabled!
    head 404 unless ENV['PQC_E2EE_EXPERIMENTAL'] == 'true'
  end

  def serialize_conversation(conversation)
    memberships = conversation.pqc_conversation_members.to_a
    group_memberships = if conversation.ready_at?
                          memberships.select { |membership| membership.accepted? && membership.joined_at? }
                        else
                          memberships.select(&:accepted?)
                        end
    member_ids = group_memberships.map(&:account_id)

    {
      id: conversation.token,
      creator_account_id: conversation.creator_account_id.to_s,
      member_account_ids: member_ids.map(&:to_s).sort,
      invited_account_ids: memberships.filter(&:invited?).map { |membership| membership.account_id.to_s }.sort,
      pending_addition_account_ids: conversation.ready_at? ? memberships.filter { |membership| membership.accepted? && !membership.joined_at? }.map { |membership| membership.account_id.to_s }.sort : [],
      declined_account_ids: memberships.filter(&:declined?).map { |membership| membership.account_id.to_s }.sort,
      my_invitation_status: memberships.find { |membership| membership.account_id == current_account.id }&.invitation_status,
      leave_requested_account_ids: memberships.filter_map { |membership| membership.account_id if membership.leave_requested_at? }.map(&:to_s).sort,
      member_devices: devices_for_members(member_ids).map do |device|
        {
          account_id: device.account_id.to_s,
          id: device.id,
          actor_uri: ActivityPub::TagManager.instance.uri_for(device.account),
          device_id: device.device_id,
          fingerprint: device.fingerprint,
          revocation_pending: device.revocation_pending_at.present?,
        }
      end,
      joined_device_ids: joined_devices_for(conversation).sort,
      created_at: conversation.created_at,
      updated_at: conversation.updated_at,
      ready_at: conversation.ready_at,
    }
  end

  def devices_for_members(member_ids)
    return PqcDevice.unrevoked.includes(:account).where(account_id: member_ids) unless @pqc_devices_by_account_id

    member_ids.flat_map { |account_id| @pqc_devices_by_account_id.fetch(account_id, []) }
  end

  def joined_devices_for(conversation)
    return conversation.pqc_conversation_devices.joins(:pqc_device).merge(PqcDevice.unrevoked).pluck('pqc_devices.device_id') unless conversation.association(:pqc_conversation_devices).loaded?

    conversation.pqc_conversation_devices.filter_map do |conversation_device|
      device = conversation_device.pqc_device
      device.device_id if device && !device.revoked_at?
    end
  end

  def update_invitation_status(status)
    membership = @conversation.pqc_conversation_members.find_by!(account_id: current_account.id)
    PqcConversation.transaction do
      @conversation.lock!
      membership.lock!
      raise ArgumentError, 'The creator does not have an invitation to respond to' if @conversation.creator_account_id == current_account.id
      raise ArgumentError, 'This account has already joined the MLS group' if membership.joined_at?
      if membership.public_send("#{status}?")
        next
      elsif status == :accepted && !membership.invited?
        raise ArgumentError, 'A declined invitation must be reissued by the creator'
      elsif status == :declined && !membership.invited? && !membership.accepted?
        raise ArgumentError, 'A declined invitation cannot be changed'
      end

      membership.update!(invitation_status: status)
      @conversation.touch
    end

    render json: serialize_conversation(@conversation)
  rescue ArgumentError => e
    render json: { error: e.message }, status: 422
  end
end
