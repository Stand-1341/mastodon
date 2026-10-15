# frozen_string_literal: true

class Pqc::Messaging::InviteGroupMemberService < BaseService
  MAX_MEMBERS = 10

  class InvalidInvitationError < StandardError; end

  def call(conversation:, creator:, account_id:)
    raise InvalidInvitationError, 'Only the conversation creator can invite a member' unless conversation.creator_account_id == creator.id

    created = false
    PqcConversation.transaction do
      conversation.lock!
      raise InvalidInvitationError, 'Initial encrypted group setup is not complete' unless conversation.ready_at?

      account = Account.find_by(id: account_id, domain: nil)
      raise InvalidInvitationError, 'The invitee must be a local account' if account.nil?

      membership = conversation.pqc_conversation_members.find_by(account_id: account.id)
      if account.id == creator.id
        raise InvalidInvitationError, 'The creator must already be a joined group member to add another device' unless membership&.joined_at?

        next
      end

      if membership&.joined_at?
        next
      elsif membership&.declined?
        raise InvalidInvitationError, 'An encrypted conversation can have at most 10 active or invited accounts' if conversation.pqc_conversation_members.where(invitation_status: %w(invited accepted)).count >= MAX_MEMBERS

        membership.update!(invitation_status: :invited)
        created = true
      elsif membership.nil?
        raise InvalidInvitationError, 'An encrypted conversation can have at most 10 active or invited accounts' if conversation.pqc_conversation_members.where(invitation_status: %w(invited accepted)).count >= MAX_MEMBERS

        conversation.pqc_conversation_members.create!(account:, invitation_status: :invited)
        created = true
      end

      conversation.touch if created
    end

    { conversation:, created: }
  end
end
