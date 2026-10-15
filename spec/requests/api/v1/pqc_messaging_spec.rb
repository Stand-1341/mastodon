# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'PQC messaging relay API' do
  include_context 'with API authentication', oauth_scopes: 'write:statuses'

  around do |example|
    ClimateControl.modify(PQC_E2EE_EXPERIMENTAL: 'true') { example.run }
  end

  before do |example|
    next if example.metadata[:real_device_auth]

    # These relay behavior specs predate device PoP and exercise service policy.
    # The authenticator's ML-DSA verification and replay behavior is covered by
    # its dedicated specs; the real HTTP boundary is covered separately.
    allow(Pqc::Messaging::DeviceRequestAuthenticator).to receive(:call) do |request:, account:|
      device_id = request.headers['X-PQC-Device-ID'] || request.params[:device_id] || request.params[:sender_device_id] || request.params[:setup_device_id] || request.params[:exclude_device_id]
      device_id ||= PqcDevice.find_by(account:, id: request.path_parameters[:id])&.device_id
      device_id ||= PqcDevice.active.find_by!(account:).device_id
      PqcDevice.active.find_by!(account:, device_id:)
    end
  end

  describe 'device registration' do
    let(:key_package) { 'opaque-public-key-package'.b }

    let!(:device_id) { register_device }

    let!(:conversation_id) { create_conversation }

    def register_device
      auth_public_key = '0'.b * Pqc::Messaging::DeviceRequestAuthenticator::PUBLIC_KEY_BYTES
      post '/api/v1/pqc_devices', headers: headers, params: {
        device_id: 'browser-device-1',
        fingerprint: Digest::SHA256.hexdigest(auth_public_key),
        device_auth_public_key: Base64.strict_encode64(auth_public_key),
        key_package: Base64.strict_encode64(key_package),
      }
      expect(response).to have_http_status(201), response.body
      response.parsed_body.fetch('id')
    end

    def create_conversation
      post '/api/v1/pqc_conversations', headers: headers, params: { account_ids: [user.account_id], setup_device_id: PqcDevice.find(device_id).device_id }
      expect(response).to have_http_status(201), response.body
      conversation_id = response.parsed_body.fetch('id')
      setup_device = PqcDevice.find(device_id)
      setup_deliveries = PqcDevice.active.where(account_id: user.account_id).map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('commit') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: setup_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201), response.body
      conversation_id
    end

    it 'registers and lists the public device identity' do
      expect(PqcDevice.exists?(id: device_id)).to be true
      get '/api/v1/pqc_devices', headers: headers
      expect(response.parsed_body).to contain_exactly(include('device_id' => 'browser-device-1', 'fingerprint' => PqcDevice.find(device_id).fingerprint))
    end

    it 'makes a KeyPackage available once per authorized conversation member' do
      second_device = create_test_device(user.account)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: user.account_id }
      expect(response.parsed_body).to contain_exactly(include('device_id' => second_device.device_id, 'key_package' => Base64.strict_encode64('test-package')))
      expect(response.parsed_body.first.fetch('actor_uri')).to eq(ActivityPub::TagManager.instance.uri_for(user.account))
      expect(response.headers['Cache-Control']).to include('no-store')
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: user.account_id }
      expect(response.parsed_body).to be_empty
    end

    it 'publishes the same canonical ActivityPub URI in conversation device identities' do
      get '/api/v1/pqc_conversations', headers: headers

      expect(response).to have_http_status(200)
      expect(response.parsed_body.first.fetch('member_devices')).to include(
        include('device_id' => 'browser-device-1', 'actor_uri' => ActivityPub::TagManager.instance.uri_for(user.account))
      )
    end

    it 'can exclude the requesting device without consuming its own KeyPackage' do
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: {
        conversation_id:,
        account_id: user.account_id,
        exclude_device_id: 'browser-device-1',
      }

      expect(response).to have_http_status(200)
      expect(response.parsed_body).to be_empty
      expect(PqcDevice.find(device_id).key_package_consumed_at).to be_nil
    end

    it 'adds the creator’s new device to an already active MLS group' do
      sender_device = PqcDevice.find(device_id)
      target_device = create_test_device(user.account)
      post "/api/v1/pqc_conversations/#{conversation_id}/invite_member", headers: headers, params: { account_id: user.account_id }
      expect(response).to have_http_status(200), response.body
      expect(response.parsed_body.fetch('invited_account_ids')).to be_empty

      request_id = SecureRandom.uuid
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: {
        conversation_id:,
        account_id: user.account_id,
        exclude_device_id: sender_device.device_id,
        request_id:,
      }
      expect(response).to have_http_status(200), response.body
      expect(response.parsed_body).to contain_exactly(include('device_id' => target_device.device_id))

      deliveries = [{ client_message_id: SecureRandom.uuid, recipient_device_id: target_device.device_id, ciphertext: Base64.strict_encode64('new-device welcome') }]
      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: {
        account_id: user.account_id,
        sender_device_id: sender_device.device_id,
        operation_id: SecureRandom.uuid,
        key_package_request_id: request_id,
        target_device_ids: [target_device.device_id],
        deliveries:,
      }

      expect(response).to have_http_status(201), response.body
      expect(response.parsed_body.dig('conversation', 'joined_device_ids')).to contain_exactly(sender_device.device_id, target_device.device_id)
      expect(response.parsed_body.dig('conversation', 'member_account_ids')).to contain_exactly(user.account_id.to_s)
    end

    it 'returns the same consumed KeyPackage for a retried fetch request' do
      second_device = create_test_device(user.account)
      request_id = SecureRandom.uuid
      params = { conversation_id:, account_id: user.account_id, request_id: }

      get '/api/v1/pqc_devices/key_packages', headers: headers, params: params
      expect(response.parsed_body).to contain_exactly(include('device_id' => second_device.device_id, 'key_package' => Base64.strict_encode64('test-package')))

      get '/api/v1/pqc_devices/key_packages', headers: headers, params: params
      expect(response.parsed_body).to contain_exactly(include('device_id' => second_device.device_id, 'key_package' => Base64.strict_encode64('test-package')))

      get '/api/v1/pqc_devices/key_packages', headers: headers, params: params.merge(request_id: SecureRandom.uuid)
      expect(response.parsed_body).to be_empty

      replacement_package = 'rotated-public-key-package'.b
      patch "/api/v1/pqc_devices/#{second_device.id}/key_package", headers: headers, params: { key_package: Base64.strict_encode64(replacement_package) }
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: params
      expect(response.parsed_body).to be_empty
      expect(PqcDevice.find(device_id).key_package_consumed_at).to be_nil

      get '/api/v1/pqc_devices/key_packages', headers: headers, params: params.merge(request_id: SecureRandom.uuid)
      expect(response.parsed_body).to contain_exactly(include('key_package' => Base64.strict_encode64(replacement_package)))
    end

    # rubocop:disable-next RSpec/ExampleLength
    it 'does not replay a claimed KeyPackage into another conversation' do
      participant = Fabricate(:user)
      device = create_test_device(participant.account)
      sender_device = PqcDevice.find(device_id)
      first_conversation_id = create_pending_conversation([participant.account_id], sender_device)
      request_id = SecureRandom.uuid
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id: first_conversation_id, account_id: participant.account_id, request_id: }
      expect(response.parsed_body).to contain_exactly(include('device_id' => device.device_id))
      setup_deliveries = [sender_device, device].map do |recipient|
        { client_message_id: SecureRandom.uuid, recipient_device_id: recipient.device_id, ciphertext: Base64.strict_encode64('welcome') }
      end
      post "/api/v1/pqc_conversations/#{first_conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201)

      second_conversation_id = create_pending_conversation([participant.account_id], sender_device)
      second_setup_deliveries = [sender_device, device].map do |recipient|
        { client_message_id: SecureRandom.uuid, recipient_device_id: recipient.device_id, ciphertext: Base64.strict_encode64('welcome') }
      end
      post "/api/v1/pqc_conversations/#{second_conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: second_setup_deliveries }
      expect(response).to have_http_status(201)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id: second_conversation_id, account_id: participant.account_id, request_id: }

      expect(response).to have_http_status(200)
      expect(response.parsed_body).to be_empty
      expect(device.reload.key_package_claim_conversation_id).to eq(PqcConversation.find_by!(token: first_conversation_id).id)
    end

    it 'rejects committing a consumed KeyPackage claim in a different conversation' do
      sender_device = PqcDevice.find(device_id)
      second_conversation_id = create_pending_conversation([user.account_id], sender_device)
      setup_delivery = { client_message_id: SecureRandom.uuid, recipient_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('setup') }
      post "/api/v1/pqc_conversations/#{second_conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: [setup_delivery] }
      expect(response).to have_http_status(201), response.body
      target_device = create_test_device(user.account)

      request_id = SecureRandom.uuid
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: {
        conversation_id:,
        account_id: user.account_id,
        exclude_device_id: sender_device.device_id,
        request_id:,
      }
      expect(response).to have_http_status(200), response.body
      expect(response.parsed_body).to contain_exactly(include('device_id' => target_device.device_id))

      delivery = { client_message_id: SecureRandom.uuid, recipient_device_id: target_device.device_id, ciphertext: Base64.strict_encode64('welcome') }
      post "/api/v1/pqc_conversations/#{second_conversation_id}/commit_member", headers: headers, params: {
        account_id: user.account_id,
        sender_device_id: sender_device.device_id,
        operation_id: SecureRandom.uuid,
        key_package_request_id: request_id,
        target_device_ids: [target_device.device_id],
        deliveries: [delivery],
      }

      expect(response).to have_http_status(422), response.body
      second_conversation = PqcConversation.find_by!(token: second_conversation_id)
      expect(second_conversation.pqc_conversation_devices.where(pqc_device_id: target_device.id)).to_not exist
      expect(second_conversation.pqc_messages.count).to eq(1)
      expect(target_device.reload.key_package_claim_conversation_id).to eq(PqcConversation.find_by!(token: conversation_id).id)
    end

    it 'does not let a non-member consume another account’s KeyPackage' do
      outsider = Fabricate(:user)
      outsider_token = Fabricate(:accessible_access_token, resource_owner_id: outsider.id, scopes: 'write:statuses')

      get '/api/v1/pqc_devices/key_packages',
          headers: { 'Authorization' => "Bearer #{outsider_token.token}" },
          params: { conversation_id:, account_id: user.account_id }

      expect(response).to have_http_status(404)
      expect(PqcDevice.find(device_id).key_package_consumed_at).to be_nil
    end

    it 'rotates a consumed KeyPackage' do
      second_device = create_test_device(user.account)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: user.account_id }
      replacement_package = 'replacement-public-key-package'.b
      patch "/api/v1/pqc_devices/#{second_device.id}/key_package", headers: headers, params: { key_package: Base64.strict_encode64(replacement_package) }
      expect(response).to have_http_status(200)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: user.account_id }
      expect(response.parsed_body).to contain_exactly(include('key_package' => Base64.strict_encode64(replacement_package)))
    end

    it 'starts revocation and blocks the device while it remains enrolled in an MLS group' do
      delete "/api/v1/pqc_devices/#{device_id}", headers: headers
      expect(response).to have_http_status(202)
      expect(PqcDevice.find(device_id).revoked_at).to be_nil
      expect(PqcDevice.find(device_id).revocation_pending_at).to be_present
      get '/api/v1/pqc_devices', headers: headers
      expect(response.parsed_body).to contain_exactly(include('device_id' => 'browser-device-1'))
    end
  end

  describe 'device request authentication', :real_device_auth do
    it 'requires and accepts a valid ML-DSA-87 proof for device revocation' do
      private_key = OpenSSL::PKey.generate_key('ML-DSA-87')
      raw_public_key = OpenSSL::ASN1.decode(private_key.public_to_der).value.last.value
      device = PqcDevice.create!(
        account: user.account,
        device_id: SecureRandom.uuid,
        fingerprint: Digest::SHA256.hexdigest(raw_public_key),
        auth_public_key: raw_public_key,
        key_package: 'test-package'.b
      )
      path = "/api/v1/pqc_devices/#{device.id}"
      delete path, headers: headers
      expect(response).to have_http_status(401)

      timestamp = Time.current.to_i.to_s
      nonce = SecureRandom.uuid
      signed_bytes = "Mastodon-PQC-Device-Auth-v1\nDELETE\n#{path}\n#{timestamp}\n#{nonce}\n#{Digest::SHA256.hexdigest('')}"
      signature = Base64.strict_encode64(private_key.sign(nil, signed_bytes))

      delete path, headers: headers.merge(
        'X-PQC-Device-ID' => device.device_id,
        'X-PQC-Device-Timestamp' => timestamp,
        'X-PQC-Device-Nonce' => nonce,
        'X-PQC-Device-Signature' => signature
      )

      expect(response).to have_http_status(200), response.body
      expect(device.reload.revoked_at).to be_present
    end

    it 'requires device proof before accepting a conversation invitation' do
      participant = Fabricate(:user)
      private_key = OpenSSL::PKey.generate_key('ML-DSA-87')
      raw_public_key = OpenSSL::ASN1.decode(private_key.public_to_der).value.last.value
      device = PqcDevice.create!(
        account: participant.account,
        device_id: SecureRandom.uuid,
        fingerprint: Digest::SHA256.hexdigest(raw_public_key),
        auth_public_key: raw_public_key,
        key_package: 'test-package'.b
      )
      conversation = PqcConversation.create!(creator_account: user.account)
      conversation.pqc_conversation_members.create!(account: user.account, invitation_status: :accepted)
      conversation.pqc_conversation_members.create!(account: participant.account, invitation_status: :invited)
      token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
      request_path = "/api/v1/pqc_conversations/#{conversation.token}/accept_invitation"
      request_headers = { 'Authorization' => "Bearer #{token.token}" }

      post request_path, headers: request_headers, params: {}, as: :json
      expect(response).to have_http_status(401)
      expect(conversation.pqc_conversation_members.find_by!(account: participant.account)).to be_invited

      timestamp = Time.current.to_i.to_s
      nonce = SecureRandom.uuid
      signed_bytes = "Mastodon-PQC-Device-Auth-v1\nPOST\n#{request_path}\n#{timestamp}\n#{nonce}\n#{Digest::SHA256.hexdigest('{}')}"
      signature = Base64.strict_encode64(private_key.sign(nil, signed_bytes))
      post request_path, headers: request_headers.merge(
        'X-PQC-Device-ID' => device.device_id,
        'X-PQC-Device-Timestamp' => timestamp,
        'X-PQC-Device-Nonce' => nonce,
        'X-PQC-Device-Signature' => signature
      ), params: {}, as: :json

      expect(response).to have_http_status(200), response.body
      expect(conversation.pqc_conversation_members.find_by!(account: participant.account)).to be_accepted
    end
  end

  describe 'opaque conversation relay' do
    it 'shows pending invitation metadata without exposing messages or KeyPackages' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      recipient_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)
      PqcConversation.find_by!(token: conversation_id).pqc_conversation_members.find_by!(account_id: participant.account_id).update!(invitation_status: :invited)

      participant_token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
      participant_headers = { 'Authorization' => "Bearer #{participant_token.token}" }
      get '/api/v1/pqc_conversations', headers: participant_headers
      expect(response.parsed_body).to contain_exactly(include('id' => conversation_id, 'my_invitation_status' => 'invited'))
      get "/api/v1/pqc_conversations/#{conversation_id}", headers: participant_headers
      expect(response).to have_http_status(200)
      get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: participant_headers, params: { device_id: recipient_device.device_id }
      expect(response).to have_http_status(404)
      get '/api/v1/pqc_devices/key_packages', headers: participant_headers, params: { conversation_id:, account_id: participant.account_id }
      expect(response).to have_http_status(404)
      expect(recipient_device.reload.key_package_consumed_at).to be_nil
    end

    # rubocop:disable-next RSpec/ExampleLength
    it 'requires invite acceptance before publishing invitee KeyPackages or activating membership' do
      participant = Fabricate(:user)
      creator_device = create_test_device(user.account)
      recipient_device = create_test_device(participant.account)
      post '/api/v1/pqc_conversations', headers: headers, params: { account_ids: [participant.account_id], setup_device_id: creator_device.device_id }
      conversation_id = response.parsed_body.fetch('id')
      expect(response.parsed_body.fetch('member_account_ids')).to eq([user.account_id.to_s])
      expect(response.parsed_body.fetch('invited_account_ids')).to eq([participant.account_id.to_s])

      setup_delivery = { client_message_id: SecureRandom.uuid, recipient_device_id: recipient_device.device_id, ciphertext: Base64.strict_encode64('welcome') }
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: creator_device.device_id, deliveries: [setup_delivery] }
      expect(response).to have_http_status(422)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: participant.account_id }
      expect(response).to have_http_status(404)

      participant_token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
      participant_headers = { 'Authorization' => "Bearer #{participant_token.token}" }
      post "/api/v1/pqc_conversations/#{conversation_id}/accept_invitation", headers: participant_headers
      expect(response).to have_http_status(200)
      expect(response.parsed_body.fetch('my_invitation_status')).to eq('accepted')
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: participant.account_id }
      expect(response.parsed_body).to contain_exactly(include('device_id' => recipient_device.device_id))

      final_setup_deliveries = [creator_device, recipient_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64(device == creator_device ? 'commit' : 'welcome') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: creator_device.device_id, deliveries: final_setup_deliveries }
      expect(response).to have_http_status(201)
    end

    it 'lets an invitee decline and excludes the account from the activated group' do
      participant = Fabricate(:user)
      creator_device = create_test_device(user.account)
      create_test_device(participant.account)
      post '/api/v1/pqc_conversations', headers: headers, params: { account_ids: [participant.account_id], setup_device_id: creator_device.device_id }
      conversation_id = response.parsed_body.fetch('id')
      participant_token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
      participant_headers = { 'Authorization' => "Bearer #{participant_token.token}" }

      post "/api/v1/pqc_conversations/#{conversation_id}/decline_invitation", headers: participant_headers
      expect(response).to have_http_status(200)
      expect(response.parsed_body.fetch('my_invitation_status')).to eq('declined')
      setup_delivery = { client_message_id: SecureRandom.uuid, recipient_device_id: creator_device.device_id, ciphertext: Base64.strict_encode64('commit') }
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: creator_device.device_id, deliveries: [setup_delivery] }
      expect(response).to have_http_status(201)
      expect(response.parsed_body.dig('conversation', 'member_account_ids')).to eq([user.account_id.to_s])
      get "/api/v1/pqc_conversations/#{conversation_id}", headers: participant_headers
      expect(response).to have_http_status(404)
    end

    it 'does not expose an active group invitation until it is accepted' do
      participant = Fabricate(:user)
      conversation_id = create_conversation(user.account_id)
      invitee_device = create_test_device(participant.account)
      participant_headers = invite_to_active_conversation(conversation_id, participant)

      get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: participant_headers, params: { device_id: invitee_device.device_id }
      expect(response).to have_http_status(404)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: participant.account_id }
      expect(response).to have_http_status(404)
      expect(invitee_device.reload.key_package_consumed_at).to be_nil
    end

    it 'restricts stateful KeyPackage claims to the conversation creator' do
      participant = Fabricate(:user)
      creator_device = create_test_device(user.account)
      participant_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], creator_device)
      deliveries = [creator_device, participant_device].map do |member_device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: member_device.device_id, ciphertext: Base64.strict_encode64('setup') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: creator_device.device_id, deliveries: }
      expect(response).to have_http_status(201)

      added_device = create_test_device(participant.account)
      participant_token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
      participant_headers = { 'Authorization' => "Bearer #{participant_token.token}" }
      get '/api/v1/pqc_devices/key_packages', headers: participant_headers, params: { conversation_id:, account_id: participant.account_id, request_id: SecureRandom.uuid }

      expect(response).to have_http_status(404)
      expect(added_device.reload.key_package_consumed_at).to be_nil
    end

    it 'joins an accepted active invite only after the Welcome commit is stored' do
      participant = Fabricate(:user)
      conversation_id = create_conversation(user.account_id)
      invitee_device = create_test_device(participant.account)
      participant_headers = invite_to_active_conversation(conversation_id, participant)

      post "/api/v1/pqc_conversations/#{conversation_id}/accept_invitation", headers: participant_headers
      expect(response).to have_http_status(200)
      expect(response.parsed_body.fetch('pending_addition_account_ids')).to contain_exactly(participant.account_id.to_s)
      expect(response.parsed_body.fetch('member_account_ids')).to contain_exactly(user.account_id.to_s)
      get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: participant_headers, params: { device_id: invitee_device.device_id }
      expect(response).to have_http_status(404)
      creator_device = PqcDevice.find_by!(device_id: PqcConversation.find_by!(token: conversation_id).setup_device_id)
      key_package_request_id = SecureRandom.uuid
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: participant.account_id, request_id: key_package_request_id }
      expect(response.parsed_body).to contain_exactly(include('device_id' => invitee_device.device_id))
      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: {
        account_id: participant.account_id,
        sender_device_id: creator_device.device_id,
        operation_id: SecureRandom.uuid,
        key_package_request_id:,
        target_device_ids: [invitee_device.device_id],
        deliveries: [{ client_message_id: SecureRandom.uuid, recipient_device_id: invitee_device.device_id, ciphertext: Base64.strict_encode64('welcome') }],
      }
      expect(response).to have_http_status(201), response.body
      expect(response.parsed_body.dig('conversation', 'member_account_ids')).to contain_exactly(user.account_id.to_s, participant.account_id.to_s)
      get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: participant_headers, params: { device_id: invitee_device.device_id }
      expect(response).to have_http_status(200)
      expect(response.parsed_body).to contain_exactly(include('ciphertext' => Base64.strict_encode64('welcome')))
    end

    it 'activates initial membership and stores all setup deliveries atomically' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      recipient_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)
      deliveries = [
        { client_message_id: SecureRandom.uuid, recipient_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('commit') },
        { client_message_id: SecureRandom.uuid, recipient_device_id: recipient_device.device_id, ciphertext: Base64.strict_encode64('welcome') },
      ]
      params = { sender_device_id: sender_device.device_id, deliveries: }
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: params
      expect(response).to have_http_status(201)
      expect(response.parsed_body.dig('conversation', 'ready_at')).to be_present
      expect(response.parsed_body.fetch('message_ids').size).to eq(2)
      expect(response.parsed_body.dig('conversation', 'joined_device_ids')).to contain_exactly(sender_device.device_id, recipient_device.device_id)
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id)).count).to eq(2)

      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: params
      expect(response).to have_http_status(200)
      expect(response.parsed_body.fetch('message_ids').size).to eq(2)
    end

    it 'rejects empty initial setup deliveries' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)

      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: [] }

      expect(response).to have_http_status(422)
      expect(PqcConversation.find_by!(token: conversation_id).ready_at).to be_nil
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id))).to be_empty
    end

    it 'activates initial setup after every other active member device receives a protocol delivery' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      recipient_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)

      deliveries = [{ client_message_id: SecureRandom.uuid, recipient_device_id: recipient_device.device_id, ciphertext: Base64.strict_encode64('welcome') }]
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: }

      expect(response).to have_http_status(201), response.body
      expect(response.parsed_body.dig('conversation', 'ready_at')).to be_present
      expect(response.parsed_body.dig('conversation', 'joined_device_ids')).to contain_exactly(sender_device.device_id, recipient_device.device_id)
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id)).pluck(:recipient_device_id)).to eq([recipient_device.device_id])
    end

    it 'rejects duplicate setup deliveries to one device when another device is missing' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      recipient_device = create_test_device(participant.account)
      create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)
      deliveries = Array.new(2) do
        { client_message_id: SecureRandom.uuid, recipient_device_id: recipient_device.device_id, ciphertext: Base64.strict_encode64('welcome') }
      end

      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: }

      expect(response).to have_http_status(422)
      expect(PqcConversation.find_by!(token: conversation_id).ready_at).to be_nil
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id))).to be_empty
    end

    it 'binds pending setup to the browser device that created the group' do
      setup_device = create_test_device(user.account)
      other_device = create_test_device(user.account)
      conversation_id = create_pending_conversation([user.account_id], setup_device)

      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: other_device.device_id, deliveries: [] }

      expect(response).to have_http_status(422)
      expect(PqcConversation.find_by!(token: conversation_id).ready_at).to be_nil
    end

    it 'removes a member and delivers the MLS removal commit to every remaining device atomically' do
      removed_account = Fabricate(:user)
      remaining_account = Fabricate(:user)
      sender_device = create_test_device(user.account)
      removed_device = create_test_device(removed_account.account)
      remaining_device = create_test_device(remaining_account.account)
      conversation_id = create_pending_conversation([removed_account.account_id, remaining_account.account_id], sender_device)
      setup_deliveries = [sender_device, removed_device, remaining_device].map { |device| { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('setup') } }
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201)
      deliveries = [{ client_message_id: SecureRandom.uuid, recipient_device_id: remaining_device.device_id, ciphertext: Base64.strict_encode64('remove commit') }]
      params = { account_id: removed_account.account_id, sender_device_id: sender_device.device_id, operation_id: SecureRandom.uuid, deliveries: }

      post "/api/v1/pqc_conversations/#{conversation_id}/remove_member", headers: headers, params: params

      expect(response).to have_http_status(201)
      expect(response.parsed_body.dig('conversation', 'member_account_ids')).to_not include(removed_account.account_id.to_s)
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id), client_message_id: deliveries.pluck(:client_message_id)).pluck(:recipient_device_id)).to eq([remaining_device.device_id])
      expect(PqcDevice.find(removed_device.id).revoked_at).to be_nil

      post "/api/v1/pqc_conversations/#{conversation_id}/remove_member", headers: headers, params: params
      expect(response).to have_http_status(200)
      get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: { 'Authorization' => "Bearer #{Fabricate(:accessible_access_token, resource_owner_id: removed_account.id, scopes: 'write:statuses').token}" }, params: { device_id: removed_device.device_id }
      expect(response).to have_http_status(404)
    end

    # rubocop:disable-next RSpec/ExampleLength
    # rubocop:disable-next RSpec/MultipleExpectations
    it 'blocks relay use immediately and finalizes revocation after MLS device removal' do
      sender_device = create_test_device(user.account)
      target_device = create_test_device(user.account)
      remaining_account = Fabricate(:user)
      remaining_device = create_test_device(remaining_account.account)
      conversation_id = create_pending_conversation([remaining_account.account_id], sender_device)
      setup_deliveries = [sender_device, target_device, remaining_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('setup') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201)

      delete "/api/v1/pqc_devices/#{target_device.id}", headers: headers.merge('X-PQC-Device-ID' => sender_device.device_id)
      expect(response).to have_http_status(202)
      expect(target_device.reload.revoked_at).to be_nil
      expect(target_device.revocation_pending_at).to be_present
      get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: headers, params: { device_id: target_device.device_id }
      expect(response).to have_http_status(404)

      deliveries = [{ client_message_id: SecureRandom.uuid, recipient_device_id: remaining_device.device_id, ciphertext: Base64.strict_encode64('device removal commit') }]
      removal_params = {
        target_device_id: target_device.device_id,
        sender_device_id: sender_device.device_id,
        operation_id: SecureRandom.uuid,
        deliveries:,
      }
      post "/api/v1/pqc_conversations/#{conversation_id}/remove_device", headers: headers, params: removal_params

      expect(response).to have_http_status(201), response.body
      expect(response.parsed_body.dig('conversation', 'joined_device_ids')).to contain_exactly(sender_device.device_id, remaining_device.device_id)
      message_ids = response.parsed_body.fetch('message_ids')
      post "/api/v1/pqc_conversations/#{conversation_id}/remove_device", headers: headers, params: removal_params
      expect(response).to have_http_status(200), response.body
      expect(response.parsed_body.fetch('message_ids')).to eq(message_ids)
      expect(target_device.reload.revoked_at).to be_present

      delete "/api/v1/pqc_devices/#{target_device.id}", headers: headers.merge('X-PQC-Device-ID' => sender_device.device_id)
      expect(response).to have_http_status(200)
      expect(target_device.reload.revoked_at).to be_present
    end

    it 'rolls back member removal when a remaining active device would miss the commit' do
      removed_account = Fabricate(:user)
      remaining_account = Fabricate(:user)
      sender_device = create_test_device(user.account)
      removed_device = create_test_device(removed_account.account)
      remaining_device = create_test_device(remaining_account.account)
      conversation_id = create_pending_conversation([removed_account.account_id, remaining_account.account_id], sender_device)
      setup_deliveries = [sender_device, removed_device, remaining_device].map { |device| { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('setup') } }
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      params = { account_id: removed_account.account_id, sender_device_id: sender_device.device_id, operation_id: SecureRandom.uuid, deliveries: [] }

      post "/api/v1/pqc_conversations/#{conversation_id}/remove_member", headers: headers, params: params

      expect(response).to have_http_status(422)
      expect(PqcConversation.find_by!(token: conversation_id).accounts).to include(removed_account.account)
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id)).count).to eq(setup_deliveries.size)
    end

    it 'records idempotency for removal when no remaining recipient devices need the commit' do
      removed_account = Fabricate(:user)
      sender_device = create_test_device(user.account)
      removed_device = create_test_device(removed_account.account)
      conversation_id = create_pending_conversation([removed_account.account_id], sender_device)
      setup_deliveries = [sender_device, removed_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('setup') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      params = { account_id: removed_account.account_id, sender_device_id: sender_device.device_id, operation_id: SecureRandom.uuid, deliveries: [] }

      post "/api/v1/pqc_conversations/#{conversation_id}/remove_member", headers: headers, params: params
      expect(response).to have_http_status(201)
      post "/api/v1/pqc_conversations/#{conversation_id}/remove_member", headers: headers, params: params
      expect(response).to have_http_status(200)
      post "/api/v1/pqc_conversations/#{conversation_id}/remove_member", headers: headers, params: params.merge(operation_id: SecureRandom.uuid)
      expect(response).to have_http_status(422)
    end

    describe 'participant departure' do
      let(:participant) { Fabricate(:user) }
      let(:second_participant) { Fabricate(:user) }
      let(:creator_device) { create_test_device(user.account) }
      let(:participant_device) { create_test_device(participant.account) }
      let(:second_device) { create_test_device(second_participant.account) }
      let(:conversation_id) do
        id = create_pending_conversation([participant.account_id, second_participant.account_id], creator_device)
        devices = [creator_device, participant_device, second_device]
        deliveries = devices.map { |device| { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('setup') } }
        post "/api/v1/pqc_conversations/#{id}/complete_setup", headers: headers, params: { sender_device_id: creator_device.device_id, deliveries: }
        id
      end
      let(:participant_headers) do
        token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
        { 'Authorization' => "Bearer #{token.token}" }
      end
      let(:second_headers) do
        token = Fabricate(:accessible_access_token, resource_owner_id: second_participant.id, scopes: 'write:statuses')
        { 'Authorization' => "Bearer #{token.token}" }
      end

      it 'records the departure request without removing MLS membership' do
        id = conversation_id
        expect(response).to have_http_status(201)
        post "/api/v1/pqc_conversations/#{id}/request_leave", headers: participant_headers
        expect(response).to have_http_status(200)
        expect(response.parsed_body.fetch('leave_requested_account_ids')).to include(participant.account_id.to_s)
        expect(response.parsed_body.fetch('member_account_ids')).to include(participant.account_id.to_s)

        post "/api/v1/pqc_conversations/#{id}/request_leave", headers: headers
        expect(response).to have_http_status(422)
      end

      it 'does not let a non-creator remove a member without that member requesting departure' do
        id = conversation_id
        expect(response).to have_http_status(201)
        params = {
          account_id: participant.account_id,
          sender_device_id: second_device.device_id,
          operation_id: SecureRandom.uuid,
          deliveries: [],
        }

        post "/api/v1/pqc_conversations/#{id}/remove_member", headers: second_headers, params: params
        expect(response).to have_http_status(422)
        expect(PqcConversation.find_by!(token: id).accounts).to include(participant.account)
      end

      it 'allows another member to commit the requested removal and retry idempotently' do
        id = conversation_id
        expect(response).to have_http_status(201)
        post "/api/v1/pqc_conversations/#{id}/request_leave", headers: participant_headers
        params = {
          account_id: participant.account_id,
          sender_device_id: second_device.device_id,
          operation_id: SecureRandom.uuid,
          deliveries: [{ client_message_id: SecureRandom.uuid, recipient_device_id: creator_device.device_id, ciphertext: Base64.strict_encode64('departure commit') }],
        }

        post "/api/v1/pqc_conversations/#{id}/remove_member", headers: second_headers, params: params
        expect(response).to have_http_status(201)
        expect(response.parsed_body.dig('conversation', 'member_account_ids')).to_not include(participant.account_id.to_s)

        post "/api/v1/pqc_conversations/#{id}/remove_member", headers: second_headers, params: params
        expect(response).to have_http_status(200)
      end
    end

    it 'rolls back group activation when any initial delivery target is invalid' do
      sender_device = PqcDevice.create!(account: user.account, device_id: SecureRandom.uuid, fingerprint: 'a' * 64, key_package: 'sender-package'.b)
      post '/api/v1/pqc_conversations', headers: headers, params: { account_ids: [user.account_id], setup_device_id: sender_device.device_id }
      conversation_id = response.parsed_body.fetch('id')
      params = {
        sender_device_id: sender_device.device_id,
        deliveries: [
          { client_message_id: SecureRandom.uuid, recipient_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('valid') },
          { client_message_id: SecureRandom.uuid, recipient_device_id: 'unknown-device', ciphertext: Base64.strict_encode64('invalid') },
        ],
      }

      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: params

      expect(response).to have_http_status(422)
      expect(PqcConversation.find_by!(token: conversation_id).ready_at).to be_nil
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id))).to be_empty
    end

    # This example exercises the full invitation, claim, commit, and retry contract.
    # rubocop:disable-next RSpec/ExampleLength, RSpec/MultipleExpectations
    it 'atomically adds a local member and stores the ordered encrypted Welcome and commit deliveries' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      existing_member_device = create_test_device(user.account)
      conversation_id = create_pending_conversation([user.account_id], sender_device)
      setup_deliveries = [sender_device, existing_member_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('initial commit') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201)
      welcome_device = PqcDevice.create!(account: participant.account, device_id: SecureRandom.uuid, fingerprint: 'f' * 64, key_package: 'welcome-package'.b)
      deliveries = [
        { client_message_id: SecureRandom.uuid, recipient_device_id: existing_member_device.device_id, ciphertext: Base64.strict_encode64('commit') },
        { client_message_id: SecureRandom.uuid, recipient_device_id: welcome_device.device_id, ciphertext: Base64.strict_encode64('welcome') },
      ]
      request_id = SecureRandom.uuid
      params = { account_id: participant.account_id, sender_device_id: sender_device.device_id, operation_id: SecureRandom.uuid, key_package_request_id: request_id, target_device_ids: [welcome_device.device_id], deliveries: }

      invite_and_accept_member(conversation_id, participant)
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: { conversation_id:, account_id: participant.account_id, request_id: }
      expect(response.parsed_body).to contain_exactly(include('device_id' => welcome_device.device_id))

      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: params
      expect(response).to have_http_status(201)
      expect(response.parsed_body.fetch('conversation').fetch('member_account_ids')).to contain_exactly(user.account_id.to_s, participant.account_id.to_s)
      expect(response.parsed_body.fetch('message_ids')).to have_attributes(size: 2)
      committed_messages = PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id), client_message_id: deliveries.pluck(:client_message_id))
      expect(committed_messages.order(:id).pluck(:ciphertext, :recipient_device_id)).to eq(
        [
          ['commit'.b, existing_member_device.device_id],
          ['welcome'.b, welcome_device.device_id],
        ]
      )

      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: params
      expect(response).to have_http_status(200)
      expect(PqcConversationMember.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id)).count).to eq(2)
      expect(committed_messages.count).to eq(2)
      expect(PqcConversation.find_by!(token: conversation_id).pqc_conversation_devices.joins(:pqc_device).pluck('pqc_devices.device_id')).to contain_exactly(sender_device.device_id, existing_member_device.device_id, welcome_device.device_id)

      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: params.merge(key_package_request_id: SecureRandom.uuid)
      expect(response).to have_http_status(409), response.body
    end

    # This example verifies an additional device joining an existing MLS member.
    # rubocop:disable-next RSpec/ExampleLength
    it 'adds a second device to an existing member using a claimed KeyPackage and retries idempotently' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      joined_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)
      setup_deliveries = [sender_device, joined_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('initial commit') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201)
      expect(response.parsed_body.dig('conversation', 'joined_device_ids')).to contain_exactly(sender_device.device_id, joined_device.device_id)

      added_device = create_test_device(participant.account)
      operation_id = SecureRandom.uuid
      key_package_request_id = SecureRandom.uuid
      get '/api/v1/pqc_devices/key_packages', headers: headers, params: {
        conversation_id:,
        account_id: participant.account_id,
        request_id: key_package_request_id,
      }
      expect(response.parsed_body).to contain_exactly(include('device_id' => added_device.device_id))

      deliveries = [joined_device, added_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64("add device #{device.device_id}") }
      end
      params = {
        account_id: participant.account_id,
        sender_device_id: sender_device.device_id,
        operation_id:,
        key_package_request_id:,
        target_device_ids: [added_device.device_id],
        deliveries:,
      }

      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: params
      expect(response).to have_http_status(201), response.body
      expect(response.parsed_body.dig('conversation', 'joined_device_ids')).to contain_exactly(sender_device.device_id, joined_device.device_id, added_device.device_id)
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id), client_message_id: deliveries.pluck(:client_message_id)).count).to eq(2)

      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: params
      expect(response).to have_http_status(200), response.body
      expect(response.parsed_body.fetch('message_ids').size).to eq(2)
      expect(PqcConversation.find_by!(token: conversation_id).pqc_conversation_devices.count).to eq(3)
    end

    it 'rolls back membership and all deliveries if one target device is invalid' do
      participant = Fabricate(:user)
      conversation_id = create_conversation(user.account_id)
      sender_device = PqcDevice.find_by!(device_id: PqcConversation.find_by!(token: conversation_id).setup_device_id)
      params = {
        account_id: participant.account_id,
        sender_device_id: sender_device.device_id,
        operation_id: SecureRandom.uuid,
        key_package_request_id: SecureRandom.uuid,
        target_device_ids: ['revoked-or-unknown'],
        deliveries: [
          { client_message_id: SecureRandom.uuid, recipient_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('commit') },
          { client_message_id: SecureRandom.uuid, recipient_device_id: 'revoked-or-unknown', ciphertext: Base64.strict_encode64('welcome') },
        ],
      }

      invite_and_accept_member(conversation_id, participant)

      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member", headers: headers, params: params

      expect(response).to have_http_status(422)
      membership = PqcConversation.find_by!(token: conversation_id).pqc_conversation_members.find_by!(account_id: participant.account_id)
      expect(membership).to be_accepted
      expect(membership.joined_at).to be_nil
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id)).count).to eq(1)
    end

    it 'does not let another member add accounts' do
      participant = Fabricate(:user)
      another = Fabricate(:user)
      conversation_id = create_conversation(participant.account_id)
      token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')

      post "/api/v1/pqc_conversations/#{conversation_id}/invite_member", headers: headers, params: { account_id: another.account_id }
      another_token = Fabricate(:accessible_access_token, resource_owner_id: another.id, scopes: 'write:statuses')
      create_test_device(another.account)
      post "/api/v1/pqc_conversations/#{conversation_id}/accept_invitation", headers: { 'Authorization' => "Bearer #{another_token.token}" }

      sender_device = PqcDevice.create!(account: participant.account, device_id: SecureRandom.uuid, fingerprint: '2' * 64, key_package: 'sender-package'.b)
      post "/api/v1/pqc_conversations/#{conversation_id}/commit_member",
           headers: { 'Authorization' => "Bearer #{token.token}" },
           params: {
             account_id: another.account_id,
             sender_device_id: sender_device.device_id,
             operation_id: SecureRandom.uuid,
             key_package_request_id: SecureRandom.uuid,
             target_device_ids: [sender_device.device_id],
             deliveries: [{ client_message_id: SecureRandom.uuid, recipient_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('commit') }],
           }

      expect(response).to have_http_status(422)
      membership = PqcConversation.find_by!(token: conversation_id).pqc_conversation_members.find_by!(account_id: another.account_id)
      expect(membership).to be_accepted
      expect(membership.joined_at).to be_nil
    end

    it 'accepts ordered setup commits addressed more than once to an already-added member device' do
      participant = Fabricate(:user)
      sender_device = create_test_device(user.account)
      creator_second_device = create_test_device(user.account)
      participant_device = create_test_device(participant.account)
      participant_second_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)
      deliveries = [
        [creator_second_device, 'welcome for creator device'],
        [participant_device, 'welcome for first participant device'],
        [creator_second_device, 'commit after first participant device'],
        [participant_device, 'commit after second participant device'],
        [participant_second_device, 'welcome for second participant device'],
      ].map do |device, ciphertext|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64(ciphertext) }
      end

      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: }

      expect(response).to have_http_status(201), response.body
      expect(response.parsed_body.fetch('message_ids')).to have_attributes(size: deliveries.size)
      expect(PqcConversation.find_by!(token: conversation_id).ready_at).to be_present
      expect(PqcMessage.where(pqc_conversation: PqcConversation.find_by!(token: conversation_id)).order(:id).pluck(:recipient_device_id, :ciphertext)).to eq(
        [
          [creator_second_device.device_id, 'welcome for creator device'.b],
          [participant_device.device_id, 'welcome for first participant device'.b],
          [creator_second_device.device_id, 'commit after first participant device'.b],
          [participant_device.device_id, 'commit after second participant device'.b],
          [participant_second_device.device_id, 'welcome for second participant device'.b],
        ]
      )
    end

    # This example checks setup enrollment and separate per-device ciphertext visibility.
    # rubocop:disable-next RSpec/ExampleLength
    it 'delivers ciphertext only to authorized conversation members' do
      participant = Fabricate(:user)
      outsider = Fabricate(:user)
      sender_device = create_test_device(user.account)
      participant_device = create_test_device(participant.account)
      participant_second_device = create_test_device(participant.account)
      conversation_id = create_pending_conversation([participant.account_id], sender_device)
      setup_deliveries = [sender_device, participant_device, participant_second_device].map do |device|
        { client_message_id: SecureRandom.uuid, recipient_device_id: device.device_id, ciphertext: Base64.strict_encode64('initial commit') }
      end
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: setup_deliveries }
      expect(response).to have_http_status(201)
      ciphertext = SecureRandom.random_bytes(128)
      message_id = send_message(conversation_id, sender_device.device_id, ciphertext)

      targeted_ciphertext = SecureRandom.random_bytes(64)
      send_message(conversation_id, sender_device.device_id, targeted_ciphertext, participant_device.device_id)
      second_device_ciphertext = SecureRandom.random_bytes(32)
      send_message(conversation_id, sender_device.device_id, second_device_ciphertext, participant_second_device.device_id)
      expect(PqcMessage.order(:id).last(2).pluck(:recipient_device_id)).to contain_exactly(participant_device.device_id, participant_second_device.device_id)
      expect_authorized_delivery(conversation_id, participant, participant_device, participant_second_device, ciphertext, targeted_ciphertext, second_device_ciphertext)
      expect_outsider_denied(conversation_id, outsider)
      expect(PqcMessage.find(message_id).ciphertext).to eq(ciphertext)
    end

    it 'returns the original relay message when a client retries the same message ID' do
      sender_device = create_test_device(user.account)
      conversation_id = create_pending_conversation([user.account_id], sender_device)
      setup_delivery = { client_message_id: SecureRandom.uuid, recipient_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('setup') }
      post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: sender_device.device_id, deliveries: [setup_delivery] }
      expect(response).to have_http_status(201)
      message_id = SecureRandom.uuid
      params = { sender_device_id: sender_device.device_id, ciphertext: Base64.strict_encode64('opaque payload'), client_message_id: message_id }

      post "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: headers, params: params
      expect(response).to have_http_status(201)
      first_id = response.parsed_body.fetch('id')

      post "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: headers, params: params
      expect(response).to have_http_status(200)
      expect(response.parsed_body.fetch('id')).to eq(first_id)
      expect(PqcMessage.where(client_message_id: message_id).count).to eq(1)

      post "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: headers, params: params.merge(ciphertext: Base64.strict_encode64('different payload'))
      expect(response).to have_http_status(409)
    end

    it 'hides the experimental endpoints when the feature flag is disabled' do
      ClimateControl.modify(PQC_E2EE_EXPERIMENTAL: 'false') do
        get '/api/v1/pqc_devices', headers: headers
      end

      expect(response).to have_http_status(404)
    end
  end

  def create_conversation(account_id)
    setup_device = create_test_device(user.account)
    conversation_id = create_pending_conversation([account_id], setup_device)
    setup_delivery = { client_message_id: SecureRandom.uuid, recipient_device_id: setup_device.device_id, ciphertext: Base64.strict_encode64('commit') }
    post "/api/v1/pqc_conversations/#{conversation_id}/complete_setup", headers: headers, params: { sender_device_id: setup_device.device_id, deliveries: [setup_delivery] }
    expect(response).to have_http_status(201), response.body
    conversation_id
  end

  def create_pending_conversation(account_ids, setup_device)
    post '/api/v1/pqc_conversations', headers: headers, params: { account_ids:, setup_device_id: setup_device.device_id }
    expect(response).to have_http_status(201), response.body
    expect(response.parsed_body.fetch('ready_at')).to be_nil
    conversation_id = response.parsed_body.fetch('id')
    PqcConversation.find_by!(token: conversation_id).pqc_conversation_members.where.not(account_id: user.account_id).update_all(invitation_status: 'accepted')
    conversation_id
  end

  def create_test_device(account)
    auth_public_key = '0'.b * Pqc::Messaging::DeviceRequestAuthenticator::PUBLIC_KEY_BYTES
    PqcDevice.create!(account:, device_id: SecureRandom.uuid, fingerprint: Digest::SHA256.hexdigest(auth_public_key), auth_public_key:, key_package: 'test-package'.b)
  end

  def invite_and_accept_member(conversation_id, participant)
    create_test_device(participant.account) unless PqcDevice.active.exists?(account: participant.account)
    post "/api/v1/pqc_conversations/#{conversation_id}/invite_member", headers: headers, params: { account_id: participant.account_id }
    expect(response).to have_http_status(201), response.body
    token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
    post "/api/v1/pqc_conversations/#{conversation_id}/accept_invitation", headers: { 'Authorization' => "Bearer #{token.token}" }
    expect(response).to have_http_status(200), response.body
  end

  def invite_to_active_conversation(conversation_id, participant)
    post "/api/v1/pqc_conversations/#{conversation_id}/invite_member", headers: headers, params: { account_id: participant.account_id }
    expect(response).to have_http_status(201), response.body
    token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
    { 'Authorization' => "Bearer #{token.token}" }
  end

  def send_message(conversation_id, sender_device_id, ciphertext, recipient_device_id = nil)
    post "/api/v1/pqc_conversations/#{conversation_id}/messages",
         headers: headers,
         params: { sender_device_id:, ciphertext: Base64.strict_encode64(ciphertext), recipient_device_id: }
    expect(response).to have_http_status(201), response.body

    response.parsed_body.fetch('id')
  end

  def expect_authorized_delivery(conversation_id, participant, participant_device, participant_second_device, ciphertext, targeted_ciphertext, second_device_ciphertext)
    get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: headers, params: { device_id: PqcConversation.find_by!(token: conversation_id).pqc_conversation_devices.joins(:pqc_device).merge(PqcDevice.where(account: user.account)).pick('pqc_devices.device_id') }
    expect(response.parsed_body).to contain_exactly(
      include('ciphertext' => Base64.strict_encode64('initial commit')),
      include('ciphertext' => Base64.strict_encode64(ciphertext))
    )

    token = Fabricate(:accessible_access_token, resource_owner_id: participant.id, scopes: 'write:statuses')
    participant_headers = { 'Authorization' => "Bearer #{token.token}" }
    get '/api/v1/pqc_devices', headers: participant_headers
    expect(response.parsed_body).to contain_exactly(include('device_id' => participant_device.device_id), include('device_id' => participant_second_device.device_id))
    get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: participant_headers, params: { device_id: participant_device.device_id }
    expect(response.parsed_body).to contain_exactly(
      include('ciphertext' => Base64.strict_encode64('initial commit')),
      include('ciphertext' => Base64.strict_encode64(ciphertext)),
      include('ciphertext' => Base64.strict_encode64(targeted_ciphertext), 'recipient_device_id' => participant_device.device_id)
    )
    get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: participant_headers, params: { device_id: participant_second_device.device_id }
    expect(response.parsed_body).to contain_exactly(
      include('ciphertext' => Base64.strict_encode64('initial commit')),
      include('ciphertext' => Base64.strict_encode64(ciphertext)),
      include('ciphertext' => Base64.strict_encode64(second_device_ciphertext), 'recipient_device_id' => participant_second_device.device_id)
    )
  end

  def expect_outsider_denied(conversation_id, outsider)
    token = Fabricate(:accessible_access_token, resource_owner_id: outsider.id, scopes: 'write:statuses')
    get "/api/v1/pqc_conversations/#{conversation_id}/messages", headers: { 'Authorization' => "Bearer #{token.token}" }, params: { device_id: PqcDevice.active.where(account: outsider).pick(:device_id) || 'unknown-device' }
    expect(response).to have_http_status(404)
  end
end
