# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'ML-DSA ActivityPub federation' do
  include PqcKeyProvisioningHelpers

  let(:origin) { Fabricate(:account, username: 'pqc_origin') }
  let(:relay_signer) { Fabricate(:account, username: 'pqc_relay') }
  let(:recipient) { Fabricate(:account, username: 'pqc_recipient') }
  let(:destination) { Fabricate(:remote_account, username: recipient.username, domain: 'receiver.example', uri: 'https://receiver.example/users/pqc_recipient', inbox_url: receiver_inbox, shared_inbox_url: '', protocol: :activitypub) }
  let(:receiver_inbox) { 'https://receiver.example/users/pqc_recipient/inbox' }
  let(:original) { Fabricate(:status, account: origin, text: 'Native ML-DSA: café 🔐', visibility: :public) }
  let(:actor_documents) { {} }

  around do |example|
    ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true', AUTHORIZED_FETCH: 'false') do
      on_instance('receiver.example') { example.run }
    end
  end

  before do
    generate_real_ml_dsa_44_key
    on_instance('sender.example') do
      ActivityPub::GeneratePqcKeyService.new.call(origin)
      publish_actor(origin)
      destination.follow!(origin)
    end
    on_instance('relay.example') { publish_actor(relay_signer) }
    recipient

    # Only the transport is simulated. The exact DeliveryWorker HTTP body and
    # headers enter the real inbox controller and its signature verification.
    stub_request(:post, receiver_inbox).to_return do |request|
      on_instance('receiver.example') do
        post URI(receiver_inbox).path, params: request.body, headers: request.headers
        { status: response.status, body: response.body, headers: response.headers }
      end
    end
  end

  it 'discovers published Multikeys and accepts a real dual-signed Create through the inbox' do
    secured = distribute(original)
    expect(Keypair.find_by(uri: secured.dig('proof', 'verificationMethod'))).to be_nil
    # Sender and receiver share this test database; remove the sender row after
    # serializing so it cannot be mistaken for the receiver's copy.
    original.delete
    deliver(secured)

    received = Status.find_by!(uri: secured.dig('object', 'id'))
    expect(received.text).to include('Native ML-DSA: café 🔐')
    expect(received.account).to be_remote
    expect(received.account.domain).to eq('sender.example')
    expect_published_key_verifies(secured, received.account)
    expect(ActivityPub::LinkedDataSignature.new(secured).verify_actor!).to eq(received.account)
    expect(a_request(:get, actor_request_uri(actor_documents.fetch('sender.example')))).to have_been_made.at_least_once
  end

  it 'uses ML-DSA alone to authorize relayed Create, Update, reply, Announce and Delete activities' do
    created = distribute(original)
    deliver(created.without('signature'), hide_sender_status: original)
    received = Status.find_by!(uri: created.dig('object', 'id'))
    expect_published_key_verifies(created, received.account)
    recipient.follow!(received.account)

    original.update!(text: 'Edited with ML-DSA', edited_at: 1.second.from_now)
    updated = distribute(original, worker: ActivityPub::StatusUpdateDistributionWorker)
    expect(updated['type']).to eq('Update')
    deliver(updated.without('signature'), hide_sender_status: original)
    expect(received.reload.text).to include('Edited with ML-DSA')

    reply = Fabricate(:status, account: origin, text: 'ML-DSA reply', thread: original, visibility: :public)
    replied = distribute(reply)
    deliver(replied.without('signature'), hide_sender_status: reply)
    expect(Status.find_by!(uri: replied.dig('object', 'id')).thread).to eq(received)

    boost = Fabricate(:status, account: origin, reblog: original)
    announced = distribute(boost)
    expect(announced['type']).to eq('Announce')
    deliver(announced.without('signature'), hide_sender_status: [boost, original])
    expect(received.reblogs.where(account: received.account)).to exist

    deliver_delete(original, received)
  end

  it 'forwards the original dual-signed reply without invalidating either signature' do
    root = Fabricate(:status, account: recipient, text: 'Local root')
    root.update_column(:uri, ActivityPub::TagManager.instance.uri_for(root))
    third_party = Fabricate(:remote_account, domain: 'third.example', inbox_url: 'https://third.example/inbox', shared_inbox_url: '', protocol: :activitypub)
    third_party.follow!(recipient)
    reply = Fabricate(:status, account: origin, text: 'Dual-signed reply', thread: root, visibility: :public)
    secured = distribute(reply)

    deliver(secured, hide_sender_status: reply)
    ActivityPub::RawDistributionWorker.drain

    forwarded = ActivityPub::DeliveryWorker.jobs.find { |job| job['args'][2] == third_party.inbox_url }
    expect(forwarded).to be_present
    expect(JSON.parse(forwarded['args'].first)).to eq(secured)
    remote_origin = Status.find_by!(uri: secured.dig('object', 'id')).account
    expect_published_key_verifies(JSON.parse(forwarded['args'].first), remote_origin)
    expect(ActivityPub::LinkedDataSignature.new(JSON.parse(forwarded['args'].first)).verify_actor!).to eq(remote_origin)
  end

  it 'verifies an actor id object after JSON-LD compaction changes it to a URI' do
    document = distribute(original).without('proof', 'signature')
    document['actor'] = { 'id' => document.fetch('actor') }
    proof_only = on_instance('sender.example') do
      ActivityPub::ObjectIntegrityProof.new(document).sign!(origin)
    end
    proof_only['signature'] = { 'type' => 'RsaSignature2017', 'signatureValue' => 'invalid' }

    deliver(proof_only, hide_sender_status: original)

    received = Status.find_by!(uri: proof_only.dig('object', 'id'))
    expect(received.text).to include('Native ML-DSA: café 🔐')
    expect(received.account.domain).to eq('sender.example')
  end

  {
    'modified content' => ->(document) { document['object']['content'] = 'Forged content' },
    'modified signed document context' => ->(document) { document['@context'] = document['@context'].reverse },
    'modified proof value' => ->(document) { document['proof']['proofValue'] = "u#{Base64.urlsafe_encode64('forged', padding: false)}" },
    'modified signed creation time' => ->(document) { document['proof']['created'] = 1.hour.ago.utc.iso8601 },
    'modified signed expiry' => ->(document) { document['proof']['expires'] = 1.hour.from_now.utc.iso8601 },
    'expired proof' => ->(document) { document['proof']['expires'] = 1.hour.ago.utc.iso8601 },
    'wrong proof purpose' => ->(document) { document['proof']['proofPurpose'] = 'authentication' },
    'wrong proof type' => ->(document) { document['proof']['type'] = 'InvalidProof' },
    'unauthorized key' => ->(document) { document['proof']['verificationMethod'] = "#{document['actor']}#unpublished-key" },
  }.each do |description, tamper|
    it "does not persist a relayed activity with #{description}" do
      secured = distribute(original).without('signature')
      tamper.call(secured)

      deliver(secured)

      expect(Status.where(uri: secured.dig('object', 'id')).where.not(account_id: origin.id)).to_not exist
    end
  end

  it 'rejects an expired verification key even when its signed proof has not expired' do
    secured = distribute(original)
    remote_key = ActivityPub::FetchRemoteKeyService.new.call(secured.dig('proof', 'verificationMethod'), suppress_errors: false)
    remote_key.update!(expires_at: 1.minute.ago)

    deliver(secured.without('signature'))

    expect(Status.where(uri: secured.dig('object', 'id')).where.not(account_id: origin.id)).to_not exist
  end

  it 'rejects a revoked verification key with a valid native signature' do
    secured = distribute(original)
    remote_key = ActivityPub::FetchRemoteKeyService.new.call(secured.dig('proof', 'verificationMethod'), suppress_errors: false)
    remote_key.update!(revoked: true)

    deliver(secured.without('signature'))

    expect(Status.where(uri: secured.dig('object', 'id')).where.not(account_id: origin.id)).to_not exist
  end

  it 'rejects a verification key whose stored algorithm does not match the proof suite' do
    secured = distribute(original)
    remote_key = ActivityPub::FetchRemoteKeyService.new.call(secured.dig('proof', 'verificationMethod'), suppress_errors: false)
    remote_key.update!(type: :ed25519)

    deliver(secured.without('signature'))

    expect(Status.where(uri: secured.dig('object', 'id')).where.not(account_id: origin.id)).to_not exist
  end

  def on_instance(domain)
    previous_local_domain = Rails.configuration.x.local_domain
    previous_web_domain = Rails.configuration.x.web_domain
    previous_url_options = ActionMailer::Base.default_url_options
    Rails.configuration.x.local_domain = domain
    Rails.configuration.x.web_domain = domain
    ActionMailer::Base.default_url_options = previous_url_options.merge(host: domain, protocol: 'https')
    host! domain
    yield
  ensure
    Rails.configuration.x.local_domain = previous_local_domain
    Rails.configuration.x.web_domain = previous_web_domain
    ActionMailer::Base.default_url_options = previous_url_options
    host! previous_web_domain
  end

  def publish_actor(account)
    get "/users/#{account.username}", headers: { 'Accept' => 'application/activity+json' }
    expect(response).to have_http_status(200)
    actor = response.parsed_body
    domain = Rails.configuration.x.local_domain
    actor_documents[domain] = actor
    stub_request(:get, actor_request_uri(actor)).to_return(body: actor.to_json, headers: { 'Content-Type' => 'application/activity+json' })
    %w(outbox followers following).each do |collection|
      uri = actor.fetch(collection)
      get URI(uri).path, headers: { 'Accept' => 'application/activity+json' }
      expect(response).to have_http_status(200)
      stub_request(:get, uri).to_return(body: response.body, headers: { 'Content-Type' => 'application/activity+json' })
    end

    get '/.well-known/webfinger', params: { resource: "acct:#{account.username}@#{domain}" }
    expect(response).to have_http_status(200)
    stub_request(:get, "https://#{domain}/.well-known/webfinger").with(query: { resource: "acct:#{account.username}@#{domain}" }).to_return(body: response.body, headers: { 'Content-Type' => 'application/jrd+json' })
  end

  def actor_request_uri(actor)
    /\A#{Regexp.escape(actor.fetch('id'))}(?:\#.*)?\z/
  end

  def distribute(status, worker: ActivityPub::DistributionWorker)
    on_instance('sender.example') { worker.new.perform(status.id) }
    job = ActivityPub::DeliveryWorker.jobs.reverse.find { |delivery| delivery['args'][2] == receiver_inbox }
    expect(job).to be_present
    secured = JSON.parse(job['args'].first)
    expect(secured.dig('proof', 'cryptosuite')).to eq('mldsa44-jcs-2024')
    expect(secured.dig('signature', 'type')).to eq('RsaSignature2017')
    secured
  end

  def deliver_delete(status, received)
    deleted = on_instance('sender.example') do
      Class.new { include Payloadable }.new.serialize_payload(status, ActivityPub::DeleteNoteSerializer, signer: origin, always_sign: true)
    end.deep_stringify_keys

    expect(deleted['type']).to eq('Delete')
    deliver(deleted.without('signature'), hide_sender_status: status)
    expect(Status.where(id: received.id)).to_not exist
  end

  def deliver(document, hide_sender_status: nil)
    hidden_statuses = Array(hide_sender_status).compact.index_with(&:deleted_at)
    hidden_statuses.each_key { |status| status.update_columns(deleted_at: Time.current) }
    on_instance('relay.example') do
      ActivityPub::DeliveryWorker.new.perform(document.to_json, relay_signer.id, receiver_inbox)
    end
    expect(response).to have_http_status(202)
    expect(ActivityPub::ProcessingWorker.jobs).to_not be_empty
    queued_body = ActivityPub::ProcessingWorker.jobs.last.fetch('args').at(1)
    expect(JSON.parse(queued_body)).to eq(document)
    ActivityPub::ProcessingWorker.drain
  ensure
    hidden_statuses.each do |status, deleted_at|
      status.update_columns(deleted_at: deleted_at)
      status.reload
    end
  end

  def expect_published_key_verifies(document, remote_actor)
    key = Keypair.find_by!(uri: document.dig('proof', 'verificationMethod'))
    expect(key.account).to eq(remote_actor)
    expect(key.private_key).to be_nil
    published = Array(actor_documents.fetch('sender.example').fetch('assertionMethod')).find { |entry| entry['id'] == key.uri }
    expect(Multibase.decode_key_to_pem(published.fetch('publicKeyMultibase'))).to eq([:'ml-dsa-44', key.public_key])
    expect(ActivityPub::ObjectIntegrityProof.new(document.without('signature')).verify_actor!).to eq(remote_actor)
  end
end
