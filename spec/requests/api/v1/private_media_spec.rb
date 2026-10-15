# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'Private media API' do
  include_context 'with API authentication', oauth_scopes: 'write:media'

  around do |example|
    Dir.mktmpdir('pqc-private-media-request') do |storage_root|
      ClimateControl.modify(
        PQC_PRIVATE_MEDIA_ENCRYPTION: 'true',
        PQC_MEDIA_LOCAL_KEK: Base64.strict_encode64('r' * 32),
        PQC_PRIVATE_MEDIA_ROOT: storage_root
      ) do
        example.run
      end
    end
  end

  describe 'POST /api/v1/private_media' do
    it 'stores encrypted bytes and returns an authenticated download route' do
      plaintext = Rails.root.join('spec', 'fixtures', 'files', 'attachment.jpg').binread

      post '/api/v1/private_media', headers: headers, params: { file: fixture_file_upload('attachment.jpg', 'image/jpeg') }

      expect(response).to have_http_status(201)
      expect(response.parsed_body).to include('content_type' => 'application/octet-stream', 'byte_size' => plaintext.bytesize)

      object = user.account.private_media_objects.find(response.parsed_body.fetch('id'))
      ciphertext = Pqc::PrivateMedia::Storage.new.read(object.storage_key)
      expect(ciphertext).to_not include(plaintext)

      get response.parsed_body.fetch('url'), headers: headers

      expect(response).to have_http_status(200)
      expect(response.body.b).to eq(plaintext)
      expect(response.headers['Cache-Control']).to include('no-store')
      expect(response.headers['X-Content-Type-Options']).to eq('nosniff')
    end

    it 'returns payload too large when the account storage quota is exhausted' do
      token = SecureRandom.uuid
      user.account.private_media_objects.create!(
        token: token,
        storage_key: "pqc-private-media/#{token}",
        byte_size: Pqc::PrivateMedia::CreateService::MAX_ACCOUNT_STORAGE,
        wrapped_key: 'wrapped-key',
        key_encryption_provider: 'test-provider',
        nonce: 'nonce',
        auth_tag: 'tag'
      )

      post '/api/v1/private_media', headers: headers, params: { file: fixture_file_upload('attachment.jpg', 'image/jpeg') }

      expect(response).to have_http_status(413)
      expect(response.parsed_body.fetch('error')).to include('1 GB per account')
    end

    it 'does not allow another account to retrieve an object' do
      upload = fixture_file_upload('attachment.jpg', 'image/jpeg')
      object = Pqc::PrivateMedia::CreateService.new.call(Fabricate(:account), upload)

      get "/api/v1/private_media/#{object.id}", headers: headers

      expect(response).to have_http_status(404)
    end

    it 'hides the endpoint while the feature flag is off' do
      ClimateControl.modify(PQC_PRIVATE_MEDIA_ENCRYPTION: 'false') do
        post '/api/v1/private_media', headers: headers, params: { file: fixture_file_upload('attachment.jpg', 'image/jpeg') }
      end

      expect(response).to have_http_status(404)
    end
  end

  describe 'DELETE /api/v1/private_media/:id' do
    it 'removes the encrypted object and its database record' do
      object = Pqc::PrivateMedia::CreateService.new.call(user.account, fixture_file_upload('attachment.jpg', 'image/jpeg'))
      storage_key = object.storage_key

      delete "/api/v1/private_media/#{object.id}", headers: headers

      expect(response).to have_http_status(200)
      expect(PrivateMediaObject.exists?(object.id)).to be(false)
      expect { Pqc::PrivateMedia::Storage.new.read(storage_key) }
        .to raise_error(Pqc::PrivateMedia::Storage::StorageError)
    end

    it 'preserves the database record when encrypted storage cannot be read or deleted' do
      object = Pqc::PrivateMedia::CreateService.new.call(user.account, fixture_file_upload('attachment.jpg', 'image/jpeg'))
      storage = instance_double(Pqc::PrivateMedia::Storage)
      allow(Pqc::PrivateMedia::Storage).to receive(:new).and_return(storage)
      allow(storage).to receive(:read).and_raise(Pqc::PrivateMedia::Storage::StorageError, 'storage unavailable')

      delete "/api/v1/private_media/#{object.id}", headers: headers

      expect(response).to have_http_status(503)
      expect(PrivateMediaObject.exists?(object.id)).to be(true)
    end
  end
end
