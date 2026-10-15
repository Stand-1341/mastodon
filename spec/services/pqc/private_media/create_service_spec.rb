# frozen_string_literal: true

require 'rails_helper'
require 'aws-sdk-kms'

RSpec.describe Pqc::PrivateMedia::CreateService do
  let(:account) { Fabricate(:account) }
  let(:local_key) { Base64.strict_encode64('m' * 32) }
  let(:plaintext) { "private media bytes \x00 and UTF-8: café".b }

  around do |example|
    Dir.mktmpdir('pqc-private-media') do |storage_root|
      ClimateControl.modify(
        PQC_MEDIA_LOCAL_KEK: local_key,
        PQC_PRIVATE_MEDIA_ROOT: storage_root
      ) do
        example.run
      end
    end
  end

  def uploaded_file(contents)
    file = Tempfile.new('pqc-private-media-upload')
    file.binmode
    file.write(contents)
    file.rewind
    ActionDispatch::Http::UploadedFile.new(tempfile: file, filename: 'private.txt', type: 'text/plain')
  end

  it 'stores only authenticated ciphertext and decrypts it for the owning account' do
    object = described_class.new.call(account, uploaded_file(plaintext))
    stored = Pqc::PrivateMedia::Storage.new.read(object.storage_key)

    expect(stored).to_not include(plaintext)
    expect(object.key_encryption_provider).to eq(Pqc::PrivateMedia::DataKey::LOCAL_PROVIDER)
    expect(Pqc::PrivateMedia::DecryptService.new.call(object)).to eq(plaintext)
  end

  it 'encrypts and retrieves an object through the AWS KMS data-key provider' do
    kms_client = instance_spy(Aws::KMS::Client)
    kms_data_key = 'd' * 32
    kms_ciphertext_blob = 'kms-wrapped-data-key'.b
    allow(Aws::KMS::Client).to receive(:new).with(region: 'us-east-1', endpoint: nil).and_return(kms_client)
    allow(kms_client).to receive_messages(
      generate_data_key: double(plaintext: kms_data_key.dup, ciphertext_blob: kms_ciphertext_blob),
      decrypt: double(plaintext: kms_data_key.dup)
    )

    object = nil
    ClimateControl.modify(PQC_MEDIA_KMS_KEY_ID: 'alias/mastodon-private-media') do
      object = described_class.new.call(account, uploaded_file(plaintext))
      stored = Pqc::PrivateMedia::Storage.new.read(object.storage_key)

      expect(object.key_encryption_provider).to eq(Pqc::PrivateMedia::DataKey::AWS_KMS_PROVIDER)
      expect(Base64.strict_decode64(object.wrapped_key)).to eq(kms_ciphertext_blob)
      expect(stored).to_not include(plaintext)
      expect(Pqc::PrivateMedia::DecryptService.new.call(object)).to eq(plaintext)
    end

    encryption_context = { 'object_token' => object.token, 'account_id' => account.id.to_s }
    expect(kms_client).to have_received(:generate_data_key).with(
      key_id: 'alias/mastodon-private-media',
      key_spec: 'AES_256',
      encryption_context:
    )
    expect(kms_client).to have_received(:decrypt).with(
      ciphertext_blob: kms_ciphertext_blob,
      encryption_context:
    )
  end

  it 'rejects ciphertext tampering' do
    object = described_class.new.call(account, uploaded_file(plaintext))
    path = Pathname.new(ENV.fetch('PQC_PRIVATE_MEDIA_ROOT')).join(object.token)
    ciphertext = File.binread(path)
    ciphertext.setbyte(-1, ciphertext.getbyte(-1) ^ 1)
    File.binwrite(path, ciphertext)

    expect { Pqc::PrivateMedia::DecryptService.new.call(object) }
      .to raise_error(Pqc::PrivateMedia::DecryptService::DecryptionError)
  end

  it 'rejects empty and oversized uploads' do
    expect { described_class.new.call(account, uploaded_file('')) }
      .to raise_error(described_class::InvalidUploadError)

    oversized_upload = double(read: '', size: described_class::MAX_FILE_SIZE + 1)
    expect { described_class.new.call(account, oversized_upload) }
      .to raise_error(described_class::InvalidUploadError)
  end

  it 'enforces the per-account storage quota at the exact byte limit' do
    filler_token = SecureRandom.uuid
    account.private_media_objects.create!(
      token: filler_token,
      storage_key: "pqc-private-media/#{filler_token}",
      byte_size: described_class::MAX_ACCOUNT_STORAGE - plaintext.bytesize,
      wrapped_key: 'wrapped-key',
      key_encryption_provider: 'test-provider',
      nonce: 'nonce',
      auth_tag: 'tag'
    )

    described_class.new.call(account, uploaded_file(plaintext))
    expect(account.private_media_objects.sum(:byte_size)).to eq(described_class::MAX_ACCOUNT_STORAGE)

    expect { described_class.new.call(account, uploaded_file('next object')) }
      .to raise_error(described_class::QuotaExceededError)
    expect(account.private_media_objects.sum(:byte_size)).to eq(described_class::MAX_ACCOUNT_STORAGE)
  end

  it 'enforces the actual bytes read even when the upload reports a smaller size' do
    upload = double(size: 1)
    allow(upload).to receive(:read).with(described_class::MAX_FILE_SIZE + 1).and_return('x' * (described_class::MAX_FILE_SIZE + 1))

    expect { described_class.new.call(account, upload) }
      .to raise_error(described_class::InvalidUploadError)
    expect(PrivateMediaObject.count).to eq(0)
  end

  it 'removes the database record and ciphertext when storage write fails' do
    storage = instance_double(Pqc::PrivateMedia::Storage)
    allow(Pqc::PrivateMedia::Storage).to receive(:new).and_return(storage)
    allow(storage).to receive(:write).and_raise(Pqc::PrivateMedia::Storage::StorageError, 'write failed')
    allow(storage).to receive(:delete)

    expect { described_class.new.call(account, uploaded_file(plaintext)) }
      .to raise_error(Pqc::PrivateMedia::Storage::StorageError)
    expect(PrivateMediaObject.count).to eq(0)
    expect(storage).to have_received(:delete).with(start_with('pqc-private-media/'))
  end
end
