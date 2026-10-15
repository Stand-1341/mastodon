# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Pqc::PrivateMedia::CleanupOrphansService do
  let(:account) { Fabricate(:account) }

  around do |example|
    Dir.mktmpdir('pqc-private-media-orphans') do |storage_root|
      ClimateControl.modify(PQC_PRIVATE_MEDIA_ROOT: storage_root) { example.run }
    end
  end

  def add_tracked_object(account, token)
    account.private_media_objects.create!(
      token:,
      storage_key: "pqc-private-media/#{token}",
      byte_size: 10,
      wrapped_key: 'wrapped-key',
      key_encryption_provider: 'test-provider',
      nonce: 'nonce',
      auth_tag: 'tag'
    )
  end

  it 'defaults to reporting old orphans without deleting and preserves tracked and recent objects' do
    storage = Pqc::PrivateMedia::Storage.new
    orphan_token = SecureRandom.uuid
    recent_token = SecureRandom.uuid
    tracked_token = SecureRandom.uuid
    orphan_key = "pqc-private-media/#{orphan_token}"
    recent_key = "pqc-private-media/#{recent_token}"
    tracked_key = "pqc-private-media/#{tracked_token}"
    storage.write(orphan_key, 'orphan')
    storage.write(recent_key, 'recent')
    storage.write(tracked_key, 'tracked')
    add_tracked_object(account, tracked_token)
    old_time = 48.hours.ago.to_time
    File.utime(old_time, old_time, Pathname.new(ENV.fetch('PQC_PRIVATE_MEDIA_ROOT')).join(orphan_token))

    report = described_class.new.call

    expect(report).to include(dry_run: true, orphan_candidates: 1, deleted: 0, failed: 0)
    expect(storage.read(orphan_key)).to eq('orphan')
    expect(storage.read(recent_key)).to eq('recent')
    expect(storage.read(tracked_key)).to eq('tracked')
  end

  it 'deletes only confirmed old orphan blobs' do
    storage = Pqc::PrivateMedia::Storage.new
    orphan_token = SecureRandom.uuid
    tracked_token = SecureRandom.uuid
    orphan_key = "pqc-private-media/#{orphan_token}"
    tracked_key = "pqc-private-media/#{tracked_token}"
    storage.write(orphan_key, 'orphan')
    storage.write(tracked_key, 'tracked')
    add_tracked_object(account, tracked_token)
    old_time = 48.hours.ago.to_time
    File.utime(old_time, old_time, Pathname.new(ENV.fetch('PQC_PRIVATE_MEDIA_ROOT')).join(orphan_token))

    report = described_class.new.call(dry_run: false)

    expect(report).to include(dry_run: false, orphan_candidates: 1, deleted: 1, failed: 0)
    expect { storage.read(orphan_key) }.to raise_error(Pqc::PrivateMedia::Storage::StorageError)
    expect(storage.read(tracked_key)).to eq('tracked')
  end

  it 'rejects cleanup ages shorter than one day' do
    expect { described_class.new.call(older_than: 23.hours) }
      .to raise_error(described_class::UnsafeAgeError)
  end
end
