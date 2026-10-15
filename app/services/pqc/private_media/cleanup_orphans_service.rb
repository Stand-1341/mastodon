# frozen_string_literal: true

class Pqc::PrivateMedia::CleanupOrphansService < BaseService
  MINIMUM_AGE = 24.hours
  BATCH_SIZE = 500

  class UnsafeAgeError < StandardError; end

  def call(older_than: MINIMUM_AGE, dry_run: true, now: Time.current)
    raise UnsafeAgeError, 'Orphan cleanup age must be at least 24 hours' if older_than < MINIMUM_AGE

    storage = Pqc::PrivateMedia::Storage.new
    cutoff = now - older_than
    candidates = 0
    deleted = 0
    failed = 0
    batch = []

    storage.each_object do |storage_key, last_modified|
      next unless valid_storage_key?(storage_key) && last_modified < cutoff

      batch << storage_key
      next if batch.size < BATCH_SIZE

      counts = process_batch(batch, storage, dry_run)
      candidates += counts[:candidates]
      deleted += counts[:deleted]
      failed += counts[:failed]
      batch.clear
    end

    counts = process_batch(batch, storage, dry_run)
    candidates += counts[:candidates]
    deleted += counts[:deleted]
    failed += counts[:failed]

    { older_than_seconds: older_than.to_i, dry_run:, orphan_candidates: candidates, deleted:, failed: }
  end

  private

  def process_batch(storage_keys, storage, dry_run)
    return { candidates: 0, deleted: 0, failed: 0 } if storage_keys.empty?

    tracked_keys = PrivateMediaObject.where(storage_key: storage_keys).pluck(:storage_key).to_set
    orphans = storage_keys.reject { |storage_key| tracked_keys.include?(storage_key) }
    deleted = 0
    failed = 0

    unless dry_run
      orphans.each do |storage_key|
        storage.delete(storage_key)
        deleted += 1
      rescue Pqc::PrivateMedia::Storage::StorageError => e
        failed += 1
        Rails.logger.error("Private media orphan cleanup failed (#{e.class})")
      end
    end

    { candidates: orphans.size, deleted:, failed: }
  end

  def valid_storage_key?(storage_key)
    storage_key.is_a?(String) && storage_key.match?(%r{\Apqc-private-media/[0-9a-f-]{36}\z}i)
  end
end
