# frozen_string_literal: true

require 'json'
require 'openssl'

namespace :pqc do
  desc 'Benchmark RSA-only and RSA plus ML-DSA ActivityPub signing for one local account'
  task :benchmark, [:username, :iterations] => :environment do |_task, args|
    username = args[:username].to_s.strip.delete_prefix('@')
    abort 'Usage: rake pqc:benchmark[username,iterations] (one local username required)' if username.blank?
    abort 'Only local accounts can be benchmarked; supply a username without a domain' if username.include?('@')

    account = Account.find_local(username)
    abort "Local account #{username.inspect} not found" if account.nil?

    report = Pqc::ActivityPubSigningBenchmark.new(account, iterations: args[:iterations].presence || Pqc::ActivityPubSigningBenchmark::DEFAULT_ITERATIONS).call
    puts JSON.pretty_generate(report)
  rescue ArgumentError => e
    abort e.message
  end

  desc 'Provision an ML-DSA-44 key for one local account (idempotent; does not enable signing)'
  task :generate_key, [:username] => :environment do |_task, args|
    username = args[:username].to_s.strip.delete_prefix('@')
    abort 'Usage: rake pqc:generate_key[username] (one local username required)' if username.blank?
    abort 'Only local accounts can be provisioned; supply a username without a domain' if username.include?('@')

    account = Account.find_local(username)
    abort "Local account #{username.inspect} not found; remote accounts cannot be provisioned" if account.nil?

    keypair = ActiveRecord::Base.logger.silence(Logger::FATAL) do
      ActivityPub::GeneratePqcKeyService.new.call(account)
    end
    puts "ML-DSA-44 key available for @#{account.username}: #{keypair.full_uri}"
  rescue ActivityPub::GeneratePqcKeyService::UnsupportedRuntimeError => e
    abort e.message
  end

  desc 'Verify that one local account can decrypt and use its stored ML-DSA-44 key'
  task :verify_key, [:username] => :environment do |_task, args|
    username = args[:username].to_s.strip.delete_prefix('@')
    abort 'Usage: rake pqc:verify_key[username] (one local username required)' if username.blank?
    abort 'Only local accounts can be checked; supply a username without a domain' if username.include?('@')

    account = Account.find_local(username)
    abort "Local account #{username.inspect} not found" if account.nil?

    keypair, verified = ActiveRecord::Base.logger.silence(Logger::FATAL) do
      keypair = account.keypairs.usable.find_by(type: :'ml-dsa-44')
      abort "No usable ML-DSA-44 key found for @#{account.username}" if keypair.nil?

      challenge = OpenSSL::Random.random_bytes(32)
      signature = keypair.keypair.sign(nil, challenge)
      [keypair, OpenSSL::PKey.read(keypair.public_key).verify(nil, signature, challenge)]
    end
    abort "ML-DSA-44 private/public key mismatch for @#{account.username}" unless verified

    puts "ML-DSA-44 stored key round-trip verified for @#{account.username}: #{keypair.full_uri}"
  rescue OpenSSL::PKey::PKeyError, NotImplementedError => e
    abort "Unable to use the stored ML-DSA-44 key; check Active Record Encryption key custody and OpenSSL 3.5+ provider support: #{e.message}"
  end

  desc 'Verify private-media data-key wrapping and unwrapping without storing or printing key material'
  task verify_media_key: :environment do
    context = { 'object_token' => SecureRandom.uuid, 'account_id' => 'pqc-media-verification' }
    data_key, wrapped_key, provider = Pqc::PrivateMedia::DataKey.generate(context)
    decrypted_key = Pqc::PrivateMedia::DataKey.decrypt(wrapped_key, provider, context)
    verified = data_key.bytesize == 32 && decrypted_key.bytesize == 32 && ActiveSupport::SecurityUtils.secure_compare(data_key, decrypted_key)
    abort 'Private-media key round-trip failed' unless verified

    puts "Private-media #{provider} data-key round-trip verified"
  rescue Pqc::PrivateMedia::DataKey::ConfigurationError => e
    abort "Unable to use the configured private-media key provider: #{e.message}"
  ensure
    data_key&.replace("\0" * data_key.bytesize)
    decrypted_key&.replace("\0" * decrypted_key.bytesize)
  end

  desc 'Exercise AWS KMS data-key wrapping against a local KMS-compatible endpoint'
  task verify_local_media_kms: :environment do
    abort 'Local KMS verification is restricted to development and test' unless Rails.env.local?

    endpoint = ENV['PQC_MEDIA_KMS_ENDPOINT'].presence
    uri = URI.parse(endpoint) if endpoint
    abort 'Set PQC_MEDIA_KMS_ENDPOINT to a local KMS-compatible endpoint' unless uri&.host.in?(%w(local-kms localhost 127.0.0.1 ::1))
    abort 'Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for the local KMS emulator' if ENV['AWS_ACCESS_KEY_ID'].blank? || ENV['AWS_SECRET_ACCESS_KEY'].blank?

    require 'aws-sdk-kms'

    client = Aws::KMS::Client.new(
      region: ENV['AWS_REGION'].presence || ENV.fetch('S3_REGION', 'us-east-1'),
      endpoint:,
      credentials: Aws::Credentials.new(ENV.fetch('AWS_ACCESS_KEY_ID'), ENV.fetch('AWS_SECRET_ACCESS_KEY'))
    )
    key_id = client.create_key(description: 'Ephemeral Mastodon local private-media verification').key_metadata.key_id
    previous_key_id = ENV.fetch('PQC_MEDIA_KMS_KEY_ID', nil)
    ENV['PQC_MEDIA_KMS_KEY_ID'] = key_id

    context = { 'object_token' => SecureRandom.uuid, 'account_id' => 'pqc-media-local-kms-verification' }
    data_key, wrapped_key, provider = Pqc::PrivateMedia::DataKey.generate(context)
    decrypted_key = Pqc::PrivateMedia::DataKey.decrypt(wrapped_key, provider, context)
    verified = provider == Pqc::PrivateMedia::DataKey::AWS_KMS_PROVIDER &&
               ActiveSupport::SecurityUtils.secure_compare(data_key, decrypted_key)
    abort 'Local KMS private-media round-trip failed' unless verified

    begin
      Pqc::PrivateMedia::DataKey.decrypt(wrapped_key, provider, context.merge('account_id' => 'different-owner'))
      abort 'Local KMS accepted a different owner encryption context'
    rescue Pqc::PrivateMedia::DataKey::ConfigurationError
      # Expected: KMS authenticates the encryption context with the ciphertext.
    end

    client.schedule_key_deletion(key_id:, pending_window_in_days: 7)
    key_scheduled_for_deletion = true
    puts 'Local KMS private-media round-trip and encryption-context binding verified'
  rescue Pqc::PrivateMedia::DataKey::ConfigurationError => e
    abort "Unable to use the local KMS key provider: #{e.message}"
  ensure
    ENV['PQC_MEDIA_KMS_KEY_ID'] = previous_key_id if defined?(previous_key_id)
    if defined?(client) && client && defined?(key_id) && key_id && !key_scheduled_for_deletion
      client.schedule_key_deletion(key_id:, pending_window_in_days: 7)
    end
    data_key&.replace("\0" * data_key.bytesize)
    decrypted_key&.replace("\0" * decrypted_key.bytesize)
  end

  desc 'Report or delete untracked private-media blobs older than 24 hours; deletion requires the explicit delete argument'
  task :cleanup_media_orphans, [:older_than_hours, :confirm] => :environment do |_task, args|
    older_than_hours = Integer(args[:older_than_hours].presence || 24)
    abort 'Orphan cleanup age must be at least 24 hours' if older_than_hours < 24

    dry_run = args[:confirm] != 'delete'
    report = Pqc::PrivateMedia::CleanupOrphansService.new.call(older_than: older_than_hours.hours, dry_run:)
    puts JSON.pretty_generate(report)
    abort 'Private-media orphan cleanup could not delete every candidate' if report[:failed].positive?
  rescue ArgumentError
    abort 'Usage: rake pqc:cleanup_media_orphans[24,delete] (defaults to dry-run)'
  rescue Pqc::PrivateMedia::CleanupOrphansService::UnsafeAgeError => e
    abort e.message
  end

  desc 'Emit a machine-readable PQC deployment inventory baseline'
  task inventory: :environment do
    encryption_key_names = %w(
      ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
      ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
      ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT
    )

    database_configuration = ActiveRecord::Base.configurations
      .configs_for(env_name: Rails.env, name: 'primary')
      &.configuration_hash || {}
    database_tls = ActiveRecord::Base.connection.select_one(<<~SQL.squish)
      SELECT current_setting('server_version') AS server_version,
             current_setting('ssl_groups', true) AS server_tls_groups,
             ssl,
             version AS tls_version,
             cipher
        FROM pg_stat_ssl
       WHERE pid = pg_backend_pid()
    SQL
    database_tls_groups = database_tls['server_tls_groups']&.split(':') || []

    storage = Paperclip::Attachment.default_options[:storage]
    storage_provider = case storage
                       when :fog
                         Paperclip::Attachment.default_options.dig(:fog_credentials, :provider) || 'Fog'
                       when :s3
                         'S3'
                       when :azure
                         'Azure'
                       when :filesystem
                         'Filesystem'
                       else
                         'Unknown'
                       end

    backup_age = ENV['PQC_BACKUP_AGE'].presence
    custody_pointer = ENV['PQC_AR_ENCRYPTION_CUSTODY_POINTER'].presence
    media_key_provider = if ENV['PQC_MEDIA_KMS_KEY_ID'].present?
                           'AWS-KMS'
                         elsif ENV['PQC_MEDIA_LOCAL_KEK'].present? && Rails.env.local?
                           'local-development-key'
                         else
                           'unconfigured'
                         end

    local_account_count = Account.local.count
    accounts_with_usable_ml_dsa_key = Account.local
      .joins(:keypairs)
      .merge(Keypair.where(type: :'ml-dsa-44').usable)
      .distinct.count

    inventory = {
      schema_version: 4,
      generated_at: Time.current.iso8601,
      deployed_sha: Mastodon::Version.source_commit.presence,
      ruby_version: RUBY_DESCRIPTION,
      openssl_version: OpenSSL::OPENSSL_VERSION,
      openssl_library_version: OpenSSL.const_defined?(:OPENSSL_LIBRARY_VERSION) ? OpenSSL::OPENSSL_LIBRARY_VERSION : nil,
      database_sslmode: database_configuration['sslmode'] || database_configuration[:sslmode],
      database_tls: {
        server_version: database_tls['server_version'],
        encrypted: database_tls['ssl'],
        tls_version: database_tls['tls_version'],
        cipher: database_tls['cipher'],
        server_tls_groups: database_tls_groups,
        hybrid_group_enforced: database_tls_groups == ['X25519MLKEM768'],
      },
      activitypub: {
        pqc_signing_enabled: ENV['PQC_ACTIVITYPUB_SIGNING'] == 'true',
        pqc_inbound_proof_required: ENV['PQC_ACTIVITYPUB_REQUIRE_PROOF'] == 'true',
        key_provisioning: 'explicit_per_account',
        local_account_count:,
        accounts_with_usable_ml_dsa_key:,
        accounts_missing_usable_ml_dsa_key: local_account_count - accounts_with_usable_ml_dsa_key,
        public_key_publication: 'usable_keys_regardless_of_signing',
      },
      media_backend: {
        storage: storage.to_s,
        provider: storage_provider.to_s,
      },
      private_media: {
        encryption_enabled: ENV['PQC_PRIVATE_MEDIA_ENCRYPTION'] == 'true',
        cipher: 'AES-256-GCM',
        key_encryption_provider: media_key_provider,
        access_policy: 'owner_only',
        max_upload_bytes: Pqc::PrivateMedia::CreateService::MAX_FILE_SIZE,
        account_quota_bytes: Pqc::PrivateMedia::CreateService::MAX_ACCOUNT_STORAGE,
      },
      encrypted_messaging: {
        experimental_relay_enabled: ENV['PQC_E2EE_EXPERIMENTAL'] == 'true',
        protocol: 'MLS_256_XWING_AES256GCM_SHA512_MLDSA87',
        cipher_suite_id: '0xf011',
        cipher_suite_registry_status: 'ts-mls private-use; not IANA assigned',
        cross_client_interoperability: false,
        relay_payloads: 'opaque_ciphertext',
        user_interface_available: true,
        local_private_state_persisted: true,
        recovery_storage: 'passphrase_encrypted_localstorage',
        portable_recovery_available: true,
        creator_can_add_local_members: true,
        durable_outbound_queue: true,
        idempotent_message_delivery: true,
        idempotent_key_package_claims: true,
        recoverable_group_setup: true,
        atomic_initial_group_setup: true,
        atomic_member_addition: true,
        atomic_member_removal: true,
        member_departure_requests: true,
        pre_setup_invitation_acceptance: true,
        active_member_invitation_acceptance: true,
        production_ready: false,
      },
      active_record_encryption: {
        required_key_environment_variables: encryption_key_names.map do |name|
          { name:, configured: ENV[name].present? }
        end,
        custody_pointer:,
        custody_pointer_prompt: 'Set PQC_AR_ENCRYPTION_CUSTODY_POINTER to a non-secret secret-manager or protected-backup reference; never provide key material.',
      },
      backup_age: {
        latest_successful_backup_age: backup_age,
        operator_input_required: backup_age.nil?,
        prompt: 'Set PQC_BACKUP_AGE (for example, 6h or 3d) to the age of the latest successful backup.',
      },
    }

    puts JSON.pretty_generate(inventory)
  end
end
