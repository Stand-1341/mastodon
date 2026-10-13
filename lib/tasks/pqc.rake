# frozen_string_literal: true

require 'json'
require 'openssl'

namespace :pqc do
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

    inventory = {
      schema_version: 1,
      generated_at: Time.current.iso8601,
      deployed_sha: Mastodon::Version.source_commit.presence,
      ruby_version: RUBY_DESCRIPTION,
      openssl_version: OpenSSL::OPENSSL_VERSION,
      openssl_library_version: OpenSSL.const_defined?(:OPENSSL_LIBRARY_VERSION) ? OpenSSL::OPENSSL_LIBRARY_VERSION : nil,
      database_sslmode: database_configuration['sslmode'] || database_configuration[:sslmode],
      media_backend: {
        storage: storage.to_s,
        provider: storage_provider.to_s,
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
