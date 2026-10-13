# frozen_string_literal: true

require 'rails_helper'
require 'rake'
require 'json'
require 'stringio'

RSpec.describe Rake::Task do
  describe 'pqc:inventory' do
    subject(:task) { described_class['pqc:inventory'] }

    before do
      Rails.application.load_tasks
      task.reenable
    end

    it 'emits a JSON inventory without exposing encryption key material' do
      key_values = %w(
        ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
        ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
        ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT
      ).filter_map { |key| ENV[key] if ENV[key].present? }
      original_stdout = $stdout
      output = StringIO.new

      begin
        $stdout = output
        task.invoke
      ensure
        $stdout = original_stdout
      end

      json = output.string
      inventory = JSON.parse(json)

      expect(inventory).to include(
        'schema_version' => 1,
        'deployed_sha' => Mastodon::Version.source_commit.presence
      )
      expect(inventory).to include(
        'ruby_version',
        'openssl_version',
        'openssl_library_version',
        'database_sslmode',
        'media_backend',
        'active_record_encryption',
        'backup_age'
      )
      expect([true, false]).to include(inventory.dig('backup_age', 'operator_input_required'))
      expect(inventory.dig('active_record_encryption', 'required_key_environment_variables')).to all(include('name', 'configured'))
      key_values.each { |value| expect(json).to_not include(value) }
    end
  end
end
