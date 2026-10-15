# frozen_string_literal: true

require 'rails_helper'
require 'fileutils'
require 'tmpdir'

RSpec.describe 'PostgreSQL TLS configuration', type: :feature do
  subject(:db_config) { ActiveSupport::ConfigurationFile.parse(Rails.root.join('config', 'database.yml')) }

  let(:sslmode) { nil }
  let(:sslrootcert) { nil }
  let(:db_host) { nil }
  let(:database_url) { nil }
  let(:require_hybrid_tls) { nil }
  let(:hybrid_ca_path) { nil }
  let(:directory) { Dir.mktmpdir('mastodon-db-tls-') }
  let(:ca_path) { File.join(directory, 'CA with spaces #1.pem') }
  let(:connection_configs) { db_config.slice('development', 'test', 'production').values.flat_map(&:values) }
  let(:resolved_config) do
    configurations = db_config.except('default')
    configurations['test']['primary']['url'] = ENV['DATABASE_URL'] if ENV['DATABASE_URL'].present?

    ActiveRecord::DatabaseConfigurations.new(configurations)
      .configs_for(env_name: 'test', name: 'primary').configuration_hash
  end

  around do |example|
    # These specs test libpq path configuration, not certificate negotiation.
    File.write(ca_path, 'CA file fixture')
    ClimateControl.modify DB_HOST: db_host, DB_SSLMODE: sslmode, DB_SSLROOTCERT: sslrootcert,
                          DATABASE_URL: database_url, PRIMARY_DATABASE_URL: nil, REPLICA_DATABASE_URL: nil,
                          PQC_REQUIRE_HYBRID_DB_TLS: require_hybrid_tls,
                          PQC_HYBRID_DB_TLS_CA_PATH: hybrid_ca_path, REPLICA_DB_HOST: nil do
      example.run
    end
  ensure
    FileUtils.remove_entry(directory)
  end

  def database_url_with(params)
    "postgresql://mastodon:password@database.example/mastodon?#{URI.encode_www_form(params).gsub('+', '%20')}"
  end

  it 'defaults to require in every environment without replacing the normal trust configuration' do
    expect(db_config.dig('default', 'sslmode')).to eq('require')
    connection_configs.each do |config|
      expect(config['sslmode']).to eq('require')
      expect(config).to_not have_key('sslrootcert')
    end
  end

  context 'with the explicit local TLS opt-out' do
    let(:sslmode) { 'disable' }

    it 'keeps primary and replica connections in plaintext' do
      expect(connection_configs).to all(include('sslmode' => 'disable'))
    end
  end

  %w(require verify-full).each do |mode|
    context "with DB_SSLMODE=#{mode} and DB_SSLROOTCERT" do
      let(:sslmode) { mode }
      let(:sslrootcert) { ca_path }

      it 'passes the CA path unchanged to primary and replica libpq connections' do
        expect(connection_configs).to all(include('sslmode' => mode, 'sslrootcert' => ca_path))
      end
    end

    context "with DB_SSLMODE=#{mode} and URL certificates" do
      let(:sslmode) { mode }
      let(:database_url) do
        database_url_with(sslrootcert: ca_path, sslcert: ca_path, sslkey: ca_path)
      end

      it 'preserves URL CA and client certificate options when Active Record merges the configuration' do
        expect(resolved_config).to include(sslmode: mode, sslrootcert: ca_path, sslcert: ca_path, sslkey: ca_path)
      end
    end
  end

  context 'with a literal plus sign in a URL certificate path' do
    let(:ca_path) { File.join(directory, 'CA+1.pem') }
    let(:database_url) { database_url_with(sslrootcert: ca_path).gsub('%2B', '+') }

    it 'checks the same literal path that Active Record passes to libpq' do
      expect(resolved_config[:sslrootcert]).to eq(ca_path)
    end
  end

  context 'with a URL that explicitly disables TLS' do
    let(:database_url) { 'postgresql://mastodon@database.example/mastodon?sslmode=disable' }

    it 'preserves Active Record URL precedence' do
      expect(resolved_config[:sslmode]).to eq('disable')
    end
  end

  context 'when hybrid database TLS is required' do
    let(:require_hybrid_tls) { 'true' }
    let(:db_host) { 'db' }
    let(:hybrid_ca_path) { ca_path }
    let(:sslmode) { 'verify-full' }
    let(:sslrootcert) { ca_path }
    let(:database_url) { 'postgresql://mastodon@db/mastodon' }

    it 'accepts an in-cluster URL with inherited verified TLS settings' do
      expect { db_config }.to_not raise_error
      expect(resolved_config).to include(host: 'db', sslmode: 'verify-full')
    end

    context 'with a URL that changes the database host' do
      let(:database_url) { 'postgresql://mastodon@other-db/mastodon' }

      it 'fails closed during configuration' do
        expect { db_config }.to raise_error(ArgumentError, /requires DATABASE_URL to connect to db/)
      end
    end

    context 'with a URL that disables certificate verification' do
      let(:database_url) { 'postgresql://mastodon@db/mastodon?sslmode=require' }

      it 'fails closed during configuration' do
        expect { db_config }.to raise_error(ArgumentError, /requires DATABASE_URL sslmode=verify-full/)
      end
    end
  end

  context 'with a CA from DB_SSLROOTCERT and a URL without TLS options' do
    let(:sslrootcert) { ca_path }
    let(:database_url) { 'postgresql://mastodon@database.example/mastodon' }

    it 'keeps the environment CA path after URL merging' do
      expect(resolved_config).to include(sslmode: 'require', sslrootcert: ca_path)
    end
  end

  context 'with different environment and URL CA paths' do
    let(:sslrootcert) { ca_path }
    let(:database_url) { database_url_with(sslrootcert: other_ca_path) }
    let(:other_ca_path) { File.join(directory, 'url-ca.pem') }

    before { File.write(other_ca_path, 'URL CA file fixture') }

    it 'preserves Active Record URL precedence for the CA' do
      expect(resolved_config[:sslrootcert]).to eq(other_ca_path)
    end
  end

  %w(typo VERIFY-FULL no-verify).push('').each do |mode|
    context "with invalid DB_SSLMODE=#{mode.inspect}" do
      let(:sslmode) { mode }

      it 'rejects the mode actionably' do
        expect { db_config }.to raise_error(ArgumentError, /Invalid DB_SSLMODE/)
      end
    end
  end

  context 'with an invalid URL mode' do
    let(:database_url) { 'postgresql://mastodon@database.example/mastodon?sslmode=typo' }

    it 'rejects the mode rather than relying on a fallback' do
      expect { db_config }.to raise_error(ArgumentError, /Invalid sslmode in DATABASE_URL/)
    end
  end

  ['', 'missing.pem'].each do |path|
    context "with invalid DB_SSLROOTCERT=#{path.inspect}" do
      let(:sslrootcert) { path.empty? ? path : File.join(directory, path) }

      it 'fails actionably instead of leaving libpq to ignore a missing CA in require mode' do
        expect { db_config }.to raise_error(ArgumentError, /Unable to read DB_SSLROOTCERT.*readable PEM CA file/)
      end
    end
  end

  context 'with a directory instead of a CA file' do
    let(:sslrootcert) { directory }

    it 'fails actionably' do
      expect { db_config }.to raise_error(ArgumentError, /Unable to read DB_SSLROOTCERT/)
    end
  end

  context 'with an empty CA file' do
    let(:sslrootcert) { ca_path }

    before { File.write(ca_path, '') }

    it 'fails actionably instead of using a different trust configuration' do
      expect { db_config }.to raise_error(ArgumentError, /Unable to read DB_SSLROOTCERT.*CA file is empty/)
    end
  end

  context 'with an unreadable CA file' do
    let(:sslrootcert) { ca_path }

    before do
      allow(File).to receive(:open).and_call_original
      allow(File).to receive(:open).with(ca_path, 'rb').and_raise(Errno::EACCES)
    end

    it 'reports the variable and filesystem failure' do
      expect { db_config }.to raise_error(ArgumentError, /Unable to read DB_SSLROOTCERT.*Permission denied/)
    end
  end

  %w(DATABASE_URL PRIMARY_DATABASE_URL REPLICA_DATABASE_URL).each do |name|
    it "fails actionably for a missing CA path in #{name}" do
      url = database_url_with(sslmode: 'require', sslrootcert: File.join(directory, 'missing.pem'))
      ClimateControl.modify name => url do
        expect { db_config }.to raise_error(ArgumentError, /Unable to read #{name} sslrootcert/)
      end
    end
  end

  context 'with a missing CA even when TLS is disabled' do
    let(:sslmode) { 'disable' }
    let(:sslrootcert) { File.join(directory, 'missing.pem') }

    it 'rejects the explicit bad path rather than carrying a latent trust configuration error' do
      expect { db_config }.to raise_error(ArgumentError, /Unable to read DB_SSLROOTCERT/)
    end
  end

  it 'keeps an explicit opt-out for local development environments' do
    expect(Rails.root.join('.env.vagrant').read).to include('DB_SSLMODE=disable')
  end

  it 'keeps an explicit opt-out for CI' do
    ci = Rails.root.join('.github', 'workflows', 'test-ruby.yml').read
    expect(ci).to include('DB_SSLMODE')
    expect(ci).to include('disable')
  end

  it 'documents the opt-out variable in the production sample env' do
    env_sample = Rails.root.join('.env.production.sample').read
    expect(env_sample).to include('DB_SSLMODE')
  end

  it 'does not silently fall back to prefer anywhere' do
    raw = Rails.root.join('config', 'database.yml').read
    expect(raw).to_not match(/sslmode:\s*prefer/)
  end

  context 'with docs/PQC.md deployment notes' do
    subject(:doc) { Rails.root.join('docs', 'PQC.md').read }

    it 'exists and documents the OpenSSL 3.5 requirement' do
      expect(doc).to include('OpenSSL 3.5')
    end

    it 'documents that Phase 1 is configuration-only (no app code change)' do
      expect(doc.downcase).to match(/does\s+not\s+change\s+.*(?:application\s+)?code|configuration.only/)
    end

    it 'documents the postgres TLS provisioning caveat for the compose service' do
      expect(doc).to match(/postgres/i)
      expect(doc).to match(/tls|ssl/i)
    end
  end
end
