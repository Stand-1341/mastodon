# frozen_string_literal: true

# Phase 0 verification: Rails DB SSL default hardened from `prefer` to
# `require` for TCP connections, with explicit documented opt-outs for
# local dev/CI (socket or DB_SSLMODE=disable), per docs/PQC.md.

require 'rails_helper'

RSpec.describe 'PQC Phase 0 database TLS defaults', type: :feature do
  subject(:db_config) { YAML.safe_load(Rails.root.join('config/database.yml').read, aliases: true) }

  it 'defaults sslmode to require via the shared default anchor (inherited by production)' do
    expect(db_config.dig('default', 'sslmode')).to include('require')
    expect(db_config.dig('production')).to be_present # section exists, inherits default
  end

  it 'keeps an explicit opt-out for local development environments' do
    expect(Rails.root.join('.env.vagrant').read).to include('DB_SSLMODE=disable')
  end

  it 'keeps an explicit opt-out for CI' do
    ci = Rails.root.join('.github/workflows/test-ruby.yml').read
    expect(ci).to include('DB_SSLMODE')
    expect(ci).to include('disable')
  end

  it 'documents the opt-out variable in the production sample env' do
    env_sample = Rails.root.join('.env.production.sample').read
    expect(env_sample).to include('DB_SSLMODE')
  end

  it 'does not silently fall back to prefer anywhere' do
    raw = Rails.root.join('config/database.yml').read
    expect(raw).not_to match(/sslmode:\s*prefer/)
  end
end

RSpec.describe 'docs/PQC.md deployment notes', type: :feature do
  subject(:doc) { Rails.root.join('docs/PQC.md').read }

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
