# frozen_string_literal: true

# Phase 1 verification: the shipped nginx template must advertise the hybrid
# PQ key exchange group WITH classical fallback, on TLS 1.3, with operator
# verification guidance. Pure text/structure assertions — no nginx binary
# required (binary-level `nginx -t` runs separately in CI/dev).

require 'rails_helper'

RSpec.describe 'dist/nginx.conf PQC hybrid TLS template', type: :feature do
  subject(:conf) { Rails.root.join('dist/nginx.conf').read }

  it 'enables TLS 1.3' do
    expect(conf).to match(/ssl_protocols\s+.*TLSv1\.3/)
  end

  it 'advertises the hybrid X25519MLKEM768 group first' do
    directives = conf.scan(/(?:ssl_groups|ssl_conf_command\s+Groups)\s+([^;]+);/).flatten
    expect(directives).not_to be_empty, 'expected ssl_groups or ssl_conf_command Groups directive'
    groups = directives.first.split[0].split(':')
    expect(groups.first).to eq('X25519MLKEM768')
  end

  it 'keeps classical fallback groups for non-PQ peers' do
    directives = conf.scan(/(?:ssl_groups|ssl_conf_command\s+Groups)\s+([^;]+);/).flatten
    groups = directives.first.split[0].split(':')
    %w[X25519 P-256].each do |fallback|
      expect(groups).to include(fallback), "expected classical fallback #{fallback} in: #{groups}"
    end
  end

  it 'documents the OpenSSL 3.5+ linkage requirement' do
    expect(conf).to include('OpenSSL 3.5')
  end

  it 'documents how to verify negotiation with openssl s_client' do
    expect(conf).to include('s_client')
  end

  it 'places the TLS groups directive in a TLS (server) context' do
    lines = conf.lines
    idx = lines.index { |l| l =~ /ssl_groups|ssl_conf_command\s+Groups/ }
    expect(idx).to be_present
    preceding = lines[0..idx].join
    expect(preceding).to match(/server\s*\{/)
  end
end
