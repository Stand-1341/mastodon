# frozen_string_literal: true

require 'rails_helper'

require 'digest'
require 'open3'
require 'tmpdir'

# These two scripts are operator-facing and standalone: neither boots Rails, so
# unlike the rest of the suite they can be exercised as real processes. Their
# whole job is to tell the truth about a runtime, so the assertions are about
# behaviour under failure rather than about a happy path.
RSpec.describe 'PQC operator scripts' do
  # Compares versions like "3.5.0" without pulling in Gem::Version semantics
  # for a string that comes from the openssl binary itself.
  def openssl_version_at_least?(minimum)
    output, status = Open3.capture2e('openssl', 'version')
    return false unless status.success?

    found = output[/OpenSSL\s+(\d+\.\d+(?:\.\d+)?)/, 1]
    return false if found.nil?

    found.split('.').map(&:to_i).zip(minimum.split('.').map(&:to_i)) do |have, want|
      return true if have > want
      return false if have < want
    end
    true
  rescue Errno::ENOENT
    false
  end

  def run_script(*command)
    Open3.capture3(*command)
  end

  describe 'bin/pqc-doctor' do
    subject(:run) { run_script(RbConfig.ruby, Rails.root.join('bin/pqc-doctor').to_s) }

    it 'always reports a verdict and a next step, whatever the runtime' do
      stdout, _stderr, _status = run

      expect(stdout).to include('RESULT:')
      expect(stdout).to include('Next:')
    end

    it 'never dumps a stack trace as its primary output' do
      stdout, stderr, _status = run
      combined = stdout + stderr

      expect(combined).to_not match(/\.rb:\d+:in [`']/)
      expect(combined).to_not match(/from .*\.rb:\d+/)
    end

    it 'exits 0 or 1 and nothing else' do
      _stdout, _stderr, status = run

      expect(status.exitstatus).to be_in([0, 1])
    end

    context 'when the runtime cannot generate ML-DSA-87 keys' do
      before do
        skip 'this host has a capable OpenSSL' if openssl_version_at_least?('3.5.0')
      end

      it 'fails and names the OpenSSL version as the reason' do
        stdout, _stderr, status = run

        expect(status.exitstatus).to eq(1)
        expect(stdout).to match(/FAIL.*OpenSSL/i)
      end
    end
  end

  describe 'bin/pqc-tls-init' do
    around do |example|
      Dir.mktmpdir('pqc-tls-spec') do |directory|
        @directory = directory
        example.run
      end
    end

    attr_reader :directory

    let(:secrets) { File.join(directory, 'secrets') }
    let(:tls) { File.join(secrets, 'postgres-tls') }
    let(:command) { ['sh', Rails.root.join('bin/pqc-tls-init').to_s, '--secrets-dir', secrets] }

    def generate
      run_script(*command)
    end

    it 'writes the full certificate set the production overlay mounts' do
      _stdout, _stderr, status = generate

      expect(status.exitstatus).to eq(0)
      expect(File).to exist(File.join(tls, 'ca.crt'))
      expect(File).to exist(File.join(tls, 'ca.key'))
      expect(File).to exist(File.join(tls, 'server.crt'))
      expect(File).to exist(File.join(tls, 'server.key'))
      expect(File).to exist(File.join(secrets, 'postgres-superuser-password'))
    end

    it 'keeps private material private' do
      generate

      %w[ca.key server.key].each do |name|
        mode = File.stat(File.join(tls, name)).mode & 0o777
        expect(mode).to eq(0o600), "#{name} was written mode #{format('%04o', mode)}"
      end

      password_mode = File.stat(File.join(secrets, 'postgres-superuser-password')).mode & 0o777
      expect(password_mode).to eq(0o600)
    end

    it 'issues a server certificate for the db hostname that chains to its own CA' do
      generate

      _stdout, _stderr, status = run_script(
        'openssl', 'verify',
        '-CAfile', File.join(tls, 'ca.crt'),
        '-verify_hostname', 'db',
        File.join(tls, 'server.crt')
      )

      expect(status.exitstatus).to eq(0)
    end

    it 'is idempotent, so a rerun cannot silently rotate the CA under a running stack' do
      generate
      before = [File.join(tls, 'ca.crt'), File.join(secrets, 'postgres-superuser-password')]
               .map { |path| Digest::SHA256.file(path).hexdigest }

      generate
      after = [File.join(tls, 'ca.crt'), File.join(secrets, 'postgres-superuser-password')]
              .map { |path| Digest::SHA256.file(path).hexdigest }

      expect(after).to eq(before)
    end

    it 'refuses to run rather than continue when a private key is world-readable' do
      generate
      ca_key = File.join(tls, 'ca.key')
      File.chmod(0o644, ca_key)

      stdout, _stderr, status = generate

      expect(status.exitstatus).to eq(1)
      expect(stdout).to match(/readable by group or others/)
      expect(stdout).to include(ca_key)
    end

    it 'rejects an unknown flag instead of guessing' do
      _stdout, _stderr, status = run_script(*command, '--not-a-real-flag')

      expect(status.exitstatus).to eq(1)
    end

    it 'documents itself on request without writing anything' do
      stdout, _stderr, status = run_script(*command, '--help')

      expect(status.exitstatus).to eq(0)
      expect(stdout).to include('--secrets-dir')
      expect(File).to_not exist(secrets)
    end
  end
end
