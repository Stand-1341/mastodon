# frozen_string_literal: true

require 'rails_helper'
require 'rake'

RSpec.describe Rake::Task do
  include PqcKeyProvisioningHelpers

  describe 'pqc:verify_key' do
    subject(:task) { described_class['pqc:verify_key'] }

    let(:account) { Fabricate(:account, username: 'alice') }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc.rake')
        example.run
      end
    end

    before do
      generate_real_ml_dsa_44_key
      ActivityPub::GeneratePqcKeyService.new.call(account)
    end

    it 'decrypts, signs, and verifies a fresh challenge without printing key material' do
      expect { task.invoke('alice') }.to output(/ML-DSA-44 stored key round-trip verified for @alice:/).to_stdout
    end

    it 'refuses to check an account without a usable key' do
      account.keypairs.where(type: :'ml-dsa-44').update_all(revoked: true)

      expect do
        expect { task.invoke('alice') }.to raise_error(SystemExit)
      end.to output(/No usable ML-DSA-44 key found for @alice/).to_stderr
    end
  end
end
