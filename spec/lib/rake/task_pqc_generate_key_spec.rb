# frozen_string_literal: true

require 'rails_helper'
require 'rake'

RSpec.describe Rake::Task do
  include PqcKeyProvisioningHelpers

  describe 'pqc:generate_key' do
    subject(:task) { described_class['pqc:generate_key'] }

    let(:account) { Fabricate(:account, username: 'alice') }
    let(:public_key) { synthetic_ml_dsa_87_public_key }
    let(:private_key) { SigningKeysHelpers::PRIVATE_RSA_TEST_KEY }
    let(:native_key) { instance_double(OpenSSL::PKey::PKey, private_to_pem: private_key, public_to_pem: public_key) }

    around do |example|
      Rake.with_application do
        described_class.define_task(:environment)
        load Rails.root.join('lib', 'tasks', 'pqc.rake')
        example.run
      end
    end

    before do
      allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-87').and_return(native_key)
    end

    it 'provisions only the specified local account and outputs only the account and public key URI' do
      other_account = Fabricate(:account)
      other_key_count = other_account.keypairs.count
      account.keypairs.where(type: :'ml-dsa-87').delete_all
      key_count = Keypair.count

      ClimateControl.modify PQC_ACTIVITYPUB_SIGNING: 'false' do
        expect { task.invoke('alice') }.to output(%r{\AML-DSA-87 key available for @alice: https?://[^\n]+#ml-dsa-87-[a-f0-9]{32}\n\z}).to_stdout
      end

      expect(account.keypairs.find_by!(type: :'ml-dsa-87')).to have_attributes(public_key: public_key, private_key: private_key)
      expect(Keypair.count).to eq(key_count + 1)
      expect(other_account.keypairs.count).to eq(other_key_count)
    end

    it 'is idempotent when an administrator invokes it again' do
      account.keypairs.where(type: :'ml-dsa-87').delete_all

      expect { task.invoke('alice') }.to output(/ML-DSA-87 key available for @alice:/).to_stdout
      task.reenable
      existing_key = account.keypairs.find_by!(type: :'ml-dsa-87')
      existing_attributes = existing_key.attributes

      expect do
        expect { task.invoke('alice') }.to output(/ML-DSA-87 key available for @alice:/).to_stdout
      end.to_not change(Keypair, :count)
      expect(existing_key.reload.attributes).to eq(existing_attributes)
    end

    it 'explains that a missing argument requires one local username' do
      expect do
        expect { task.invoke }.to raise_error(SystemExit)
      end.to output(/one local username required/).to_stderr
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'reports an unknown local username without generating a key' do
      expect do
        expect { task.invoke('missing') }.to raise_error(SystemExit)
      end.to output(/Local account "missing" not found/).to_stderr
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'rejects a remote account handle' do
      Fabricate(:account, username: 'alice', domain: 'remote.example')

      expect do
        expect { task.invoke('alice@remote.example') }.to raise_error(SystemExit)
      end.to output(/Only local accounts can be provisioned/).to_stderr
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'does not provision a remote-only username' do
      remote_account = Fabricate(:account, username: 'alice', domain: 'remote.example')

      expect do
        expect { task.invoke('alice') }.to raise_error(SystemExit)
      end.to output(/remote accounts cannot be provisioned/).to_stderr
      expect(remote_account.keypairs.pluck(:type)).to eq(['rsa'])
      expect(OpenSSL::PKey).to_not have_received(:generate_key)
    end

    it 'reports unsupported runtimes without private key output or partial database changes' do
      account.keypairs.where(type: :'ml-dsa-87').delete_all
      allow(OpenSSL::PKey).to receive(:generate_key).with('ML-DSA-87').and_raise(OpenSSL::PKey::PKeyError, 'unsupported')

      expect do
        expect { task.invoke('alice') }.to raise_error(SystemExit)
      end.to output(/OpenSSL 3\.5 or newer/).to_stderr
      expect(account.keypairs.where(type: :'ml-dsa-87')).to be_empty
    end
  end
end
