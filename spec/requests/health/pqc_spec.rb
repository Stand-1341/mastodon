# frozen_string_literal: true

require 'rails_helper'
# `lib/` is on the load path once the environment is booted; requiring the
# collector here mirrors the controller so `capability?` can be stubbed before
# the first request loads the controller.
require 'mastodon/prometheus_exporter/pqc_collector'

# Spec type is inferred from this file's path (spec/requests), like the other
# request specs in this repo.
RSpec.describe 'PQC health endpoint' do
  include PqcKeyProvisioningHelpers

  let(:collector) { Mastodon::PrometheusExporter::PqcCollector }
  let(:documented_keys) do
    %w(status capability signing_enabled accounts_with_key accounts_missing_key)
  end

  # Accounts provision an ML-DSA-87 key on creation when the runtime supports
  # it, so the host OpenSSL build must never decide the outcome of an example.
  # Deleting the keys explicitly pins the account to the "missing key" state.
  def remove_ml_dsa_keys(account)
    account.keypairs.where(type: :'ml-dsa-87').delete_all
  end

  describe 'GET /health/pqc' do
    # spec_helper loads db/seeds, which creates the instance actor as a local
    # account with only an RSA key. Without removing it, every count here starts
    # at one and the "empty database" examples could never mean what they say.
    before { Account.where(id: Account::INSTANCE_ACTOR_ID).delete_all }

    it 'responds with 200 without authentication' do
      get '/health/pqc'

      expect(response).to have_http_status(200)
      expect(response.media_type).to eq('application/json')
    end

    it 'returns exactly the documented keys' do
      get '/health/pqc'

      expect(response.parsed_body.keys).to contain_exactly(*documented_keys)
      expect([true, false]).to include(response.parsed_body['capability'])
      expect([true, false]).to include(response.parsed_body['signing_enabled'])
    end

    context 'with an empty database' do
      before do
        # `status` also reflects runtime capability, so pin it here: this
        # example is about an empty account set, not about the host OpenSSL.
        allow(collector).to receive(:capability?).and_return(true)
      end

      it 'reports ok' do
        ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: nil) do
          get '/health/pqc'

          expect(response.parsed_body).to include(
            'status' => 'ok',
            'signing_enabled' => true,
            'accounts_with_key' => 0,
            'accounts_missing_key' => 0
          )
        end
      end
    end

    context 'when the runtime cannot generate ML-DSA-87 keys' do
      before do
        allow(collector).to receive(:capability?).and_return(false)
      end

      it 'reports degraded even when no account is missing a key' do
        ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true') do
          get '/health/pqc'

          expect(response.parsed_body).to include(
            'status' => 'degraded',
            'capability' => false,
            'accounts_missing_key' => 0
          )
        end
      end
    end

    context 'when a local account has no usable ML-DSA-87 key' do
      before do
        allow(collector).to receive(:capability?).and_return(true)
        account = Fabricate(:account)
        remove_ml_dsa_keys(account)
      end

      it 'reports degraded and counts the account as missing a key' do
        ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'true') do
          get '/health/pqc'

          expect(response.parsed_body).to include(
            'status' => 'degraded',
            'signing_enabled' => true
          )
          expect(response.parsed_body['accounts_missing_key']).to be >= 1
        end
      end
    end

    context 'when signing is explicitly disabled' do
      before do
        account = Fabricate(:account)
        remove_ml_dsa_keys(account)
      end

      it 'reports ok because an explicit opt-out is not a fault' do
        ClimateControl.modify(PQC_ACTIVITYPUB_SIGNING: 'false') do
          get '/health/pqc'

          expect(response.parsed_body).to include(
            'status' => 'ok',
            'signing_enabled' => false
          )
          expect(response.parsed_body['accounts_missing_key']).to be >= 1
        end
      end
    end

    context 'with an account that has ML-DSA-87 key material' do
      let!(:account) { Fabricate(:account, username: 'pqc_health_probe') }

      before do
        remove_ml_dsa_keys(account)
        Fabricate(:keypair, account: account, type: :'ml-dsa-87', public_key: synthetic_ml_dsa_87_public_key)
      end

      it 'does not expose usernames or key material' do
        get '/health/pqc'

        expect(response.body).to_not include(account.username)
        expect(response.body).to_not include('PUBLIC KEY')
        expect(response.body).to_not include('PRIVATE KEY')
        expect(response.body).to_not include('ml-dsa')
        expect(response.parsed_body['accounts_with_key']).to be >= 1
      end
    end
  end
end
