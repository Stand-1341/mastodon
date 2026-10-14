# frozen_string_literal: true

require 'rails_helper'

RSpec.describe 'Data Integrity v2 context' do # rubocop:disable RSpec/DescribeClass
  include JsonLdHelper

  let(:context_url) { 'https://w3id.org/security/data-integrity/v2' }
  let(:security) { 'https://w3id.org/security#' }
  let(:date_time) { 'http://www.w3.org/2001/XMLSchema#dateTime' }
  let(:proof) do
    {
      'type' => 'DataIntegrityProof',
      'created' => '2026-10-13T12:00:00Z',
      'expires' => '2026-10-14T12:00:00Z',
      'cryptosuite' => 'mldsa44-jcs-2024',
      'verificationMethod' => 'https://example.com/actor#multikey',
      'proofPurpose' => 'assertionMethod',
      'proofValue' => 'z1234',
      'challenge' => 'challenge',
      'domain' => 'example.com',
      'nonce' => 'nonce',
      'previousProof' => 'https://example.com/proofs/previous',
    }
  end
  let(:expected_proof) do
    {
      '@type' => ["#{security}DataIntegrityProof"],
      'http://purl.org/dc/terms/created' => [{ '@value' => proof['created'], '@type' => date_time }],
      "#{security}expiration" => [{ '@value' => proof['expires'], '@type' => date_time }],
      "#{security}cryptosuite" => [{ '@value' => proof['cryptosuite'], '@type' => "#{security}cryptosuiteString" }],
      "#{security}verificationMethod" => [{ '@id' => proof['verificationMethod'] }],
      "#{security}proofPurpose" => [{ '@id' => "#{security}assertionMethod" }],
      "#{security}proofValue" => [{ '@value' => proof['proofValue'], '@type' => "#{security}multibase" }],
      "#{security}challenge" => [{ '@value' => proof['challenge'] }],
      "#{security}domain" => [{ '@value' => proof['domain'] }],
      "#{security}nonce" => [{ '@value' => proof['nonce'] }],
      "#{security}previousProof" => [{ '@id' => proof['previousProof'] }],
    }
  end
  let(:contexts) do
    [
      'https://www.w3.org/ns/activitystreams',
      'https://w3id.org/security/v1',
      'https://www.w3.org/ns/cid/v1',
      context_url,
    ]
  end
  let(:activity) do
    {
      '@context' => contexts,
      'id' => 'https://example.com/activities/1',
      'type' => 'Create',
      'actor' => 'https://example.com/actor',
      'object' => {
        'id' => 'https://example.com/notes/1',
        'type' => 'Note',
        'content' => 'Hello world',
      },
      'proof' => proof,
    }
  end

  before do
    allow(self).to receive(:load_jsonld_context).and_raise('Unexpected remote JSON-LD context download')
  end

  describe 'offline preloading' do
    it 'expands the complete type-scoped proof with the official IRIs and datatypes' do
      expect(expand(proof.merge('@context' => context_url))).to eq([expected_proof])
      expect(self).to_not have_received(:load_jsonld_context)
    end

    it 'also preloads the HTTP alias' do
      expect(expand(proof.merge('@context' => context_url.sub('https:', 'http:')))).to eq([expected_proof])
    end

    it 'uses the official graph container for proofs' do
      document = { '@context' => context_url, 'id' => activity['id'], 'proof' => proof }

      expect(expand(document)).to eq(
        [
          {
            '@id' => activity['id'],
            "#{security}proof" => [{ '@graph' => [expected_proof] }],
          },
        ]
      )
    end

    it 'does not apply DataIntegrityProof terms outside the type-scoped context' do
      document = { '@context' => context_url, 'id' => activity['id'], 'cryptosuite' => proof['cryptosuite'], 'proofValue' => proof['proofValue'], 'created' => proof['created'], 'proof' => proof }

      expect(expand(document).first.keys).to contain_exactly('@id', "#{security}proof")
    end

    it 'preserves protected term definitions' do
      document = proof.merge('@context' => [context_url, { 'proof' => 'https://example.com/proof' }])

      expect { expand(document) }.to raise_error(JSON::LD::JsonLdError::ProtectedTermRedefinition)
    end

    {
      'assertionMethod' => 'assertionMethod',
      'authentication' => 'authenticationMethod',
      'capabilityInvocation' => 'capabilityInvocationMethod',
      'capabilityDelegation' => 'capabilityDelegationMethod',
      'keyAgreement' => 'keyAgreementMethod',
    }.each do |purpose, term|
      it "expands the #{purpose} proof purpose as a vocabulary IRI" do
        document = proof.merge('@context' => context_url, 'proofPurpose' => purpose)

        expect(expand(document).first["#{security}proofPurpose"]).to eq([{ '@id' => "#{security}#{term}" }])
      end
    end
  end

  describe 'layering with ActivityStreams, security/v1 and CID' do
    it 'preserves the ActivityStreams object and the scoped proof graph' do
      expanded = expand(activity).first

      expect(expanded['@type']).to eq(['https://www.w3.org/ns/activitystreams#Create'])
      expect(expanded['https://www.w3.org/ns/activitystreams#object'].first).to include(
        '@id' => activity['object']['id'],
        '@type' => ['https://www.w3.org/ns/activitystreams#Note'],
        'https://www.w3.org/ns/activitystreams#content' => [{ '@value' => 'Hello world' }]
      )
      expect(expanded["#{security}proof"]).to eq([{ '@graph' => [expected_proof] }])
    end

    it 'preserves CID Multikey terms alongside a Data Integrity proof' do
      document = {
        '@context' => contexts,
        'id' => 'https://example.com/actor',
        'type' => 'Person',
        'assertionMethod' => {
          'id' => proof['verificationMethod'],
          'type' => 'Multikey',
          'controller' => 'https://example.com/actor',
          'publicKeyMultibase' => 'z5678',
        },
        'proof' => proof,
      }
      expanded = expand(document).first

      expect(expanded["#{security}assertionMethod"]).to eq(
        [
          {
            '@id' => proof['verificationMethod'],
            '@type' => ["#{security}Multikey"],
            "#{security}controller" => [{ '@id' => document['id'] }],
            "#{security}publicKeyMultibase" => [{ '@value' => 'z5678', '@type' => "#{security}multibase" }],
          },
        ]
      )
      expect(expanded["#{security}proof"]).to eq([{ '@graph' => [expected_proof] }])
    end

    it 'preserves legacy RSA signature terms without applying the proof scope to them' do
      signature = {
        'created' => proof['created'],
        'expires' => proof['expires'],
        'creator' => 'https://example.com/actor#main-key',
        'signatureValue' => 'rsa-signature',
      }
      expanded = expand(activity.merge('signature' => signature)).first

      expect(expanded["#{security}signature"]).to eq(
        [
          {
            'http://purl.org/dc/terms/created' => [{ '@value' => signature['created'], '@type' => date_time }],
            "#{security}expiration" => [{ '@value' => signature['expires'], '@type' => date_time }],
            'http://purl.org/dc/terms/creator' => [{ '@id' => signature['creator'] }],
            "#{security}signatureValue" => [{ '@value' => signature['signatureValue'] }],
          },
        ]
      )
    end

    it 'does not change the canonical activity graph just by adding the v2 context' do
      document = activity.without('proof')
      original_document = document.merge('@context' => contexts.without(context_url))

      expect(canonicalize(document)).to eq(canonicalize(original_document))
    end

    context 'when the proof carries its own local context' do
      let(:activity) do
        super().merge('@context' => contexts.without(context_url), 'proof' => proof.merge('@context' => context_url))
      end

      it 'retains proof triples during canonicalization' do
        expect(canonicalize(activity)).to include(
          "<#{security}DataIntegrityProof>",
          "<#{security}cryptosuite>",
          "\"#{proof['proofValue']}\"^^<#{security}multibase>"
        )
      end
    end
  end

  describe 'the canonical document hash used by RSA signatures' do
    let(:document) { activity.merge('signature' => { 'signatureValue' => 'not-part-of-document-hash' }).without('signature') }

    it 'canonicalizes offline and includes the proof value and metadata' do
      expect(canonicalize(document)).to include(
        "<#{security}DataIntegrityProof>",
        '<http://purl.org/dc/terms/created>',
        "<#{security}expiration>",
        "<#{security}verificationMethod> <#{proof['verificationMethod']}>",
        "<#{security}proofPurpose> <#{security}assertionMethod>",
        "\"#{proof['cryptosuite']}\"^^<#{security}cryptosuiteString>",
        "\"#{proof['proofValue']}\"^^<#{security}multibase>"
      )
      expect(self).to_not have_received(:load_jsonld_context)
    end

    it 'changes when the proof value or any scoped proof metadata is changed' do
      original_hash = Digest::SHA256.hexdigest(canonicalize(document))

      proof.except('type').each do |term, value|
        changed_value = case term
                        when 'created', 'expires'
                          (Time.iso8601(value) + 1.second).iso8601
                        when 'proofPurpose'
                          'authentication'
                        else
                          "#{value}-changed"
                        end
        changed_document = document.merge('proof' => proof.merge(term => changed_value))

        expect(Digest::SHA256.hexdigest(canonicalize(changed_document))).to_not eq(original_hash), "Changing #{term} must change the canonical document hash"
      end
    end

    it 'changes when the proof is removed' do
      expect(Digest::SHA256.hexdigest(canonicalize(document.without('proof')))).to_not eq(Digest::SHA256.hexdigest(canonicalize(document)))
    end
  end

  def expand(document)
    JSON::LD::API.expand(document, documentLoader: method(:load_jsonld_context))
  end
end
