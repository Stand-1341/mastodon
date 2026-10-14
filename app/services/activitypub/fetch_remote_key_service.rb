# frozen_string_literal: true

class ActivityPub::FetchRemoteKeyService < BaseService
  include JsonLdHelper

  class Error < StandardError; end

  # Returns a usable keypair authorized by its actor
  # This is to be used when we know a key URI but don't know the associated account URI,
  # otherwise use `ActivityPub::FetchRemoteActorService`.
  def call(uri, suppress_errors: true, force_refresh: false)
    raise Error, 'No key URI given' if uri.blank?

    @suppress_errors = suppress_errors
    @force_refresh = force_refresh
    @uri = uri
    @json = fetch_resource(uri, false)

    raise Error, "Unable to fetch key JSON at #{uri}" if @json.nil?
    raise Error, "Unsupported JSON-LD context for document #{uri}" unless supported_context_for_type?(@json)
    raise Error, "Unexpected object type for key #{uri}" unless expected_type?
    return keypair_from_actor_json(@json['id'], @json) if actor_type?

    raise Error, "Invalid actor URI for key #{uri}" unless owner_uri.is_a?(String) && !unsupported_uri_scheme?(owner_uri)

    @owner = fetch_resource(owner_uri, true)

    raise Error, "Unable to fetch actor JSON #{owner_uri}" if @owner.nil?
    raise Error, "Unsupported JSON-LD context for document #{owner_uri}" unless supported_context?(@owner)
    raise Error, "Unexpected object type for actor #{owner_uri} (expected any of: #{SUPPORTED_TYPES})" unless expected_owner_type?

    unless confirmed_owner?
      # Prune withdrawn keys on refresh, but do not discover actors for unauthorized keys.
      find_actor(owner_uri, @owner, only_existing: true)
      raise Error, "publicKey id for #{owner_uri} does not correspond to #{@json['id']}"
    end

    keypair_from_actor_json(owner_uri, @owner)
  rescue Error => e
    Rails.logger.debug { "Fetching key #{uri} failed: #{e.message}" }
    raise unless suppress_errors
  end

  private

  def supported_context_for_type?(json)
    case @json['type']
    when 'Multikey'
      equals_or_includes?(json['@context'], 'https://www.w3.org/ns/cid/v1')
    else
      supported_context?(json) || (supported_security_context?(@json) && @json['owner'].present? && !actor_type?)
    end
  end

  def keypair_from_actor_json(actor_uri, actor_json)
    actor = find_actor(actor_uri, actor_json)
    return if actor.nil?

    keypair = actor.keypairs.find_by(uri: @uri)
    return keypair if keypair&.usable?
    return if keypair.present?

    Keypair.from_legacy_account(actor, uri: @uri) if actor.public_key.present?
  end

  def find_actor(uri, prefetched_body, only_existing: false)
    # Profile freshness alone does not imply that the requested key is known or usable.
    # Explicit refreshes also revalidate the actor's authorization of an otherwise usable key.
    actor = ActivityPub::TagManager.instance.uri_to_actor(uri)
    return if actor.nil? && only_existing
    return actor if !@force_refresh && actor.present? && !actor.possibly_stale? && actor.keypairs.find_by(uri: @uri)&.usable?

    ActivityPub::FetchRemoteActorService.new.call(uri, prefetched_body: prefetched_body, suppress_errors: @suppress_errors)
  end

  def expected_type?
    actor_type? || public_key?
  end

  def actor_type?
    equals_or_includes_any?(@json['type'], ActivityPub::FetchRemoteActorService::SUPPORTED_TYPES)
  end

  def public_key?
    if @json['type'] == 'Multikey'
      @json['publicKeyMultibase'].present? && @json['controller'].present?
    else
      @json['publicKeyPem'].present? && @json['owner'].present?
    end
  end

  def owner_uri
    value = @json[@json['type'] == 'Multikey' ? 'controller' : 'owner']
    value.is_a?(Hash) ? value['id'] : value
  end

  def expected_owner_type?
    equals_or_includes_any?(@owner['type'], ActivityPub::FetchRemoteActorService::SUPPORTED_TYPES)
  end

  def confirmed_owner?
    case @json['type']
    when 'Multikey'
      as_array(@owner['assertionMethod']).map { |value| value_or_id(value) }.include?(@json['id'])
    else
      as_array(@owner['publicKey']).map { |value| value_or_id(value) }.include?(@json['id'])
    end
  end
end
