# frozen_string_literal: true

class ActivityPub::MultikeySerializer < ActivityPub::Serializer
  context :controlled_identifiers

  attributes :id, :type, :controller, :public_key_multibase

  attribute :expires, if: -> { object.expires_at.present? }

  def id
    object.full_uri
  end

  def type
    'Multikey'
  end

  def controller
    ActivityPub::TagManager.instance.uri_for(object.actor)
  end

  def public_key_multibase
    Multibase.encode_key_from_pem(object.public_key, type: object.type)
  end

  def expires
    object.expires_at.iso8601
  end
end
