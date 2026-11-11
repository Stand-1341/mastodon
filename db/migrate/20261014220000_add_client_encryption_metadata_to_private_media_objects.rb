# frozen_string_literal: true

class AddClientEncryptionMetadataToPrivateMediaObjects < ActiveRecord::Migration[8.1]
  def change
    add_column :private_media_objects, :client_nonce, :string
    add_column :private_media_objects, :client_auth_tag, :string
    add_column :private_media_objects, :device_key_envelopes, :text
  end
end
