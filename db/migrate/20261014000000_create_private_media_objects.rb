# frozen_string_literal: true

class CreatePrivateMediaObjects < ActiveRecord::Migration[8.1]
  def change
    create_table :private_media_objects do |t|
      t.references :account, null: false, foreign_key: true
      t.uuid :token, null: false
      t.string :storage_key, null: false
      t.string :content_type, null: false, default: 'application/octet-stream'
      t.bigint :byte_size, null: false
      t.text :wrapped_key, null: false
      t.string :key_encryption_provider, null: false
      t.string :nonce, null: false
      t.string :auth_tag, null: false

      t.timestamps
    end

    add_index :private_media_objects, :token, unique: true
    add_index :private_media_objects, :storage_key, unique: true
  end
end
