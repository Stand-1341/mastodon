# frozen_string_literal: true

class CreatePqcMessagingRelay < ActiveRecord::Migration[8.1]
  def change
    create_table :pqc_devices do |t|
      t.references :account, null: false, foreign_key: true
      t.string :device_id, null: false
      t.string :fingerprint, null: false
      t.binary :key_package, null: false
      t.datetime :key_package_consumed_at
      t.datetime :revoked_at

      t.timestamps
    end

    add_index :pqc_devices, [:account_id, :device_id], unique: true

    create_table :pqc_conversations do |t|
      t.references :creator_account, null: false, foreign_key: { to_table: :accounts }
      t.uuid :token, null: false, default: -> { 'gen_random_uuid()' }

      t.timestamps
    end

    add_index :pqc_conversations, :token, unique: true

    create_table :pqc_conversation_members do |t|
      t.references :pqc_conversation, null: false, foreign_key: true
      t.references :account, null: false, foreign_key: true

      t.timestamps
    end

    add_index :pqc_conversation_members, [:pqc_conversation_id, :account_id], unique: true, name: 'index_pqc_members_on_conversation_and_account'
    add_index :pqc_conversation_members, [:account_id, :pqc_conversation_id], name: 'index_pqc_members_on_account_and_conversation'

    create_table :pqc_messages do |t|
      t.references :pqc_conversation, null: false, foreign_key: true
      t.references :account, null: false, foreign_key: true
      t.binary :ciphertext, null: false

      t.timestamps
    end

    add_index :pqc_messages, [:pqc_conversation_id, :id]
  end
end
