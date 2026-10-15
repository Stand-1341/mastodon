# frozen_string_literal: true

# == Schema Information
#
# Table name: pqc_conversations
#
#  id                 :bigint(8)        not null, primary key
#  ready_at           :datetime
#  token              :uuid             not null
#  created_at         :datetime         not null
#  updated_at         :datetime         not null
#  creator_account_id :bigint(8)        not null
#  setup_device_id    :string
#
class PqcConversation < ApplicationRecord
  before_validation :assign_token, on: :create

  belongs_to :creator_account, class_name: 'Account'
  has_many :pqc_conversation_members, dependent: :destroy
  has_many :accounts, through: :pqc_conversation_members
  has_many :pqc_messages, dependent: :delete_all
  has_many :pqc_member_removals, dependent: :delete_all
  has_many :pqc_conversation_devices, dependent: :delete_all
  has_many :pqc_member_additions, dependent: :delete_all

  validates :token, presence: true, uniqueness: true

  private

  def assign_token
    self.token ||= SecureRandom.uuid
  end
end
