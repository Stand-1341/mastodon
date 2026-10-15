# frozen_string_literal: true

require 'rails_helper'
require 'aws-sdk-s3'

RSpec.describe Pqc::PrivateMedia::Storage do
  describe '#each_object' do
    it 'lists every object under the private-media prefix in S3' do
      storage_key = "pqc-private-media/#{SecureRandom.uuid}"
      modified_at = 2.days.ago
      page = double(contents: [double(key: storage_key, last_modified: modified_at)])
      response = double
      allow(response).to receive(:each_page).and_yield(page)
      client = instance_double(Aws::S3::Client, list_objects_v2: response)
      allow(Aws::S3::Client).to receive(:new).and_return(client)

      objects = ClimateControl.modify(S3_ENABLED: 'true', S3_BUCKET: 'private-media') do
        described_class.new.each_object.to_a
      end

      expect(Aws::S3::Client).to have_received(:new).with(
        region: 'us-east-1', endpoint: nil, force_path_style: false,
        access_key_id: nil, secret_access_key: nil
      )
      expect(client).to have_received(:list_objects_v2).with(bucket: 'private-media', prefix: 'pqc-private-media/')
      expect(objects).to eq([[storage_key, modified_at]])
    end

    it 'ignores non-UUID files and symlinks in filesystem storage' do
      Dir.mktmpdir('pqc-private-media-list') do |storage_root|
        token = SecureRandom.uuid
        valid_path = Pathname.new(storage_root).join(token)
        File.binwrite(valid_path, 'ciphertext')
        File.binwrite(Pathname.new(storage_root).join('unrelated'), 'unrelated')
        File.symlink(valid_path, Pathname.new(storage_root).join(SecureRandom.uuid))

        objects = ClimateControl.modify(PQC_PRIVATE_MEDIA_ROOT: storage_root) do
          described_class.new.each_object.to_a
        end

        expect(objects.map(&:first)).to eq(["pqc-private-media/#{token}"])
      end
    end
  end
end
