# frozen_string_literal: true

module Pqc
  module PrivateMedia
    class Storage
      class StorageError < StandardError; end

      def write(storage_key, data)
        if s3_enabled?
          s3_client.put_object(bucket: s3_bucket, key: storage_key, body: data, content_type: 'application/octet-stream')
        else
          path = filesystem_path(storage_key)
          FileUtils.mkdir_p(path.dirname)
          temporary_path = "#{path}.#{SecureRandom.hex(8)}.tmp"
          File.open(temporary_path, 'wb', 0o600) { |file| file.write(data) }
          File.rename(temporary_path, path)
        end
      rescue => e
        raise StorageError, "Private media write failed: #{e.class}"
      ensure
        FileUtils.rm_f(temporary_path) if defined?(temporary_path) && temporary_path.present?
      end

      def read(storage_key)
        if s3_enabled?
          s3_client.get_object(bucket: s3_bucket, key: storage_key).body.read
        else
          File.binread(filesystem_path(storage_key))
        end
      rescue => e
        raise StorageError, "Private media read failed: #{e.class}"
      end

      def delete(storage_key)
        if s3_enabled?
          s3_client.delete_object(bucket: s3_bucket, key: storage_key)
        else
          FileUtils.rm_f(filesystem_path(storage_key))
        end
      rescue => e
        raise StorageError, "Private media delete failed: #{e.class}"
      end

      def each_object
        return enum_for(:each_object) unless block_given?

        if s3_enabled?
          s3_client.list_objects_v2(bucket: s3_bucket, prefix: 'pqc-private-media/').each_page do |page|
            page.contents.each { |object| yield object.key, object.last_modified }
          end
        else
          root = private_media_root
          Dir.glob(root.join('*')).each do |path|
            next if File.symlink?(path) || !File.file?(path)

            token = File.basename(path)
            yield "pqc-private-media/#{token}", File.mtime(path) if token.match?(/\A[0-9a-f-]{36}\z/i)
          end
        end
      rescue => e
        raise StorageError, "Private media listing failed: #{e.class}"
      end

      private

      def s3_enabled?
        ENV['S3_ENABLED'] == 'true'
      end

      def s3_client
        require 'aws-sdk-s3'

        Aws::S3::Client.new(
          region: ENV.fetch('S3_REGION', 'us-east-1'),
          endpoint: ENV.fetch('S3_ENDPOINT', nil),
          force_path_style: ENV.key?('S3_ENDPOINT') && ENV['S3_OVERRIDE_PATH_STYLE'] != 'true',
          access_key_id: ENV.fetch('AWS_ACCESS_KEY_ID', nil),
          secret_access_key: ENV.fetch('AWS_SECRET_ACCESS_KEY', nil)
        )
      end

      def s3_bucket
        ENV.fetch('S3_BUCKET')
      end

      def filesystem_path(storage_key)
        token = storage_key.delete_prefix('pqc-private-media/')
        raise StorageError, 'Invalid private media storage key' unless token.match?(/\A[0-9a-f-]{36}\z/i)

        root = private_media_root
        path = root.join(token).cleanpath
        raise StorageError, 'Invalid private media storage path' unless path.dirname == root

        path
      end

      def private_media_root
        Pathname.new(ENV.fetch('PQC_PRIVATE_MEDIA_ROOT') { Rails.root.join('storage', 'pqc-private-media') }).expand_path
      end
    end
  end
end
