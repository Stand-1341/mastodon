import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { rmSync, writeFileSync } from 'node:fs';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const timestamp = Math.floor(Date.now() / 1000).toString();
const nonce = randomUUID();
const deviceId = `interop-${randomUUID()}`;
const signedBytes = `Mastodon-PQC-Device-Auth-v1\nGET\n/api/v1/pqc_devices\n${timestamp}\n${nonce}\n${'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}`;
const keyPair = ml_dsa87.keygen();
const signature = ml_dsa87.sign(new TextEncoder().encode(signedBytes), keyPair.secretKey);
const fixturePath = '/tmp/pqc-noble-openssl-interoperability.json';
writeFileSync(fixturePath, JSON.stringify({ deviceId, timestamp, nonce, publicKey: Buffer.from(keyPair.publicKey).toString('base64'), signature: Buffer.from(signature).toString('base64') }));
keyPair.secretKey.fill(0);

const ruby = `
require 'json'
fixture = JSON.parse(File.read('${fixturePath}'))
account = Account.find_by!(username: ENV.fetch('PQC_TEST_ACCOUNT', 'pqcalice'))
ApplicationRecord.transaction do
  device = PqcDevice.create!(account:, device_id: fixture.fetch('deviceId'), fingerprint: '0' * 64, key_package: 'test', auth_public_key: Base64.strict_decode64(fixture.fetch('publicKey')))
  algorithm = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new(Pqc::Messaging::DeviceRequestAuthenticator::ML_DSA_87_OID)])
  spki = OpenSSL::ASN1::Sequence.new([algorithm, OpenSSL::ASN1::BitString.new(device[:auth_public_key])])
  pkey = OpenSSL::PKey.read(spki.to_der)
  env = Rack::MockRequest.env_for('/api/v1/pqc_devices', method: 'GET')
  env['rack.input'] = StringIO.new('')
  env['HTTP_X_PQC_DEVICE_ID'] = fixture.fetch('deviceId')
  env['HTTP_X_PQC_DEVICE_TIMESTAMP'] = fixture.fetch('timestamp')
  env['HTTP_X_PQC_DEVICE_NONCE'] = fixture.fetch('nonce')
  env['HTTP_X_PQC_DEVICE_SIGNATURE'] = fixture.fetch('signature')
  message = "Mastodon-PQC-Device-Auth-v1\nGET\n/api/v1/pqc_devices\n#{fixture.fetch('timestamp')}\n#{fixture.fetch('nonce')}\n#{Digest::SHA256.hexdigest('')}"
  puts "OpenSSL direct verify: #{pkey.verify(nil, Base64.strict_decode64(fixture.fetch('signature')), message)}"
  verified = Pqc::Messaging::DeviceRequestAuthenticator.call(request: ActionDispatch::Request.new(env), account:)
  raise 'Verifier authenticated the wrong device' unless verified.id == device.id
  puts 'Noble ML-DSA-87 signature accepted by Mastodon OpenSSL verifier'
  raise ActiveRecord::Rollback
end
`;

try {
  execFileSync('bin/rails', ['runner', ruby], { stdio: 'inherit' });
} finally {
  rmSync(fixturePath, { force: true });
}
