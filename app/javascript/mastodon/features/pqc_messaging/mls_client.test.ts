import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  createApplicationMessage,
  createCommit,
  createGroup,
  decode,
  defaultProposalTypes,
  joinGroup,
  keyPackageDecoder,
  mlsMessageDecoder,
  mlsMessageEncoder,
  privateKeyPackageDecoder,
  processMessage,
  protocolVersions,
  wireformats,
  encode,
} from 'ts-mls';

import {
  addPqcGroupMember,
  createPqcApplicationMessage,
  createPqcCommit,
  createPqcGroup,
  createPqcMlsContext,
  deserializePqcGroupState,
  createPqcAttachmentEnvelope,
  decodePqcAttachmentEnvelope,
  fingerprintPublicKey,
  generatePqcDeviceKeyPackage,
  getPqcMlsCiphersuite,
  joinPqcGroup,
  processPqcApplicationMessage,
  processPqcMessage,
  pqcDeviceAuthPublicKey,
  PQC_MLS_CIPHERSUITE_ID,
  restorePqcGroupState,
  rotatePqcDeviceKeyPackage,
  removePqcGroupMembers,
  restorePqcRecoveryData,
  sealPqcGroupState,
  sealPqcRecoveryData,
  serializePqcGroupState,
  signPqcDeviceRequest,
  sealVerifiedPqcRecoveryData,
  trustPqcDevice,
  verifyPqcDeviceBinding,
} from './mls_client';
import {
  decryptPqcPrivateMedia,
  encryptPqcPrivateMedia,
} from './private_media';

describe('PQC MLS client', () => {
  it('accepts only the unified ML-DSA-87 MLS suite', async () => {
    await expect(getPqcMlsCiphersuite(0x0052)).rejects.toThrow(
      'Unsupported MLS cipher suite 0x0052',
    );
    await expect(
      getPqcMlsCiphersuite(PQC_MLS_CIPHERSUITE_ID),
    ).resolves.toBeDefined();
  });

  it('encrypts and decrypts private media with a device-bound envelope', async () => {
    const recipient = ml_kem1024.keygen();
    const plaintext = new TextEncoder().encode('private media bytes');
    const token = 'b2d2dc46-96f7-4f5b-8a83-949bc86c8159';
    const encrypted = await encryptPqcPrivateMedia(
      plaintext,
      'browser-device',
      recipient.publicKey,
      '123456',
      token,
    );

    await expect(
      decryptPqcPrivateMedia(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.authTag,
        encrypted.envelope,
        'browser-device',
        recipient.secretKey,
        '123456',
        token,
      ),
    ).resolves.toSatisfy((actual: Uint8Array) => {
      const matches = actual.every((byte, index) => byte === plaintext[index]);
      actual.fill(0);
      return matches;
    });
    const uppercaseToken = token.toUpperCase();
    const uppercaseEncrypted = await encryptPqcPrivateMedia(
      plaintext,
      'browser-device',
      recipient.publicKey,
      '123456',
      uppercaseToken,
    );
    expect(uppercaseEncrypted.token).toBe(token);
    await expect(
      decryptPqcPrivateMedia(
        uppercaseEncrypted.ciphertext,
        uppercaseEncrypted.nonce,
        uppercaseEncrypted.authTag,
        uppercaseEncrypted.envelope,
        'browser-device',
        recipient.secretKey,
        '123456',
        uppercaseToken,
      ),
    ).resolves.toSatisfy((actual: Uint8Array) => {
      const matches = actual.every((byte, index) => byte === plaintext[index]);
      actual.fill(0);
      return matches;
    });
    const wrongDeviceEnvelope = { ...encrypted.envelope };
    await expect(
      decryptPqcPrivateMedia(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.authTag,
        wrongDeviceEnvelope,
        'different-device',
        recipient.secretKey,
        '123456',
        token,
      ),
    ).rejects.toThrow(/another device/);
    wrongDeviceEnvelope.kem_ciphertext = '';
    wrongDeviceEnvelope.wrapped_key = '';
    const wrongAccountEnvelope = { ...encrypted.envelope };
    await expect(
      decryptPqcPrivateMedia(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.authTag,
        wrongAccountEnvelope,
        'browser-device',
        recipient.secretKey,
        '654321',
        token,
      ),
    ).rejects.toThrow(/authenticated/);
    wrongAccountEnvelope.kem_ciphertext = '';
    wrongAccountEnvelope.wrapped_key = '';
    uppercaseEncrypted.ciphertext.fill(0);
    uppercaseEncrypted.nonce.fill(0);
    uppercaseEncrypted.authTag.fill(0);
    uppercaseEncrypted.envelope.kem_ciphertext = '';
    uppercaseEncrypted.envelope.wrapped_key = '';
    encrypted.ciphertext.fill(0);
    encrypted.nonce.fill(0);
    encrypted.authTag.fill(0);
    encrypted.envelope.kem_ciphertext = '';
    encrypted.envelope.wrapped_key = '';
    plaintext.fill(0);
    recipient.publicKey.fill(0);
    recipient.secretKey.fill(0);
  });

  it('rejects empty, oversized, and malformed private media inputs before decryption', async () => {
    const recipient = ml_kem1024.keygen();
    const maximum = await encryptPqcPrivateMedia(
      new Uint8Array(32 * 1024 * 1024),
      'browser-device',
      recipient.publicKey,
      '123456',
      '45dc1248-c9b7-44a2-96f4-63f90886b1bf',
    );
    expect(maximum.ciphertext).toHaveLength(32 * 1024 * 1024);
    maximum.ciphertext.fill(0);
    maximum.nonce.fill(0);
    maximum.authTag.fill(0);
    maximum.envelope.kem_ciphertext = '';
    maximum.envelope.wrapped_key = '';
    const valid = await encryptPqcPrivateMedia(
      new Uint8Array([7]),
      'browser-device',
      recipient.publicKey,
      '123456',
      '4da9d561-d705-436b-8dc7-ed10aa215af7',
    );

    await expect(
      decryptPqcPrivateMedia(
        new Uint8Array(),
        valid.nonce,
        valid.authTag,
        valid.envelope,
        'browser-device',
        recipient.secretKey,
        '123456',
        valid.token,
      ),
    ).rejects.toThrow(/metadata/);
    await expect(
      encryptPqcPrivateMedia(
        new Uint8Array(32 * 1024 * 1024 + 1),
        'browser-device',
        recipient.publicKey,
        '123456',
        valid.token,
      ),
    ).rejects.toThrow(/32 MiB/);
    await expect(
      decryptPqcPrivateMedia(
        valid.ciphertext,
        valid.nonce,
        valid.authTag,
        { ...valid.envelope, kem_ciphertext: '%%%=' },
        'browser-device',
        recipient.secretKey,
        '123456',
        valid.token,
      ),
    ).rejects.toThrow();
    await expect(
      decryptPqcPrivateMedia(
        valid.ciphertext,
        valid.nonce,
        valid.authTag,
        { ...valid.envelope, wrapped_key: '%%%=' },
        'browser-device',
        recipient.secretKey,
        '123456',
        valid.token,
      ),
    ).rejects.toThrow();
    valid.ciphertext.fill(0);
    valid.nonce.fill(0);
    valid.authTag.fill(0);
    valid.envelope.kem_ciphertext = '';
    valid.envelope.wrapped_key = '';
    maximum.envelope.kem_ciphertext = '';
    maximum.envelope.wrapped_key = '';
    recipient.publicKey.fill(0);
    recipient.secretKey.fill(0);
  });

  it('rejects modified encrypted private media bytes', async () => {
    const recipient = ml_kem1024.keygen();
    const encrypted = await encryptPqcPrivateMedia(
      new TextEncoder().encode('authenticated media'),
      'browser-device',
      recipient.publicKey,
      '123456',
      '3d7b2b0c-6c3d-4ec2-a311-c1d011cf74bc',
    );
    encrypted.ciphertext[0] = (encrypted.ciphertext[0] ?? 0) ^ 1;

    await expect(
      decryptPqcPrivateMedia(
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.authTag,
        encrypted.envelope,
        'browser-device',
        recipient.secretKey,
        '123456',
        encrypted.token,
      ),
    ).rejects.toThrow(/authenticated/);
    recipient.secretKey.fill(0);
    encrypted.ciphertext.fill(0);
    encrypted.envelope.kem_ciphertext = '';
    encrypted.envelope.wrapped_key = '';
    encrypted.nonce.fill(0);
    encrypted.authTag.fill(0);
  });

  it('uses the same ML-DSA-87 device identity for MLS and HTTP authentication', async () => {
    const device = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
    );
    const mlsPackage = required(
      decode(keyPackageDecoder, device.publicPackage),
    );
    const mlsPublicKey = mlsPackage.leafNode.signaturePublicKey;
    const body = '{"message":"test"}';
    const method = 'POST';
    const path = '/api/v1/pqc_conversations/test/messages';
    const timestamp = '1792000000';
    const nonce = 'a33b1dd8-e9b5-4f5c-99f8-92b2b9f73b63';
    const bodyDigest = Array.from(
      new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)),
      ),
      (byte) => byte.toString(16).padStart(2, '0'),
    ).join('');
    const signed = `Mastodon-PQC-Device-Auth-v1\n${method}\n${path}\n${timestamp}\n${nonce}\n${bodyDigest}`;
    const signature = await signPqcDeviceRequest(
      device,
      method,
      path,
      timestamp,
      nonce,
      body,
    );

    expect(pqcDeviceAuthPublicKey(device)).toEqual(mlsPublicKey);
    expect(device.mediaKemPublicKey).toHaveLength(1568);
    expect(device.mediaKemPrivateKey).toHaveLength(3168);
    expect(
      ml_kem1024.getPublicKey(device.mediaKemPrivateKey ?? new Uint8Array()),
    ).toEqual(device.mediaKemPublicKey);
    expect(
      ml_dsa87.verify(
        signature,
        new TextEncoder().encode(signed),
        mlsPublicKey,
      ),
    ).toBe(true);
    expect(await fingerprintPublicKey(mlsPublicKey)).toBe(device.fingerprint);
  });

  it('verifies that an account ML-DSA-87 key certified a messaging device', async () => {
    const actorUri = 'https://example.test/users/alice';
    const deviceId = 'alice-device';
    const keyPair = ml_dsa87.keygen();
    const fingerprint = await fingerprintPublicKey(keyPair.publicKey);
    const verificationMethod = `${actorUri}#ml-dsa-87-test`;
    const issuedAt = 1792000000;
    const ciphersuiteId = '0xf011';
    const message = [
      'Mastodon-PQC-Device-Binding-v1',
      actorUri,
      deviceId,
      fingerprint,
      ciphersuiteId,
      verificationMethod,
      issuedAt,
    ].join('\n');
    const signature = ml_dsa87.sign(
      new TextEncoder().encode(message),
      keyPair.secretKey,
    );
    const taggedPublicKey = new Uint8Array(2594);
    taggedPublicKey.set([0x92, 0x24]);
    taggedPublicKey.set(keyPair.publicKey, 2);
    const multibase = `u${btoa(String.fromCharCode(...taggedPublicKey))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')}`;
    const toBase64Url = (bytes: Uint8Array) =>
      `u${btoa(String.fromCharCode(...bytes))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')}`;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            id: actorUri,
            assertionMethod: [
              {
                id: verificationMethod,
                type: 'Multikey',
                controller: actorUri,
                publicKeyMultibase: multibase,
              },
            ],
          }),
      }),
    );

    await expect(
      verifyPqcDeviceBinding(
        {
          version: 1,
          actor_uri: actorUri,
          device_id: deviceId,
          fingerprint,
          ciphersuite_id: ciphersuiteId,
          verification_method: verificationMethod,
          issued_at: issuedAt,
          signature: toBase64Url(signature),
        },
        actorUri,
        deviceId,
        fingerprint,
      ),
    ).resolves.toBe(true);
    vi.unstubAllGlobals();
  });

  it('supports a raw two-device exchange in the selected library suite', async () => {
    const aliceKeys = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
    );
    const bobKeys = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-device',
    );
    const trusted = new Map<string, string>([
      [aliceKeys.identity, aliceKeys.fingerprint],
      [bobKeys.identity, bobKeys.fingerprint],
    ]);
    const alicePublic = required(
      decode(keyPackageDecoder, aliceKeys.publicPackage),
    );
    const bobPublic = required(
      decode(keyPackageDecoder, bobKeys.publicPackage),
    );
    const alicePrivate = required(
      decode(privateKeyPackageDecoder, aliceKeys.privatePackage),
    );
    const bobPrivate = required(
      decode(privateKeyPackageDecoder, bobKeys.privatePackage),
    );
    const context = await createPqcMlsContext(trusted);
    const aliceState = await createGroup({
      context,
      groupId: new TextEncoder().encode('raw-test'),
      keyPackage: alicePublic,
      privateKeyPackage: alicePrivate,
    });
    const keyPackageMessage = encode(mlsMessageEncoder, {
      keyPackage: bobPublic,
      wireformat: wireformats.mls_key_package,
      version: protocolVersions.mls10,
    });
    const bobMessage = required(mlsMessageDecoder(keyPackageMessage, 0))[0];
    if (bobMessage.wireformat !== wireformats.mls_key_package)
      throw new Error('Expected an MLS KeyPackage');
    const commit = await createCommit({
      context,
      state: aliceState,
      extraProposals: [
        {
          proposalType: defaultProposalTypes.add,
          add: { keyPackage: bobMessage.keyPackage },
        },
      ],
    });
    const welcomeBytes = encode(mlsMessageEncoder, required(commit.welcome));
    const welcomeMessage = required(mlsMessageDecoder(welcomeBytes, 0))[0];
    if (welcomeMessage.wireformat !== wireformats.mls_welcome)
      throw new Error('Expected an MLS Welcome');
    const bobState = await joinGroup({
      context,
      welcome: welcomeMessage.welcome,
      keyPackage: bobPublic,
      privateKeys: bobPrivate,
      ratchetTree: commit.newState.ratchetTree,
    });
    const sent = await createApplicationMessage({
      context,
      state: commit.newState,
      message: new TextEncoder().encode('raw round trip'),
    });
    const messageBytes = encode(mlsMessageEncoder, sent.message);
    const message = required(mlsMessageDecoder(messageBytes, 0))[0];
    if (message.wireformat !== wireformats.mls_private_message)
      throw new Error('Expected an MLS private message');
    const received = await processMessage({
      context,
      state: bobState,
      message,
    });
    if (received.kind === 'newState')
      throw new Error('Expected application data');
    expect(new TextDecoder().decode(received.message)).toBe('raw round trip');
    aliceKeys.privatePackage.fill(0);
    bobKeys.privatePackage.fill(0);
  });

  it('creates a hybrid group and exchanges an encrypted message between fingerprint-trusted devices', async () => {
    const testEnv = import.meta.env as Record<
      string,
      string | boolean | undefined
    >;
    const alice = await generatePqcDeviceKeyPackage(
      typeof testEnv.VITE_PQC_TEST_ALICE_URI === 'string'
        ? testEnv.VITE_PQC_TEST_ALICE_URI
        : 'https://example.test/users/alice',
      'alice-device',
    );
    const bob = await generatePqcDeviceKeyPackage(
      typeof testEnv.VITE_PQC_TEST_BOB_URI === 'string'
        ? testEnv.VITE_PQC_TEST_BOB_URI
        : 'https://example.test/users/bob',
      'bob-device',
    );
    const aliceTrust = new Map<string, string>();
    const bobTrust = new Map<string, string>();
    trustPqcDevice(aliceTrust, alice.identity, alice.fingerprint);
    trustPqcDevice(aliceTrust, bob.identity, bob.fingerprint);
    trustPqcDevice(bobTrust, alice.identity, alice.fingerprint);
    trustPqcDevice(bobTrust, bob.identity, bob.fingerprint);

    try {
      const aliceContext = await createPqcMlsContext(aliceTrust);
      const bobContext = await createPqcMlsContext(bobTrust);
      const aliceState = await createPqcGroup(
        aliceContext,
        'capstone-test-group',
        alice,
      );
      const added = await addPqcGroupMember(
        aliceContext,
        aliceState,
        bob.keyPackageMessage,
      );
      const joinedBobState = await joinPqcGroup(bobContext, added.welcome, bob);
      const commit = await createPqcCommit(aliceContext, added.state);
      const updatedBob = await processPqcMessage(
        bobContext,
        joinedBobState,
        commit.ciphertext,
      );
      expect(updatedBob.kind).toBe('state');
      const sealedState = await sealPqcGroupState(
        commit.state,
        'capstone test state passphrase',
      );
      const restoredAliceState = await restorePqcGroupState(
        sealedState,
        'capstone test state passphrase',
      );
      const serializedState = serializePqcGroupState(restoredAliceState);
      const restoredLocalState = deserializePqcGroupState(serializedState);
      await expect(
        restorePqcGroupState(sealedState, 'incorrect passphrase'),
      ).rejects.toThrow(/Unable to decrypt/);
      const sent = await createPqcApplicationMessage(
        aliceContext,
        restoredLocalState,
        'post-quantum encrypted message',
      );
      const received = await processPqcApplicationMessage(
        bobContext,
        updatedBob.state,
        sent.ciphertext,
      );

      expect(received.plaintext).toBe('post-quantum encrypted message');
      expect(received.state).toBeDefined();
    } finally {
      aliceTrust.clear();
      bobTrust.clear();
      alice.publicPackage.fill(0);
      alice.keyPackageMessage.fill(0);
      bob.publicPackage.fill(0);
      bob.keyPackageMessage.fill(0);
    }
  });

  it('encrypts attachments inside the ML-DSA-87-authenticated MLS message and verifies their digest', async () => {
    const alice = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-attachment-device',
    );
    const bob = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-attachment-device',
    );
    const trusted = new Map<string, string>([
      [alice.identity, alice.fingerprint],
      [bob.identity, bob.fingerprint],
    ]);

    try {
      const context = await createPqcMlsContext(trusted);
      const aliceState = await createPqcGroup(
        context,
        'attachment-authentication-test',
        alice,
      );
      const addition = await addPqcGroupMember(
        context,
        aliceState,
        bob.keyPackageMessage,
      );
      const bobState = await joinPqcGroup(context, addition.welcome, bob);
      const file = new File([new Uint8Array([1, 3, 3, 7])], 'proof.bin', {
        type: 'application/octet-stream',
      });
      const fileBytes = new Uint8Array([1, 3, 3, 7]);
      Object.defineProperty(file, 'arrayBuffer', {
        value: () => Promise.resolve(fileBytes.slice().buffer),
      });
      const envelope = await createPqcAttachmentEnvelope(file);
      const sent = await createPqcApplicationMessage(
        context,
        addition.state,
        JSON.stringify({ ...envelope, caption: 'signed attachment' }),
      );
      const received = await processPqcApplicationMessage(
        context,
        bobState,
        sent.ciphertext,
      );
      const decoded = await decodePqcAttachmentEnvelope(received.plaintext);

      expect(decoded?.envelope.caption).toBe('signed attachment');
      expect(decoded?.envelope.sha256).toBe(envelope.sha256);
      expect(Array.from(decoded?.bytes ?? [])).toEqual([1, 3, 3, 7]);

      const tampered = JSON.parse(received.plaintext) as {
        data: string;
      };
      tampered.data = 'AQIDBA==';
      await expect(
        decodePqcAttachmentEnvelope(JSON.stringify(tampered)),
      ).resolves.toBeNull();
    } finally {
      trusted.clear();
      alice.publicPackage.fill(0);
      alice.keyPackageMessage.fill(0);
      bob.publicPackage.fill(0);
      bob.keyPackageMessage.fill(0);
    }
  });

  it('adds a member to a running group and advances existing and joining members', async () => {
    const alice = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
    );
    const bob = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-device',
    );
    const carol = await generatePqcDeviceKeyPackage(
      'https://example.test/users/carol',
      'carol-device',
    );
    const trusted = new Map<string, string>([
      [alice.identity, alice.fingerprint],
      [bob.identity, bob.fingerprint],
      [carol.identity, carol.fingerprint],
    ]);

    try {
      const context = await createPqcMlsContext(trusted);
      let aliceState = await createPqcGroup(
        context,
        'add-member-test-group',
        alice,
      );
      const bobAddition = await addPqcGroupMember(
        context,
        aliceState,
        bob.keyPackageMessage,
      );
      aliceState = bobAddition.state;
      let bobState = await joinPqcGroup(context, bobAddition.welcome, bob);

      const carolAddition = await addPqcGroupMember(
        context,
        aliceState,
        carol.keyPackageMessage,
      );
      aliceState = carolAddition.state;
      const bobCommit = await processPqcMessage(
        context,
        bobState,
        carolAddition.commit,
      );
      expect(bobCommit.kind).toBe('state');
      if (bobCommit.kind !== 'state')
        throw new Error('Expected Bob to process the membership commit');
      bobState = bobCommit.state;
      const carolState = await joinPqcGroup(
        context,
        carolAddition.welcome,
        carol,
      );

      const sent = await createPqcApplicationMessage(
        context,
        aliceState,
        'member update applied',
      );
      const bobReceived = await processPqcApplicationMessage(
        context,
        bobState,
        sent.ciphertext,
      );
      const carolReceived = await processPqcApplicationMessage(
        context,
        carolState,
        sent.ciphertext,
      );
      expect(bobReceived.plaintext).toBe('member update applied');
      expect(carolReceived.plaintext).toBe('member update applied');
    } finally {
      trusted.clear();
      alice.publicPackage.fill(0);
      alice.keyPackageMessage.fill(0);
      bob.publicPackage.fill(0);
      bob.keyPackageMessage.fill(0);
      carol.publicPackage.fill(0);
      carol.keyPackageMessage.fill(0);
    }
  });

  it('removes a member with an MLS Remove proposal and prevents access to the next epoch', async () => {
    const alice = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-remove-device',
    );
    const bob = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-remove-device',
    );
    const carol = await generatePqcDeviceKeyPackage(
      'https://example.test/users/carol',
      'carol-remove-device',
    );
    const trusted = new Map<string, string>([
      [alice.identity, alice.fingerprint],
      [bob.identity, bob.fingerprint],
      [carol.identity, carol.fingerprint],
    ]);

    try {
      const context = await createPqcMlsContext(trusted);
      let aliceState = await createPqcGroup(
        context,
        'remove-member-test-group',
        alice,
      );
      const bobAddition = await addPqcGroupMember(
        context,
        aliceState,
        bob.keyPackageMessage,
      );
      aliceState = bobAddition.state;
      let bobState = await joinPqcGroup(context, bobAddition.welcome, bob);
      const carolAddition = await addPqcGroupMember(
        context,
        aliceState,
        carol.keyPackageMessage,
      );
      aliceState = carolAddition.state;
      const bobAdvance = await processPqcMessage(
        context,
        bobState,
        carolAddition.commit,
      );
      if (bobAdvance.kind !== 'state')
        throw new Error('Expected Bob to process Carol’s addition commit');
      bobState = bobAdvance.state;
      const carolState = await joinPqcGroup(
        context,
        carolAddition.welcome,
        carol,
      );

      const removal = await removePqcGroupMembers(context, aliceState, [
        carol.identity,
      ]);
      aliceState = removal.state;
      const bobRemoval = await processPqcMessage(
        context,
        bobState,
        removal.commit,
      );
      if (bobRemoval.kind !== 'state')
        throw new Error('Expected Bob to process the removal commit');
      bobState = bobRemoval.state;

      const sent = await createPqcApplicationMessage(
        context,
        aliceState,
        'removed member cannot read this',
      );
      const bobReceived = await processPqcApplicationMessage(
        context,
        bobState,
        sent.ciphertext,
      );
      expect(bobReceived.plaintext).toBe('removed member cannot read this');
      await expect(
        processPqcApplicationMessage(context, carolState, sent.ciphertext),
      ).rejects.toThrow();
    } finally {
      trusted.clear();
      alice.privatePackage.fill(0);
      bob.privatePackage.fill(0);
      carol.privatePackage.fill(0);
    }
  });

  it('rejects a device unless its fingerprint was explicitly confirmed', async () => {
    const device = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
    );
    const trustedDevices = new Map<string, string>();

    expect(() => {
      trustPqcDevice(trustedDevices, device.identity, '00'.repeat(32));
    }).toThrow(/does not match/);
    expect(trustedDevices.size).toBe(0);

    device.privatePackage.fill(0);
    device.mediaKemPrivateKey?.fill(0);
  });

  it('rotates one-time KeyPackages while preserving the verified device signing identity', async () => {
    const device = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
    );
    const rotated = await rotatePqcDeviceKeyPackage(device);
    const publicPackage = required(
      decode(keyPackageDecoder, rotated.publicPackage),
    );
    const trustedDevices = new Map<string, string>([
      [rotated.identity, rotated.fingerprint],
    ]);
    const context = await createPqcMlsContext(trustedDevices);
    const state = await createPqcGroup(
      context,
      'rotated-key-package-test',
      rotated,
    );

    expect(rotated.identity).toBe(device.identity);
    expect(rotated.fingerprint).toBe(device.fingerprint);
    expect(rotated.keyPackageMessage).not.toEqual(device.keyPackageMessage);
    expect(
      await fingerprintPublicKey(publicPackage.leafNode.signaturePublicKey),
    ).toBe(device.fingerprint);
    expect(state.groupContext.groupId).toBeDefined();

    device.privatePackage.fill(0);
    device.mediaKemPrivateKey?.fill(0);
    rotated.privatePackage.fill(0);
    rotated.mediaKemPrivateKey?.fill(0);
    trustedDevices.clear();
  });

  it('preserves a claimed KeyPackage private key when rotation happens before Welcome processing', async () => {
    const alice = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
    );
    const bob = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-device',
    );
    const trusted = new Map<string, string>([
      [alice.identity, alice.fingerprint],
      [bob.identity, bob.fingerprint],
    ]);

    try {
      await rotatePqcDeviceKeyPackage(bob);
      const context = await createPqcMlsContext(trusted);
      const aliceState = await createPqcGroup(
        context,
        'rotate-before-welcome-test',
        alice,
      );
      const added = await addPqcGroupMember(
        context,
        aliceState,
        bob.keyPackageMessage,
      );
      const bobState = await joinPqcGroup(context, added.welcome, bob);
      const sent = await createPqcApplicationMessage(
        context,
        added.state,
        'welcome decrypted after key rotation',
      );
      const received = await processPqcApplicationMessage(
        context,
        bobState,
        sent.ciphertext,
      );

      expect(received.plaintext).toBe('welcome decrypted after key rotation');
    } finally {
      trusted.clear();
      alice.privatePackage.fill(0);
      alice.mediaKemPrivateKey?.fill(0);
      bob.privatePackage.fill(0);
      bob.mediaKemPrivateKey?.fill(0);
    }
  });

  it('seals browser recovery data and rejects an incorrect passphrase', async () => {
    const original = new TextEncoder().encode('encrypted device recovery');
    const sealed = await sealPqcRecoveryData(
      original,
      'strong recovery passphrase',
    );

    expect(
      new TextDecoder().decode(
        await restorePqcRecoveryData(sealed, 'strong recovery passphrase'),
      ),
    ).toBe('encrypted device recovery');
    await expect(
      restorePqcRecoveryData(sealed, 'another wrong passphrase'),
    ).rejects.toThrow(/Unable to decrypt/);
  });

  it('rotates the encryption passphrase without changing recovery data', async () => {
    const original = new TextEncoder().encode(
      'device keys and pending MLS state',
    );
    const firstEnvelope = await sealPqcRecoveryData(
      original,
      'original recovery passphrase',
    );
    const recovered = await restorePqcRecoveryData(
      firstEnvelope,
      'original recovery passphrase',
    );
    const rotatedEnvelope = await sealVerifiedPqcRecoveryData(
      recovered,
      'replacement recovery passphrase',
    );

    await expect(
      restorePqcRecoveryData(rotatedEnvelope, 'original recovery passphrase'),
    ).rejects.toThrow(/Unable to decrypt/);
    expect(
      new TextDecoder().decode(
        await restorePqcRecoveryData(
          rotatedEnvelope,
          'replacement recovery passphrase',
        ),
      ),
    ).toBe('device keys and pending MLS state');
    recovered.fill(0);
  });
});

const required = <T>(value: T | undefined): T => {
  if (value === undefined) throw new Error('Expected a decoded MLS value');

  return value;
};
