import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
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

import { DRAFT_PQC_MLS_CIPHERSUITE_ID } from './cipher_suite_ids';
import {
  addPqcGroupMember,
  createPqcApplicationMessage,
  createPqcCommit,
  createPqcGroup,
  createPqcMlsContext,
  deserializePqcGroupState,
  fingerprintPublicKey,
  generatePqcDeviceKeyPackage,
  getPqcDeviceCiphersuiteId,
  joinPqcGroup,
  processPqcApplicationMessage,
  processPqcMessage,
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
} from './mls_client';

describe('PQC MLS client', () => {
  it('selects and retains the draft hybrid suite through KeyPackage rotation and group state restore', async () => {
    const alice = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );
    const bob = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-device',
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );
    const trust = new Map([
      [alice.identity, alice.fingerprint],
      [bob.identity, bob.fingerprint],
    ]);
    const context = await createPqcMlsContext(
      trust,
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );
    const state = await createPqcGroup(
      context,
      'draft-suite-client-test',
      alice,
    );
    const restoredState = deserializePqcGroupState(
      serializePqcGroupState(state),
    );
    const rotated = await rotatePqcDeviceKeyPackage(bob);

    expect(getPqcDeviceCiphersuiteId(alice)).toBe(DRAFT_PQC_MLS_CIPHERSUITE_ID);
    expect(restoredState.groupContext.cipherSuite).toBe(
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );
    expect(getPqcDeviceCiphersuiteId(rotated)).toBe(
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );

    alice.privatePackage.fill(0);
    bob.privatePackage.fill(0);
    rotated.privatePackage.fill(0);
  });

  it('keeps HTTP device authentication keys independent from MLS identity keys', async () => {
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

    expect(device.deviceAuthPublicKey).toHaveLength(2592);
    expect(device.deviceAuthPrivateKey).toBeDefined();
    expect(device.deviceAuthPublicKey).not.toEqual(mlsPublicKey);
    expect(
      ml_dsa87.verify(
        signature,
        new TextEncoder().encode(signed),
        device.deviceAuthPublicKey,
      ),
    ).toBe(true);
    expect(await fingerprintPublicKey(mlsPublicKey)).toBe(device.fingerprint);
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
      bob.privatePackage.fill(0);
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
