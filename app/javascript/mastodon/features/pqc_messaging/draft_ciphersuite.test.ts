import {
  createApplicationMessage,
  createCommit,
  createGroup,
  decode,
  defaultCredentialTypes,
  defaultProposalTypes,
  generateKeyPackageWithKey,
  generateSignatureKeyPair,
  joinGroup,
  mlsMessageDecoder,
  mlsMessageEncoder,
  processMessage,
  encode,
  wireformats,
} from 'ts-mls';
import type { Credential } from 'ts-mls';

import { DRAFT_PQC_MLS_CIPHERSUITE_ID } from './cipher_suite_ids';
import { createDraftPqcMlsCiphersuite } from './draft_ciphersuite';
import {
  addPqcGroupMember,
  createPqcGroup,
  createPqcMlsContext,
  generatePqcDeviceKeyPackage,
  LEGACY_PQC_MLS_CIPHERSUITE_ID,
} from './mls_client';

describe('draft PQ MLS cipher suite', () => {
  it('rejects a KeyPackage from a different suite before group mutation', async () => {
    const alice = await generatePqcDeviceKeyPackage(
      'https://example.test/users/alice',
      'alice-device',
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );
    const bob = await generatePqcDeviceKeyPackage(
      'https://example.test/users/bob',
      'bob-device',
      LEGACY_PQC_MLS_CIPHERSUITE_ID,
    );
    const context = await createPqcMlsContext(
      new Map([
        [alice.identity, alice.fingerprint],
        [bob.identity, bob.fingerprint],
      ]),
      DRAFT_PQC_MLS_CIPHERSUITE_ID,
    );
    const state = await createPqcGroup(context, 'draft-mismatch-test', alice);

    await expect(
      addPqcGroupMember(context, state, bob.keyPackageMessage),
    ).rejects.toThrow('different MLS cipher suite');
    alice.privatePackage.fill(0);
    bob.privatePackage.fill(0);
  });

  it('creates a two-device group and exchanges an encrypted message using suite 0x0052', async () => {
    const cipherSuite = await createDraftPqcMlsCiphersuite();
    const makePackage = async (identity: string) => {
      const credential: Credential = {
        credentialType: defaultCredentialTypes.basic,
        identity: new TextEncoder().encode(identity),
      };
      const signatureKeyPair = await generateSignatureKeyPair(cipherSuite);
      const generated = await generateKeyPackageWithKey({
        credential,
        signatureKeyPair,
        cipherSuite,
      });
      return generated;
    };
    const alice = await makePackage(
      'https://example.test/users/alice\nalice-device',
    );
    const bob = await makePackage('https://example.test/users/bob\nbob-device');
    const context = {
      cipherSuite,
      authService: {
        validateCredential: () => Promise.resolve(true),
        validateSuccessorCredential: () => Promise.resolve(true),
      },
    };

    expect(alice.publicPackage.cipherSuite).toBe(DRAFT_PQC_MLS_CIPHERSUITE_ID);
    expect(alice.publicPackage.leafNode.signaturePublicKey).toHaveLength(1_312);

    const aliceState = await createGroup({
      context,
      groupId: new TextEncoder().encode('draft-pq-suite-test'),
      keyPackage: alice.publicPackage,
      privateKeyPackage: alice.privatePackage,
    });
    const addition = await createCommit({
      context,
      state: aliceState,
      ratchetTreeExtension: true,
      extraProposals: [
        {
          proposalType: defaultProposalTypes.add,
          add: { keyPackage: bob.publicPackage },
        },
      ],
    });

    const welcome = addition.welcome;
    expect(welcome).toBeDefined();
    if (!welcome) throw new Error('Expected an MLS Welcome');
    const welcomeMessage = decode(
      mlsMessageDecoder,
      encode(mlsMessageEncoder, welcome),
    );
    if (
      welcomeMessage?.wireformat !== wireformats.mls_welcome ||
      !('welcome' in welcomeMessage)
    )
      throw new Error('Expected an MLS Welcome');
    const bobState = await joinGroup({
      context,
      welcome: welcomeMessage.welcome,
      keyPackage: bob.publicPackage,
      privateKeys: bob.privatePackage,
      ratchetTree: addition.newState.ratchetTree,
    });
    const sent = await createApplicationMessage({
      context,
      state: addition.newState,
      message: new TextEncoder().encode('draft PQ MLS round trip'),
    });
    const received = await processMessage({
      context,
      state: bobState,
      message: sent.message,
    });

    expect(received.kind).toBe('applicationMessage');
    if (received.kind !== 'applicationMessage')
      throw new Error('Expected encrypted application data');
    expect(new TextDecoder().decode(received.message)).toBe(
      'draft PQ MLS round trip',
    );
  });
});
