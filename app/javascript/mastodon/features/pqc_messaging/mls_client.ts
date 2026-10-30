import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  clientStateDecoder,
  clientStateEncoder,
  createApplicationMessage,
  createCommit,
  createGroup,
  decode,
  defaultCredentialTypes,
  defaultProposalTypes,
  encode,
  generateKeyPackageWithKey,
  generateSignatureKeyPair,
  getCiphersuiteImpl,
  getGroupMembers,
  joinGroup,
  keyPackageDecoder,
  keyPackageEncoder,
  mlsMessageDecoder,
  mlsMessageEncoder,
  privateKeyPackageDecoder,
  privateKeyPackageEncoder,
  processMessage,
  protocolVersions,
  wireformats,
  zeroOutUint8Array,
} from 'ts-mls';
import type { ClientState, Credential, MlsContext } from 'ts-mls';

import type { PqcDeviceBindingCertificate } from './relay_api';

export const PQC_MLS_CIPHERSUITE = 'MLS_256_XWING_AES256GCM_SHA512_MLDSA87';
export const PQC_MLS_CIPHERSUITE_ID = 0xf011;

export interface PqcDeviceKeyPackage {
  identity: string;
  fingerprint: string;
  publicPackage: Uint8Array;
  keyPackageMessage: Uint8Array;
  privatePackage: Uint8Array;
}

export type PqcMlsContext = MlsContext;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const pqcCiphersuite = getCiphersuiteImpl(PQC_MLS_CIPHERSUITE);

export const getPqcMlsCiphersuite = async (id: number) => {
  if (id === PQC_MLS_CIPHERSUITE_ID) return pqcCiphersuite;

  throw new Error(
    `Unsupported MLS cipher suite 0x${id.toString(16).padStart(4, '0')}`,
  );
};

export const getPqcDeviceCiphersuiteId = (
  keyPackage: PqcDeviceKeyPackage,
): number =>
  decodeRequired(keyPackageDecoder, keyPackage.publicPackage).cipherSuite;

export const createPqcMlsContext = async (
  trustedDevices: ReadonlyMap<string, string>,
  cipherSuiteId = PQC_MLS_CIPHERSUITE_ID,
): Promise<PqcMlsContext> => ({
  cipherSuite: await getPqcMlsCiphersuite(cipherSuiteId),
  authService: {
    validateCredential: async (credential, signaturePublicKey) =>
      validateCredential(trustedDevices, credential, signaturePublicKey),
    validateSuccessorCredential: (oldCredential, newCredential) => {
      const oldIdentity = credentialIdentity(oldCredential);
      const newIdentity = credentialIdentity(newCredential);

      return Promise.resolve(
        oldIdentity === newIdentity && trustedDevices.has(oldIdentity),
      );
    },
  },
});

export const generatePqcDeviceKeyPackage = async (
  actorUri: string,
  deviceId: string,
  cipherSuiteId = PQC_MLS_CIPHERSUITE_ID,
): Promise<PqcDeviceKeyPackage> => {
  const impl = await getPqcMlsCiphersuite(cipherSuiteId);
  const signatureKeyPair = await generateSignatureKeyPair(impl);
  // MLS membership and device API requests use this one ML-DSA identity.
  const fingerprint = await fingerprintPublicKey(signatureKeyPair.publicKey);
  const identity = `${actorUri}\n${deviceId}\n${fingerprint}`;
  const credential: Credential = {
    credentialType: defaultCredentialTypes.basic,
    identity: encoder.encode(identity),
  };

  const result = await generateKeyPackageWithKey({
    credential,
    signatureKeyPair,
    cipherSuite: impl,
  });

  const encodedPublicPackage = encode(keyPackageEncoder, result.publicPackage);

  return {
    identity,
    fingerprint,
    publicPackage: encodedPublicPackage,
    keyPackageMessage: encode(mlsMessageEncoder, {
      wireformat: wireformats.mls_key_package,
      keyPackage: result.publicPackage,
      version: protocolVersions.mls10,
    }),
    privatePackage: encode(privateKeyPackageEncoder, result.privatePackage),
  };
};

export const pqcDeviceAuthPublicKey = (
  keyPackage: PqcDeviceKeyPackage,
): Uint8Array => {
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  return Uint8Array.from(publicPackage.leafNode.signaturePublicKey);
};

export const rotatePqcDeviceKeyPackage = async (
  keyPackage: PqcDeviceKeyPackage,
): Promise<PqcDeviceKeyPackage> => {
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  const impl = await getPqcMlsCiphersuite(publicPackage.cipherSuite);
  // The MLS decoder may return Uint8Array views backed by its input. Rotation
  // must not wipe the claimed package: the client still needs its private HPKE
  // key to open the Welcome addressed to that package.
  const decodedPrivatePackage = decodeRequired(
    privateKeyPackageDecoder,
    Uint8Array.from(keyPackage.privatePackage),
  );
  const signatureKeyPair = {
    signKey: Uint8Array.from(decodedPrivatePackage.signaturePrivateKey),
    publicKey: Uint8Array.from(publicPackage.leafNode.signaturePublicKey),
  };

  try {
    const credential: Credential = {
      credentialType: defaultCredentialTypes.basic,
      identity: encoder.encode(keyPackage.identity),
    };
    const result = await generateKeyPackageWithKey({
      credential,
      signatureKeyPair,
      cipherSuite: impl,
    });
    const encodedPublicPackage = encode(
      keyPackageEncoder,
      result.publicPackage,
    );

    return {
      identity: keyPackage.identity,
      fingerprint: keyPackage.fingerprint,
      publicPackage: encodedPublicPackage,
      keyPackageMessage: encode(mlsMessageEncoder, {
        wireformat: wireformats.mls_key_package,
        keyPackage: result.publicPackage,
        version: protocolVersions.mls10,
      }),
      privatePackage: encode(privateKeyPackageEncoder, result.privatePackage),
    };
  } finally {
    wipePrivateKeyPackage(decodedPrivatePackage);
    zeroOutUint8Array(signatureKeyPair.signKey);
    zeroOutUint8Array(signatureKeyPair.publicKey);
  }
};

export const signPqcDeviceRequest = async (
  keyPackage: PqcDeviceKeyPackage,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: string,
): Promise<Uint8Array> => {
  const bodyDigest = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(body),
  );
  const bodyDigestHex = Array.from(new Uint8Array(bodyDigest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
  const message = `Mastodon-PQC-Device-Auth-v1\n${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyDigestHex}`;

  // The API request signature uses the same private key as the MLS credential.
  const privatePackage = decodeRequired(
    privateKeyPackageDecoder,
    keyPackage.privatePackage,
  );
  const signKey = Uint8Array.from(privatePackage.signaturePrivateKey);
  try {
    const publicPackage = decodeRequired(
      keyPackageDecoder,
      keyPackage.publicPackage,
    );
    const impl = await getPqcMlsCiphersuite(publicPackage.cipherSuite);
    return await impl.signature.sign(signKey, encoder.encode(message));
  } finally {
    zeroOutUint8Array(signKey);
    wipePrivateKeyPackage(privatePackage);
  }
};

export const trustPqcDevice = (
  trustedDevices: Map<string, string>,
  identity: string,
  confirmedFingerprint: string,
): void => {
  const identityFingerprint = identity.split('\n').at(-1);

  if (!identityFingerprint || identityFingerprint !== confirmedFingerprint) {
    throw new Error(
      'The confirmed fingerprint does not match the device identity',
    );
  }

  trustedDevices.set(identity, confirmedFingerprint);
};

export const createPqcGroup = async (
  context: PqcMlsContext,
  groupId: string,
  keyPackage: PqcDeviceKeyPackage,
): Promise<ClientState> => {
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  const decodedPrivatePackage = decodeRequired(
    privateKeyPackageDecoder,
    keyPackage.privatePackage,
  );
  const privatePackage = clonePrivateKeyPackage(decodedPrivatePackage);

  try {
    return await createGroup({
      context,
      groupId: encoder.encode(groupId),
      keyPackage: publicPackage,
      privateKeyPackage: privatePackage,
    });
  } finally {
    wipePrivateKeyPackage(decodedPrivatePackage);
    zeroOutUint8Array(keyPackage.privatePackage);
  }
};

export const addPqcGroupMember = async (
  context: PqcMlsContext,
  state: ClientState,
  encodedPublicPackage: Uint8Array,
): Promise<{ state: ClientState; commit: Uint8Array; welcome: Uint8Array }> => {
  const keyPackageMessage = decodeRequired(
    mlsMessageDecoder,
    encodedPublicPackage,
  );
  if (
    keyPackageMessage.wireformat !== wireformats.mls_key_package ||
    !('keyPackage' in keyPackageMessage)
  )
    throw new Error('Expected an MLS KeyPackage message');
  if (keyPackageMessage.keyPackage.cipherSuite !== context.cipherSuite.id) {
    throw new Error(
      'The invited device KeyPackage uses a different MLS cipher suite; register a device using the group suite',
    );
  }

  const commit = await createCommit({
    context,
    state,
    ratchetTreeExtension: true,
    extraProposals: [
      {
        proposalType: defaultProposalTypes.add,
        add: { keyPackage: keyPackageMessage.keyPackage },
      },
    ],
  });
  if (!commit.welcome)
    throw new Error('MLS did not create a Welcome message for the new member');
  commit.consumed.forEach(zeroOutUint8Array);

  return {
    state: commit.newState,
    commit: encode(mlsMessageEncoder, commit.commit),
    welcome: encode(mlsMessageEncoder, commit.welcome),
  };
};

export const removePqcGroupMembers = async (
  context: PqcMlsContext,
  state: ClientState,
  identities: string[],
): Promise<{ state: ClientState; commit: Uint8Array }> => {
  const identitiesToRemove = new Set(identities);
  if (
    identitiesToRemove.size === 0 ||
    identitiesToRemove.size !== identities.length
  )
    throw new Error('Choose one or more distinct group devices to remove');

  const leafIndices = state.ratchetTree.flatMap((node, nodeIndex) => {
    const candidate = node as unknown as
      | { nodeType: number; leaf: { credential: Credential } }
      | undefined;
    if (
      candidate?.nodeType !== 1 ||
      !identitiesToRemove.has(credentialIdentity(candidate.leaf.credential))
    )
      return [];
    return [nodeIndex / 2];
  });
  if (leafIndices.length !== identitiesToRemove.size)
    throw new Error('One or more selected devices are not in this MLS group');
  if (leafIndices.length >= getGroupMembers(state).length)
    throw new Error('An MLS group must retain at least one device');

  const result = await createCommit({
    context,
    state,
    extraProposals: leafIndices.map((removed) => ({
      proposalType: defaultProposalTypes.remove,
      remove: { removed },
    })),
  });
  result.consumed.forEach(zeroOutUint8Array);

  return {
    state: result.newState,
    commit: encode(mlsMessageEncoder, result.commit),
  };
};

export const createPqcCommit = async (
  context: PqcMlsContext,
  state: ClientState,
): Promise<{ state: ClientState; ciphertext: Uint8Array }> => {
  const result = await createCommit({ context, state });
  result.consumed.forEach(zeroOutUint8Array);

  return {
    state: result.newState,
    ciphertext: encode(mlsMessageEncoder, result.commit),
  };
};

export const joinPqcGroup = async (
  context: PqcMlsContext,
  welcomeBytes: Uint8Array,
  keyPackage: PqcDeviceKeyPackage,
  ratchetTree?: ClientState['ratchetTree'],
): Promise<ClientState> => {
  const welcomeMessage = decodeRequired(mlsMessageDecoder, welcomeBytes);
  const publicPackage = decodeRequired(
    keyPackageDecoder,
    keyPackage.publicPackage,
  );
  const decodedPrivatePackage = decodeRequired(
    privateKeyPackageDecoder,
    keyPackage.privatePackage,
  );
  const privatePackage = clonePrivateKeyPackage(decodedPrivatePackage);
  if (
    welcomeMessage.wireformat !== wireformats.mls_welcome ||
    !('welcome' in welcomeMessage)
  )
    throw new Error('Expected an MLS Welcome message');

  try {
    return await joinGroup({
      context,
      welcome: welcomeMessage.welcome,
      keyPackage: publicPackage,
      privateKeys: privatePackage,
      ratchetTree,
    });
  } finally {
    wipePrivateKeyPackage(decodedPrivatePackage);
    zeroOutUint8Array(keyPackage.privatePackage);
  }
};

export const createPqcApplicationMessage = async (
  context: PqcMlsContext,
  state: ClientState,
  plaintext: string,
): Promise<{ state: ClientState; ciphertext: Uint8Array }> => {
  const result = await createApplicationMessage({
    context,
    state,
    message: encoder.encode(plaintext),
  });
  result.consumed.forEach(zeroOutUint8Array);

  return {
    state: result.newState,
    ciphertext: encode(mlsMessageEncoder, result.message),
  };
};

export interface PqcAttachmentEnvelope {
  version: 1;
  type: 'attachment';
  name: string;
  mediaType: string;
  byteLength: number;
  sha256: string;
  data: string;
  caption?: string;
}

// The envelope is serialized inside an MLS application message. MLS therefore
// encrypts it for the group and authenticates the sender's exact attachment
// bytes through the suite's member signature.
export const createPqcAttachmentEnvelope = async (
  file: File,
): Promise<PqcAttachmentEnvelope> => {
  if (!file.size) throw new Error('Attachments cannot be empty');
  // The relay currently caps encoded MLS messages at 1 MiB. Leave room for
  // envelope metadata, base64 expansion, and MLS framing.
  if (file.size > 512 * 1024)
    throw new Error('Attachments must be 512 KiB or smaller');
  const bytes = new Uint8Array(await file.arrayBuffer());
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const chunks: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    chunks.push(
      String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)),
    );
  }

  return {
    version: 1,
    type: 'attachment',
    name: file.name,
    mediaType: file.type || 'application/octet-stream',
    byteLength: bytes.length,
    sha256: Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join(''),
    data: btoa(chunks.join('')),
  };
};

export const decodePqcAttachmentEnvelope = async (
  value: string,
): Promise<{ envelope: PqcAttachmentEnvelope; bytes: Uint8Array } | null> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }

  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !('version' in parsed) ||
    parsed.version !== 1 ||
    !('type' in parsed) ||
    parsed.type !== 'attachment' ||
    !('name' in parsed) ||
    typeof parsed.name !== 'string' ||
    parsed.name.length === 0 ||
    parsed.name.length > 255 ||
    !('mediaType' in parsed) ||
    typeof parsed.mediaType !== 'string' ||
    parsed.mediaType.length > 255 ||
    !('byteLength' in parsed) ||
    typeof parsed.byteLength !== 'number' ||
    !Number.isSafeInteger(parsed.byteLength) ||
    parsed.byteLength <= 0 ||
    parsed.byteLength > 512 * 1024 ||
    !('sha256' in parsed) ||
    typeof parsed.sha256 !== 'string' ||
    !/^[0-9a-f]{64}$/.test(parsed.sha256) ||
    !('data' in parsed) ||
    typeof parsed.data !== 'string' ||
    ('caption' in parsed &&
      (typeof parsed.caption !== 'string' || parsed.caption.length > 10_000))
  )
    return null;

  try {
    const binary = atob(parsed.data);
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    if (bytes.length !== parsed.byteLength) return null;
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const sha256 = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
    if (sha256 !== parsed.sha256) return null;

    return { envelope: parsed as PqcAttachmentEnvelope, bytes };
  } catch {
    return null;
  }
};

export const processPqcApplicationMessage = async (
  context: PqcMlsContext,
  state: ClientState,
  ciphertext: Uint8Array,
): Promise<{ state: ClientState; plaintext: string }> => {
  const result = await processPqcMessage(context, state, ciphertext);
  if (result.kind !== 'application')
    throw new Error('Expected an MLS application message');

  return result;
};

export const processPqcMessage = async (
  context: PqcMlsContext,
  state: ClientState,
  ciphertext: Uint8Array,
): Promise<
  | { kind: 'application'; state: ClientState; plaintext: string }
  | { kind: 'state'; state: ClientState }
> => {
  const message = decodeRequired(mlsMessageDecoder, ciphertext);
  if (
    message.wireformat !== wireformats.mls_private_message &&
    message.wireformat !== wireformats.mls_public_message
  ) {
    throw new Error('Expected an MLS framed message');
  }
  const result = await processMessage({ context, state, message });
  result.consumed.forEach(zeroOutUint8Array);
  if (result.kind === 'newState')
    return { kind: 'state', state: result.newState };

  return {
    kind: 'application',
    state: result.newState,
    plaintext: decoder.decode(result.message),
  };
};

export const serializePqcGroupState = (state: ClientState): Uint8Array =>
  encode(clientStateEncoder, state);

export const deserializePqcGroupState = (
  serializedState: Uint8Array,
): ClientState => decodeRequired(clientStateDecoder, serializedState);

const PQC_STATE_FORMAT_VERSION = 1;
const PQC_STATE_SALT_BYTES = 16;
const PQC_STATE_NONCE_BYTES = 12;
const PQC_STATE_PBKDF2_ITERATIONS = 310_000;
const PQC_STATE_AUTHENTICATED_DATA = encoder.encode(
  'mastodon-pqc-mls-state-v1',
);
const PQC_RECOVERY_AUTHENTICATED_DATA = encoder.encode(
  'mastodon-pqc-local-recovery-v1',
);

export const sealPqcRecoveryData = async (
  data: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> => {
  validateStatePassphrase(passphrase);
  const salt = crypto.getRandomValues(new Uint8Array(PQC_STATE_SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(PQC_STATE_NONCE_BYTES));
  const key = await derivePqcStateKey(passphrase, salt);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(PQC_RECOVERY_AUTHENTICATED_DATA),
      },
      key,
      asArrayBuffer(data),
    ),
  );

  return Uint8Array.from([
    PQC_STATE_FORMAT_VERSION,
    ...salt,
    ...nonce,
    ...encrypted,
  ]);
};

export const restorePqcRecoveryData = async (
  sealedData: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> => {
  validateStatePassphrase(passphrase);
  const headerSize = 1 + PQC_STATE_SALT_BYTES + PQC_STATE_NONCE_BYTES;
  if (
    sealedData.byteLength <= headerSize ||
    sealedData[0] !== PQC_STATE_FORMAT_VERSION
  )
    throw new Error('Invalid encrypted PQC recovery data');

  const salt = sealedData.slice(1, 1 + PQC_STATE_SALT_BYTES);
  const nonceStart = 1 + PQC_STATE_SALT_BYTES;
  const nonce = sealedData.slice(
    nonceStart,
    nonceStart + PQC_STATE_NONCE_BYTES,
  );
  const ciphertext = sealedData.slice(headerSize);
  const key = await derivePqcStateKey(passphrase, salt);
  try {
    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: asArrayBuffer(nonce),
          additionalData: asArrayBuffer(PQC_RECOVERY_AUTHENTICATED_DATA),
        },
        key,
        asArrayBuffer(ciphertext),
      ),
    );
  } catch {
    throw new Error(
      'Unable to decrypt local PQC recovery data with this passphrase',
    );
  }
};

export const sealVerifiedPqcRecoveryData = async (
  plaintext: Uint8Array,
  replacementPassphrase: string,
): Promise<Uint8Array> => {
  const replacement = await sealPqcRecoveryData(
    plaintext,
    replacementPassphrase,
  );
  const verification = await restorePqcRecoveryData(
    replacement,
    replacementPassphrase,
  );
  try {
    if (
      verification.byteLength !== plaintext.byteLength ||
      verification.some((byte, index) => byte !== plaintext[index])
    ) {
      throw new Error('The updated recovery record could not be verified');
    }
  } finally {
    verification.fill(0);
  }

  return replacement;
};

export const sealPqcGroupState = async (
  state: ClientState,
  passphrase: string,
): Promise<Uint8Array> => {
  validateStatePassphrase(passphrase);
  const salt = crypto.getRandomValues(new Uint8Array(PQC_STATE_SALT_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(PQC_STATE_NONCE_BYTES));
  const key = await derivePqcStateKey(passphrase, salt);
  const plaintext = encode(clientStateEncoder, state);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(PQC_STATE_AUTHENTICATED_DATA),
      },
      key,
      asArrayBuffer(plaintext),
    ),
  );

  return Uint8Array.from([
    PQC_STATE_FORMAT_VERSION,
    ...salt,
    ...nonce,
    ...encrypted,
  ]);
};

export const restorePqcGroupState = async (
  sealedState: Uint8Array,
  passphrase: string,
): Promise<ClientState> => {
  validateStatePassphrase(passphrase);
  const headerSize = 1 + PQC_STATE_SALT_BYTES + PQC_STATE_NONCE_BYTES;
  if (
    sealedState.byteLength <= headerSize ||
    sealedState[0] !== PQC_STATE_FORMAT_VERSION
  )
    throw new Error('Invalid encrypted MLS state');

  const salt = sealedState.slice(1, 1 + PQC_STATE_SALT_BYTES);
  const nonceStart = 1 + PQC_STATE_SALT_BYTES;
  const nonce = sealedState.slice(
    nonceStart,
    nonceStart + PQC_STATE_NONCE_BYTES,
  );
  const ciphertext = sealedState.slice(headerSize);
  const key = await derivePqcStateKey(passphrase, salt);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: asArrayBuffer(nonce),
        additionalData: asArrayBuffer(PQC_STATE_AUTHENTICATED_DATA),
      },
      key,
      asArrayBuffer(ciphertext),
    );
  } catch {
    throw new Error('Unable to decrypt MLS state with this passphrase');
  }

  return decodeRequired(clientStateDecoder, new Uint8Array(plaintext));
};

export const fingerprintPublicKey = async (
  publicKey: Uint8Array,
): Promise<string> => {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    Uint8Array.from(publicKey),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
};

export const verifyPqcDeviceBinding = async (
  certificate: PqcDeviceBindingCertificate | null | undefined,
  actorUri: string,
  deviceId: string,
  fingerprint: string,
): Promise<boolean> => {
  if (
    certificate?.version !== 1 ||
    certificate.actor_uri !== actorUri ||
    certificate.device_id !== deviceId ||
    certificate.fingerprint !== fingerprint ||
    certificate.ciphersuite_id !== `0x${PQC_MLS_CIPHERSUITE_ID.toString(16)}` ||
    !Number.isSafeInteger(certificate.issued_at) ||
    certificate.issued_at <= 0 ||
    !certificate.verification_method.startsWith(`${actorUri}#`) ||
    !certificate.signature.startsWith('u')
  ) {
    return false;
  }

  try {
    const response = await fetch(actorUri, {
      headers: { Accept: 'application/activity+json' },
    });
    if (!response.ok) return false;
    const actor = (await response.json()) as {
      id?: string;
      assertionMethod?: unknown;
    };
    if (actor.id !== actorUri) return false;

    const methods: unknown[] = Array.isArray(actor.assertionMethod)
      ? actor.assertionMethod
      : actor.assertionMethod
        ? [actor.assertionMethod]
        : [];
    const method = methods.find(
      (
        entry,
      ): entry is {
        publicKeyMultibase: string;
      } => {
        if (!entry || typeof entry !== 'object') return false;

        const candidate = entry as Record<string, unknown>;
        return (
          candidate.id === certificate.verification_method &&
          candidate.type === 'Multikey' &&
          candidate.controller === actorUri &&
          typeof candidate.publicKeyMultibase === 'string'
        );
      },
    );
    if (!method) return false;

    const publicKey = decodeMldsa87Multibase(method.publicKeyMultibase);
    const signature = decodeBase64Url(certificate.signature.slice(1));
    const message = [
      'Mastodon-PQC-Device-Binding-v1',
      actorUri,
      deviceId,
      fingerprint,
      certificate.ciphersuite_id,
      certificate.verification_method,
      certificate.issued_at,
    ].join('\n');

    return ml_dsa87.verify(signature, encoder.encode(message), publicKey);
  } catch {
    return false;
  }
};

export const verifyPqcKeyPackageBinding = async (
  certificate: PqcDeviceBindingCertificate | null | undefined,
  actorUri: string,
  deviceId: string,
  fingerprint: string,
  encodedKeyPackageMessage: Uint8Array,
): Promise<boolean> => {
  try {
    const message = decodeRequired(mlsMessageDecoder, encodedKeyPackageMessage);
    if (
      message.wireformat !== wireformats.mls_key_package ||
      !('keyPackage' in message)
    )
      return false;

    const keyPackage = message.keyPackage;
    if (keyPackage.cipherSuite !== PQC_MLS_CIPHERSUITE_ID) return false;
    if (
      credentialIdentity(keyPackage.leafNode.credential) !==
        `${actorUri}\n${deviceId}\n${fingerprint}` ||
      (await fingerprintPublicKey(keyPackage.leafNode.signaturePublicKey)) !==
        fingerprint
    )
      return false;

    return await verifyPqcDeviceBinding(
      certificate,
      actorUri,
      deviceId,
      fingerprint,
    );
  } catch {
    return false;
  }
};

const decodeMldsa87Multibase = (encoded: string): Uint8Array => {
  if (!encoded.startsWith('u'))
    throw new Error('Unsupported Multibase encoding');
  const bytes = decodeBase64Url(encoded.slice(1));
  if (bytes.length !== 2594 || bytes[0] !== 0x92 || bytes[1] !== 0x24)
    throw new Error('Invalid ML-DSA-87 Multikey');
  return bytes.slice(2);
};

const decodeBase64Url = (encoded: string): Uint8Array => {
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const validateCredential = async (
  trustedDevices: ReadonlyMap<string, string>,
  credential: Credential,
  signaturePublicKey: Uint8Array,
): Promise<boolean> => {
  let identity: string;
  try {
    identity = credentialIdentity(credential);
  } catch {
    return false;
  }

  const expectedFingerprint = trustedDevices.get(identity);
  if (
    !expectedFingerprint ||
    expectedFingerprint !== (await fingerprintPublicKey(signaturePublicKey))
  ) {
    return false;
  }

  return true;
};

const credentialIdentity = (credential: Credential): string => {
  if (
    credential.credentialType !== defaultCredentialTypes.basic ||
    !('identity' in credential)
  )
    throw new Error('Unsupported MLS credential type');

  return decoder.decode(credential.identity);
};

const decodeRequired = <T>(
  codec: Parameters<typeof decode<T>>[0],
  bytes: Uint8Array,
): T => {
  const decoded = decode(codec, bytes);
  if (decoded === undefined) throw new Error('Invalid MLS encoding');

  return decoded;
};

const clonePrivateKeyPackage = (privatePackage: {
  initPrivateKey: Uint8Array;
  hpkePrivateKey: Uint8Array;
  signaturePrivateKey: Uint8Array;
}) => ({
  initPrivateKey: Uint8Array.from(privatePackage.initPrivateKey),
  hpkePrivateKey: Uint8Array.from(privatePackage.hpkePrivateKey),
  signaturePrivateKey: Uint8Array.from(privatePackage.signaturePrivateKey),
});

const wipePrivateKeyPackage = (privatePackage: {
  initPrivateKey: Uint8Array;
  hpkePrivateKey: Uint8Array;
  signaturePrivateKey: Uint8Array;
}): void => {
  zeroOutUint8Array(privatePackage.initPrivateKey);
  zeroOutUint8Array(privatePackage.hpkePrivateKey);
  zeroOutUint8Array(privatePackage.signaturePrivateKey);
};

const validateStatePassphrase = (passphrase: string): void => {
  if (passphrase.length < 12)
    throw new Error(
      'MLS state passphrases must contain at least 12 characters',
    );
};

const derivePqcStateKey = async (
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> => {
  const material = await crypto.subtle.importKey(
    'raw',
    asArrayBuffer(encoder.encode(passphrase)),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: asArrayBuffer(salt),
      iterations: PQC_STATE_PBKDF2_ITERATIONS,
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
};

const asArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
  Uint8Array.from(bytes).buffer;
