import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FC, SyntheticEvent } from 'react';

import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import type { ClientState } from 'ts-mls';

import { Column } from '@/mastodon/components/column';
import { ColumnHeader } from '@/mastodon/components/column_header';
import { useCurrentAccountId } from '@/mastodon/hooks/useAccountId';

import { DRAFT_PQC_MLS_CIPHERSUITE_ID } from './cipher_suite_ids';
import { acquirePqcDeviceSessionLock } from './device_session_lock';
import {
  addPqcGroupMember,
  createPqcApplicationMessage,
  createPqcGroup,
  createPqcMlsContext,
  deserializePqcGroupState,
  fingerprintPublicKey,
  getPqcDeviceCiphersuiteId,
  generatePqcDeviceKeyPackage,
  LEGACY_PQC_MLS_CIPHERSUITE_ID,
  joinPqcGroup,
  processPqcMessage,
  pqcDeviceAuthPublicKey,
  removePqcGroupMembers,
  restorePqcRecoveryData,
  rotatePqcDeviceKeyPackage,
  sealVerifiedPqcRecoveryData,
  sealPqcRecoveryData,
  serializePqcGroupState,
  signPqcDeviceRequest,
  trustPqcDevice,
} from './mls_client';
import type { PqcDeviceKeyPackage, PqcMlsContext } from './mls_client';
import {
  commitPqcConversationMember,
  acceptPqcConversationInvitation,
  completePqcGroupSetup,
  createPqcConversation,
  decodePqcKeyPackage,
  decodePqcMessage,
  declinePqcConversationInvitation,
  fetchPqcActorUri,
  fetchPqcKeyPackages,
  fetchPqcMessages,
  invitePqcConversationMember,
  listPqcConversations,
  listPqcDevices,
  publishPqcKeyPackage,
  registerPqcDevice,
  removePqcConversationMember,
  removePqcConversationDevice,
  requestPqcConversationLeave,
  revokePqcDevice,
  sendPqcMessage,
  setPqcDeviceRequestSigner,
} from './relay_api';
import type {
  PqcConversation,
  PqcDevice,
  PqcDeviceRequestSigner,
  PqcDeviceRevocationResult,
  PqcKeyPackage,
  PqcPendingOutbound,
} from './relay_api';

interface LocalDeviceSession {
  accountId: string;
  apiDevice: PqcDevice;
  actorUri: string;
  keyPackage: PqcDeviceKeyPackage;
}

interface ActiveConversation {
  conversation: PqcConversation;
  context: PqcMlsContext;
  state: ClientState | undefined;
  lastMessageId: number;
  messages: PqcDisplayMessage[];
  pendingOutbound: PqcPendingOutbound[];
  pendingMemberAddition?: PqcPendingMemberAddition;
  pendingMemberRemoval?: {
    accountId: string;
    operationId: `${string}-${string}-${string}-${string}-${string}`;
  };
  pendingDeviceRemoval?: {
    deviceId: string;
    operationId: `${string}-${string}-${string}-${string}-${string}`;
  };
  pendingGroupSetup?: {
    accountIds: string[];
    keyPackages: PqcKeyPackage[];
    activeDeviceIds: string[];
    fetchRequestId?: string;
    finalizing?: boolean;
  };
}

interface PqcPendingMemberAddition {
  accountId: string;
  operationId?: `${string}-${string}-${string}-${string}-${string}`;
  keyPackages: PqcKeyPackage[];
  targetDeviceIds?: string[];
  fetchRequestId?: string;
  addedDeviceIds?: string[];
  batchReady?: boolean;
}

interface PqcDisplayMessage {
  id: number;
  sender: string;
  text: string;
}

interface LocalRecoveryRecord {
  version: 1;
  device: {
    apiDevice: PqcDevice;
    actorUri: string;
    identity: string;
    fingerprint: string;
    publicPackage: string;
    keyPackageMessage: string;
    privatePackage: string;
    deviceAuthPublicKey?: string;
    deviceAuthPrivateKey?: string;
  };
  activeConversations?: {
    conversation: PqcConversation;
    serializedState: string;
    lastMessageId: number;
    messages?: PqcDisplayMessage[];
    pendingOutbound?: PqcPendingOutbound[];
    pendingMemberAddition?: PqcPendingMemberAddition;
    pendingMemberRemoval?: {
      accountId: string;
      operationId: `${string}-${string}-${string}-${string}-${string}`;
    };
    pendingDeviceRemoval?: {
      deviceId: string;
      operationId: `${string}-${string}-${string}-${string}-${string}`;
    };
    pendingGroupSetup?: {
      accountIds: string[];
      keyPackages: PqcKeyPackage[];
      activeDeviceIds: string[];
      fetchRequestId?: string;
      finalizing?: boolean;
    };
  }[];
}

const MAX_RECOVERED_MESSAGES = 100;

const restorePqcDeviceKeyPackage = async (
  savedDevice: LocalRecoveryRecord['device'],
): Promise<PqcDeviceKeyPackage> => {
  if (
    savedDevice.identity !==
      `${savedDevice.actorUri}\n${savedDevice.apiDevice.device_id}\n${savedDevice.fingerprint}` ||
    savedDevice.apiDevice.fingerprint !== savedDevice.fingerprint
  ) {
    throw new Error(
      'The saved device identity does not match its registered fingerprint',
    );
  }

  const keyPackage: PqcDeviceKeyPackage = {
    identity: savedDevice.identity,
    fingerprint: savedDevice.fingerprint,
    publicPackage: decodeBase64(savedDevice.publicPackage),
    keyPackageMessage: decodeBase64(savedDevice.keyPackageMessage),
    privatePackage: decodeBase64(savedDevice.privatePackage),
    deviceAuthPublicKey: new Uint8Array(),
    deviceAuthPrivateKey: savedDevice.deviceAuthPrivateKey
      ? decodeBase64(savedDevice.deviceAuthPrivateKey)
      : undefined,
  };

  try {
    if (keyPackage.deviceAuthPrivateKey) {
      keyPackage.deviceAuthPublicKey = savedDevice.deviceAuthPublicKey
        ? decodeBase64(savedDevice.deviceAuthPublicKey)
        : new Uint8Array();
      const derivedPublicKey = ml_dsa87.getPublicKey(
        keyPackage.deviceAuthPrivateKey,
      );
      if (
        derivedPublicKey.length !== 2592 ||
        keyPackage.deviceAuthPublicKey.length !== derivedPublicKey.length ||
        !derivedPublicKey.every(
          (byte, index) => byte === keyPackage.deviceAuthPublicKey[index],
        )
      ) {
        throw new Error(
          'The saved device authentication keypair does not match',
        );
      }
    } else {
      // Legacy recovery records used the MLS signing key for device authentication.
      keyPackage.deviceAuthPublicKey = pqcDeviceAuthPublicKey(keyPackage);
      if (
        (await fingerprintPublicKey(keyPackage.deviceAuthPublicKey)) !==
        savedDevice.fingerprint
      ) {
        throw new Error(
          'The saved device key does not match its registered fingerprint',
        );
      }
    }

    return keyPackage;
  } catch (error) {
    keyPackage.privatePackage.fill(0);
    throw error;
  }
};

/* eslint react/jsx-no-bind: off */
export const PqcMessagingPage: FC = () => {
  const currentAccountId = useCurrentAccountId();
  const recoveryStorageKey = currentAccountId
    ? `mastodon:pqc:recovery:v1:${currentAccountId}`
    : null;
  const [device, setDevice] = useState<LocalDeviceSession | null>(null);
  const [newDeviceCipherSuiteId, setNewDeviceCipherSuiteId] = useState(
    LEGACY_PQC_MLS_CIPHERSUITE_ID,
  );
  const [recoveryPassphrase, setRecoveryPassphrase] = useState('');
  const [passphraseVerification, setPassphraseVerification] = useState('');
  const [replacementPassphrase, setReplacementPassphrase] = useState('');
  const [
    replacementPassphraseConfirmation,
    setReplacementPassphraseConfirmation,
  ] = useState('');
  const [recoveryAvailable, setRecoveryAvailable] = useState(false);
  const [devices, setDevices] = useState<PqcDevice[]>([]);
  const [conversations, setConversations] = useState<PqcConversation[]>([]);
  const [pendingConversation, setPendingConversation] =
    useState<PqcConversation | null>(null);
  const [pendingMemberAccountId, setPendingMemberAccountId] = useState<
    string | null
  >(null);
  const [pendingTrustUpdate, setPendingTrustUpdate] = useState(false);
  const [active, setActive] = useState<ActiveConversation | null>(null);
  const [recoveredConversations, setRecoveredConversations] = useState<
    ActiveConversation[]
  >([]);
  const [participantIds, setParticipantIds] = useState('');
  const [memberAccountId, setMemberAccountId] = useState('');
  const [removeMemberAccountId, setRemoveMemberAccountId] = useState('');
  const [draft, setDraft] = useState('');
  const [messages, setMessages] = useState<PqcDisplayMessage[]>([]);
  const [fingerprintsConfirmed, setFingerprintsConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const deviceSessionLockRelease = useRef<(() => void) | null>(null);
  const pageMounted = useRef(false);

  const acquireDeviceSessionLock = async () => {
    if (!currentAccountId) throw new Error('Your account is not loaded yet');
    if (deviceSessionLockRelease.current) return;
    const release = await acquirePqcDeviceSessionLock(currentAccountId);
    if (!pageMounted.current) {
      release();
      throw new Error(
        'The encrypted messaging page closed before the device lock was acquired',
      );
    }
    deviceSessionLockRelease.current = release;
  };

  const releaseDeviceSessionLock = () => {
    deviceSessionLockRelease.current?.();
    deviceSessionLockRelease.current = null;
  };

  useEffect(() => {
    pageMounted.current = true;
    return () => {
      pageMounted.current = false;
      deviceSessionLockRelease.current?.();
      deviceSessionLockRelease.current = null;
    };
  }, []);

  const reload = useCallback(async () => {
    const [nextDevices, nextConversations] = await Promise.all([
      listPqcDevices(),
      listPqcConversations(),
    ]);
    setDevices(nextDevices);
    setConversations(nextConversations);
  }, []);

  useEffect(() => {
    // Initial API hydration is an external subscription to server state.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void reload().catch((cause: unknown) => {
      setError(errorText(cause));
    });
  }, [reload]);

  useEffect(() => {
    if (!recoveryStorageKey) return;

    try {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setRecoveryAvailable(localStorage.getItem(recoveryStorageKey) !== null);
    } catch {
      setError('This browser does not allow local encrypted recovery storage');
    }
  }, [recoveryStorageKey]);

  useEffect(() => {
    if (!device) {
      setPqcDeviceRequestSigner(null);
      return;
    }

    setPqcDeviceRequestSigner({
      deviceId: device.apiDevice.device_id,
      sign: (method, path, body, timestamp, nonce) =>
        signPqcDeviceRequest(
          device.keyPackage,
          method,
          path,
          timestamp,
          nonce,
          body,
        ),
    });

    return () => {
      setPqcDeviceRequestSigner(null);
    };
  }, [device]);

  const trustMap = useMemo(() => {
    if (!device || !active) return null;

    const map = new Map<string, string>();
    for (const memberDevice of active.conversation.member_devices) {
      trustPqcDevice(
        map,
        `${memberDevice.actor_uri}\n${memberDevice.device_id}\n${memberDevice.fingerprint}`,
        memberDevice.fingerprint,
      );
    }

    return map;
  }, [active, device]);

  const refreshMessages = useCallback(async () => {
    if (!device || !active || !trustMap) return;
    if (active.pendingMemberRemoval || active.pendingDeviceRemoval)
      throw new Error(
        'Finish the saved group removal before receiving messages',
      );
    if (active.pendingOutbound.length > 0) {
      const drained = await drainPqcOutbox(
        active,
        device,
        recoveredConversations,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      const nextRecovered = upsertRecoveredConversation(
        recoveredConversations,
        drained,
      );
      setActive(drained);
      setRecoveredConversations(nextRecovered);
      await saveRecovery(
        device,
        nextRecovered,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      return;
    }

    const latestConversations = await listPqcConversations();
    setConversations(latestConversations);
    const latestConversation = latestConversations.find(
      ({ id }) => id === active.conversation.id,
    );
    if (
      latestConversation &&
      !sameDeviceFingerprints(active.conversation, latestConversation)
    ) {
      setPendingConversation(latestConversation);
      setPendingMemberAccountId(null);
      setPendingTrustUpdate(true);
      setFingerprintsConfirmed(false);
      setError(
        'Conversation devices changed. Verify the displayed fingerprints before receiving more messages.',
      );
      return;
    }

    const relayMessages = await fetchPqcMessages(
      active.conversation.id,
      device.apiDevice.device_id,
      active.lastMessageId,
    );
    let currentDevice = device;
    let nextState = active.state;
    let cursor = active.lastMessageId;
    const received: PqcDisplayMessage[] = [];

    for (const message of relayMessages) {
      cursor = Math.max(cursor, message.id);
      if (message.sender_device_id === device.apiDevice.device_id) continue;
      if (
        message.recipient_device_id &&
        message.recipient_device_id !== device.apiDevice.device_id
      )
        continue;

      const payload = decodePqcMessage(message.ciphertext);
      if (!nextState) {
        if (message.recipient_device_id !== device.apiDevice.device_id)
          continue;
        const consumedKeyPackage = currentDevice.keyPackage;
        const nextKeyPackage =
          await rotatePqcDeviceKeyPackage(consumedKeyPackage);
        await publishPqcKeyPackage(
          currentDevice.apiDevice.id,
          nextKeyPackage.keyPackageMessage,
          nextKeyPackage.deviceAuthPublicKey,
        );
        currentDevice = { ...currentDevice, keyPackage: nextKeyPackage };
        setDevice(currentDevice);
        nextState = await joinPqcGroup(
          active.context,
          payload,
          consumedKeyPackage,
        );
        continue;
      }

      const processed = await processPqcMessage(
        active.context,
        nextState,
        payload,
      );
      nextState = processed.state;
      if (processed.kind === 'application')
        received.push({
          id: message.id,
          sender: message.sender_account_id,
          text: processed.plaintext,
        });
    }

    if (nextState) {
      const nextMessages = [...active.messages, ...received].slice(
        -MAX_RECOVERED_MESSAGES,
      );
      const updated = {
        ...active,
        state: nextState,
        lastMessageId: cursor,
        messages: nextMessages,
      };
      const nextRecovered = upsertRecoveredConversation(
        recoveredConversations,
        updated,
      );
      setRecoveredConversations(nextRecovered);
      setActive(updated);
      setMessages(nextMessages);
      await saveRecovery(
        currentDevice,
        nextRecovered,
        recoveryPassphrase,
        recoveryStorageKey,
      );
    } else {
      setActive({ ...active, state: nextState, lastMessageId: cursor });
    }
  }, [
    active,
    device,
    recoveredConversations,
    recoveryPassphrase,
    recoveryStorageKey,
    trustMap,
  ]);

  const createDevice = async () => {
    if (!currentAccountId) throw new Error('Your account is not loaded yet');
    if (recoveryPassphrase.length < 12)
      throw new Error('Choose a recovery passphrase of at least 12 characters');

    await acquireDeviceSessionLock();
    let keyPackage: PqcDeviceKeyPackage | null = null;
    try {
      if (recoveryStorageKey && localStorage.getItem(recoveryStorageKey)) {
        setRecoveryAvailable(true);
        throw new Error(
          'An encrypted messaging device is already saved for this account; unlock it or erase its recovery first',
        );
      }

      const accountId = currentAccountId;
      const actorUri = await fetchPqcActorUri(accountId);
      const deviceId = crypto.randomUUID();
      keyPackage = await generatePqcDeviceKeyPackage(
        actorUri,
        deviceId,
        newDeviceCipherSuiteId,
      );
      const apiDevice = await registerPqcDevice(
        deviceId,
        keyPackage.fingerprint,
        keyPackage.deviceAuthPublicKey,
        keyPackage.keyPackageMessage,
      );
      const session = { accountId, actorUri, apiDevice, keyPackage };
      await saveRecovery(
        session,
        recoveredConversations,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      setDevice(session);
      setRecoveryAvailable(true);
    } catch (cause) {
      keyPackage?.privatePackage.fill(0);
      releaseDeviceSessionLock();
      throw cause;
    }

    await reload();
  };

  const unlockDevice = async () => {
    if (!currentAccountId || !recoveryStorageKey)
      throw new Error('Your account is not loaded yet');
    const encoded = localStorage.getItem(recoveryStorageKey);
    if (!encoded)
      throw new Error('No encrypted recovery record exists in this browser');

    const plaintext = await restorePqcRecoveryData(
      decodeBase64(encoded),
      recoveryPassphrase,
    );
    try {
      const record = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(plaintext),
      ) as Partial<LocalRecoveryRecord>;
      const savedDevice = record.device;
      if (record.version !== 1 || !savedDevice)
        throw new Error('Unsupported or incomplete local recovery record');

      const [activeDevices, nextConversations] = await Promise.all([
        listPqcDevices(),
        listPqcConversations(),
      ]);
      const apiDevice = activeDevices.find(
        ({ id, device_id, fingerprint }) =>
          id === savedDevice.apiDevice.id &&
          device_id === savedDevice.apiDevice.device_id &&
          fingerprint === savedDevice.fingerprint,
      );
      if (!apiDevice)
        throw new Error(
          'This device is revoked or no longer matches the saved recovery record',
        );
      if (apiDevice.revocation_pending)
        throw new Error(
          'This device is pending removal from its MLS groups. Keep its recovery data until revocation is complete.',
        );
      if (!apiDevice.device_auth_ready)
        throw new Error(
          'This device predates ML-DSA request authentication. Register a new device and re-enroll it in your groups.',
        );

      const keyPackage = await restorePqcDeviceKeyPackage(savedDevice);
      const restoredDevice: LocalDeviceSession = {
        accountId: currentAccountId,
        apiDevice,
        actorUri: savedDevice.actorUri,
        keyPackage,
      };

      const restoredGroups: ActiveConversation[] = [];
      for (const savedGroup of record.activeConversations ?? []) {
        // Only restore the fingerprint snapshot the user previously confirmed.
        // New server-listed devices need a fresh out-of-band verification flow.
        const conversation = savedGroup.conversation;
        const state = deserializePqcGroupState(
          decodeBase64(savedGroup.serializedState),
        );
        const context = await contextForConversation(
          conversation,
          restoredDevice,
          state.groupContext.cipherSuite,
        );
        restoredGroups.push({
          conversation,
          context,
          state,
          lastMessageId: savedGroup.lastMessageId,
          messages: savedGroup.messages ?? [],
          pendingOutbound: savedGroup.pendingOutbound ?? [],
          pendingMemberAddition: savedGroup.pendingMemberAddition,
          pendingMemberRemoval: savedGroup.pendingMemberRemoval,
          pendingDeviceRemoval: savedGroup.pendingDeviceRemoval,
          pendingGroupSetup: savedGroup.pendingGroupSetup,
        });
      }

      await acquireDeviceSessionLock();
      setDevices(activeDevices);
      setConversations(nextConversations);
      setDevice(restoredDevice);
      setRecoveredConversations(restoredGroups);
      setActive(restoredGroups[0] ?? null);
      setMessages(restoredGroups[0]?.messages ?? []);
    } finally {
      plaintext.fill(0);
    }
  };

  const exportRecovery = () => {
    if (!recoveryStorageKey) throw new Error('Your account is not loaded yet');
    const encryptedRecord = localStorage.getItem(recoveryStorageKey);
    if (!encryptedRecord)
      throw new Error('No encrypted recovery record exists in this browser');

    const url = URL.createObjectURL(
      new Blob([encryptedRecord], { type: 'application/octet-stream' }),
    );
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `mastodon-pqc-recovery-${currentAccountId}.pqc`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(URL.revokeObjectURL.bind(URL, url), 0);
  };

  const changeRecoveryPassphrase = async (
    event: SyntheticEvent<HTMLFormElement>,
  ) => {
    event.preventDefault();
    if (!device || !recoveryStorageKey)
      throw new Error(
        'Unlock this device before changing its recovery passphrase',
      );
    if (passphraseVerification.length < 12)
      throw new Error('Enter the current recovery passphrase');
    if (replacementPassphrase.length < 12)
      throw new Error(
        'The new recovery passphrase must contain at least 12 characters',
      );
    if (replacementPassphrase !== replacementPassphraseConfirmation)
      throw new Error('The new recovery passphrases do not match');

    const previousRecord = localStorage.getItem(recoveryStorageKey);
    if (!previousRecord)
      throw new Error('No encrypted recovery record exists in this browser');

    const plaintext = await restorePqcRecoveryData(
      decodeBase64(previousRecord),
      passphraseVerification,
    );
    try {
      const record = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(plaintext),
      ) as Partial<LocalRecoveryRecord>;
      if (
        record.version !== 1 ||
        record.device?.apiDevice.id !== device.apiDevice.id ||
        record.device.identity !== device.keyPackage.identity ||
        record.device.fingerprint !== device.keyPackage.fingerprint
      ) {
        throw new Error(
          'The recovery record does not match this unlocked device',
        );
      }

      const replacement = await sealVerifiedPqcRecoveryData(
        plaintext,
        replacementPassphrase,
      );

      if (localStorage.getItem(recoveryStorageKey) !== previousRecord) {
        throw new Error(
          'The recovery record changed in another browser tab. Reload before changing its passphrase.',
        );
      }
      localStorage.setItem(recoveryStorageKey, encodeBase64(replacement));
      setRecoveryPassphrase(replacementPassphrase);
      setPassphraseVerification('');
      setReplacementPassphrase('');
      setReplacementPassphraseConfirmation('');
    } finally {
      plaintext.fill(0);
    }
  };

  const importRecovery = async (event: SyntheticEvent<HTMLInputElement>) => {
    if (device)
      throw new Error(
        'Lock the current messaging device before importing recovery data',
      );
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    if (!file || !recoveryStorageKey) return;
    if (file.size > 32 * 1024 * 1024)
      throw new Error('Encrypted recovery files must be smaller than 32 MiB');

    const previousRecord = localStorage.getItem(recoveryStorageKey);
    const importedRecord = (await file.text()).trim();
    const verifiedPlaintext = await restorePqcRecoveryData(
      decodeBase64(importedRecord),
      recoveryPassphrase,
    );
    verifiedPlaintext.fill(0);
    await acquireDeviceSessionLock();
    try {
      if (localStorage.getItem(recoveryStorageKey) !== previousRecord) {
        throw new Error(
          'The recovery record changed in another tab. Reload before importing this file.',
        );
      }
      localStorage.setItem(recoveryStorageKey, importedRecord);
      setRecoveryAvailable(true);
      await unlockDevice();
    } catch (cause) {
      if (localStorage.getItem(recoveryStorageKey) === importedRecord) {
        if (previousRecord === null)
          localStorage.removeItem(recoveryStorageKey);
        else localStorage.setItem(recoveryStorageKey, previousRecord);
      }
      setRecoveryAvailable(localStorage.getItem(recoveryStorageKey) !== null);
      releaseDeviceSessionLock();
      throw cause;
    }
  };

  const lockDevice = () => {
    device?.keyPackage.privatePackage.fill(0);
    releaseDeviceSessionLock();
    setDevice(null);
    setActive(null);
    setRecoveredConversations([]);
    setMessages([]);
    setRecoveryPassphrase('');
  };

  const revokeRegisteredDevice = async (registeredDevice: PqcDevice) => {
    const lockWasAlreadyHeld = deviceSessionLockRelease.current !== null;
    await acquireDeviceSessionLock();
    try {
      const result = await revokePqcDevice(registeredDevice.id);
      if (result?.revocation_pending) {
        if (device?.apiDevice.id === registeredDevice.id) {
          device.keyPackage.privatePackage.fill(0);
          releaseDeviceSessionLock();
          setDevice(null);
          setActive(null);
          setRecoveredConversations([]);
          setRecoveryAvailable(
            Boolean(
              recoveryStorageKey && localStorage.getItem(recoveryStorageKey),
            ),
          );
          setRecoveryPassphrase('');
          setError(
            'Revocation is pending until this device is removed from every MLS group. Its encrypted recovery was kept so group removal can be completed.',
          );
        }
        await reload();
        return;
      }

      if (device?.apiDevice.id === registeredDevice.id) {
        device.keyPackage.privatePackage.fill(0);
        releaseDeviceSessionLock();
        setDevice(null);
        setActive(null);
        setRecoveredConversations([]);
        if (recoveryStorageKey) localStorage.removeItem(recoveryStorageKey);
        setRecoveryAvailable(false);
      }
      await reload();
    } finally {
      if (!lockWasAlreadyHeld && device?.apiDevice.id !== registeredDevice.id)
        releaseDeviceSessionLock();
    }
  };

  const forgetRecovery = async () => {
    if (!recoveryStorageKey) throw new Error('Your account is not loaded yet');
    const encoded = localStorage.getItem(recoveryStorageKey);
    if (!encoded) throw new Error('No local recovery record exists');
    const plaintext = await restorePqcRecoveryData(
      decodeBase64(encoded),
      recoveryPassphrase,
    );
    let record: Partial<LocalRecoveryRecord>;
    try {
      record = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(plaintext),
      ) as Partial<LocalRecoveryRecord>;
    } finally {
      plaintext.fill(0);
    }
    if (!record.device)
      throw new Error('The local recovery record is incomplete');
    const savedDevice = record.device;

    await acquireDeviceSessionLock();
    try {
      const activeDevices = await listPqcDevices();
      const remoteDevice = activeDevices.find(
        ({ id }) => id === savedDevice.apiDevice.id,
      );
      if (remoteDevice) {
        if (
          remoteDevice.device_id !== savedDevice.apiDevice.device_id ||
          remoteDevice.fingerprint !== savedDevice.fingerprint
        ) {
          throw new Error(
            'The saved recovery device does not match the registered device; recovery was kept',
          );
        }
        if (remoteDevice.revocation_pending) {
          throw new Error(
            'Revocation is pending until this device is removed from every MLS group. Its encrypted recovery was kept.',
          );
        }
        if (!remoteDevice.device_auth_ready) {
          throw new Error(
            'This device cannot authenticate its revocation request; its encrypted recovery was kept',
          );
        }

        const keyPackage = await restorePqcDeviceKeyPackage(savedDevice);
        const signer: PqcDeviceRequestSigner = {
          deviceId: savedDevice.apiDevice.device_id,
          sign: (method, path, body, timestamp, nonce) =>
            signPqcDeviceRequest(
              keyPackage,
              method,
              path,
              timestamp,
              nonce,
              body,
            ),
        };
        let result: PqcDeviceRevocationResult | undefined;
        try {
          result = await revokePqcDevice(remoteDevice.id, signer);
        } finally {
          keyPackage.privatePackage.fill(0);
        }
        if (result?.revocation_pending) {
          await reload();
          throw new Error(
            'Revocation is pending until this device is removed from every MLS group. Its encrypted recovery was kept.',
          );
        }
      }

      localStorage.removeItem(recoveryStorageKey);
      device?.keyPackage.privatePackage.fill(0);
      releaseDeviceSessionLock();
      setDevice(null);
      setActive(null);
      setRecoveredConversations([]);
      setRecoveryAvailable(false);
      setRecoveryPassphrase('');
      await reload();
    } catch (cause) {
      releaseDeviceSessionLock();
      throw cause;
    }
  };

  const withBusy = async (operation: () => Promise<void> | void) => {
    setError('');
    setBusy(true);
    try {
      await operation();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  };

  const createConversation = async (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    await withBusy(async () => {
      if (!device || !currentAccountId)
        throw new Error('Register this browser as a device first');
      const ids = [
        ...new Set(
          participantIds
            .split(',')
            .map((value) => value.trim())
            .filter(isValidLocalAccountId),
        ),
      ];
      if (ids.length === 0)
        throw new Error('Enter at least one local account ID');

      const conversation = await createPqcConversation(
        ids,
        device.apiDevice.device_id,
      );
      setConversations((existing) => [
        conversation,
        ...existing.filter((item) => item.id !== conversation.id),
      ]);
      setPendingConversation(conversation);
      setPendingMemberAccountId(null);
      setPendingTrustUpdate(false);
      setFingerprintsConfirmed(false);
    });
  };

  const answerInvitation = async (accept: boolean) => {
    await withBusy(async () => {
      if (pendingConversation?.my_invitation_status !== 'invited')
        throw new Error(
          'This conversation has no pending invitation for your account',
        );
      const conversation = accept
        ? await acceptPqcConversationInvitation(pendingConversation.id)
        : await declinePqcConversationInvitation(pendingConversation.id);
      setConversations((existing) =>
        accept
          ? [
              conversation,
              ...existing.filter((item) => item.id !== conversation.id),
            ]
          : existing.filter((item) => item.id !== conversation.id),
      );
      setPendingConversation(accept ? conversation : null);
      setFingerprintsConfirmed(false);
    });
  };

  const refreshPendingConversation = async () => {
    await withBusy(async () => {
      if (!pendingConversation) return;
      const latest = (await listPqcConversations()).find(
        ({ id }) => id === pendingConversation.id,
      );
      if (!latest) throw new Error('This invitation is no longer available');
      setConversations((existing) => [
        latest,
        ...existing.filter((item) => item.id !== latest.id),
      ]);
      setPendingConversation(latest);
      setFingerprintsConfirmed(false);
    });
  };

  const openConversation = (conversation: PqcConversation) => {
    if (active?.conversation.id === conversation.id && active.state) {
      if (active.pendingMemberRemoval || active.pendingDeviceRemoval) return;
      if (active.pendingMemberAddition) {
        setPendingConversation(
          conversation.invited_account_ids.includes(
            active.pendingMemberAddition.accountId,
          )
            ? conversation
            : active.pendingMemberAddition.keyPackages.length > 0
              ? conversationWithPendingMember(
                  conversation,
                  active.pendingMemberAddition,
                )
              : conversation,
        );
        setPendingMemberAccountId(active.pendingMemberAddition.accountId);
        setPendingTrustUpdate(false);
        setFingerprintsConfirmed(false);
        return;
      }
      if (sameDeviceFingerprints(active.conversation, conversation)) {
        if (active.pendingGroupSetup) {
          setPendingConversation(conversation);
          setPendingMemberAccountId(null);
          setPendingTrustUpdate(false);
          setFingerprintsConfirmed(true);
        }
        return;
      }

      setPendingConversation(conversation);
      setPendingMemberAccountId(null);
      setPendingTrustUpdate(true);
      setFingerprintsConfirmed(false);
      return;
    }
    setPendingMemberAccountId(null);
    setPendingTrustUpdate(false);
    const recovered = recoveredConversations.find(
      ({ conversation: saved }) => saved.id === conversation.id,
    );
    if (recovered) {
      setActive(recovered);
      if (recovered.pendingMemberAddition) {
        setPendingConversation(
          conversation.invited_account_ids.includes(
            recovered.pendingMemberAddition.accountId,
          )
            ? conversation
            : recovered.pendingMemberAddition.keyPackages.length > 0
              ? conversationWithPendingMember(
                  conversation,
                  recovered.pendingMemberAddition,
                )
              : conversation,
        );
        setPendingMemberAccountId(recovered.pendingMemberAddition.accountId);
        setPendingTrustUpdate(false);
        setFingerprintsConfirmed(false);
      } else if (recovered.pendingGroupSetup) {
        setPendingConversation(conversation);
        setPendingMemberAccountId(null);
        setPendingTrustUpdate(false);
        setFingerprintsConfirmed(true);
      } else {
        setPendingConversation(null);
      }
      setMessages(recovered.messages);
      return;
    }
    setActive(null);
    setMessages([]);
    setPendingConversation(conversation);
    setPendingMemberAccountId(null);
    setFingerprintsConfirmed(false);
  };

  const prepareMemberAddition = async (
    event: SyntheticEvent<HTMLFormElement>,
  ) => {
    event.preventDefault();
    await withBusy(async () => {
      if (
        !device ||
        !active?.state ||
        !currentAccountId ||
        active.conversation.creator_account_id !== currentAccountId
      ) {
        throw new Error(
          'Only the conversation creator can add a member to an active group',
        );
      }
      if (active.pendingGroupSetup)
        throw new Error(
          'Finish the current group setup before adding another member',
        );
      if (active.pendingMemberRemoval || active.pendingDeviceRemoval)
        throw new Error(
          'Finish the saved group removal before adding another member',
        );
      const accountId = memberAccountId.trim();
      if (!isValidLocalAccountId(accountId))
        throw new Error('Enter a valid local account ID');

      let nextActive = active;
      if (
        nextActive.pendingMemberAddition &&
        nextActive.pendingMemberAddition.accountId !== accountId
      ) {
        throw new Error(
          'Finish or cancel the current member addition before preparing another',
        );
      }
      if (
        !nextActive.pendingMemberAddition &&
        nextActive.pendingOutbound.length > 0
      ) {
        nextActive = await drainPqcOutbox(
          nextActive,
          device,
          recoveredConversations,
          recoveryPassphrase,
          recoveryStorageKey,
        );
      }
      let addition = nextActive.pendingMemberAddition;
      if (!addition) {
        addition = {
          accountId,
          operationId: crypto.randomUUID(),
          keyPackages: [],
          fetchRequestId: crypto.randomUUID(),
          addedDeviceIds: [],
        };
        nextActive = { ...nextActive, pendingMemberAddition: addition };
      } else if (!addition.operationId) {
        addition = { ...addition, operationId: crypto.randomUUID() };
        nextActive = { ...nextActive, pendingMemberAddition: addition };
        const saved = upsertRecoveredConversation(
          recoveredConversations,
          nextActive,
        );
        setActive(nextActive);
        setRecoveredConversations(saved);
        await saveRecovery(
          device,
          saved,
          recoveryPassphrase,
          recoveryStorageKey,
        );
      }
      const invitation = await invitePqcConversationMember(
        nextActive.conversation.id,
        accountId,
      );
      nextActive = { ...nextActive, conversation: invitation };
      const invitedRecovery = upsertRecoveredConversation(
        recoveredConversations,
        nextActive,
      );
      setActive(nextActive);
      setRecoveredConversations(invitedRecovery);
      await saveRecovery(
        device,
        invitedRecovery,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      if (invitation.invited_account_ids.includes(accountId)) {
        setPendingConversation(invitation);
        setPendingMemberAccountId(accountId);
        setPendingTrustUpdate(false);
        setFingerprintsConfirmed(false);
        return;
      }
      if (!addition.batchReady && addition.keyPackages.length === 0) {
        if (!addition.fetchRequestId)
          throw new Error(
            'The saved KeyPackage request is missing; restore the encrypted recovery record',
          );
        const keyPackages = await fetchPqcKeyPackages(
          nextActive.conversation.id,
          accountId,
          addition.fetchRequestId,
        );
        if (keyPackages.length === 0) {
          const cleared = { ...nextActive, pendingMemberAddition: undefined };
          const saved = upsertRecoveredConversation(
            recoveredConversations,
            cleared,
          );
          setActive(cleared);
          setRecoveredConversations(saved);
          await saveRecovery(
            device,
            saved,
            recoveryPassphrase,
            recoveryStorageKey,
          );
          throw new Error(
            'This account needs an unjoined registered browser device before it can be added',
          );
        }
        addition = {
          ...addition,
          keyPackages,
          targetDeviceIds: keyPackages.map(({ device_id }) => device_id),
        };
        nextActive = { ...nextActive, pendingMemberAddition: addition };
        const saved = upsertRecoveredConversation(
          recoveredConversations,
          nextActive,
        );
        setActive(nextActive);
        setRecoveredConversations(saved);
        await saveRecovery(
          device,
          saved,
          recoveryPassphrase,
          recoveryStorageKey,
        );
      }

      const conversation = conversationWithPendingMember(
        nextActive.conversation,
        addition,
      );
      setActive(nextActive);
      setPendingConversation(conversation);
      setPendingMemberAccountId(accountId);
      setPendingTrustUpdate(false);
      setFingerprintsConfirmed(false);
    });
  };

  const commitPendingMemberRemoval = async (group: ActiveConversation) => {
    if (!device || !group.pendingMemberRemoval)
      throw new Error('The saved member-removal operation is missing');

    const result = await removePqcConversationMember(
      group.conversation.id,
      group.pendingMemberRemoval.accountId,
      device.apiDevice.device_id,
      group.pendingMemberRemoval.operationId,
      group.pendingOutbound,
    );
    const updated: ActiveConversation = {
      ...group,
      conversation: result.conversation,
      context: await contextForConversation(
        result.conversation,
        device,
        group.state?.groupContext.cipherSuite,
      ),
      pendingOutbound: [],
      pendingMemberRemoval: undefined,
      lastMessageId: Math.max(group.lastMessageId, ...result.message_ids, 0),
    };
    const nextRecovered = upsertRecoveredConversation(
      recoveredConversations,
      updated,
    );
    setActive(updated);
    setRecoveredConversations(nextRecovered);
    setConversations((existing) => [
      result.conversation,
      ...existing.filter((item) => item.id !== result.conversation.id),
    ]);
    setRemoveMemberAccountId('');
    await saveRecovery(
      device,
      nextRecovered,
      recoveryPassphrase,
      recoveryStorageKey,
    );
  };

  const commitPendingDeviceRemoval = async (group: ActiveConversation) => {
    if (!device || !group.pendingDeviceRemoval)
      throw new Error('The saved device-removal operation is missing');

    const result = await removePqcConversationDevice(
      group.conversation.id,
      group.pendingDeviceRemoval.deviceId,
      device.apiDevice.device_id,
      group.pendingDeviceRemoval.operationId,
      group.pendingOutbound,
    );
    const updated: ActiveConversation = {
      ...group,
      conversation: result.conversation,
      context: await contextForConversation(
        result.conversation,
        device,
        group.state?.groupContext.cipherSuite,
      ),
      pendingOutbound: [],
      pendingDeviceRemoval: undefined,
      lastMessageId: Math.max(group.lastMessageId, ...result.message_ids, 0),
    };
    const nextRecovered = upsertRecoveredConversation(
      recoveredConversations,
      updated,
    );
    setActive(updated);
    setRecoveredConversations(nextRecovered);
    setConversations((existing) => [
      result.conversation,
      ...existing.filter((item) => item.id !== result.conversation.id),
    ]);
    await saveRecovery(
      device,
      nextRecovered,
      recoveryPassphrase,
      recoveryStorageKey,
    );
  };

  const removeGroupDevice = async (targetDeviceId: string) => {
    await withBusy(async () => {
      if (!device || !active?.state || !currentAccountId)
        throw new Error(
          'Unlock a registered device before removing a group device',
        );
      if (targetDeviceId === device.apiDevice.device_id)
        throw new Error(
          'Use another registered device to remove this device from its MLS groups',
        );
      if (
        active.pendingGroupSetup ||
        active.pendingMemberAddition ||
        active.pendingMemberRemoval ||
        active.pendingDeviceRemoval ||
        active.pendingOutbound.length > 0
      ) {
        throw new Error(
          'Finish the current encrypted group operation before removing a device',
        );
      }

      const latest = (await listPqcConversations()).find(
        ({ id }) => id === active.conversation.id,
      );
      if (!latest) throw new Error('The conversation is no longer available');
      if (!sameDeviceFingerprints(active.conversation, latest)) {
        setPendingConversation(latest);
        setPendingTrustUpdate(true);
        setFingerprintsConfirmed(false);
        throw new Error(
          'A group device changed. Review and confirm the current fingerprints before removing a device.',
        );
      }

      const joinedDeviceIds = new Set(latest.joined_device_ids);
      const target = latest.member_devices.find(
        ({ device_id }) => device_id === targetDeviceId,
      );
      if (!target || !joinedDeviceIds.has(targetDeviceId))
        throw new Error(
          'That device is not an active member of this MLS group',
        );
      if (
        target.account_id !== currentAccountId &&
        latest.creator_account_id !== currentAccountId &&
        !target.revocation_pending
      )
        throw new Error(
          'Only the device owner or group creator can remove that device unless revocation has started',
        );

      const removal = await removePqcGroupMembers(
        active.context,
        active.state,
        [`${target.actor_uri}\n${target.device_id}\n${target.fingerprint}`],
      );
      const deliveries = latest.member_devices
        .filter(
          ({ device_id }) =>
            joinedDeviceIds.has(device_id) &&
            device_id !== targetDeviceId &&
            device_id !== device.apiDevice.device_id,
        )
        .map((memberDevice): PqcPendingOutbound => ({
          clientMessageId: crypto.randomUUID(),
          ciphertext: encodeBase64(removal.commit),
          recipientDeviceId: memberDevice.device_id,
        }));
      const pendingRemoval: ActiveConversation = {
        ...active,
        state: removal.state,
        pendingOutbound: deliveries,
        pendingDeviceRemoval: {
          deviceId: targetDeviceId,
          operationId: crypto.randomUUID(),
        },
      };
      const nextRecovered = upsertRecoveredConversation(
        recoveredConversations,
        pendingRemoval,
      );
      setActive(pendingRemoval);
      setRecoveredConversations(nextRecovered);
      await saveRecovery(
        device,
        nextRecovered,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      await commitPendingDeviceRemoval(pendingRemoval);
    });
  };

  const removeGroupMember = async (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    await withBusy(async () => {
      if (!device || !active?.state || !currentAccountId) {
        throw new Error('Unlock a registered device before removing a member');
      }
      const isCreator =
        active.conversation.creator_account_id === currentAccountId;
      if (
        !isCreator &&
        active.conversation.leave_requested_account_ids.length === 0
      )
        throw new Error(
          'Only the creator can remove a member without a departure request',
        );
      if (
        active.pendingGroupSetup ||
        active.pendingMemberAddition ||
        active.pendingMemberRemoval ||
        active.pendingDeviceRemoval ||
        active.pendingOutbound.length > 0
      ) {
        throw new Error(
          'Finish the current encrypted group operation before removing a member',
        );
      }

      const accountId = removeMemberAccountId.trim();
      if (!isValidLocalAccountId(accountId) || accountId === currentAccountId) {
        throw new Error('Enter a valid member account ID other than your own');
      }
      if (!active.conversation.member_account_ids.includes(accountId))
        throw new Error('That account is not a member of this conversation');
      if (
        !isCreator &&
        !active.conversation.leave_requested_account_ids.includes(accountId)
      )
        throw new Error(
          'Only the creator can remove a member without a departure request',
        );

      const latest = (await listPqcConversations()).find(
        ({ id }) => id === active.conversation.id,
      );
      if (!latest) throw new Error('The conversation is no longer available');
      if (!sameDeviceFingerprints(active.conversation, latest)) {
        setPendingConversation(latest);
        setPendingTrustUpdate(true);
        setFingerprintsConfirmed(false);
        throw new Error(
          'A group device changed. Review and confirm the current fingerprints before removing a member.',
        );
      }

      const joinedDeviceIds = new Set(latest.joined_device_ids);
      const removedDevices = latest.member_devices.filter(
        ({ account_id: memberId, device_id }) =>
          memberId === accountId && joinedDeviceIds.has(device_id),
      );
      if (removedDevices.length === 0)
        throw new Error('The member has no active devices in this group');
      const removal = await removePqcGroupMembers(
        active.context,
        active.state,
        removedDevices.map(
          ({ actor_uri, device_id, fingerprint }) =>
            `${actor_uri}\n${device_id}\n${fingerprint}`,
        ),
      );
      const deliveries = latest.member_devices
        .filter(
          ({ account_id: memberId, device_id }) =>
            memberId !== accountId &&
            joinedDeviceIds.has(device_id) &&
            device_id !== device.apiDevice.device_id,
        )
        .map((memberDevice): PqcPendingOutbound => ({
          clientMessageId: crypto.randomUUID(),
          ciphertext: encodeBase64(removal.commit),
          recipientDeviceId: memberDevice.device_id,
        }));
      const pendingRemoval: ActiveConversation = {
        ...active,
        state: removal.state,
        pendingOutbound: deliveries,
        pendingMemberRemoval: { accountId, operationId: crypto.randomUUID() },
      };
      const nextRecovered = upsertRecoveredConversation(
        recoveredConversations,
        pendingRemoval,
      );
      setActive(pendingRemoval);
      setRecoveredConversations(nextRecovered);
      await saveRecovery(
        device,
        nextRecovered,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      await commitPendingMemberRemoval(pendingRemoval);
    });
  };

  const requestToLeaveGroup = async () => {
    await withBusy(async () => {
      if (
        !device ||
        !active ||
        !currentAccountId ||
        active.conversation.creator_account_id === currentAccountId
      ) {
        throw new Error(
          'The group creator cannot request to leave this prototype group',
        );
      }
      if (
        active.pendingGroupSetup ||
        active.pendingMemberAddition ||
        active.pendingMemberRemoval ||
        active.pendingDeviceRemoval ||
        active.pendingOutbound.length > 0
      ) {
        throw new Error(
          'Finish the current encrypted group operation before requesting to leave',
        );
      }
      const conversation = await requestPqcConversationLeave(
        active.conversation.id,
      );
      const updated = { ...active, conversation };
      const nextRecovered = upsertRecoveredConversation(
        recoveredConversations,
        updated,
      );
      setActive(updated);
      setRecoveredConversations(nextRecovered);
      setConversations((existing) => [
        conversation,
        ...existing.filter((item) => item.id !== conversation.id),
      ]);
      await saveRecovery(
        device,
        nextRecovered,
        recoveryPassphrase,
        recoveryStorageKey,
      );
    });
  };

  const startPendingConversation = async () => {
    await withBusy(async () => {
      if (!device || !currentAccountId || !pendingConversation)
        throw new Error(
          'Choose a conversation and register this browser as a device first',
        );

      const latestConversations = await listPqcConversations();
      setConversations(latestConversations);
      const latestConversation = latestConversations.find(
        ({ id }) => id === pendingConversation.id,
      );
      const isMemberAddition = pendingMemberAccountId !== null;
      const addition = active?.pendingMemberAddition;
      let conversation = pendingConversation;
      if (!isMemberAddition && latestConversation)
        conversation = latestConversation;
      if (!isMemberAddition && conversation.my_invitation_status === 'invited')
        throw new Error(
          'Accept or decline this invitation before joining a group',
        );
      if (
        !isMemberAddition &&
        conversation.creator_account_id === currentAccountId &&
        conversation.invited_account_ids.length > 0
      ) {
        throw new Error(
          'Wait for every invitee to accept or decline before starting group setup',
        );
      }
      if (
        !isMemberAddition &&
        conversation.creator_account_id !== currentAccountId &&
        !conversation.ready_at
      ) {
        throw new Error(
          'You accepted this invitation. Wait for the creator to finish group setup.',
        );
      }
      if (isMemberAddition) {
        if (
          !active?.state ||
          active.conversation.id !== pendingConversation.id ||
          addition?.accountId !== pendingMemberAccountId
        ) {
          throw new Error(
            'The saved member-add operation is missing; resume it from the encrypted recovery state',
          );
        }

        const latestAdditionConversation =
          latestConversation ?? active.conversation;
        if (
          latestAdditionConversation.invited_account_ids.includes(
            pendingMemberAccountId,
          )
        ) {
          setPendingConversation(latestAdditionConversation);
          setError(
            'Wait for this account to accept or decline the invitation before continuing.',
          );
          return;
        }
        if (
          !latestAdditionConversation.pending_addition_account_ids.includes(
            pendingMemberAccountId,
          ) &&
          !latestAdditionConversation.member_account_ids.includes(
            pendingMemberAccountId,
          )
        ) {
          throw new Error(
            'This account has no accepted invitation for the group addition',
          );
        }

        if (!addition.batchReady && addition.keyPackages.length === 0) {
          if (!addition.fetchRequestId)
            throw new Error(
              'The saved KeyPackage request is missing; restore the encrypted recovery record',
            );
          const keyPackages = await fetchPqcKeyPackages(
            active.conversation.id,
            pendingMemberAccountId,
            addition.fetchRequestId,
          );
          if (keyPackages.length === 0)
            throw new Error(
              'This account needs an unjoined registered browser device before it can be added',
            );

          const updatedAddition = {
            ...addition,
            keyPackages,
            targetDeviceIds: keyPackages.map(({ device_id }) => device_id),
          };
          const updatedActive = {
            ...active,
            pendingMemberAddition: updatedAddition,
          };
          const updatedRecovered = upsertRecoveredConversation(
            recoveredConversations,
            updatedActive,
          );
          setActive(updatedActive);
          setRecoveredConversations(updatedRecovered);
          await saveRecovery(
            device,
            updatedRecovered,
            recoveryPassphrase,
            recoveryStorageKey,
          );
          setPendingConversation(
            conversationWithPendingMember(
              latestConversation ?? active.conversation,
              updatedAddition,
            ),
          );
          setFingerprintsConfirmed(false);
          setError('Review the new device fingerprints before continuing.');
          return;
        }

        const latest = latestConversation ?? active.conversation;
        if (
          !sameDeviceFingerprintsExceptAccount(
            active.conversation,
            latest,
            pendingMemberAccountId,
          )
        ) {
          setPendingConversation(
            conversationWithPendingMember(latest, addition),
          );
          setFingerprintsConfirmed(false);
          setError(
            'An existing group device changed. Review the current fingerprints before continuing.',
          );
          return;
        }

        if (
          !addition.batchReady &&
          latest.member_account_ids.includes(pendingMemberAccountId) &&
          !sameAccountDeviceFingerprints(
            latest,
            pendingMemberAccountId,
            addition.keyPackages,
          )
        ) {
          setPendingConversation(
            conversationWithPendingMember(latest, addition),
          );
          setFingerprintsConfirmed(false);
          setError(
            'The prospective member device list changed. Review the current fingerprints before continuing.',
          );
          return;
        }

        conversation = conversationWithPendingMember(latest, addition);
      } else if (
        latestConversation &&
        !sameDeviceFingerprints(pendingConversation, latestConversation)
      ) {
        setPendingConversation(latestConversation);
        setFingerprintsConfirmed(false);
        setError(
          'The member device list changed. Review the current fingerprints before continuing.',
        );
        return;
      }
      if (!fingerprintsConfirmed)
        throw new Error(
          'Confirm that you checked the displayed fingerprints out of band',
        );

      const context = await contextForConversation(
        conversation,
        device,
        active?.conversation.id === conversation.id
          ? active.state?.groupContext.cipherSuite
          : undefined,
      );
      if (pendingTrustUpdate) {
        if (!active?.state || active.conversation.id !== conversation.id)
          throw new Error(
            'Resume the active group before reviewing device changes',
          );
        const nextActive = { ...active, conversation, context };
        const nextRecovered = upsertRecoveredConversation(
          recoveredConversations,
          nextActive,
        );
        setActive(nextActive);
        setRecoveredConversations(nextRecovered);
        await saveRecovery(
          device,
          nextRecovered,
          recoveryPassphrase,
          recoveryStorageKey,
        );
      } else if (pendingMemberAccountId !== null) {
        if (!active?.state)
          throw new Error(
            'The saved member-add operation is missing; resume it from the encrypted recovery state',
          );
        let nextActive: ActiveConversation = active;
        let nextAddition =
          nextActive.pendingMemberAddition as PqcPendingMemberAddition;
        if (
          !nextAddition.batchReady &&
          nextActive.pendingOutbound.length > 0 &&
          nextAddition.addedDeviceIds?.length === 0
        ) {
          nextActive = await drainPqcOutbox(
            nextActive,
            device,
            recoveredConversations,
            recoveryPassphrase,
            recoveryStorageKey,
          );
          setActive(nextActive);
          nextAddition =
            nextActive.pendingMemberAddition as PqcPendingMemberAddition;
        }
        let packages = nextAddition.keyPackages;
        if (
          !nextAddition.batchReady &&
          packages.length === 0 &&
          nextAddition.fetchRequestId
        ) {
          packages = await fetchPqcKeyPackages(
            conversation.id,
            pendingMemberAccountId,
            nextAddition.fetchRequestId,
          );
          if (packages.length > 0) {
            nextAddition = { ...nextAddition, keyPackages: packages };
            nextActive = { ...nextActive, pendingMemberAddition: nextAddition };
          }
        }
        if (packages.length === 0) {
          nextActive = { ...nextActive, pendingMemberAddition: undefined };
          const noPackages = upsertRecoveredConversation(
            recoveredConversations,
            nextActive,
          );
          setActive(nextActive);
          setRecoveredConversations(noPackages);
          await saveRecovery(
            device,
            noPackages,
            recoveryPassphrase,
            recoveryStorageKey,
          );
          throw new Error(
            'This account needs an unjoined registered browser device before it can be added',
          );
        }
        const fetchedGroups = upsertRecoveredConversation(
          recoveredConversations,
          nextActive,
        );
        setActive(nextActive);
        setRecoveredConversations(fetchedGroups);
        await saveRecovery(
          device,
          fetchedGroups,
          recoveryPassphrase,
          recoveryStorageKey,
        );

        if (!nextAddition.batchReady) {
          const targetDeviceIds = new Set(
            nextAddition.targetDeviceIds ??
              packages.map(({ device_id }) => device_id),
          );
          const existingDeviceIds = active.conversation.member_devices
            .map(({ device_id }) => device_id)
            .filter(
              (deviceId) =>
                active.conversation.joined_device_ids.includes(deviceId) &&
                deviceId !== device.apiDevice.device_id &&
                !targetDeviceIds.has(deviceId),
            );
          let addedDeviceIds = nextAddition.addedDeviceIds ?? [];

          for (
            let packageIndex = 0;
            packageIndex < packages.length;
            packageIndex += 1
          ) {
            const remotePackage = packages[packageIndex];
            if (!remotePackage) continue;
            const added = await addPqcGroupMember(
              context,
              nextActive.state as ClientState,
              decodePqcKeyPackage(remotePackage.key_package),
            );
            const commitRecipients = [
              ...new Set([...existingDeviceIds, ...addedDeviceIds]),
            ];
            const commitDeliveries = commitRecipients.map(
              (recipientDeviceId): PqcPendingOutbound => ({
                clientMessageId: crypto.randomUUID(),
                ciphertext: encodeBase64(added.commit),
                recipientDeviceId,
              }),
            );
            nextAddition = {
              ...nextAddition,
              keyPackages: packages.slice(packageIndex + 1),
              addedDeviceIds: [...addedDeviceIds, remotePackage.device_id],
            };
            nextActive = {
              ...nextActive,
              conversation: active.conversation,
              context,
              state: added.state,
              pendingMemberAddition: nextAddition,
              pendingOutbound: [
                ...nextActive.pendingOutbound,
                ...commitDeliveries,
                {
                  clientMessageId: crypto.randomUUID(),
                  ciphertext: encodeBase64(added.welcome),
                  recipientDeviceId: remotePackage.device_id,
                },
              ],
            };
            const saved = upsertRecoveredConversation(
              recoveredConversations,
              nextActive,
            );
            setActive(nextActive);
            setRecoveredConversations(saved);
            await saveRecovery(
              device,
              saved,
              recoveryPassphrase,
              recoveryStorageKey,
            );
            addedDeviceIds = nextAddition.addedDeviceIds ?? [];
            packages = nextAddition.keyPackages;
            packageIndex = -1;
          }

          nextAddition = { ...nextAddition, batchReady: true };
          nextActive = { ...nextActive, pendingMemberAddition: nextAddition };
          const saved = upsertRecoveredConversation(
            recoveredConversations,
            nextActive,
          );
          setActive(nextActive);
          setRecoveredConversations(saved);
          await saveRecovery(
            device,
            saved,
            recoveryPassphrase,
            recoveryStorageKey,
          );
        }

        if (
          !nextAddition.operationId ||
          !nextAddition.fetchRequestId ||
          !nextAddition.targetDeviceIds?.length
        )
          throw new Error(
            'The saved device-addition operation is incomplete; resume it from the encrypted recovery state',
          );
        const result = await commitPqcConversationMember(
          conversation.id,
          pendingMemberAccountId,
          device.apiDevice.device_id,
          nextAddition.operationId,
          nextAddition.fetchRequestId,
          nextAddition.targetDeviceIds,
          nextActive.pendingOutbound,
        );
        nextActive = {
          ...nextActive,
          conversation: result.conversation,
          context: await contextForConversation(
            result.conversation,
            device,
            nextActive.state?.groupContext.cipherSuite,
          ),
          pendingOutbound: [],
          pendingMemberAddition: undefined,
          lastMessageId: Math.max(
            nextActive.lastMessageId,
            ...result.message_ids,
          ),
        };
        const nextRecovered = upsertRecoveredConversation(
          recoveredConversations,
          nextActive,
        );
        setActive(nextActive);
        setRecoveredConversations(nextRecovered);
        await saveRecovery(
          device,
          nextRecovered,
          recoveryPassphrase,
          recoveryStorageKey,
        );
        setConversations((existing) => [
          result.conversation,
          ...existing.filter((item) => item.id !== result.conversation.id),
        ]);
        setPendingConversation(null);
        setPendingMemberAccountId(null);
        setMemberAccountId('');
      } else if (
        conversation.creator_account_id === currentAccountId &&
        !conversation.ready_at
      ) {
        let nextDevice = device;
        let nextActive: ActiveConversation;
        if (
          active?.conversation.id === conversation.id &&
          active.state &&
          active.pendingGroupSetup
        ) {
          nextActive = { ...active, conversation, context };
        } else {
          const nextKeyPackage = await rotatePqcDeviceKeyPackage(
            device.keyPackage,
          );
          await publishPqcKeyPackage(
            device.apiDevice.id,
            nextKeyPackage.keyPackageMessage,
            nextKeyPackage.deviceAuthPublicKey,
          );
          nextDevice = { ...device, keyPackage: nextKeyPackage };
          setDevice(nextDevice);
          await saveRecovery(
            nextDevice,
            recoveredConversations,
            recoveryPassphrase,
            recoveryStorageKey,
          );

          const state = await createPqcGroup(
            context,
            conversation.id,
            device.keyPackage,
          );
          nextActive = {
            conversation,
            context,
            state,
            lastMessageId: 0,
            messages: [],
            pendingOutbound: [],
            pendingGroupSetup: {
              accountIds: conversation.member_account_ids,
              keyPackages: [],
              activeDeviceIds: [],
            },
          };
        }

        const persistGroupSetup = async (updated: ActiveConversation) => {
          nextActive = updated;
          const nextRecovered = upsertRecoveredConversation(
            recoveredConversations,
            updated,
          );
          setActive(updated);
          setRecoveredConversations(nextRecovered);
          await saveRecovery(
            nextDevice,
            nextRecovered,
            recoveryPassphrase,
            recoveryStorageKey,
          );
        };

        await persistGroupSetup(nextActive);
        nextActive = await continuePqcGroupSetup(
          nextActive,
          nextDevice,
          persistGroupSetup,
        );
        const result = await completePqcGroupSetup(
          conversation.id,
          nextDevice.apiDevice.device_id,
          nextActive.pendingOutbound,
        );
        nextActive = {
          ...nextActive,
          conversation: result.conversation,
          context: await contextForConversation(
            result.conversation,
            nextDevice,
            nextActive.state?.groupContext.cipherSuite,
          ),
          lastMessageId: Math.max(
            nextActive.lastMessageId,
            ...result.message_ids,
            0,
          ),
          pendingOutbound: [],
          pendingGroupSetup: undefined,
        };
        await persistGroupSetup(nextActive);
        setDevice(nextDevice);
        setActive(nextActive);
      } else {
        setActive({
          conversation,
          context,
          state: undefined,
          lastMessageId: 0,
          messages: [],
          pendingOutbound: [],
        });
        await saveRecovery(
          device,
          recoveredConversations,
          recoveryPassphrase,
          recoveryStorageKey,
        );
      }

      setPendingConversation(null);
      setPendingMemberAccountId(null);
      setPendingTrustUpdate(false);
      setFingerprintsConfirmed(false);
    });
  };

  const sendMessage = async (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    await withBusy(async () => {
      if (!device || !active || !draft.trim()) return;
      if (!active.state)
        throw new Error('Join the conversation before sending messages');
      if (active.pendingMemberRemoval || active.pendingDeviceRemoval)
        throw new Error(
          'Finish the saved group removal before sending another message',
        );

      const latestConversations = await listPqcConversations();
      setConversations(latestConversations);
      const latestConversation = latestConversations.find(
        ({ id }) => id === active.conversation.id,
      );
      if (
        latestConversation &&
        !sameDeviceFingerprints(active.conversation, latestConversation)
      ) {
        setPendingConversation(latestConversation);
        setPendingTrustUpdate(true);
        setFingerprintsConfirmed(false);
        throw new Error(
          'Conversation devices changed. Verify the displayed fingerprints before sending messages.',
        );
      }

      if (active.pendingOutbound.length > 0) {
        const drained = await drainPqcOutbox(
          active,
          device,
          recoveredConversations,
          recoveryPassphrase,
          recoveryStorageKey,
        );
        setActive(drained);
        throw new Error(
          'Queued messages were retried. Submit the draft again if it was not already sent.',
        );
      }
      const text = draft.trim();
      const sent = await createPqcApplicationMessage(
        active.context,
        active.state,
        text,
      );
      const pending: PqcPendingOutbound = {
        clientMessageId: crypto.randomUUID(),
        ciphertext: encodeBase64(sent.ciphertext),
      };
      const queued = {
        ...active,
        state: sent.state,
        pendingOutbound: [pending],
      };
      const queuedGroups = upsertRecoveredConversation(
        recoveredConversations,
        queued,
      );
      setActive(queued);
      setRecoveredConversations(queuedGroups);
      await saveRecovery(
        device,
        queuedGroups,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      const relayMessage = await sendPqcMessage(
        active.conversation.id,
        device.apiDevice.device_id,
        sent.ciphertext,
        undefined,
        pending.clientMessageId,
      );
      const nextMessages = [
        ...active.messages,
        { id: relayMessage.id, sender: 'You', text: draft.trim() },
      ].slice(-MAX_RECOVERED_MESSAGES);
      const nextActive = {
        ...queued,
        pendingOutbound: [],
        lastMessageId: Math.max(active.lastMessageId, relayMessage.id),
        messages: nextMessages,
      };
      setActive(nextActive);
      const nextRecovered = upsertRecoveredConversation(
        recoveredConversations,
        nextActive,
      );
      setRecoveredConversations(nextRecovered);
      await saveRecovery(
        device,
        nextRecovered,
        recoveryPassphrase,
        recoveryStorageKey,
      );
      setMessages(nextMessages);
      setDraft('');
    });
  };

  return (
    <Column label='Experimental post-quantum encrypted messaging'>
      <ColumnHeader title='Experimental encrypted messaging' />
      <div className='scrollable'>
        <div className='column__berlin'>
          <p role='status'>
            This is an experimental MLS prototype. Messages here are separate
            from ordinary Mastodon direct messages.
          </p>
          <p>
            The server relays encrypted payloads but still sees conversation
            members, timing, and message sizes. The client library and cipher
            suite have not had a formal security audit.
          </p>

          {error && <p role='alert'>{error}</p>}
          <section aria-labelledby='pqc-recovery-title'>
            <h2 id='pqc-recovery-title'>Device recovery</h2>
            <p>
              Only one tab at this site address can hold the messaging device
              unlocked. Lock it in the other tab before continuing here.
            </p>
            <label htmlFor='pqc-recovery-passphrase'>
              Recovery passphrase (at least 12 characters)
            </label>
            <input
              id='pqc-recovery-passphrase'
              type='password'
              autoComplete='new-password'
              disabled={busy || Boolean(device)}
              value={recoveryPassphrase}
              onChange={(event) => {
                setRecoveryPassphrase(event.currentTarget.value);
              }}
            />
            {!device && recoveryAvailable && (
              <button
                type='button'
                className='button'
                disabled={busy || recoveryPassphrase.length < 12}
                onClick={() => void withBusy(unlockDevice)}
              >
                Unlock saved device
              </button>
            )}
            {recoveryAvailable && (
              <button
                type='button'
                className='button'
                disabled={busy}
                onClick={() => {
                  void withBusy(exportRecovery);
                }}
              >
                Export encrypted recovery file
              </button>
            )}
            {!device && (
              <div>
                <label htmlFor='pqc-recovery-file'>
                  Import encrypted recovery file
                </label>
                <input
                  id='pqc-recovery-file'
                  type='file'
                  accept='.pqc,application/octet-stream,text/plain'
                  disabled={busy || recoveryPassphrase.length < 12}
                  onChange={(event) =>
                    void withBusy(async () => {
                      await importRecovery(event);
                    })
                  }
                />
              </div>
            )}
            {!device && !recoveryAvailable && (
              <>
                <label htmlFor='pqc-new-device-suite'>
                  MLS cipher suite for this device
                </label>
                <select
                  id='pqc-new-device-suite'
                  value={newDeviceCipherSuiteId}
                  disabled={busy}
                  onChange={(event) => {
                    setNewDeviceCipherSuiteId(
                      Number(event.currentTarget.value),
                    );
                  }}
                >
                  <option value={LEGACY_PQC_MLS_CIPHERSUITE_ID}>
                    Existing experimental suite (0xf011)
                  </option>
                  <option value={DRAFT_PQC_MLS_CIPHERSUITE_ID}>
                    Draft hybrid suite (0x0052, requires matching devices)
                  </option>
                </select>
                {newDeviceCipherSuiteId === DRAFT_PQC_MLS_CIPHERSUITE_ID && (
                  <p>
                    Draft suite 0x0052 interoperates with the pinned OpenMLS
                    test peer. Its codepoint is provisional, so use it only
                    between matching test clients.
                  </p>
                )}
                <button
                  type='button'
                  className='button'
                  disabled={busy || recoveryPassphrase.length < 12}
                  onClick={() => void withBusy(createDevice)}
                >
                  Register this browser as a device
                </button>
              </>
            )}
            {device && (
              <button
                type='button'
                className='button'
                disabled={busy}
                onClick={lockDevice}
              >
                Lock this device
              </button>
            )}
            {device && recoveryAvailable && (
              <form
                onSubmit={(event) =>
                  void withBusy(async () => {
                    await changeRecoveryPassphrase(event);
                  })
                }
              >
                <h3>Change this browser’s recovery passphrase</h3>
                <label htmlFor='pqc-current-passphrase'>
                  Current passphrase
                </label>
                <input
                  id='pqc-current-passphrase'
                  type='password'
                  autoComplete='current-password'
                  value={passphraseVerification}
                  disabled={busy}
                  onChange={(event) => {
                    setPassphraseVerification(event.currentTarget.value);
                  }}
                />
                <label htmlFor='pqc-new-passphrase'>New passphrase</label>
                <input
                  id='pqc-new-passphrase'
                  type='password'
                  autoComplete='new-password'
                  value={replacementPassphrase}
                  disabled={busy}
                  onChange={(event) => {
                    setReplacementPassphrase(event.currentTarget.value);
                  }}
                />
                <label htmlFor='pqc-confirm-passphrase'>
                  Confirm new passphrase
                </label>
                <input
                  id='pqc-confirm-passphrase'
                  type='password'
                  autoComplete='new-password'
                  value={replacementPassphraseConfirmation}
                  disabled={busy}
                  onChange={(event) => {
                    setReplacementPassphraseConfirmation(
                      event.currentTarget.value,
                    );
                  }}
                />
                <button
                  type='submit'
                  className='button'
                  disabled={
                    busy ||
                    passphraseVerification.length < 12 ||
                    replacementPassphrase.length < 12 ||
                    replacementPassphrase !== replacementPassphraseConfirmation
                  }
                >
                  Change recovery passphrase
                </button>
                <p>
                  This updates the encrypted copy in this browser. Export a new
                  recovery file afterward; older exports still use the old
                  passphrase. A forgotten passphrase cannot be reset.
                </p>
              </form>
            )}
            {!device && recoveryAvailable && (
              <button
                type='button'
                className='button'
                disabled={busy || recoveryPassphrase.length < 12}
                onClick={() => void withBusy(forgetRecovery)}
              >
                Erase recovery and revoke device
              </button>
            )}
            <p>
              Recovery files contain encrypted device keys and group state. Keep
              both the file and its passphrase safe; the passphrase is not sent
              to the server.
            </p>
            <p>
              Restoring a file clones the same MLS device. Close and lock the
              old browser session before using the restored one; concurrent
              copies can desynchronize the group.
            </p>
          </section>
          {!device ? (
            <p>Unlock or register a device to use encrypted messaging.</p>
          ) : (
            <section aria-labelledby='pqc-device-title'>
              <h2 id='pqc-device-title'>This browser device</h2>
              <p>
                Fingerprint: <code>{device.keyPackage.fingerprint}</code>
              </p>
              <p>
                Private keys and active MLS state are saved locally in encrypted
                form. Enter the recovery passphrase after a reload to restore
                this browser.
              </p>
              <p>{devices.length} device(s) registered on this account.</p>
            </section>
          )}
          {devices.map((registeredDevice) => {
            const enrolledGroups = conversations.filter(
              ({ joined_device_ids }) =>
                joined_device_ids.includes(registeredDevice.device_id),
            );

            return (
              <p key={registeredDevice.id}>
                {registeredDevice.device_id} ·{' '}
                <code>{registeredDevice.fingerprint}</code> ·{' '}
                {enrolledGroups.length} group(s)
                {registeredDevice.revocation_pending &&
                enrolledGroups.length > 0 ? (
                  <>
                    <span>
                      Revocation is pending. Open each group and remove this
                      device to finish.
                    </span>
                    {enrolledGroups.map((conversation) => (
                      <button
                        key={`pending-revoke-${registeredDevice.id}-${conversation.id}`}
                        type='button'
                        className='button'
                        disabled={busy || !device}
                        onClick={() => {
                          openConversation(conversation);
                        }}
                      >
                        Open group {conversation.id} to remove device
                      </button>
                    ))}
                  </>
                ) : (
                  <button
                    type='button'
                    className='button'
                    disabled={busy || !device}
                    onClick={() =>
                      void withBusy(async () => {
                        await revokeRegisteredDevice(registeredDevice);
                      })
                    }
                  >
                    {registeredDevice.revocation_pending
                      ? 'Finalize revocation'
                      : enrolledGroups.length > 0
                        ? 'Block and begin revocation'
                        : 'Revoke'}
                  </button>
                )}
              </p>
            );
          })}

          <form onSubmit={(event) => void createConversation(event)}>
            <h2>Create an encrypted conversation</h2>
            <label htmlFor='pqc-account-ids'>
              Local account IDs, comma separated
            </label>
            <input
              id='pqc-account-ids'
              value={participantIds}
              onChange={(event) => {
                setParticipantIds(event.currentTarget.value);
              }}
              placeholder='123, 456'
            />
            <button type='submit' className='button' disabled={busy || !device}>
              Create conversation
            </button>
          </form>

          <section aria-labelledby='pqc-conversations-title'>
            <h2 id='pqc-conversations-title'>Encrypted conversations</h2>
            <button
              type='button'
              className='button'
              disabled={busy}
              onClick={() => void withBusy(reload)}
            >
              Refresh
            </button>
            {conversations.map((conversation) => (
              <div key={conversation.id}>
                <code>{conversation.id}</code>
                <p>Members: {conversation.member_account_ids.join(', ')}</p>
                {conversation.invited_account_ids.length > 0 && (
                  <p>
                    Invitations awaiting response:{' '}
                    {conversation.invited_account_ids.join(', ')}
                  </p>
                )}
                {conversation.declined_account_ids.length > 0 && (
                  <p>
                    Declined invitations:{' '}
                    {conversation.declined_account_ids.join(', ')}
                  </p>
                )}
                <p>
                  {conversation.member_devices
                    .map(
                      ({ device_id, fingerprint }) =>
                        `${device_id}: ${fingerprint}`,
                    )
                    .join(' · ')}
                </p>
                <button
                  type='button'
                  className='button'
                  disabled={
                    busy ||
                    (!device &&
                      conversation.my_invitation_status !== 'invited' &&
                      !(
                        conversation.my_invitation_status === 'accepted' &&
                        (!conversation.ready_at ||
                          conversation.pending_addition_account_ids.includes(
                            currentAccountId ?? '',
                          ))
                      ))
                  }
                  onClick={() => {
                    openConversation(conversation);
                  }}
                >
                  {active?.conversation.id === conversation.id && active.state
                    ? sameDeviceFingerprints(active.conversation, conversation)
                      ? 'Resume'
                      : 'Review device changes'
                    : 'Review / join'}
                </button>
              </div>
            ))}
          </section>

          {pendingConversation && (
            <section aria-labelledby='pqc-verification-title'>
              {pendingConversation.my_invitation_status === 'invited' ? (
                <>
                  <h2 id='pqc-verification-title'>
                    Encrypted group invitation
                  </h2>
                  <p>
                    {pendingConversation.ready_at
                      ? 'Accept to let the creator add your registered devices to the active MLS group, or decline. Your account will not receive group messages until the creator commits the Welcome.'
                      : 'Accept to let the creator include your registered devices in the initial MLS group, or decline before any group messages exist.'}
                  </p>
                  <button
                    type='button'
                    className='button'
                    disabled={busy}
                    onClick={() => void answerInvitation(true)}
                  >
                    Accept invitation
                  </button>
                  <button
                    type='button'
                    className='button'
                    disabled={busy}
                    onClick={() => void answerInvitation(false)}
                  >
                    Decline invitation
                  </button>
                </>
              ) : pendingConversation.my_invitation_status === 'accepted' &&
                pendingConversation.creator_account_id !== currentAccountId &&
                (!pendingConversation.ready_at ||
                  pendingConversation.pending_addition_account_ids.includes(
                    currentAccountId ?? '',
                  )) ? (
                <>
                  <h2 id='pqc-verification-title'>
                    {pendingConversation.ready_at
                      ? 'Waiting for the Welcome commit'
                      : 'Waiting for group setup'}
                  </h2>
                  <p>
                    {pendingConversation.ready_at
                      ? 'You accepted. Your account will not receive group messages until the creator adds your devices to the MLS group.'
                      : 'You accepted this invitation. Your account is not part of an active MLS group until the creator completes setup.'}
                  </p>
                  <button
                    type='button'
                    className='button'
                    disabled={busy}
                    onClick={() => void refreshPendingConversation()}
                  >
                    Refresh invitation status
                  </button>
                </>
              ) : pendingConversation.creator_account_id === currentAccountId &&
                pendingMemberAccountId !== null &&
                pendingConversation.invited_account_ids.includes(
                  pendingMemberAccountId,
                ) ? (
                <>
                  <h2 id='pqc-verification-title'>
                    Waiting for member acceptance
                  </h2>
                  <p>
                    Account {pendingMemberAccountId} must accept or decline
                    before its KeyPackages can be fetched.
                  </p>
                  <button
                    type='button'
                    className='button'
                    disabled={busy}
                    onClick={() => void refreshPendingConversation()}
                  >
                    Refresh invitation status
                  </button>
                </>
              ) : pendingConversation.creator_account_id === currentAccountId &&
                pendingConversation.invited_account_ids.length > 0 ? (
                <>
                  <h2 id='pqc-verification-title'>Waiting for invitees</h2>
                  <p>
                    Every invitee must accept or decline before you can create
                    the MLS group. Waiting on:{' '}
                    {pendingConversation.invited_account_ids.join(', ')}
                  </p>
                  <button
                    type='button'
                    className='button'
                    disabled={busy}
                    onClick={() => void refreshPendingConversation()}
                  >
                    Refresh invitation status
                  </button>
                </>
              ) : (
                <>
                  <h2 id='pqc-verification-title'>
                    {pendingTrustUpdate
                      ? 'Verify new device fingerprints'
                      : 'Verify devices before continuing'}
                  </h2>
                  <p>
                    Compare each fingerprint with its owner using a separate
                    trusted channel before accepting it.
                  </p>
                  <ul>
                    {pendingConversation.member_devices.map((memberDevice) => (
                      <li key={memberDevice.id}>
                        Account {memberDevice.account_id}, device{' '}
                        {memberDevice.device_id}:{' '}
                        <code>{memberDevice.fingerprint}</code>
                      </li>
                    ))}
                  </ul>
                  <label>
                    <input
                      type='checkbox'
                      checked={fingerprintsConfirmed}
                      onChange={(event) => {
                        setFingerprintsConfirmed(event.currentTarget.checked);
                      }}
                    />
                    I verified these fingerprints out of band
                  </label>
                  <button
                    type='button'
                    className='button'
                    disabled={busy || !fingerprintsConfirmed || !device}
                    onClick={() => void startPendingConversation()}
                  >
                    {pendingTrustUpdate
                      ? 'Update trusted devices'
                      : pendingMemberAccountId !== null
                        ? 'Add member to encrypted group'
                        : active?.pendingGroupSetup
                          ? 'Continue encrypted group setup'
                          : !pendingConversation.ready_at &&
                              pendingConversation.creator_account_id ===
                                currentAccountId
                            ? 'Start encrypted group'
                            : 'Join encrypted group'}
                  </button>
                </>
              )}
            </section>
          )}

          {active && (
            <section aria-labelledby='pqc-active-conversation'>
              <h2 id='pqc-active-conversation'>
                Conversation {active.conversation.id}
              </h2>
              {active.pendingOutbound.length > 0 &&
                !active.pendingMemberRemoval &&
                !active.pendingDeviceRemoval && (
                  <p role='status'>
                    {active.pendingOutbound.length} encrypted message(s) are
                    queued for delivery.
                    <button
                      type='button'
                      className='button'
                      disabled={busy || !device}
                      onClick={() =>
                        void withBusy(async () => {
                          if (!device)
                            throw new Error(
                              'Unlock this device before retrying queued messages',
                            );
                          const drained = await drainPqcOutbox(
                            active,
                            device,
                            recoveredConversations,
                            recoveryPassphrase,
                            recoveryStorageKey,
                          );
                          const nextRecovered = upsertRecoveredConversation(
                            recoveredConversations,
                            drained,
                          );
                          setActive(drained);
                          setRecoveredConversations(nextRecovered);
                          await saveRecovery(
                            device,
                            nextRecovered,
                            recoveryPassphrase,
                            recoveryStorageKey,
                          );
                        })
                      }
                    >
                      Retry delivery
                    </button>
                  </p>
                )}
              {active.pendingMemberRemoval && (
                <p role='status'>
                  Removing account {active.pendingMemberRemoval.accountId} is
                  pending. The MLS epoch is saved locally; finish the relay
                  transaction before sending or receiving more messages.
                  <button
                    type='button'
                    className='button'
                    disabled={busy || !device}
                    onClick={() =>
                      void withBusy(() => commitPendingMemberRemoval(active))
                    }
                  >
                    Resume member removal
                  </button>
                </p>
              )}
              {active.pendingDeviceRemoval && (
                <p role='status'>
                  Removing device {active.pendingDeviceRemoval.deviceId} from
                  this MLS group is pending. The new epoch is saved locally;
                  finish delivery before sending or receiving messages.
                  <button
                    type='button'
                    className='button'
                    disabled={busy || !device}
                    onClick={() =>
                      void withBusy(() => commitPendingDeviceRemoval(active))
                    }
                  >
                    Resume device removal
                  </button>
                </p>
              )}
              {active.state &&
                device &&
                active.conversation.member_devices
                  .filter(
                    ({ device_id }) =>
                      active.conversation.joined_device_ids.includes(
                        device_id,
                      ) && device_id !== device.apiDevice.device_id,
                  )
                  .map((memberDevice) => (
                    <p key={`remove-device-${memberDevice.device_id}`}>
                      Remove group device {memberDevice.device_id} ·{' '}
                      <code>{memberDevice.fingerprint}</code>
                      <button
                        type='button'
                        className='button'
                        disabled={
                          busy ||
                          Boolean(
                            active.pendingMemberRemoval ??
                            active.pendingDeviceRemoval,
                          )
                        }
                        onClick={() =>
                          void removeGroupDevice(memberDevice.device_id)
                        }
                      >
                        Remove from this group
                      </button>
                    </p>
                  ))}
              {active.state &&
                active.conversation.creator_account_id === currentAccountId && (
                  <form onSubmit={(event) => void prepareMemberAddition(event)}>
                    <label htmlFor='pqc-add-member-id'>
                      Add a member or new device by local account ID
                    </label>
                    <input
                      id='pqc-add-member-id'
                      value={memberAccountId}
                      onChange={(event) => {
                        setMemberAccountId(event.currentTarget.value);
                      }}
                      inputMode='numeric'
                    />
                    <button
                      type='submit'
                      className='button'
                      disabled={
                        busy ||
                        !memberAccountId ||
                        Boolean(
                          active.pendingMemberRemoval ??
                          active.pendingDeviceRemoval,
                        )
                      }
                    >
                      Review devices to add
                    </button>
                  </form>
                )}
              {active.state &&
                (active.conversation.creator_account_id === currentAccountId ||
                  active.conversation.leave_requested_account_ids.length >
                    0) && (
                  <form onSubmit={(event) => void removeGroupMember(event)}>
                    <label htmlFor='pqc-remove-member-id'>
                      {active.conversation.creator_account_id ===
                      currentAccountId
                        ? 'Remove local account ID'
                        : `Complete departure for account ID (${active.conversation.leave_requested_account_ids.join(', ')})`}
                    </label>
                    <input
                      id='pqc-remove-member-id'
                      value={removeMemberAccountId}
                      onChange={(event) => {
                        setRemoveMemberAccountId(event.currentTarget.value);
                      }}
                      inputMode='numeric'
                    />
                    <button
                      type='submit'
                      className='button'
                      disabled={
                        busy ||
                        !removeMemberAccountId ||
                        Boolean(
                          active.pendingMemberRemoval ??
                          active.pendingDeviceRemoval,
                        )
                      }
                    >
                      {active.conversation.creator_account_id ===
                      currentAccountId
                        ? 'Review and remove member'
                        : 'Commit requested departure'}
                    </button>
                  </form>
                )}
              {active.state &&
                active.conversation.creator_account_id !== currentAccountId &&
                !active.conversation.leave_requested_account_ids.includes(
                  currentAccountId ?? '',
                ) && (
                  <p>
                    <button
                      type='button'
                      className='button'
                      disabled={
                        busy ||
                        Boolean(
                          active.pendingMemberRemoval ??
                          active.pendingDeviceRemoval,
                        )
                      }
                      onClick={() => void requestToLeaveGroup()}
                    >
                      Request to leave this encrypted group
                    </button>
                    Another group member must commit your removal. Your devices
                    remain in the current MLS group until that commit is
                    processed.
                  </p>
                )}
              {active.conversation.leave_requested_account_ids.includes(
                currentAccountId ?? '',
              ) && (
                <p role='status'>
                  Your departure is requested. A remaining member must commit
                  your MLS removal before your device stops receiving group
                  updates.
                </p>
              )}
              <button
                type='button'
                className='button'
                disabled={
                  busy ||
                  Boolean(
                    active.pendingMemberRemoval ?? active.pendingDeviceRemoval,
                  )
                }
                onClick={() => void withBusy(refreshMessages)}
              >
                Receive new messages
              </button>
              <form onSubmit={(event) => void sendMessage(event)}>
                <label htmlFor='pqc-message-draft'>Encrypted message</label>
                <textarea
                  id='pqc-message-draft'
                  value={draft}
                  onChange={(event) => {
                    setDraft(event.currentTarget.value);
                  }}
                  maxLength={10_000}
                />
                <button
                  type='submit'
                  className='button'
                  disabled={
                    busy ||
                    !active.state ||
                    Boolean(
                      active.pendingMemberRemoval ??
                      active.pendingDeviceRemoval,
                    ) ||
                    !draft.trim()
                  }
                >
                  Encrypt and send
                </button>
              </form>
              <ol aria-live='polite'>
                {messages.map((message) => (
                  <li key={message.id}>
                    <strong>{message.sender}:</strong> {message.text}
                  </li>
                ))}
              </ol>
            </section>
          )}
        </div>
      </div>
    </Column>
  );
};

const contextForConversation = async (
  conversation: PqcConversation,
  device: LocalDeviceSession,
  cipherSuiteId = getPqcDeviceCiphersuiteId(device.keyPackage),
): Promise<PqcMlsContext> => {
  const trustedDevices = new Map<string, string>();
  for (const memberDevice of conversation.member_devices) {
    trustPqcDevice(
      trustedDevices,
      `${memberDevice.actor_uri}\n${memberDevice.device_id}\n${memberDevice.fingerprint}`,
      memberDevice.fingerprint,
    );
  }

  trustPqcDevice(
    trustedDevices,
    device.keyPackage.identity,
    device.keyPackage.fingerprint,
  );

  return createPqcMlsContext(trustedDevices, cipherSuiteId);
};

const saveRecovery = async (
  device: LocalDeviceSession,
  recoveredConversations: ActiveConversation[],
  passphrase: string,
  recoveryStorageKey: string | null,
): Promise<void> => {
  if (passphrase.length < 12)
    throw new Error(
      'A recovery passphrase of at least 12 characters is required',
    );
  if (!recoveryStorageKey) throw new Error('Your account is not loaded yet');

  const record: LocalRecoveryRecord = {
    version: 1,
    device: {
      apiDevice: device.apiDevice,
      actorUri: device.actorUri,
      identity: device.keyPackage.identity,
      fingerprint: device.keyPackage.fingerprint,
      publicPackage: encodeBase64(device.keyPackage.publicPackage),
      keyPackageMessage: encodeBase64(device.keyPackage.keyPackageMessage),
      privatePackage: encodeBase64(device.keyPackage.privatePackage),
      deviceAuthPublicKey: encodeBase64(device.keyPackage.deviceAuthPublicKey),
      deviceAuthPrivateKey: device.keyPackage.deviceAuthPrivateKey
        ? encodeBase64(device.keyPackage.deviceAuthPrivateKey)
        : undefined,
    },
    activeConversations: recoveredConversations.flatMap(
      ({
        conversation,
        state,
        lastMessageId,
        messages,
        pendingOutbound,
        pendingMemberAddition,
        pendingMemberRemoval,
        pendingDeviceRemoval,
        pendingGroupSetup,
      }) => {
        if (!state) return [];

        return [
          {
            conversation,
            serializedState: encodeBase64(serializePqcGroupState(state)),
            lastMessageId,
            messages,
            pendingOutbound,
            pendingMemberAddition,
            pendingMemberRemoval,
            pendingDeviceRemoval,
            pendingGroupSetup,
          },
        ];
      },
    ),
  };
  const encrypted = await sealPqcRecoveryData(
    new TextEncoder().encode(JSON.stringify(record)),
    passphrase,
  );

  localStorage.setItem(recoveryStorageKey, encodeBase64(encrypted));
};

const drainPqcOutbox = async (
  active: ActiveConversation,
  device: LocalDeviceSession,
  recoveredConversations: ActiveConversation[],
  passphrase: string,
  recoveryStorageKey: string | null,
): Promise<ActiveConversation> => {
  let current = active;
  while (current.pendingOutbound.length > 0) {
    const [item, ...remaining] = current.pendingOutbound;
    if (!item) break;
    const result = await sendPqcMessage(
      current.conversation.id,
      device.apiDevice.device_id,
      decodeBase64(item.ciphertext),
      item.recipientDeviceId,
      item.clientMessageId,
    );
    current = {
      ...current,
      lastMessageId: Math.max(current.lastMessageId, result.id),
      pendingOutbound: remaining,
    };
    const updatedGroups = upsertRecoveredConversation(
      recoveredConversations,
      current,
    );
    await saveRecovery(device, updatedGroups, passphrase, recoveryStorageKey);
  }
  return current;
};

const continuePqcGroupSetup = async (
  active: ActiveConversation,
  device: LocalDeviceSession,
  persist: (updated: ActiveConversation) => Promise<void>,
): Promise<ActiveConversation> => {
  let current = active;

  while (current.pendingGroupSetup) {
    const setup = current.pendingGroupSetup;
    if (setup.finalizing) break;

    if (setup.keyPackages.length === 0) {
      const [accountId, ...remainingAccountIds] = setup.accountIds;
      if (accountId === undefined) {
        current = {
          ...current,
          pendingGroupSetup: { ...setup, finalizing: true },
        };
        await persist(current);
        break;
      }

      let fetchRequestId = setup.fetchRequestId;
      if (!fetchRequestId) {
        fetchRequestId = crypto.randomUUID();
        current = {
          ...current,
          pendingGroupSetup: { ...setup, fetchRequestId },
        };
        await persist(current);
      }
      const keyPackages = await fetchPqcKeyPackages(
        current.conversation.id,
        accountId,
        fetchRequestId,
        accountId === device.accountId ? device.apiDevice.device_id : undefined,
      );
      const hasUnjoinedDevice = current.conversation.member_devices.some(
        ({ account_id, device_id }) =>
          account_id === accountId && device_id !== device.apiDevice.device_id,
      );
      if (
        keyPackages.length === 0 &&
        (accountId !== device.accountId || hasUnjoinedDevice)
      ) {
        current = {
          ...current,
          pendingGroupSetup: { ...setup, fetchRequestId: undefined },
        };
        await persist(current);
        throw new Error(
          `Account ${accountId} has no available PQC device KeyPackages. Ask them to register a device and retry.`,
        );
      }
      current = {
        ...current,
        pendingGroupSetup: {
          ...setup,
          accountIds: remainingAccountIds,
          keyPackages,
          fetchRequestId: undefined,
        },
      };
      await persist(current);
      continue;
    }

    const [remotePackage, ...remainingPackages] = setup.keyPackages;
    if (!remotePackage) continue;
    if (remotePackage.device_id === device.apiDevice.device_id) {
      current = {
        ...current,
        pendingGroupSetup: { ...setup, keyPackages: remainingPackages },
      };
      await persist(current);
      continue;
    }

    if (!current.state)
      throw new Error(
        'The saved MLS group state is missing; restore a valid recovery file before continuing',
      );
    const added = await addPqcGroupMember(
      current.context,
      current.state,
      decodePqcKeyPackage(remotePackage.key_package),
    );
    const pendingOutbound: PqcPendingOutbound[] = [
      {
        clientMessageId: crypto.randomUUID(),
        ciphertext: encodeBase64(added.welcome),
        recipientDeviceId: remotePackage.device_id,
      },
      ...setup.activeDeviceIds.map((recipientDeviceId) => ({
        clientMessageId: crypto.randomUUID(),
        ciphertext: encodeBase64(added.commit),
        recipientDeviceId,
      })),
    ];
    current = {
      ...current,
      state: added.state,
      pendingOutbound: [...current.pendingOutbound, ...pendingOutbound],
      pendingGroupSetup: {
        ...setup,
        keyPackages: remainingPackages,
        activeDeviceIds: [...setup.activeDeviceIds, remotePackage.device_id],
      },
    };
    await persist(current);
  }

  return current;
};

const encodeBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }

  return btoa(binary);
};

const decodeBase64 = (encoded: string): Uint8Array => {
  const binary = atob(encoded);

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const upsertRecoveredConversation = (
  existing: ActiveConversation[],
  conversation: ActiveConversation,
): ActiveConversation[] => [
  conversation,
  ...existing.filter(
    ({ conversation: saved }) => saved.id !== conversation.conversation.id,
  ),
];

const sameDeviceFingerprints = (
  left: PqcConversation,
  right: PqcConversation,
): boolean => {
  return (
    deviceFingerprintSnapshot(left.member_devices) ===
    deviceFingerprintSnapshot(right.member_devices)
  );
};

const sameDeviceFingerprintsExceptAccount = (
  left: PqcConversation,
  right: PqcConversation,
  excludedAccountId: string,
): boolean =>
  deviceFingerprintSnapshot(
    left.member_devices.filter(
      ({ account_id }) => account_id !== excludedAccountId,
    ),
  ) ===
  deviceFingerprintSnapshot(
    right.member_devices.filter(
      ({ account_id }) => account_id !== excludedAccountId,
    ),
  );

const sameAccountDeviceFingerprints = (
  conversation: PqcConversation,
  accountId: string,
  packages: PqcKeyPackage[],
): boolean => {
  const joinedDeviceIds = new Set(conversation.joined_device_ids);
  const pendingDevices = conversation.member_devices.filter(
    ({ account_id, device_id }) =>
      account_id === accountId && !joinedDeviceIds.has(device_id),
  );
  const packageDevices = packages.map(
    ({
      id,
      account_id: packageAccountId,
      actor_uri,
      device_id,
      fingerprint,
    }) => ({
      id,
      account_id: packageAccountId,
      actor_uri,
      device_id,
      fingerprint,
      revocation_pending: false,
    }),
  );

  return (
    deviceFingerprintSnapshot(pendingDevices) ===
    deviceFingerprintSnapshot(packageDevices)
  );
};

const deviceFingerprintSnapshot = (
  devices: PqcConversation['member_devices'],
): string =>
  devices
    .map(
      ({ actor_uri, device_id, fingerprint }) =>
        `${actor_uri}\n${device_id}\n${fingerprint}`,
    )
    .sort()
    .join('\n');

const conversationWithPendingMember = (
  conversation: PqcConversation,
  addition: PqcPendingMemberAddition,
): PqcConversation => {
  const devicesById = new Map(
    conversation.member_devices.map((memberDevice) => [
      memberDevice.device_id,
      memberDevice,
    ]),
  );
  addition.keyPackages.forEach(
    ({ id, account_id, actor_uri, device_id, fingerprint }) => {
      devicesById.set(device_id, {
        id,
        account_id,
        actor_uri,
        device_id,
        fingerprint,
        revocation_pending: false,
      });
    },
  );

  return {
    ...conversation,
    member_account_ids: [
      ...new Set([...conversation.member_account_ids, addition.accountId]),
    ].sort(compareLocalAccountIds),
    member_devices: [...devicesById.values()],
  };
};

const isValidLocalAccountId = (value: string): boolean =>
  /^[1-9][0-9]{0,19}$/.test(value);

const compareLocalAccountIds = (left: string, right: string): number => {
  const leftId = BigInt(left);
  const rightId = BigInt(right);

  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
};

const errorText = (cause: unknown): string =>
  cause instanceof Error
    ? cause.message
    : 'The encrypted messaging request failed';
