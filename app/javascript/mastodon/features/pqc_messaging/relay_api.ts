import {
  default as api,
  apiRequest,
  apiRequestGet,
  apiRequestPost,
} from 'mastodon/api';

export interface PqcDeviceRequestSigner {
  deviceId: string;
  sign: (
    method: string,
    path: string,
    body: string,
    timestamp: string,
    nonce: string,
  ) => Promise<Uint8Array>;
}

export interface PqcDeviceRevocationResult {
  revocation_pending: true;
}

let deviceRequestSigner: PqcDeviceRequestSigner | null = null;

export const setPqcDeviceRequestSigner = (
  signer: PqcDeviceRequestSigner | null,
): void => {
  deviceRequestSigner = signer;
};

export interface PqcDevice {
  id: number;
  device_id: string;
  fingerprint: string;
  device_auth_ready: boolean;
  revocation_pending: boolean;
  created_at: string;
}

export interface PqcKeyPackage {
  id: number;
  account_id: string;
  actor_uri: string;
  device_id: string;
  fingerprint: string;
  key_package: string;
}

export interface PqcConversation {
  id: string;
  creator_account_id: string;
  member_account_ids: string[];
  invited_account_ids: string[];
  pending_addition_account_ids: string[];
  declined_account_ids: string[];
  my_invitation_status: 'invited' | 'accepted' | 'declined' | null;
  leave_requested_account_ids: string[];
  member_devices: {
    account_id: string;
    id: number;
    actor_uri: string;
    device_id: string;
    fingerprint: string;
    revocation_pending: boolean;
  }[];
  joined_device_ids: string[];
  created_at: string;
  updated_at: string;
  ready_at: string | null;
}

export interface PqcRelayMessage {
  id: number;
  sender_account_id: string;
  sender_device_id: string | null;
  recipient_device_id: string | null;
  ciphertext: string;
  created_at: string;
}

export interface PqcPendingOutbound {
  clientMessageId: `${string}-${string}-${string}-${string}-${string}`;
  ciphertext: string;
  recipientDeviceId?: string;
}

export const registerPqcDevice = async (
  deviceId: string,
  fingerprint: string,
  deviceAuthPublicKey: Uint8Array,
  encodedKeyPackage: Uint8Array,
): Promise<PqcDevice> =>
  apiRequestPost<
    PqcDevice,
    {
      device_id: string;
      fingerprint: string;
      device_auth_public_key: string;
      key_package: string;
    }
  >('v1/pqc_devices', {
    device_id: deviceId,
    fingerprint,
    device_auth_public_key: encodeBase64(deviceAuthPublicKey),
    key_package: encodeBase64(encodedKeyPackage),
  });

export const listPqcDevices = (): Promise<PqcDevice[]> =>
  apiRequestGet('v1/pqc_devices');

export const fetchPqcActorUri = async (accountId: string): Promise<string> => {
  const account = await apiRequestGet<{ uri: string }>(
    `v1/accounts/${accountId}`,
  );
  return account.uri;
};

export const revokePqcDevice = (
  deviceId: number,
  signer?: PqcDeviceRequestSigner,
): Promise<PqcDeviceRevocationResult | undefined> =>
  signedRequest(
    'DELETE',
    `v1/pqc_devices/${deviceId}`,
    undefined,
    undefined,
    signer,
  );

export const publishPqcKeyPackage = async (
  deviceId: number,
  encodedKeyPackage: Uint8Array,
  deviceAuthPublicKey: Uint8Array,
): Promise<PqcDevice> =>
  signedRequest('PATCH', `v1/pqc_devices/${deviceId}/key_package`, {
    key_package: encodeBase64(encodedKeyPackage),
    device_auth_public_key: encodeBase64(deviceAuthPublicKey),
  });

export const fetchPqcKeyPackages = (
  conversationId: string,
  accountId: string,
  requestId: string,
  excludeDeviceId?: string,
): Promise<PqcKeyPackage[]> =>
  signedRequest('GET', 'v1/pqc_devices/key_packages', undefined, {
    conversation_id: conversationId,
    account_id: accountId,
    request_id: requestId,
    exclude_device_id: excludeDeviceId,
  });

export const decodePqcKeyPackage = (encoded: string): Uint8Array =>
  decodeBase64(encoded);

export const createPqcConversation = (
  accountIds: string[],
  setupDeviceId: string,
): Promise<PqcConversation> =>
  signedRequest('POST', 'v1/pqc_conversations', {
    account_ids: accountIds,
    setup_device_id: setupDeviceId,
  });

export const completePqcGroupSetup = (
  conversationId: string,
  senderDeviceId: string,
  deliveries: PqcPendingOutbound[],
): Promise<{ conversation: PqcConversation; message_ids: number[] }> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/complete_setup`,
    {
      sender_device_id: senderDeviceId,
      deliveries: deliveries.map((delivery) => ({
        client_message_id: delivery.clientMessageId,
        recipient_device_id: delivery.recipientDeviceId,
        ciphertext: delivery.ciphertext,
      })),
    },
  );

export const commitPqcConversationMember = (
  conversationId: string,
  accountId: string,
  senderDeviceId: string,
  operationId: string,
  keyPackageRequestId: string,
  targetDeviceIds: string[],
  deliveries: PqcPendingOutbound[],
): Promise<{ conversation: PqcConversation; message_ids: number[] }> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/commit_member`,
    {
      account_id: accountId,
      sender_device_id: senderDeviceId,
      operation_id: operationId,
      key_package_request_id: keyPackageRequestId,
      target_device_ids: targetDeviceIds,
      deliveries: deliveries.map((delivery) => ({
        client_message_id: delivery.clientMessageId,
        recipient_device_id: delivery.recipientDeviceId,
        ciphertext: delivery.ciphertext,
      })),
    },
  );

export const invitePqcConversationMember = (
  conversationId: string,
  accountId: string,
): Promise<PqcConversation> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/invite_member`,
    { account_id: accountId },
  );

export const removePqcConversationMember = (
  conversationId: string,
  accountId: string,
  senderDeviceId: string,
  operationId: `${string}-${string}-${string}-${string}-${string}`,
  deliveries: PqcPendingOutbound[],
): Promise<{ conversation: PqcConversation; message_ids: number[] }> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/remove_member`,
    {
      account_id: accountId,
      sender_device_id: senderDeviceId,
      operation_id: operationId,
      deliveries: deliveries.map((delivery) => ({
        client_message_id: delivery.clientMessageId,
        recipient_device_id: delivery.recipientDeviceId,
        ciphertext: delivery.ciphertext,
      })),
    },
  );

export const removePqcConversationDevice = (
  conversationId: string,
  targetDeviceId: string,
  senderDeviceId: string,
  operationId: `${string}-${string}-${string}-${string}-${string}`,
  deliveries: PqcPendingOutbound[],
): Promise<{ conversation: PqcConversation; message_ids: number[] }> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/remove_device`,
    {
      target_device_id: targetDeviceId,
      sender_device_id: senderDeviceId,
      operation_id: operationId,
      deliveries: deliveries.map((delivery) => ({
        client_message_id: delivery.clientMessageId,
        recipient_device_id: delivery.recipientDeviceId,
        ciphertext: delivery.ciphertext,
      })),
    },
  );

export const requestPqcConversationLeave = (
  conversationId: string,
): Promise<PqcConversation> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/request_leave`,
    {},
  );

export const acceptPqcConversationInvitation = (
  conversationId: string,
): Promise<PqcConversation> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/accept_invitation`,
    {},
  );

export const declinePqcConversationInvitation = (
  conversationId: string,
): Promise<PqcConversation> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/decline_invitation`,
    {},
  );

export const listPqcConversations = (): Promise<PqcConversation[]> =>
  apiRequestGet('v1/pqc_conversations');

export const fetchPqcMessages = (
  conversationId: string,
  deviceId: string,
  afterId?: number,
): Promise<PqcRelayMessage[]> =>
  signedRequest(
    'GET',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/messages`,
    undefined,
    { device_id: deviceId, after_id: afterId },
  );

export const sendPqcMessage = async (
  conversationId: string,
  senderDeviceId: string,
  ciphertext: Uint8Array,
  recipientDeviceId?: string,
  clientMessageId: `${string}-${string}-${string}-${string}-${string}` = crypto.randomUUID(),
): Promise<PqcRelayMessage> =>
  signedRequest(
    'POST',
    `v1/pqc_conversations/${encodeURIComponent(conversationId)}/messages`,
    {
      sender_device_id: senderDeviceId,
      ciphertext: encodeBase64(ciphertext),
      recipient_device_id: recipientDeviceId,
      client_message_id: clientMessageId,
    },
  );

export const decodePqcMessage = (encoded: string): Uint8Array =>
  decodeBase64(encoded);

const encodeBase64 = (bytes: Uint8Array): string => {
  const chunks: string[] = [];
  const chunkSize = 0x8000;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    chunks.push(
      String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)),
    );
  }

  return btoa(chunks.join(''));
};

const signedRequest = async <T = unknown>(
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  url: string,
  data?: unknown,
  params?: unknown,
  signerOverride?: PqcDeviceRequestSigner,
): Promise<T> => {
  const signer = signerOverride ?? deviceRequestSigner;
  if (!signer)
    throw new Error(
      'Unlock a registered PQC device before using this operation',
    );

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID();
  const axiosInstance = api();
  const path = axiosInstance.getUri({ url: `/api/${url}`, params });
  const body =
    data === undefined
      ? ''
      : typeof data === 'string'
        ? data
        : JSON.stringify(data);
  const signature = await signer.sign(method, path, body, timestamp, nonce);
  const headers = {
    'X-PQC-Device-ID': signer.deviceId,
    'X-PQC-Device-Timestamp': timestamp,
    'X-PQC-Device-Nonce': nonce,
    'X-PQC-Device-Signature': encodeBase64(signature),
  };

  return apiRequest<T>(method, url, { data, params, headers });
};

const decodeBase64 = (encoded: string): Uint8Array => {
  const binary = atob(encoded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};
