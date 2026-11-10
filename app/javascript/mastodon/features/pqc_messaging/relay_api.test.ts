import { afterEach, expect, it, vi } from 'vitest';

import {
  fetchPqcActorUri,
  fetchPqcPrivateMedia,
  registerPqcDevice,
  revokePqcDevice,
  setPqcDeviceRequestSigner,
  uploadPqcPrivateMedia,
} from './relay_api';

const { apiRequestMock, apiRequestGetMock, apiRequestPostMock, apiMock } =
  vi.hoisted(() => {
    const apiRequestMock = vi.fn(
      (
        method: string,
        url: string,
        args?: { headers?: Record<string, string> },
      ) => {
        return Promise.resolve<unknown>({ method, url, args });
      },
    );
    const apiRequestGetMock = vi.fn();
    const apiRequestPostMock = vi.fn();
    const apiMock = vi.fn(() => ({
      getUri: ({ url }: { url: string }) => url,
      get: vi.fn(),
      post: vi.fn(),
    }));

    return { apiRequestMock, apiRequestGetMock, apiRequestPostMock, apiMock };
  });

vi.mock('mastodon/api', () => ({
  default: apiMock,
  apiRequest: apiRequestMock,
  apiRequestGet: apiRequestGetMock,
  apiRequestPost: apiRequestPostMock,
}));

afterEach(() => {
  setPqcDeviceRequestSigner(null);
  vi.clearAllMocks();
});

it('revokes a locked device using its recovery-derived signer', async () => {
  apiRequestMock.mockResolvedValue({ revocation_pending: true });
  const signer = {
    deviceId: 'recovered-device',
    sign: vi.fn(() => Promise.resolve(new Uint8Array([1, 2, 3]))),
  };

  await expect(revokePqcDevice(19, signer)).resolves.toEqual({
    revocation_pending: true,
  });
  expect(signer.sign).toHaveBeenCalledWith(
    'DELETE',
    '/api/v1/pqc_devices/19',
    '',
    expect.any(String),
    expect.any(String),
  );
  const [method, url, args] = apiRequestMock.mock.calls[0] ?? [];
  expect(method).toBe('DELETE');
  expect(url).toBe('v1/pqc_devices/19');
  expect(args?.headers?.['X-PQC-Device-ID']).toBe('recovered-device');
});

it('still requires a signer when recovery data is unavailable', async () => {
  await expect(revokePqcDevice(19)).rejects.toThrow(
    'Unlock a registered PQC device',
  );
});

it('returns the registered device when its media key matches the generated keypair', async () => {
  const mediaKey = new Uint8Array([2]);
  const encodedMediaKey = btoa(String.fromCharCode(...mediaKey));
  const device = {
    media_kem_public_key: encodedMediaKey,
    media_encryption_ready: true,
  };
  apiRequestPostMock.mockResolvedValue(device);

  await expect(
    registerPqcDevice(
      'device',
      'fingerprint',
      new Uint8Array([1]),
      mediaKey,
      new Uint8Array([3]),
    ),
  ).resolves.toBe(device);
  expect(apiRequestPostMock).toHaveBeenCalledWith(
    'v1/pqc_devices',
    expect.objectContaining({ media_kem_public_key: encodedMediaKey }),
  );
});

it('rejects a server-registered media key that differs from the generated keypair', async () => {
  apiRequestPostMock.mockResolvedValue({
    media_kem_public_key: 'server-selected-key',
    media_encryption_ready: true,
  });

  await expect(
    registerPqcDevice(
      'device',
      'fingerprint',
      new Uint8Array([1]),
      new Uint8Array([2]),
      new Uint8Array([3]),
    ),
  ).rejects.toThrow('Registered media key does not match this device keypair');
});

it('fetches media ciphertext and envelope metadata by the same object id', async () => {
  const metadata = {
    id: '12',
    token: 'b2d2dc46-96f7-4f5b-8a83-949bc86c8159',
    nonce: 'nonce',
    auth_tag: 'tag',
    envelopes: [],
  };
  const ciphertext = new Uint8Array([3, 4, 5]).buffer;
  apiRequestGetMock.mockResolvedValue(metadata);
  const getMock = vi.fn().mockResolvedValue({ data: ciphertext });
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: getMock,
    post: vi.fn(),
  });

  const result = await fetchPqcPrivateMedia('12');

  expect(apiRequestGetMock).toHaveBeenCalledWith(
    'v1/private_media/12/envelope',
  );
  expect(getMock).toHaveBeenCalledWith('/api/v1/private_media/12', {
    responseType: 'arraybuffer',
  });
  expect(Array.from(result.ciphertext)).toEqual([3, 4, 5]);
});

it('trims file IDs before fetching metadata and ciphertext', async () => {
  apiRequestGetMock.mockResolvedValue({
    id: '12',
    token: 'b2d2dc46-96f7-4f5b-8a83-949bc86c8159',
    nonce: 'nonce',
    auth_tag: 'tag',
    envelopes: [],
  });
  const getMock = vi.fn().mockResolvedValue({
    data: new Uint8Array([1]).buffer,
  });
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: getMock,
    post: vi.fn(),
  });

  await fetchPqcPrivateMedia(' 12 ');

  expect(apiRequestGetMock).toHaveBeenCalledWith(
    'v1/private_media/12/envelope',
  );
  expect(getMock).toHaveBeenCalledWith('/api/v1/private_media/12', {
    responseType: 'arraybuffer',
  });
});

it('rejects empty private media IDs before making requests', async () => {
  await expect(fetchPqcPrivateMedia('  \t')).rejects.toThrow(
    'Enter a private media ID',
  );
  expect(apiRequestGetMock).not.toHaveBeenCalled();
  expect(apiMock).not.toHaveBeenCalled();
});

it('does not fetch ciphertext when envelope metadata is rejected', async () => {
  apiRequestGetMock.mockRejectedValue(new Error('metadata rejected'));
  const getMock = vi.fn();
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: getMock,
    post: vi.fn(),
  });

  await expect(fetchPqcPrivateMedia('12')).rejects.toThrow('metadata rejected');
  expect(getMock).not.toHaveBeenCalled();
});

it('rejects mismatched envelope metadata before downloading ciphertext', async () => {
  apiRequestGetMock.mockResolvedValue({
    id: '13',
    token: 'b2d2dc46-96f7-4f5b-8a83-949bc86c8159',
    nonce: 'nonce',
    auth_tag: 'tag',
    envelopes: [],
  });
  const getMock = vi.fn();
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: getMock,
    post: vi.fn(),
  });

  await expect(fetchPqcPrivateMedia('12')).rejects.toThrow(
    'Private media metadata does not match the requested file',
  );
  expect(getMock).not.toHaveBeenCalled();
});

it('rejects non-numeric upload object IDs and cleans up the allocated object', async () => {
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: vi.fn(),
    post: vi.fn().mockResolvedValue({ data: { id: '12/other' } }),
  });
  apiRequestMock.mockResolvedValue(undefined);

  await expect(
    uploadPqcPrivateMedia(
      new Uint8Array([1]),
      new Uint8Array(12),
      new Uint8Array(16),
      '12345678-1234-1234-1234-123456789abc',
      { device_id: 'device', kem_ciphertext: 'kem', wrapped_key: 'key' },
    ),
  ).rejects.toThrow('Private media upload returned an invalid object id');
  expect(apiRequestPostMock).not.toHaveBeenCalled();
  expect(apiRequestMock).toHaveBeenCalledWith(
    'DELETE',
    'v1/private_media/12%2Fother',
  );
});

it('removes an uploaded object when envelope attachment fails', async () => {
  const postMock = vi.fn().mockResolvedValue({
    data: { id: '12' },
  });
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: vi.fn(),
    post: postMock,
  });
  apiRequestPostMock.mockRejectedValue(new Error('envelope rejected'));
  apiRequestMock.mockResolvedValue(undefined);
  const envelope = {
    device_id: 'browser-device',
    kem_ciphertext: 'ciphertext',
    wrapped_key: 'wrapped',
  };

  await expect(
    uploadPqcPrivateMedia(
      new Uint8Array([1]),
      new Uint8Array(12),
      new Uint8Array(16),
      '12345678-1234-1234-1234-123456789abc',
      envelope,
    ),
  ).rejects.toThrow('envelope rejected');
  expect(apiRequestMock).toHaveBeenCalledWith('DELETE', 'v1/private_media/12');
});

it('removes an uploaded object when canceled during envelope attachment', async () => {
  const postMock = vi.fn().mockResolvedValue({ data: { id: '12' } });
  apiMock.mockReturnValue({
    getUri: ({ url }: { url: string }) => url,
    get: vi.fn(),
    post: postMock,
  });
  let cancelled = false;
  apiRequestPostMock.mockImplementation(() => {
    // The user locks the device while this request is in flight.
    cancelled = true;
    return Promise.resolve({ id: '12' });
  });
  apiRequestMock.mockResolvedValue(undefined);

  await expect(
    uploadPqcPrivateMedia(
      new Uint8Array([1]),
      new Uint8Array(12),
      new Uint8Array(16),
      '12345678-1234-1234-1234-123456789abc',
      { device_id: 'device', kem_ciphertext: 'kem', wrapped_key: 'key' },
      () => cancelled,
    ),
  ).rejects.toThrow('Private media upload was canceled');

  expect(apiRequestMock).toHaveBeenCalledWith('DELETE', 'v1/private_media/12');
});

it('uses the canonical ActivityPub URI for MLS device identities', async () => {
  apiRequestGetMock.mockResolvedValue({
    url: 'https://example.test/@alice',
    uri: 'https://example.test/users/alice',
  });

  await expect(fetchPqcActorUri('123')).resolves.toBe(
    'https://example.test/users/alice',
  );
  expect(apiRequestGetMock).toHaveBeenCalledWith('v1/accounts/123');
});
