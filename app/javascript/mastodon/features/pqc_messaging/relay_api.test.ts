import { afterEach, expect, it, vi } from 'vitest';

import {
  fetchPqcActorUri,
  revokePqcDevice,
  setPqcDeviceRequestSigner,
} from './relay_api';

const { apiRequestMock, apiRequestGetMock, apiMock } = vi.hoisted(() => {
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
  const apiMock = vi.fn(() => ({ getUri: ({ url }: { url: string }) => url }));

  return { apiRequestMock, apiRequestGetMock, apiMock };
});

vi.mock('mastodon/api', () => ({
  default: apiMock,
  apiRequest: apiRequestMock,
  apiRequestGet: apiRequestGetMock,
  apiRequestPost: vi.fn(),
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
