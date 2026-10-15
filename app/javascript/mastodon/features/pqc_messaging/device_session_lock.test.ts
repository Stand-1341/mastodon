import { afterEach, describe, expect, it, vi } from 'vitest';

import { acquirePqcDeviceSessionLock } from './device_session_lock';

const originalLocks = Object.getOwnPropertyDescriptor(navigator, 'locks');

afterEach(() => {
  if (originalLocks) Object.defineProperty(navigator, 'locks', originalLocks);
  else Reflect.deleteProperty(navigator, 'locks');
});

describe('PQC messaging device session lock', () => {
  it('holds an exclusive account lock until its release callback runs', async () => {
    const request = vi.fn(
      async (
        _name: string,
        _options: LockOptions,
        callback: (lock: Lock | null) => Promise<void> | void,
      ) => callback({} as Lock),
    );
    Object.defineProperty(navigator, 'locks', {
      configurable: true,
      value: { request },
    });

    const release = await acquirePqcDeviceSessionLock('42');

    expect(request).toHaveBeenCalledWith(
      'mastodon:pqc:account:42',
      { mode: 'exclusive', ifAvailable: true },
      expect.any(Function),
    );
    expect(release).toBeTypeOf('function');
    release();
  });

  it('rejects when another tab holds the account lock', async () => {
    const request = vi.fn(
      async (
        _name: string,
        _options: LockOptions,
        callback: (lock: Lock | null) => Promise<void> | void,
      ) => callback(null),
    );
    Object.defineProperty(navigator, 'locks', {
      configurable: true,
      value: { request },
    });

    await expect(acquirePqcDeviceSessionLock('42')).rejects.toThrow(
      'already unlocked in another tab',
    );
  });

  it('fails closed when the browser has no Web Locks API', async () => {
    Object.defineProperty(navigator, 'locks', {
      configurable: true,
      value: undefined,
    });

    await expect(acquirePqcDeviceSessionLock('42')).rejects.toThrow(
      'cannot safely lock',
    );
  });
});
