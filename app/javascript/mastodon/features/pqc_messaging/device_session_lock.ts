export const acquirePqcDeviceSessionLock = async (
  accountId: string,
): Promise<() => void> => {
  const browserLocks = (navigator as unknown as { locks?: LockManager }).locks;
  if (!browserLocks) {
    throw new Error(
      'This browser cannot safely lock an encrypted messaging device across tabs',
    );
  }

  let resolveAcquisition!: (
    result: { release: () => void } | { error: unknown } | null,
  ) => void;
  const acquisition = new Promise<
    { release: () => void } | { error: unknown } | null
  >((resolve) => {
    resolveAcquisition = resolve;
  });

  const request = browserLocks.request(
    `mastodon:pqc:account:${accountId}`,
    { mode: 'exclusive', ifAvailable: true },
    (lock) => {
      if (!lock) {
        resolveAcquisition(null);
        return;
      }

      return new Promise<void>((resolve) => {
        let released = false;
        resolveAcquisition({
          release: () => {
            if (released) return;
            released = true;
            resolve();
          },
        });
      });
    },
  );

  void request.catch((error: unknown) => {
    resolveAcquisition({ error });
  });

  const result = await acquisition;
  if (!result)
    throw new Error(
      'This account’s encrypted messaging device is already unlocked in another tab at this site address',
    );
  if ('error' in result) throw result.error;

  return result.release;
};
