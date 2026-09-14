import { SignInIdentifier } from '@logto/schemas';
import { createMockUtils } from '@logto/shared/esm';

const { jest } = import.meta;
const { mockEsm } = createMockUtils(jest);
const createExperienceInteraction = jest.fn(
  (_ctx: unknown, _tenant: unknown, interactionDetails: unknown) => ({ interactionDetails })
);

mockEsm('../classes/experience-interaction.js', () => ({ default: createExperienceInteraction }));

const { default: koaPhoneVerificationCodeLock } = await import(
  './koa-phone-verification-code-lock.js'
);
const { createPhoneSendPermitGate, phoneSendLockRetryInterval, phoneSendLockWaitTimeout } =
  await import('./koa-phone-verification-code-lock.js');

class RetryableDatabaseError extends Error {
  get code() {
    return '40001';
  }
}

const phonePath = '/experience/verification/verification-code';
const createContext = (type = SignInIdentifier.Phone, jti = 'interaction-jti') => ({
  request: {
    method: 'POST',
    path: phonePath,
    body: { identifier: { type, value: 'test-recipient' } },
  },
  req: {},
  res: {},
  interactionDetails: { jti, result: { snapshot: 'stale' } },
  experienceInteraction: { snapshot: 'stale' },
});

const createMiddleware = (permitGate = createPhoneSendPermitGate()) => {
  const oneFirst = jest.fn().mockResolvedValue(true);
  const connection = { oneFirst };
  const transaction = jest.fn(
    async (
      callback: (transactionConnection: { oneFirst: typeof oneFirst }) => Promise<unknown>,
      _retryLimit?: number
    ) => callback(connection)
  );
  const freshInteractionDetails = {
    jti: 'interaction-jti',
    result: { snapshot: 'fresh' },
  };
  const interactionDetails = jest.fn().mockResolvedValue(freshInteractionDetails);
  const tenant = {
    provider: { interactionDetails },
    queries: { pool: { transaction } },
  };
  const middleware = koaPhoneVerificationCodeLock(tenant as never, permitGate);

  return {
    connection,
    freshInteractionDetails,
    interactionDetails,
    middleware,
    oneFirst,
    tenant,
    transaction,
  };
};

describe('phone verification-code interaction lock', () => {
  it('uses one shared seven-second deadline with a twenty-millisecond retry interval', () => {
    expect(phoneSendLockWaitTimeout).toBe(7000);
    expect(phoneSendLockRetryInterval).toBe(20);
  });

  it('holds one bounded advisory transaction while reloading and handling a phone send', async () => {
    const {
      freshInteractionDetails,
      interactionDetails,
      middleware,
      oneFirst,
      tenant,
      transaction,
    } = createMiddleware();
    const ctx = createContext();
    const next = jest.fn();

    await middleware(ctx as never, next);

    expect(transaction).toHaveBeenCalledTimes(1);
    expect(oneFirst).toHaveBeenCalledTimes(1);
    expect(oneFirst.mock.calls[0]?.[0].sql).toContain('pg_try_advisory_xact_lock');
    expect(oneFirst.mock.calls[0]?.[0].values).toContain('interaction-jti');
    expect(oneFirst.mock.invocationCallOrder[0]).toBeLessThan(
      interactionDetails.mock.invocationCallOrder[0] ?? 0
    );
    expect(interactionDetails.mock.invocationCallOrder[0]).toBeLessThan(
      next.mock.invocationCallOrder[0] ?? 0
    );
    expect(ctx.interactionDetails).toBe(freshInteractionDetails);
    expect(createExperienceInteraction).toHaveBeenCalledWith(ctx, tenant, freshInteractionDetails);
    expect(ctx.experienceInteraction).toEqual({ interactionDetails: freshInteractionDetails });
  });

  it('does not lock an email send', async () => {
    const { interactionDetails, middleware, oneFirst, transaction } = createMiddleware();
    const next = jest.fn();

    await middleware(createContext(SignInIdentifier.Email) as never, next);

    expect(transaction).not.toHaveBeenCalled();
    expect(oneFirst).not.toHaveBeenCalled();
    expect(interactionDetails).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('allows only one database lock holder while thirty interactions complete nested work', async () => {
    const { interactionDetails, middleware, transaction } = createMiddleware();
    /* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Model the pool's stateful advisory lock and observe overlap. */
    let activeLockHolders = 0;
    let maximumLockHolders = 0;
    let activeHandlers = 0;
    let maximumActiveHandlers = 0;

    transaction.mockImplementation(async (callback) => {
      activeLockHolders += 1;
      maximumLockHolders = Math.max(maximumLockHolders, activeLockHolders);

      try {
        return await callback({ oneFirst: jest.fn().mockResolvedValue(true) });
      } finally {
        activeLockHolders -= 1;
      }
    });

    await Promise.all(
      Array.from({ length: 30 }, async () =>
        middleware(
          createContext(SignInIdentifier.Phone, crypto.randomUUID()) as never,
          async () => {
            activeHandlers += 1;
            maximumActiveHandlers = Math.max(maximumActiveHandlers, activeHandlers);
            // Represents nested adapter/query pool work while the advisory transaction is held.
            await Promise.resolve();
            activeHandlers -= 1;
          }
        )
      )
    );

    expect(transaction.mock.calls.length).toBeGreaterThanOrEqual(30);
    expect(interactionDetails).toHaveBeenCalledTimes(30);
    expect(maximumLockHolders).toBe(1);
    expect(maximumActiveHandlers).toBe(1);
    /* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
  });

  it('still uses the PostgreSQL lock to serialize the same interaction across process gates', async () => {
    const firstProcess = createMiddleware(createPhoneSendPermitGate());
    const secondProcess = createMiddleware(createPhoneSendPermitGate());
    /* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Model one shared PostgreSQL advisory lock across two processes. */
    let databaseLocked = false;
    let activeHandlers = 0;
    let maximumActiveHandlers = 0;

    const runTransaction = async (
      callback: (connection: { oneFirst: typeof firstProcess.oneFirst }) => Promise<unknown>
    ) => {
      const lockOwnership = { acquired: false };
      const connection = {
        oneFirst: jest.fn(async () => {
          if (databaseLocked) {
            return false;
          }

          databaseLocked = true;
          lockOwnership.acquired = true;
          return true;
        }),
      };

      try {
        return await callback(connection);
      } finally {
        if (lockOwnership.acquired) {
          databaseLocked = false;
        }
      }
    };

    firstProcess.transaction.mockImplementation(runTransaction);
    secondProcess.transaction.mockImplementation(runTransaction);

    await Promise.all(
      Array.from({ length: 30 }, async (_, index) => {
        const { middleware } = index % 2 === 0 ? firstProcess : secondProcess;
        return middleware(createContext() as never, async () => {
          activeHandlers += 1;
          maximumActiveHandlers = Math.max(maximumActiveHandlers, activeHandlers);
          await Promise.resolve();
          activeHandlers -= 1;
        });
      })
    );

    expect(maximumActiveHandlers).toBe(1);
    expect(
      firstProcess.transaction.mock.calls.length + secondProcess.transaction.mock.calls.length
    ).toBeGreaterThan(30);
    /* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
  });

  it('releases the process permit when the guarded handler throws', async () => {
    const { middleware, transaction } = createMiddleware();
    const handlerError = new Error('handler failed');

    await expect(
      middleware(createContext() as never, async () => {
        throw handlerError;
      })
    ).rejects.toBe(handlerError);
    const next = jest.fn();
    await middleware(createContext() as never, next);

    expect(transaction).toHaveBeenCalledTimes(2);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('does not retry a retryable database error after the guarded side effect', async () => {
    const { connection, middleware, transaction } = createMiddleware();
    const retryableError = new RetryableDatabaseError('serialization failure after delivery');
    const sideEffect = jest.fn();
    transaction.mockImplementation(async (callback, retryLimit) => {
      try {
        return await callback(connection);
      } catch (error: unknown) {
        if (
          retryLimit !== 0 &&
          error instanceof Error &&
          'code' in error &&
          typeof error.code === 'string' &&
          error.code.startsWith('40')
        ) {
          return callback(connection);
        }

        throw error;
      }
    });

    await expect(
      middleware(createContext() as never, async () => {
        sideEffect();
        throw retryableError;
      })
    ).rejects.toBe(retryableError);

    expect(sideEffect).toHaveBeenCalledTimes(1);
    expect(transaction).toHaveBeenCalledWith(expect.any(Function), 0);
  });

  it('returns an explicit busy error without entering database or send work when permit wait expires', async () => {
    const now = jest.spyOn(Date, 'now').mockReturnValueOnce(0).mockReturnValue(7000);
    const permitGate = createPhoneSendPermitGate();
    const releaseHeldPermit = permitGate.tryAcquire();
    const { middleware, transaction } = createMiddleware(permitGate);
    const next = jest.fn();

    await expect(middleware(createContext() as never, next)).rejects.toMatchObject({
      code: 'request.rate_limited',
      status: 429,
    });

    expect(transaction).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
    releaseHeldPermit?.();
    expect(permitGate.tryAcquire()).toEqual(expect.any(Function));
    now.mockRestore();
  });
});
