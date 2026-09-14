import { SignInIdentifier } from '@logto/schemas';
import { sql } from '@silverhand/slonik';
import type { MiddlewareType } from 'koa';
import { z } from 'zod';

import RequestError from '#src/errors/RequestError/index.js';
import type TenantContext from '#src/tenants/TenantContext.js';

import ExperienceInteraction from '../classes/experience-interaction.js';
import { type ExperienceInteractionRouterContext } from '../types.js';

const phoneSendBodyGuard = z.object({
  identifier: z.object({ type: z.literal(SignInIdentifier.Phone) }),
});

export const phoneSendLockWaitTimeout = 7000;
export const phoneSendLockRetryInterval = 20;
const waitBeforeLockRetry = async () =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, phoneSendLockRetryInterval);
  });

type PhoneSendPermitGate = {
  tryAcquire: () => (() => void) | undefined;
};

export const createPhoneSendPermitGate = (): PhoneSendPermitGate => {
  const state = { held: false };

  return {
    tryAcquire: () => {
      if (state.held) {
        return;
      }

      /* eslint-disable @silverhand/fp/no-mutation -- This is the process-local single-permit state. */
      state.held = true;
      const permit = { released: false };

      return () => {
        if (permit.released) {
          return;
        }

        permit.released = true;
        state.held = false;
      };
      /* eslint-enable @silverhand/fp/no-mutation */
    },
  };
};

const processPhoneSendPermitGate = createPhoneSendPermitGate();

const throwPhoneSendBusy = () => {
  throw new RequestError({ code: 'request.rate_limited', status: 429 });
};

const acquirePhoneSendPermit = async (
  gate: PhoneSendPermitGate,
  deadline: number
): Promise<() => void> => {
  if (Date.now() >= deadline) {
    return throwPhoneSendBusy();
  }

  const release = gate.tryAcquire();
  if (release) {
    return release;
  }

  await waitBeforeLockRetry();
  return acquirePhoneSendPermit(gate, deadline);
};

/** Serialize a guarded client-selected phone send for one OIDC interaction across Core replicas. */
export default function koaPhoneVerificationCodeLock<T extends ExperienceInteractionRouterContext>(
  tenant: TenantContext,
  permitGate: PhoneSendPermitGate = processPhoneSendPermitGate
): MiddlewareType<unknown, T> {
  const { provider, queries } = tenant;

  return async (ctx, next) => {
    if (!phoneSendBodyGuard.safeParse(ctx.request.body).success) {
      return next();
    }

    const { jti } = ctx.interactionDetails;
    const deadline = Date.now() + phoneSendLockWaitTimeout;

    const runWithLock = async (): Promise<void> => {
      const result = await queries.pool.transaction(async (connection) => {
        const acquired = await connection.oneFirst<boolean>(
          sql`select pg_try_advisory_xact_lock(hashtextextended(${jti}, 0))`
        );

        if (!acquired) {
          return { acquired: false } as const;
        }

        // The initial interaction snapshot was loaded before the lock. Reload so this request sees
        // the previous phone send's persisted authorization consumption.
        ctx.interactionDetails = await provider.interactionDetails(ctx.req, ctx.res);
        ctx.experienceInteraction = new ExperienceInteraction(ctx, tenant, ctx.interactionDetails);

        await next();
        return { acquired: true } as const;
      });

      if (result.acquired) {
        return;
      }

      if (Date.now() >= deadline) {
        return throwPhoneSendBusy();
      }

      await waitBeforeLockRetry();
      await runWithLock();
    };

    const releasePermit = await acquirePhoneSendPermit(permitGate, deadline);

    try {
      await runWithLock();
    } finally {
      releasePermit();
    }
  };
}
