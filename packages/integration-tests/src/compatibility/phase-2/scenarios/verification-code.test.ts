/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake lifecycle records replacement and consumption state. */
import type { Phase2ProfileRegistries } from '../profile.js';

import {
  runVerificationCodeScenarios,
  verificationCodeScenarioIds,
  type VerificationCodeScenarioRuntime,
} from './verification-code.js';

const projection = (status: number, outcome: 'created' | 'verified' | 'error', error?: string) =>
  Object.freeze({
    status,
    contentType: 'application/json',
    cacheControl: 'no-store',
    outcome,
    handleField: outcome === 'error' ? null : ('verificationId' as const),
    expiresAt: false,
    ...(error === undefined ? {} : { error }),
  });

describe('Phase 2 verification-code scenario registry', () => {
  it('runs the closed lifecycle cases in profile order without publishing secrets', async () => {
    const secrets = ['111111', '222222', 'handle-1', 'handle-2', 'handle-3', 'handle-4'];
    let send = 0;
    const latest = new Map<string, string>();
    const consumed = new Set<string>();
    const runtime: VerificationCodeScenarioRuntime = {
      request: async ({ identifier }) => {
        send += 1;
        latest.set(identifier, `handle-${send}`);
        return Object.freeze({
          projection: projection(200, 'created'),
          delivery: `delivery-${send}`,
        });
      },
      takeDelivery: async (delivery) => {
        const sequence = Number(delivery.slice('delivery-'.length));
        return Object.freeze({
          handle: `handle-${sequence}`,
          code: sequence === 1 ? secrets[0]! : secrets[1]!,
        });
      },
      verify: async ({ code, identifier, handle }) => {
        if (identifier.startsWith('wrong-')) {
          return projection(400, 'error', 'verification_code.email_mismatch');
        }
        if (code === '000000') {
          return projection(400, 'error', 'verification_code.code_mismatch');
        }
        if (latest.get(identifier) !== handle) {
          return projection(404, 'error', 'session.verification_session_not_found');
        }
        if (consumed.has(handle)) {
          return projection(400, 'error', 'verification_code.not_found');
        }
        consumed.add(handle);
        return projection(200, 'verified');
      },
      runRetryCap: async () =>
        Object.freeze([
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.code_mismatch'),
          projection(400, 'error', 'verification_code.exceed_max_try'),
          projection(400, 'error', 'verification_code.exceed_max_try'),
        ]),
      runSendCap: async () =>
        Object.freeze({
          accepted: 10,
          capped: projection(429, 'error', 'request.message_rate_limited'),
        }),
      runFailedDelivery: async () =>
        Object.freeze({
          failed: projection(400, 'error', 'connector.invalid_config'),
          previous: projection(200, 'verified'),
        }),
      runAccountLifecycle: async () =>
        Object.freeze({
          requested: Object.freeze({
            ...projection(201, 'created'),
            handleField: 'verificationRecordId' as const,
            expiresAt: true,
          }),
          verified: Object.freeze({
            ...projection(200, 'verified'),
            handleField: 'verificationRecordId' as const,
          }),
          replay: projection(400, 'error', 'verification_code.not_found'),
        }),
    };
    const profile = {
      differentialScenarios: verificationCodeScenarioIds,
    } as unknown as Phase2ProfileRegistries;
    const results = await runVerificationCodeScenarios(profile, runtime);

    expect(results.map(({ id }) => id)).toEqual(verificationCodeScenarioIds);
    const published = JSON.stringify(results);
    for (const secret of secrets) {
      expect(published).not.toContain(secret);
    }
  });

  it('rejects a profile that omits or reorders a lifecycle case', async () => {
    await expect(
      runVerificationCodeScenarios(
        {
          differentialScenarios: [...verificationCodeScenarioIds].reverse(),
        } as unknown as Phase2ProfileRegistries,
        {} as VerificationCodeScenarioRuntime
      )
    ).rejects.toThrow('Invalid Phase 2 verification-code registry');
  });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
