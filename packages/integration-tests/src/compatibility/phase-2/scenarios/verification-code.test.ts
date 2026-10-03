/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake lifecycle records replacement and consumption state. */
import type { Phase2ProfileRegistries } from '../profile.js';

import {
  runVerificationCodeScenarios,
  VerificationCodeScenarioFailure,
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
          return projection(404, 'error', 'session.verification_session_not_found');
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

  it.each([
    [verificationCodeScenarioIds[0], 'request', 1],
    [verificationCodeScenarioIds[1], 'request', 2],
    [verificationCodeScenarioIds[2], 'request', 3],
    [verificationCodeScenarioIds[3], 'runRetryCap', 1],
    [verificationCodeScenarioIds[4], 'runSendCap', 1],
    [verificationCodeScenarioIds[5], 'runFailedDelivery', 1],
    [verificationCodeScenarioIds[6], 'verify', 5],
    [verificationCodeScenarioIds[7], 'runAccountLifecycle', 1],
  ] as const)('reports the closed scenario id when %s fails', async (scenarioId, method, call) => {
    let send = 0;
    const calls = new Map<string, number>();
    const count = (name: string): void => {
      const next = (calls.get(name) ?? 0) + 1;
      calls.set(name, next);
      if (name === method && next === call) {
        throw new Error('private runtime detail');
      }
    };
    const runtime: VerificationCodeScenarioRuntime = {
      request: async () => {
        count('request');
        send += 1;
        return Object.freeze({ projection: projection(200, 'created'), delivery: `${send}` });
      },
      takeDelivery: async (delivery) =>
        Object.freeze({ handle: `handle-${delivery}`, code: 'private-code' }),
      verify: async ({ identifier, handle }) => {
        count('verify');
        if (identifier.startsWith('wrong-')) {
          return projection(400, 'error', 'verification_code.email_mismatch');
        }
        if (identifier.startsWith('replacement') && handle === 'handle-3') {
          return projection(404, 'error', 'session.verification_session_not_found');
        }
        if (identifier.startsWith('success') && (calls.get('verify') ?? 0) === 5) {
          return projection(404, 'error', 'session.verification_session_not_found');
        }
        return projection(200, 'verified');
      },
      runRetryCap: async () => {
        count('runRetryCap');
        return Object.freeze([
          ...Array.from({ length: 10 }, () =>
            projection(400, 'error', 'verification_code.code_mismatch')
          ),
          ...Array.from({ length: 2 }, () =>
            projection(400, 'error', 'verification_code.exceed_max_try')
          ),
        ]);
      },
      runSendCap: async () => {
        count('runSendCap');
        return Object.freeze({
          accepted: 10,
          capped: projection(429, 'error', 'request.message_rate_limited'),
        });
      },
      runFailedDelivery: async () => {
        count('runFailedDelivery');
        return Object.freeze({
          failed: projection(400, 'error', 'connector.invalid_config'),
          previous: projection(200, 'verified'),
        });
      },
      runAccountLifecycle: async () => {
        count('runAccountLifecycle');
        return Object.freeze({
          requested: projection(201, 'created'),
          verified: projection(200, 'verified'),
          replay: projection(400, 'error', 'verification_code.not_found'),
        });
      },
    };
    const profile = {
      differentialScenarios: verificationCodeScenarioIds,
    } as unknown as Phase2ProfileRegistries;

    const failure = await runVerificationCodeScenarios(profile, runtime).catch(
      (error: unknown) => error
    );

    expect(failure).toBeInstanceOf(VerificationCodeScenarioFailure);
    expect(failure).toEqual(
      expect.objectContaining({
        message: 'Phase 2 verification-code scenario failed',
        scenarioId,
      })
    );
    expect(failure).not.toHaveProperty('cause');
    expect(Object.keys(failure as Record<string, unknown>)).toEqual(['scenarioId', 'name']);
    expect(String(failure)).not.toContain('private runtime detail');
  });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
