/* eslint-disable max-lines -- The reachable race matrix, barrier lifecycle controls, and credential-leak regression stay in one focused scenario suite. */
import type { JsonObject, JsonValue } from '../../normalize.js';
import type { ProtocolRequestOptions } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import { withTwoTokenRequestBarrier } from './positive-oidc-concurrency.js';
import {
  createTokenScenarioHarness,
  createTokenTestSigner,
  requireConcurrentTokenTransport,
  tokenGrantBody,
  tokenTestCredentials,
  tokenTestTarget,
} from './positive-oidc-token.test-helpers.js';
import { runTokenConcurrentCodeSingleWinner } from './token-concurrent-code-single-winner.js';

const invalidGrantBody = {
  code: 'oidc.invalid_grant',
  message: 'Grant request is invalid.',
  error_uri: 'https://openid.sh/debug/invalid_grant',
  error: 'invalid_grant',
  error_description: 'grant request is invalid',
};

const rawResponse = (status: number, body: unknown) => {
  const text = JSON.stringify(body);

  return Object.freeze({
    status,
    headers: Object.freeze([
      Object.freeze(['content-type', 'application/json; charset=utf-8'] as const),
      Object.freeze(['cache-control', 'no-store'] as const),
      Object.freeze(['content-length', String(Buffer.byteLength(text))] as const),
    ]),
    body: text,
  });
};

const successResponse = (idToken: string, suffix: string) =>
  rawResponse(
    200,
    tokenGrantBody({
      accessToken: `opaque-private-${suffix}-access-token`,
      idToken,
      refreshToken: `opaque-private-${suffix}-refresh-token`,
    })
  );

const requireJsonObject = (value: JsonValue | undefined): JsonObject => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('invalid test state');
  }

  return value;
};

type ReachableBranch = 'double-success' | 'revoked-single-success';

const scenarioState = (
  _stepId: string,
  branch: ReachableBranch = 'double-success'
): Phase1ScenarioStateProjectionInput =>
  branch === 'double-success'
    ? {
        body: {},
        semanticState: { unrelatedMutation: false },
        persistedState: {
          authorizationCodePresent: true,
          authorizationCodeConsumed: true,
          grantPresent: true,
          familyCount: 1,
          activeRefreshDescendantCount: 2,
          unrelatedMutation: false,
        },
        generatedIds: {},
        sideEffects: { sameGrantFamily: true, grantRevoked: false, unrelatedMutation: false },
      }
    : {
        body: {},
        semanticState: { unrelatedMutation: false },
        persistedState: {
          authorizationCodePresent: false,
          grantPresent: false,
          familyCount: 0,
          activeRefreshDescendantCount: 0,
          unrelatedMutation: false,
        },
        generatedIds: {},
        sideEffects: { grantRevoked: true, unrelatedMutation: false },
      };

const expectCanonicalAttempt = (
  value: Phase1ScenarioStepResult['value'],
  slot: 'attempt-a' | 'attempt-b'
) => {
  expect(value).toMatchObject({
    status: 200,
    body: { presentation: 'validated', slot },
    semanticState: { concurrentCodeRace: 'accepted', unrelatedMutation: false },
    persistedState: { acceptedOutcomeEnvelope: true, unrelatedMutation: false },
    generatedIds: {},
    sideEffects: { unrelatedMutation: false },
    tokens: [],
    outcomes: [],
  });
};

const runReachableBranch = async (
  branch: ReachableBranch,
  transformState: (
    state: Phase1ScenarioStateProjectionInput
  ) => Phase1ScenarioStateProjectionInput = (state) => state
) => {
  const signer = await createTokenTestSigner();
  const now = Math.floor(Date.now() / 1000);
  const signIdToken = async (offset: number) =>
    signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now + offset,
      exp: now + offset + 3600,
    });
  const [firstIdToken, secondIdToken] = await Promise.all([signIdToken(0), signIdToken(1)]);
  const tokenResponses =
    branch === 'double-success'
      ? [successResponse(firstIdToken, 'first'), successResponse(secondIdToken, 'second')]
      : [successResponse(firstIdToken, 'only'), rawResponse(400, invalidGrantBody)];
  const harness = createTokenScenarioHarness({
    jwk: signer.jwk,
    tokenBodies: [],
    tokenResponses,
    projectScenarioState: async ({ stepId }) => transformState(scenarioState(stepId, branch)),
  });
  const witness = requireConcurrentTokenTransport(harness.context, [
    'token-concurrent-code-attempt-a',
    'token-concurrent-code-attempt-b',
  ]);
  const steps = await runTokenConcurrentCodeSingleWinner(witness.context, {
    withPositiveOidcFlow: harness.flow,
  });

  witness.assertWitness();
  return steps;
};

describe('token.concurrent-code-single-winner', () => {
  it('accepts two concurrent presentations in one active family and publishes canonical attempts', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const signIdToken = async (offset: number) =>
      signer.sign({
        iss: `${tokenTestTarget.coreUrl}oidc`,
        sub: 'runtime-subject',
        aud: tokenTestCredentials.clientId,
        iat: now + offset,
        exp: now + offset + 3600,
      });
    const [firstIdToken, secondIdToken] = await Promise.all([signIdToken(0), signIdToken(1)]);
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'opaque-private-first-concurrent-access-token',
            idToken: firstIdToken,
            refreshToken: 'opaque-private-first-concurrent-refresh-token',
          })
        ),
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'opaque-private-second-concurrent-access-token',
            idToken: secondIdToken,
            refreshToken: 'opaque-private-second-concurrent-refresh-token',
          })
        ),
      ],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId),
    });
    const witness = requireConcurrentTokenTransport(harness.context, [
      'token-concurrent-code-attempt-a',
      'token-concurrent-code-attempt-b',
    ]);
    const steps = await runTokenConcurrentCodeSingleWinner(witness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    witness.assertWitness();
    expect(steps.map(({ stepId }) => stepId)).toEqual(['attempt-a', 'attempt-b', 'race', 'state']);
    expect(harness.requests).toHaveLength(2);
    expect(harness.requests.map(({ operation }) => operation)).toEqual([
      'token-concurrent-code-attempt-a',
      'token-concurrent-code-attempt-b',
    ]);
    expect(harness.requests[0]?.path).toBe('oidc/token');
    expect(harness.requests[0]?.options).toEqual(harness.requests[1]?.options);
    expect(new URLSearchParams(harness.requests[0]?.options?.body).get('grant_type')).toBe(
      'authorization_code'
    );
    expectCanonicalAttempt(steps[0]!.value, 'attempt-a');
    expectCanonicalAttempt(steps[1]!.value, 'attempt-b');
    expect(steps[2]?.value.outcomes).toEqual([
      {
        allowedError: 'invalid_grant',
        attempts: 2,
        kind: 'accepted',
        maximumSuccesses: 2,
        minimumSuccesses: 1,
      },
    ]);
    expect(steps[3]?.value).toMatchObject({
      semanticState: { concurrentCodeRace: 'accepted', unrelatedMutation: false },
      persistedState: { acceptedOutcomeEnvelope: true, unrelatedMutation: false },
      generatedIds: {},
      sideEffects: { unrelatedMutation: false },
    });
    expect(JSON.stringify(steps)).not.toMatch(/private|code_verifier|refresh_token/u);
  });

  it('accepts one success plus exact invalid_grant after revocation and publishes the same canonical state', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'opaque-private-single-success-access-token',
            idToken,
            refreshToken: 'opaque-private-single-success-refresh-token',
          })
        ),
        rawResponse(400, invalidGrantBody),
      ],
      projectScenarioState: async ({ stepId }) => {
        const state = scenarioState(stepId, 'revoked-single-success');

        return {
          ...state,
          persistedState: {
            ...requireJsonObject(state.persistedState),
            danglingRefreshDescendantCount: 17,
          },
        };
      },
    });
    const witness = requireConcurrentTokenTransport(harness.context, [
      'token-concurrent-code-attempt-a',
      'token-concurrent-code-attempt-b',
    ]);
    const steps = await runTokenConcurrentCodeSingleWinner(witness.context, {
      withPositiveOidcFlow: harness.flow,
    });

    witness.assertWitness();
    expect(harness.requests).toHaveLength(2);
    expect(harness.requests[0]?.options).toEqual(harness.requests[1]?.options);
    expectCanonicalAttempt(steps[0]!.value, 'attempt-a');
    expectCanonicalAttempt(steps[1]!.value, 'attempt-b');
    expect(steps[2]?.value.outcomes).toEqual([
      {
        allowedError: 'invalid_grant',
        attempts: 2,
        kind: 'accepted',
        maximumSuccesses: 2,
        minimumSuccesses: 1,
      },
    ]);
    expect(steps[3]?.value).toMatchObject({
      semanticState: { concurrentCodeRace: 'accepted', unrelatedMutation: false },
      persistedState: { acceptedOutcomeEnvelope: true, unrelatedMutation: false },
      generatedIds: {},
      sideEffects: { unrelatedMutation: false },
    });
    expect(JSON.stringify(steps)).not.toMatch(/private|code_verifier|refresh_token/u);
  });

  it('publishes deeply equal complete evidence for both scheduling-dependent branches', async () => {
    const doubleSuccess = await runReachableBranch('double-success');
    const revokedSingleSuccess = await runReachableBranch('revoked-single-success', (state) => ({
      ...state,
      persistedState: {
        ...requireJsonObject(state.persistedState),
        danglingRefreshDescendantCount: 17,
      },
    }));

    expect(revokedSingleSuccess).toEqual(doubleSuccess);
    expect(doubleSuccess.every(({ value }) => value.tokens.length === 0)).toBe(true);
  });

  it.each([
    ['double-success', 1],
    ['revoked-single-success', 1],
  ] as const)('rejects %s with active refresh descendant count %d', async (branch, count) => {
    await expect(
      runReachableBranch(branch, (state) => ({
        ...state,
        persistedState: {
          ...requireJsonObject(state.persistedState),
          activeRefreshDescendantCount: count,
        },
      }))
    ).rejects.toThrow('Phase 1 concurrent authorization code state is invalid');
  });

  it.each([
    ['two successes with revoked-family state', 'double-success', 'revoked-single-success'],
    ['one rejection with active-family state', 'single-success', 'double-success'],
  ] as const)('rejects cross-branch state: %s', async (_name, rawBranch, stateBranch) => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const tokenResponses =
      rawBranch === 'double-success'
        ? [successResponse(idToken, 'first'), successResponse(idToken, 'second')]
        : [successResponse(idToken, 'only'), rawResponse(400, invalidGrantBody)];
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses,
      projectScenarioState: async ({ stepId }) => scenarioState(stepId, stateBranch),
    });

    await expect(
      runTokenConcurrentCodeSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent authorization code state is invalid');
  });

  it('rejects a race with zero successful presentations', async () => {
    const signer = await createTokenTestSigner();
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [rawResponse(400, invalidGrantBody), rawResponse(400, invalidGrantBody)],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId, 'revoked-single-success'),
    });

    await expect(
      runTokenConcurrentCodeSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent authorization code outcomes are invalid');
  });

  it('rejects a non-invalid_grant concurrent error', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [
        successResponse(idToken, 'only'),
        rawResponse(400, { ...invalidGrantBody, error: 'invalid_request' }),
      ],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId, 'revoked-single-success'),
    });

    await expect(
      runTokenConcurrentCodeSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent token rejection is invalid');
  });

  it('rejects two successful presentations persisted in two families', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [successResponse(idToken, 'first'), successResponse(idToken, 'second')],
      projectScenarioState: async ({ stepId }) => {
        const state = scenarioState(stepId);

        return {
          ...state,
          persistedState: { ...requireJsonObject(state.persistedState), familyCount: 2 },
          sideEffects: { ...requireJsonObject(state.sideEffects), sameGrantFamily: false },
        };
      },
    });

    await expect(
      runTokenConcurrentCodeSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent authorization code state is invalid');
  });

  it('rejects an invalid dangling refresh descendant count', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [successResponse(idToken, 'only'), rawResponse(400, invalidGrantBody)],
      projectScenarioState: async ({ stepId }) => {
        const state = scenarioState(stepId, 'revoked-single-success');

        return {
          ...state,
          persistedState: {
            ...requireJsonObject(state.persistedState),
            danglingRefreshDescendantCount: -1,
          },
        };
      },
    });

    await expect(
      runTokenConcurrentCodeSingleWinner(harness.context, {
        withPositiveOidcFlow: harness.flow,
      })
    ).rejects.toThrow('Phase 1 concurrent authorization code state is invalid');
  });

  it('aborts and cleans up a barrier with only one arrival', async () => {
    const signer = await createTokenTestSigner();
    const harness = createTokenScenarioHarness({ jwk: signer.jwk, tokenBodies: [] });
    const controller = new AbortController();
    const context = { ...harness.context, signal: controller.signal };
    const attempts = [
      { operation: 'token-concurrent-abort-attempt-a', stepId: 'attempt-a' },
      { operation: 'token-concurrent-abort-attempt-b', stepId: 'attempt-b' },
    ] as const;
    const pending = withTwoTokenRequestBarrier<unknown, void>(
      context,
      [
        {
          ...attempts[0],
          run: async (raceContext) =>
            raceContext.protocol
              .forAllocation('data')
              .oidc.request(attempts[0].operation, 'oidc/token', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: 'non-secret-abort-probe',
                includeCookies: false,
              }),
        },
        {
          ...attempts[1],
          run: async (raceContext) =>
            new Promise((_resolve, reject) => {
              const onAbort = () => {
                raceContext.signal.removeEventListener('abort', onAbort);
                reject(new Error('peer aborted before transport'));
              };

              raceContext.signal.addEventListener('abort', onAbort, { once: true });
              if (raceContext.signal.aborted) {
                onAbort();
              }
            }),
        },
      ],
      {
        normalizationContext: { target: context.target, symbols: harness.dataSymbols },
        readState: async () => scenarioState('attempt-a'),
        validateState: () => null,
        consume: async () => {
          await Promise.resolve();
        },
      }
    );
    queueMicrotask(() => {
      controller.abort();
    });

    await expect(pending).rejects.toThrow('Phase 1 concurrent token requests aborted');
    expect(harness.requests).toEqual([]);
  });

  it('drains a pre-arrival peer failure without external abort', async () => {
    const signer = await createTokenTestSigner();
    const harness = createTokenScenarioHarness({ jwk: signer.jwk, tokenBodies: [] });
    const attempts = [
      { operation: 'token-concurrent-failure-attempt-a', stepId: 'attempt-a' },
      { operation: 'token-concurrent-failure-attempt-b', stepId: 'attempt-b' },
    ] as const;
    const pending = withTwoTokenRequestBarrier<unknown, void>(
      harness.context,
      [
        {
          ...attempts[0],
          run: async (raceContext) =>
            raceContext.protocol
              .forAllocation('data')
              .oidc.request(attempts[0].operation, 'oidc/token', {
                method: 'POST',
                body: 'non-secret-failure-probe',
                includeCookies: false,
              }),
        },
        {
          ...attempts[1],
          run: async () => {
            throw new Error('pre-arrival peer failed');
          },
        },
      ],
      {
        normalizationContext: { target: harness.context.target, symbols: harness.dataSymbols },
        readState: async () => scenarioState('attempt-a'),
        validateState: () => null,
        consume: async () => {
          await Promise.resolve();
        },
      }
    );

    await expect(pending).rejects.toThrow('Phase 1 concurrent token requests are invalid');
    expect(harness.requests).toEqual([]);
  });

  it('rejects a transformed credential leaked through a concurrent rejection header', async () => {
    const signer = await createTokenTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${tokenTestTarget.coreUrl}oidc`,
      sub: 'runtime-subject',
      aud: tokenTestCredentials.clientId,
      iat: now,
      exp: now + 3600,
    });
    const harness = createTokenScenarioHarness({
      jwk: signer.jwk,
      tokenBodies: [],
      tokenResponses: [
        rawResponse(
          200,
          tokenGrantBody({
            accessToken: 'opaque-private-leak-control-access-token',
            idToken,
            refreshToken: 'opaque-private-leak-control-refresh-token',
          })
        ),
        rawResponse(400, invalidGrantBody),
      ],
      projectScenarioState: async ({ stepId }) => scenarioState(stepId),
    });
    const baseProtocol = harness.context.protocol;
    const context: Phase1ScenarioRunContext = {
      ...harness.context,
      protocol: {
        ...baseProtocol,
        forAllocation: (role) => {
          const clients = baseProtocol.forAllocation(role);

          if (role !== 'data') {
            return clients;
          }

          return {
            ...clients,
            oidc: {
              ...clients.oidc,
              request: async (
                operation: string,
                path: string,
                options: ProtocolRequestOptions = {}
              ) => {
                const response = await clients.oidc.request(operation, path, options);

                if (response.status !== 400) {
                  return response;
                }
                const code = new URLSearchParams(options.body).get('code') ?? '';
                const transformed = Buffer.from(code, 'utf8')
                  .toString('hex')
                  .match(/.{2}/gu)
                  ?.map((byte) => `%${byte.toUpperCase()}`)
                  .join('');

                return Object.freeze({
                  ...response,
                  headers: Object.freeze([
                    ...response.headers,
                    Object.freeze(['x-credential-leak', transformed ?? ''] as const),
                  ]),
                });
              },
            },
          };
        },
      },
    };

    await expect(
      runTokenConcurrentCodeSingleWinner(context, { withPositiveOidcFlow: harness.flow })
    ).rejects.toThrow('Invalid phase 1 HTTP projection');
  });
});

/* eslint-enable max-lines */
