/* eslint-disable max-lines -- The closed email-pair counterexamples exercise the existing projection and verified-token envelope together. */
import { compareJson } from '../../compare.js';
import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import { SymbolTable } from '../../symbol-table.js';
import { createPhase1ProjectionEnvelope } from '../evidence-envelope.js';
import {
  assertPhase1EvidenceIsSanitized,
  createVerifiedTokenObservations,
  snapshotPhase1EvidencePreservingVerifiedTokens,
  verifyObservedJwt,
} from '../evidence.js';
import { projectUserInfoObservation } from '../projections/userinfo.js';
import {
  createTokenTestSigner,
  tokenTestTarget,
  type TokenTestSigner,
} from '../scenarios/positive-oidc-token.test-helpers.js';

import { projectPhase1HttpCompatibility } from './http-compatibility.js';

const hash = 'a'.repeat(64);
const otherHash = 'b'.repeat(64);

const keyed = (stepId: string, value: JsonValue): JsonObject => {
  const step: JsonObject = { value };
  const steps: JsonObject = { [stepId]: step };

  return { steps };
};

const fullUserInfo = (
  offsetSeconds: number,
  implementation: 'oracle' | 'candidate' = 'oracle',
  name = 'Same Name'
) =>
  projectUserInfoObservation(
    {
      status: 200,
      headers: [
        ['content-type', 'application/json'],
        ['cache-control', 'no-store'],
      ],
      body: {
        sub: 'subject',
        email: 'person@example.test',
        email_verified: true,
        name,
        created_at: (1_700_000_000 + offsetSeconds) * (implementation === 'oracle' ? 1000 : 1),
      },
      semanticState: null,
      sideEffects: null,
    },
    {
      target: tokenTestTarget,
      symbols: new SymbolTable(),
      nativeSurfaceImplementation: implementation,
    },
    { scenarioId: 'userinfo.openid', stepId: 'userinfo' }
  );

const userinfoResponse = (etag?: string, cacheControl = 'no-store') =>
  projectUserInfoObservation(
    {
      status: 200,
      headers: [
        ['content-type', 'application/json'],
        ['cache-control', cacheControl],
        ...(etag ? [['etag', etag] as const] : []),
      ],
      body: {
        sub: 'subject',
        email: 'person@example.test',
        email_verified: true,
        name: 'Same Name',
      },
      semanticState: null,
      sideEffects: null,
    },
    {
      target: tokenTestTarget,
      symbols: new SymbolTable(),
      nativeSurfaceImplementation: 'oracle',
    },
    { scenarioId: 'userinfo.openid', stepId: 'userinfo' }
  );

const nested = (stepId: string, response: unknown) =>
  keyed(stepId, { outcomes: [{ kind: 'userinfo-email', response }] } as JsonValue);

describe('Phase 1 HTTP compatibility projection', () => {
  it('projects a verified refresh ID email pair only with same-grant opaque UserInfo evidence', async () => {
    const signer = await createTokenTestSigner();
    const issuedAt = Math.floor(Date.now() / 1000);
    const common = {
      iss: 'https://oracle.example/oidc',
      sub: 'subject',
      aud: 'client',
      iat: issuedAt,
      exp: issuedAt + 3600,
      name: 'Same Name',
    };
    const makeStep = async (
      claims: JsonObject,
      scope = 'openid email profile',
      options: Readonly<{
        accessToken?: string;
        userinfo?: JsonObject;
        signer?: TokenTestSigner;
      }> = {}
    ) => {
      const signingAuthority = options.signer ?? signer;
      const token = await signingAuthority.sign({ ...common, ...claims });
      const proofs = await Promise.all(
        [token, ...(options.accessToken ? [options.accessToken] : [])].map(async (value) =>
          verifyObservedJwt(value, { keys: [signingAuthority.jwk] })
        )
      );
      const verified = createVerifiedTokenObservations(
        {
          access_token: options.accessToken ?? 'opaque-access',
          id_token: token,
          refresh_token: 'opaque-refresh',
          token_type: 'Bearer',
          scope,
        },
        {
          target: tokenTestTarget,
          symbols: new SymbolTable(),
          nativeSurfaceImplementation: 'oracle',
        },
        { boundedClaimTimestampPaths: [], proofs }
      );

      return {
        body: verified.body,
        tokens: verified.tokens,
        outcomes: [
          {
            kind: 'userinfo-email',
            response: {
              status: 200,
              body: options.userinfo ?? {
                sub: 'subject',
                email: 'person@example.test',
                email_verified: true,
              },
            },
          },
        ],
      };
    };
    const reference = await makeStep({ email: 'person@example.test', email_verified: true });
    const omitted = await makeStep({});
    const project = (oracle: unknown, candidate: unknown) =>
      projectPhase1HttpCompatibility(
        'token.refresh-rotation',
        keyed('refresh-token', oracle as JsonValue),
        keyed('refresh-token', candidate as JsonValue)
      );
    const accepted = project(reference, omitted);

    expect(compareJson(accepted.oracle, accepted.candidate)).toEqual([]);
    expect(() => createPhase1ProjectionEnvelope('oracle', accepted.oracle)).not.toThrow();
    expect(() => createPhase1ProjectionEnvelope('candidate', accepted.candidate)).not.toThrow();
    const published = snapshotPhase1EvidencePreservingVerifiedTokens({
      id: 'token.refresh-rotation',
      oracle: createPhase1ProjectionEnvelope('oracle', accepted.oracle),
      candidate: createPhase1ProjectionEnvelope('candidate', accepted.candidate),
      differences: compareJson(accepted.oracle, accepted.candidate),
    });
    expect(() => {
      assertPhase1EvidenceIsSanitized(published);
    }).not.toThrow();
    const mirror = project(reference, reference);
    expect(compareJson(mirror.oracle, mirror.candidate)).toEqual([]);
    expect(mirror.oracle).toHaveProperty('steps.refresh-token.value.tokens.1.claims.email');
    expect(reference.tokens[1]).toHaveProperty('claims.email', 'person@example.test');
    expect(accepted.oracle).not.toHaveProperty('steps.refresh-token.value.tokens.1.claims.email');
    const code = projectPhase1HttpCompatibility(
      'token.code-reuse-rejected',
      keyed('first-exchange', reference as unknown as JsonValue),
      keyed('first-exchange', omitted as unknown as JsonValue)
    );
    expect(compareJson(code.oracle, code.candidate)).toEqual([]);
    expect(() => createPhase1ProjectionEnvelope('oracle', code.oracle)).not.toThrow();

    const fullReference = {
      ...reference,
      outcomes: [{ kind: 'userinfo-email', response: fullUserInfo(0) }],
    };
    const fullOmission = {
      ...omitted,
      outcomes: [{ kind: 'userinfo-email', response: fullUserInfo(10, 'candidate') }],
    };

    for (const [scenarioId, stepId] of [
      ['token.refresh-rotation', 'refresh-token'],
      ['token.code-reuse-rejected', 'first-exchange'],
      ['token.refresh-reuse-rejected', 'rotate'],
      ['token.concurrent-refresh-single-winner', 'attempt-a'],
      ['token.concurrent-refresh-single-winner', 'attempt-b'],
    ] as const) {
      const pair = projectPhase1HttpCompatibility(
        scenarioId,
        keyed(stepId, fullReference as unknown as JsonValue),
        keyed(stepId, fullOmission as unknown as JsonValue)
      );
      const responsePath = ['steps', stepId, 'value', 'outcomes', '0', 'response'];

      expect(compareJson(pair.oracle, pair.candidate)).toEqual([]);
      expect(pair.oracle).not.toHaveProperty([
        'steps',
        stepId,
        'value',
        'tokens',
        '1',
        'claims',
        'email',
      ]);
      expect(pair.oracle).toHaveProperty([...responsePath, 'body', 'created_at'], {
        $timestamp: 1_700_000_000,
        $toleranceSeconds: 30,
      });
      expect(pair.candidate).toHaveProperty([...responsePath, 'body', 'created_at'], {
        $timestamp: 1_700_000_010,
        $toleranceSeconds: 30,
      });

      const drift = projectPhase1HttpCompatibility(
        scenarioId,
        keyed(stepId, fullReference as unknown as JsonValue),
        keyed(stepId, {
          ...fullOmission,
          outcomes: [
            { kind: 'userinfo-email', response: fullUserInfo(10, 'candidate', 'Different') },
          ],
        } as unknown as JsonValue)
      );
      expect(drift.oracle).not.toHaveProperty([
        'steps',
        stepId,
        'value',
        'tokens',
        '1',
        'claims',
        'email',
      ]);
      expect(compareJson(drift.oracle, drift.candidate)).toContainEqual({
        path: `/steps/${stepId}/value/outcomes/0/response/body/name`,
        oracle: 'Same Name',
        candidate: 'Different',
      });

      const headerDrift = projectPhase1HttpCompatibility(
        scenarioId,
        keyed(stepId, fullReference as unknown as JsonValue),
        keyed(stepId, {
          ...fullOmission,
          outcomes: [
            {
              kind: 'userinfo-email',
              response: {
                ...fullUserInfo(10, 'candidate'),
                headers: { 'content-type': ['text/plain'], 'cache-control': ['no-store'] },
              },
            },
          ],
        } as unknown as JsonValue)
      );
      expect(compareJson(headerDrift.oracle, headerDrift.candidate)).toContainEqual({
        path: `/steps/${stepId}/value/outcomes/0/response/headers/content-type/0`,
        oracle: 'application/json',
        candidate: 'text/plain',
      });
    }

    const both = projectPhase1HttpCompatibility(
      'token.concurrent-refresh-single-winner',
      {
        steps: {
          'attempt-a': { value: fullReference },
          'attempt-b': {
            value: {
              ...(await makeStep({ email: 'person@example.test', email_verified: true })),
              outcomes: fullReference.outcomes,
            },
          },
        },
      } as unknown as JsonObject,
      {
        steps: {
          'attempt-a': { value: fullOmission },
          'attempt-b': { value: { ...(await makeStep({})), outcomes: fullOmission.outcomes } },
        },
      } as unknown as JsonObject
    );
    expect(compareJson(both.oracle, both.candidate)).toEqual([]);
    for (const stepId of ['attempt-a', 'attempt-b']) {
      expect(both.oracle).not.toHaveProperty([
        'steps',
        stepId,
        'value',
        'tokens',
        '1',
        'claims',
        'email',
      ]);
    }

    const invalidAttempt = projectPhase1HttpCompatibility(
      'token.concurrent-refresh-single-winner',
      {
        steps: { 'attempt-a': { value: fullReference }, 'attempt-b': { value: fullReference } },
      } as unknown as JsonObject,
      {
        steps: {
          'attempt-a': {
            value: {
              ...fullOmission,
              outcomes: [
                {
                  kind: 'userinfo-email',
                  response: { ...fullUserInfo(10, 'candidate'), status: 401 },
                },
              ],
            },
          },
          'attempt-b': { value: fullOmission },
        },
      } as unknown as JsonObject
    );
    expect(invalidAttempt.oracle).toHaveProperty([
      'steps',
      'attempt-a',
      'value',
      'tokens',
      '1',
      'claims',
      'email',
    ]);
    expect(invalidAttempt.oracle).not.toHaveProperty([
      'steps',
      'attempt-b',
      'value',
      'tokens',
      '1',
      'claims',
      'email',
    ]);
    expect(compareJson(invalidAttempt.oracle, invalidAttempt.candidate)).toContainEqual({
      path: '/steps/attempt-a/value/tokens/1/claims/email',
      oracle: 'person@example.test',
    });

    const nullableUserInfo = { sub: 'subject', email: null, email_verified: false };
    const nullableReference = await makeStep(
      { email: null, email_verified: false },
      'openid email profile',
      { userinfo: nullableUserInfo }
    );
    const nullableOmission = await makeStep({}, 'openid email profile', {
      userinfo: nullableUserInfo,
    });
    const nullable = project(nullableReference, nullableOmission);
    expect(compareJson(nullable.oracle, nullable.candidate)).toEqual([]);
    const invalidVerificationUserInfo = { sub: 'subject', email: null, email_verified: null };
    const invalidReference = await makeStep(
      { email: null, email_verified: null },
      'openid email profile',
      { userinfo: invalidVerificationUserInfo }
    );
    const invalidOmission = await makeStep({}, 'openid email profile', {
      userinfo: invalidVerificationUserInfo,
    });
    const invalidVerification = project(invalidReference, invalidOmission);
    expect(invalidVerification.oracle).toHaveProperty(
      'steps.refresh-token.value.tokens.1.claims.email_verified',
      null
    );
    expect(compareJson(invalidVerification.oracle, invalidVerification.candidate)).not.toEqual([]);

    const compactAccess = await signer.sign({
      ...common,
      aud: 'urn:api',
      client_id: 'client',
      scope: 'read',
    });
    const compactOmission = await makeStep({}, 'openid email profile', {
      accessToken: compactAccess,
    });
    const compact = project(reference, compactOmission);
    expect(compareJson(compact.oracle, compact.candidate)).toContainEqual({
      path: '/steps/refresh-token/value/tokens/1/claims/email',
      oracle: 'person@example.test',
    });

    const otherAlgorithm = await createTokenTestSigner('RS256');
    const algorithmMismatch = project(
      reference,
      await makeStep({}, 'openid email profile', { signer: otherAlgorithm })
    );
    expect(compareJson(algorithmMismatch.oracle, algorithmMismatch.candidate)).toContainEqual({
      path: '/steps/refresh-token/value/tokens/1/header/alg',
      oracle: 'ES384',
      candidate: 'RS256',
    });

    for (const [index, candidate] of [
      { ...omitted, tokens: JSON.parse(JSON.stringify(omitted.tokens)) as JsonValue[] },
      { ...omitted, outcomes: [] },
      {
        ...omitted,
        outcomes: [
          {
            kind: 'userinfo-email',
            response: { status: 401, body: omitted.outcomes[0]?.response.body },
          },
        ],
      },
      {
        ...omitted,
        outcomes: [
          {
            kind: 'userinfo-email',
            response: {
              status: 200,
              body: { sub: 'other', email: 'person@example.test', email_verified: true },
            },
          },
        ],
      },
      {
        ...omitted,
        outcomes: [
          {
            kind: 'userinfo-email',
            response: {
              status: 200,
              body: { sub: 'subject', email: 'other@example.test', email_verified: true },
            },
          },
        ],
      },
      {
        ...omitted,
        tokens: omitted.tokens.map((token) =>
          typeof token === 'object' &&
          token !== null &&
          !Array.isArray(token) &&
          token.kind === 'access'
            ? { ...token, format: 'jwt' }
            : token
        ),
      },
      { ...omitted, body: { ...omitted.body, scope: 'openid profile' } },
      {
        ...omitted,
        tokens: omitted.tokens.map((token) =>
          typeof token === 'object' &&
          token !== null &&
          !Array.isArray(token) &&
          token.kind === 'id'
            ? { ...token, kind: 'access' }
            : token
        ),
      },
    ].entries()) {
      if (!jsonValueGuard.safeParse(candidate).success) {
        throw new Error(`Invalid candidate fixture ${index}`);
      }
      const projected = project(reference, candidate);
      expect(compareJson(projected.oracle, projected.candidate)).not.toEqual([]);
    }

    const changedClaims: readonly JsonObject[] = [
      { email: 'person@example.test' },
      { email_verified: true },
      { email: null, email_verified: null },
      { email: 'other@example.test', email_verified: true },
      { email: 'person@example.test', email_verified: true, name: 'Different' },
    ];
    const changedSteps = await Promise.all(changedClaims.map(async (claims) => makeStep(claims)));
    for (const different of changedSteps) {
      const pair = project(reference, different);
      expect(compareJson(pair.oracle, pair.candidate)).not.toEqual([]);
      expect(pair.oracle).toHaveProperty('steps.refresh-token.value.tokens.1.claims.email');
    }

    const narrowedPairs = await Promise.all(
      ['openid profile', 'email profile'].map(async (scope) =>
        Promise.all([
          makeStep({ email: 'person@example.test', email_verified: true }, scope),
          makeStep({}, scope),
        ])
      )
    );
    for (const [narrowedReference, narrowedOmission] of narrowedPairs) {
      const narrowed = project(narrowedReference, narrowedOmission);
      expect(narrowed.oracle).toHaveProperty('steps.refresh-token.value.tokens.1.claims.email');
    }
    const changedName = project(reference, await makeStep({ name: 'Different' }));
    expect(compareJson(changedName.oracle, changedName.candidate)).toContainEqual({
      path: '/steps/refresh-token/value/tokens/1/claims/name',
      oracle: 'Same Name',
      candidate: 'Different',
    });
    const addedClaim = project(reference, await makeStep({ unapproved: 'added' }));
    expect(compareJson(addedClaim.oracle, addedClaim.candidate)).toContainEqual({
      path: '/steps/refresh-token/value/tokens/1/claims/unapproved',
      candidate: 'added',
    });

    const reverse = project(omitted, reference);
    expect(compareJson(reverse.oracle, reverse.candidate)).not.toEqual([]);
    const unregistered = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', reference as unknown as JsonValue),
      keyed('token', omitted as unknown as JsonValue)
    );
    expect(compareJson(unregistered.oracle, unregistered.candidate)).not.toEqual([]);
  });
  it('removes only the exact oracle HTTP/1 persistence headers missing from the candidate', () => {
    const oracle = keyed('token', {
      headers: {
        connection: ['keep-alive'],
        'keep-alive': ['timeout=5'],
        'x-stable': ['value'],
      },
    });
    const candidate = keyed('token', { headers: { 'x-stable': ['value'] } });
    const projected = projectPhase1HttpCompatibility('token.authorization-code', oracle, candidate);

    expect(compareJson(projected.oracle, projected.candidate)).toEqual([]);
    expect(oracle).toHaveProperty(['steps', 'token', 'value', 'headers', 'connection']);
    expect(candidate).not.toHaveProperty(['steps', 'token', 'value', 'headers', 'connection']);

    const wrongValue = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', { headers: { 'keep-alive': ['timeout=6'] } }),
      keyed('token', { headers: {} })
    );
    expect(compareJson(wrongValue.oracle, wrongValue.candidate)).toEqual([
      {
        path: '/steps/token/value/headers/keep-alive',
        oracle: ['timeout=6'],
      },
    ]);

    const partialCandidateHeaders: readonly JsonObject[] = [
      { connection: ['keep-alive'] },
      { 'keep-alive': ['timeout=5'] },
    ];

    for (const candidateHeaders of partialCandidateHeaders) {
      const partial = projectPhase1HttpCompatibility(
        'token.authorization-code',
        keyed('token', {
          headers: { connection: ['keep-alive'], 'keep-alive': ['timeout=5'] },
        }),
        keyed('token', { headers: candidateHeaders })
      );

      expect(compareJson(partial.oracle, partial.candidate)).toHaveLength(1);
    }
  });

  it('projects only registered exact candidate cache hardening additions', () => {
    const noStore = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', { headers: {} }),
      keyed('account', { headers: { 'cache-control': ['no-store'] } })
    );
    expect(compareJson(noStore.oracle, noStore.candidate)).toEqual([]);

    const discovery = projectPhase1HttpCompatibility(
      'discovery.config',
      keyed('oidc-discovery', { headers: {} }),
      keyed('oidc-discovery', {
        headers: { 'cache-control': ['no-cache, max-age=0, must-revalidate'] },
      })
    );
    expect(compareJson(discovery.oracle, discovery.candidate)).toEqual([]);

    for (const [scenarioId, stepId] of [
      ['authorization.password-pkce-consent', 'consent-get'],
      ['interaction.consent-session-boundary', 'get-valid-b'],
    ] as const) {
      const consent = projectPhase1HttpCompatibility(
        scenarioId,
        keyed(stepId, { headers: {} }),
        keyed(stepId, { headers: { 'cache-control': ['no-store'] } })
      );

      expect(compareJson(consent.oracle, consent.candidate)).toEqual([]);
    }

    const unlisted = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', { headers: {} }),
      keyed('token', { headers: { 'cache-control': ['no-store'] } })
    );
    expect(compareJson(unlisted.oracle, unlisted.candidate)).toHaveLength(1);

    const wrongValue = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', { headers: {} }),
      keyed('account', { headers: { 'cache-control': ['private'] } })
    );
    expect(compareJson(wrongValue.oracle, wrongValue.candidate)).toHaveLength(1);
  });

  it('projects only registered body-bound ETag omission and strength differences', () => {
    const omitted = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('account', { headers: { 'cache-control': ['no-store'] } })
    );
    expect(compareJson(omitted.oracle, omitted.candidate)).toEqual([]);

    const missingCacheClosure = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('account', { headers: {} })
    );
    expect(compareJson(missingCacheClosure.oracle, missingCacheClosure.candidate)).toHaveLength(1);

    const weakened = projectPhase1HttpCompatibility(
      'management.application-read',
      keyed('first-party', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('first-party', {
        headers: { etag: [{ weak: true, normalizedBodySha256: hash }] },
      })
    );
    expect(compareJson(weakened.oracle, weakened.candidate)).toEqual([]);
    expect(weakened.oracle).toHaveProperty(
      ['steps', 'first-party', 'value', 'headers', 'etag'],
      [{ weak: true, normalizedBodySha256: hash }]
    );

    const wrongHash = projectPhase1HttpCompatibility(
      'management.application-read',
      keyed('first-party', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('first-party', {
        headers: { etag: [{ weak: true, normalizedBodySha256: otherHash }] },
      })
    );
    expect(compareJson(wrongHash.oracle, wrongHash.candidate)).toHaveLength(2);

    const unlisted = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('token', { headers: {} })
    );
    expect(compareJson(unlisted.oracle, unlisted.candidate)).toHaveLength(1);
  });

  it('handles the registered nested outcome ETag without changing sibling fields', () => {
    const oracle = keyed('submit', {
      headers: {},
      outcomes: [
        {
          authority: 'accepted',
          response: {
            headers: {
              'cache-control': ['no-store'],
              etag: [{ weak: false, normalizedBodySha256: hash }],
            },
            status: 303,
          },
        },
      ],
    });
    const candidate = keyed('submit', {
      headers: {},
      outcomes: [
        {
          authority: 'accepted',
          response: { headers: { 'cache-control': ['no-store'] }, status: 303 },
        },
      ],
    });
    const projected = projectPhase1HttpCompatibility(
      'authorization.password-pkce-consent',
      oracle,
      candidate
    );

    expect(compareJson(projected.oracle, projected.candidate)).toEqual([]);
    expect(oracle).toHaveProperty([
      'steps',
      'submit',
      'value',
      'outcomes',
      '0',
      'response',
      'headers',
      'etag',
    ]);
  });

  it('omits only registered nested UserInfo strong ETags with candidate cache closure', () => {
    const oracleResponse = userinfoResponse('"strong"');
    const candidateResponse = userinfoResponse();

    for (const [scenarioId, stepId] of [
      ['token.refresh-rotation', 'refresh-token'],
      ['token.code-reuse-rejected', 'first-exchange'],
      ['token.refresh-reuse-rejected', 'rotate'],
      ['token.concurrent-refresh-single-winner', 'attempt-a'],
      ['token.concurrent-refresh-single-winner', 'attempt-b'],
    ] as const) {
      const oracle = nested(stepId, oracleResponse);
      const candidate = nested(stepId, candidateResponse);
      const pointer = `/steps/${stepId}/value/outcomes/0/response/headers/etag`;
      const projected = projectPhase1HttpCompatibility(scenarioId, oracle, candidate);

      expect(compareJson(projected.oracle, projected.candidate)).toEqual([]);
      expect(oracle).toHaveProperty([
        'steps',
        stepId,
        'value',
        'outcomes',
        '0',
        'response',
        'headers',
        'etag',
      ]);

      const withoutCache = projectPhase1HttpCompatibility(
        scenarioId,
        oracle,
        nested(stepId, userinfoResponse(undefined, 'private'))
      );
      expect(compareJson(withoutCache.oracle, withoutCache.candidate)).toContainEqual({
        path: pointer,
        oracle: oracleResponse.headers.etag,
      });

      const weakTag = projectPhase1HttpCompatibility(
        scenarioId,
        nested(stepId, userinfoResponse('W/"weak"')),
        candidate
      );
      expect(compareJson(weakTag.oracle, weakTag.candidate)).toContainEqual({
        path: pointer,
        oracle: userinfoResponse('W/"weak"').headers.etag,
      });

      const reversed = projectPhase1HttpCompatibility(scenarioId, candidate, oracle);
      expect(compareJson(reversed.oracle, reversed.candidate)).toContainEqual({
        path: pointer,
        candidate: oracleResponse.headers.etag,
      });

      const otherStep = stepId === 'refresh-token' ? 'first-exchange' : 'refresh-token';
      const unlisted = projectPhase1HttpCompatibility(
        scenarioId,
        nested(otherStep, oracleResponse),
        nested(otherStep, candidateResponse)
      );
      expect(compareJson(unlisted.oracle, unlisted.candidate)).toContainEqual({
        path: `/steps/${otherStep}/value/outcomes/0/response/headers/etag`,
        oracle: oracleResponse.headers.etag,
      });
    }
  });
});
/* eslint-enable max-lines */
