/* eslint-disable max-lines -- The closed status registry and its ordered grant lifecycle are reviewed together. */
import type { TargetConfig } from '../../model.js';
import {
  observeTokenStatus,
  type TokenStatusProof,
  type TokenStatusRequest,
} from '../clients/token-status.js';
import {
  exchangePublicRefresh,
  issueConfidentialUserTokens,
  issuePublicUserTokens,
} from '../clients/user-token-issuance.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2DifferentialScenarioId, Phase2ProfileRegistries } from '../profile.js';
import type { TokenStatusProjection } from '../projections/token-status.js';

export const tokenStatusScenarioIds = Object.freeze([
  'token-status.public-access-active',
  'token-status.public-refresh-active',
  'token-status.access-wrong-hint-active',
  'token-status.refresh-no-hint-active',
  'token-status.resource-jwt-introspection-rejected',
  'token-status.resource-jwt-revocation-rejected',
  'token-status.consumed-refresh-active',
  'token-status.rotated-refresh-active',
  'token-status.consumed-refresh-revoked',
  'token-status.rotated-refresh-inactive',
  'token-status.original-access-inactive',
  'token-status.unknown-token-inactive',
  'token-status.no-auth-rejected',
  'token-status.owner-access-revoked',
  'token-status.owner-access-inactive',
  'token-status.owner-refresh-inactive',
  'token-status.missing-token-rejected',
  'token-status.duplicate-token-rejected',
  'token-status.dotted-unknown-inactive',
  'token-status.unknown-extension-inactive',
  'token-status.no-auth-precedes-missing-token',
  'token-status.confidential-basic-access-active',
  'token-status.confidential-post-access-active',
  'token-status.confidential-wrong-secret-rejected',
  'token-status.confidential-public-cross-client-inactive',
  'token-status.confidential-public-cross-client-revoked',
  'token-status.confidential-owner-after-cross-client-active',
] as const satisfies readonly Phase2DifferentialScenarioId[]);

export type TokenStatusScenarioResult = Readonly<{
  id: (typeof tokenStatusScenarioIds)[number];
  projection: TokenStatusProjection;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 token status scenario');
};

type ObservationPlan = Readonly<{
  id: TokenStatusScenarioResult['id'];
  kind?: 'introspection' | 'revocation';
  token: string;
  proof: TokenStatusProof;
  expected:
    | 'access-active'
    | 'refresh-active'
    | 'inactive'
    | 'revoked'
    | 'missing-authentication'
    | 'missing-token'
    | 'duplicate-token'
    | 'invalid-client'
    | 'unsupported-introspection'
    | 'unsupported-revocation';
  hint?: string;
  wire?: TokenStatusRequest['wire'];
  ownerClientId?: string;
  grant?: 'unchanged' | 'revoked';
}>;

// eslint-disable-next-line complexity -- One closed status contract checks each observed response shape.
const matchesContract = (
  projection: TokenStatusProjection,
  expected: ObservationPlan['expected']
): boolean => {
  switch (expected) {
    case 'access-active': {
      return (
        projection.status === 200 &&
        projection.body?.active === true &&
        projection.body.token_type === 'Bearer'
      );
    }
    case 'refresh-active': {
      return (
        projection.status === 200 &&
        projection.body?.active === true &&
        !Object.hasOwn(projection.body, 'token_type')
      );
    }
    case 'inactive': {
      return projection.status === 200 && projection.body?.active === false;
    }
    case 'revoked': {
      return projection.status === 200 && projection.body === null;
    }
    case 'missing-authentication': {
      return (
        projection.status === 400 &&
        projection.body?.error === 'invalid_request' &&
        projection.body.error_description === 'no client authentication mechanism provided'
      );
    }
    case 'missing-token': {
      return (
        projection.status === 400 &&
        projection.body?.error === 'invalid_request' &&
        projection.body.error_description === "missing required parameter 'token'"
      );
    }
    case 'duplicate-token': {
      return (
        projection.status === 400 &&
        projection.body?.error === 'invalid_request' &&
        projection.body.error_description === "'token' parameter must not be provided twice"
      );
    }
    case 'invalid-client': {
      return (
        projection.status === 401 &&
        projection.body?.error === 'invalid_client' &&
        projection.body.error_description === 'client authentication failed'
      );
    }
    case 'unsupported-introspection':
    case 'unsupported-revocation': {
      return (
        projection.status === 400 &&
        projection.body?.error === 'unsupported_token_type' &&
        projection.body.error_description ===
          (expected === 'unsupported-introspection'
            ? 'Structured JWT Tokens cannot be introspected via the introspection_endpoint'
            : 'Structured JWT Tokens cannot be revoked via the revocation_endpoint')
      );
    }
  }
};

export const runTokenStatusScenarios = async (
  profile: Phase2ProfileRegistries,
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  requestFetch: typeof fetch = fetch
): Promise<readonly TokenStatusScenarioResult[]> => {
  const start = profile.differentialScenarios.indexOf(tokenStatusScenarioIds[0]);
  const tail = profile.differentialScenarios.slice(start, start + tokenStatusScenarioIds.length);
  if (
    start < 0 ||
    tail.length !== tokenStatusScenarioIds.length ||
    tail.some((id, index) => id !== tokenStatusScenarioIds[index])
  ) {
    return fail();
  }
  const status = fixture.status ?? fail();
  const tokens = await issuePublicUserTokens(target, fixture, requestFetch);
  const publicProof = Object.freeze({ method: 'public' as const, clientId: status.client.id });
  const observe = async (plan: ObservationPlan): Promise<TokenStatusScenarioResult> => {
    try {
      const projection = await observeTokenStatus(
        {
          target,
          kind: plan.kind ?? 'introspection',
          token: plan.token,
          ...(plan.hint === undefined ? {} : { hint: plan.hint }),
          ...(plan.wire === undefined ? {} : { wire: plan.wire }),
          proof: plan.proof,
          subjectId: status.user.id,
          ownerClientId: plan.ownerClientId ?? status.client.id,
          resourceScopeName: status.resource.scopeName,
          grant: plan.grant ?? 'unchanged',
        },
        requestFetch
      );
      if (!matchesContract(projection, plan.expected)) {
        return fail();
      }
      return Object.freeze({ id: plan.id, projection });
    } catch {
      throw new Error('Phase 2 scenario failed: ' + target.label + '/' + plan.id);
    }
  };
  const publicResults = [
    await observe({
      id: tokenStatusScenarioIds[0],
      token: tokens.access,
      proof: publicProof,
      expected: 'access-active',
      hint: 'access_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[1],
      token: tokens.refresh,
      proof: publicProof,
      expected: 'refresh-active',
      hint: 'refresh_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[2],
      token: tokens.access,
      proof: publicProof,
      expected: 'access-active',
      hint: 'refresh_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[3],
      token: tokens.refresh,
      proof: publicProof,
      expected: 'refresh-active',
    }),
  ];
  const rotated = await exchangePublicRefresh(target, fixture, tokens.refresh, {
    resource: true,
    fetch: requestFetch,
  });
  const lifecycleResults = [
    await observe({
      id: tokenStatusScenarioIds[4],
      token: rotated.access,
      proof: publicProof,
      kind: 'introspection',
      expected: 'unsupported-introspection',
      hint: 'access_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[5],
      token: rotated.access,
      proof: publicProof,
      kind: 'revocation',
      expected: 'unsupported-revocation',
      hint: 'access_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[6],
      token: tokens.refresh,
      proof: publicProof,
      expected: 'refresh-active',
      hint: 'refresh_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[7],
      token: rotated.refresh,
      proof: publicProof,
      expected: 'refresh-active',
      hint: 'refresh_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[8],
      token: tokens.refresh,
      proof: publicProof,
      kind: 'revocation',
      expected: 'revoked',
      hint: 'refresh_token',
      grant: 'revoked',
    }),
    await observe({
      id: tokenStatusScenarioIds[9],
      token: rotated.refresh,
      proof: publicProof,
      expected: 'inactive',
      hint: 'refresh_token',
      grant: 'revoked',
    }),
    await observe({
      id: tokenStatusScenarioIds[10],
      token: tokens.access,
      proof: publicProof,
      expected: 'inactive',
      hint: 'access_token',
      grant: 'revoked',
    }),
  ];
  const second = await issuePublicUserTokens(target, fixture, requestFetch);
  const ownerRevocationResults = [
    await observe({
      id: tokenStatusScenarioIds[11],
      token: 'phase2-unknown-opaque',
      proof: publicProof,
      expected: 'inactive',
      hint: 'access_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[12],
      token: second.access,
      proof: { method: 'none' },
      expected: 'missing-authentication',
      hint: 'access_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[13],
      token: second.access,
      proof: publicProof,
      kind: 'revocation',
      expected: 'revoked',
      hint: 'access_token',
      grant: 'revoked',
    }),
    await observe({
      id: tokenStatusScenarioIds[14],
      token: second.access,
      proof: publicProof,
      expected: 'inactive',
      hint: 'access_token',
      grant: 'revoked',
    }),
    await observe({
      id: tokenStatusScenarioIds[15],
      token: second.refresh,
      proof: publicProof,
      expected: 'inactive',
      hint: 'refresh_token',
      grant: 'revoked',
    }),
  ];
  const formResults = [
    await observe({
      id: tokenStatusScenarioIds[16],
      token: 'not-sent-token',
      proof: publicProof,
      expected: 'missing-token',
      wire: 'missing-token',
    }),
    await observe({
      id: tokenStatusScenarioIds[17],
      token: second.access,
      proof: publicProof,
      expected: 'duplicate-token',
      wire: 'duplicate-token',
    }),
    await observe({
      id: tokenStatusScenarioIds[18],
      token: 'phase2.unknown.token',
      proof: publicProof,
      expected: 'inactive',
    }),
    await observe({
      id: tokenStatusScenarioIds[19],
      token: second.access,
      proof: publicProof,
      expected: 'inactive',
      wire: 'unknown-extension',
    }),
    await observe({
      id: tokenStatusScenarioIds[20],
      token: 'not-sent-token',
      proof: { method: 'none' },
      expected: 'missing-authentication',
      wire: 'missing-token',
    }),
  ];
  const confidentialTokens = await issueConfidentialUserTokens(target, fixture, requestFetch);
  const confidentialResults = await fixture.withSecretLease(async (lease) => {
    const clientId = status.confidentialClient.id;
    const clientSecret = lease.getStatusClientSecret();
    const basicProof = Object.freeze({ method: 'basic' as const, clientId, clientSecret });
    const postProof = Object.freeze({ method: 'post' as const, clientId, clientSecret });
    return Object.freeze([
      await observe({
        id: tokenStatusScenarioIds[21],
        token: confidentialTokens.access,
        proof: basicProof,
        expected: 'access-active',
        hint: 'access_token',
        ownerClientId: clientId,
      }),
      await observe({
        id: tokenStatusScenarioIds[22],
        token: confidentialTokens.access,
        proof: postProof,
        expected: 'access-active',
        hint: 'access_token',
        ownerClientId: clientId,
      }),
      await observe({
        id: tokenStatusScenarioIds[23],
        token: confidentialTokens.access,
        proof: { method: 'basic', clientId, clientSecret: `${clientSecret}-wrong` },
        expected: 'invalid-client',
        hint: 'access_token',
        ownerClientId: clientId,
      }),
      await observe({
        id: tokenStatusScenarioIds[24],
        token: confidentialTokens.access,
        proof: publicProof,
        expected: 'inactive',
        hint: 'access_token',
        ownerClientId: clientId,
      }),
      await observe({
        id: tokenStatusScenarioIds[25],
        token: confidentialTokens.access,
        proof: publicProof,
        kind: 'revocation',
        expected: 'revoked',
        hint: 'access_token',
        ownerClientId: clientId,
      }),
      await observe({
        id: tokenStatusScenarioIds[26],
        token: confidentialTokens.access,
        proof: basicProof,
        expected: 'access-active',
        hint: 'access_token',
        ownerClientId: clientId,
      }),
    ]);
  });
  return Object.freeze([
    ...publicResults,
    ...lifecycleResults,
    ...ownerRevocationResults,
    ...formResults,
    ...confidentialResults,
  ]);
};
/* eslint-enable max-lines */
