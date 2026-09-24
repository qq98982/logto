import type { TargetConfig } from '../../model.js';
import { observeTokenStatus, type TokenStatusProof } from '../clients/token-status.js';
import { exchangePublicRefresh, issuePublicUserTokens } from '../clients/user-token-issuance.js';
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
    | 'unsupported-introspection'
    | 'unsupported-revocation';
  hint?: string;
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
  const tail = profile.differentialScenarios.slice(-tokenStatusScenarioIds.length);
  if (
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
          proof: plan.proof,
          subjectId: status.user.id,
          ownerClientId: status.client.id,
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
  return Object.freeze([...publicResults, ...lifecycleResults]);
};
