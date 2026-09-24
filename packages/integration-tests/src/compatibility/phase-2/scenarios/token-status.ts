import type { TargetConfig } from '../../model.js';
import { observeTokenStatus, type TokenStatusProof } from '../clients/token-status.js';
import { issuePublicUserTokens } from '../clients/user-token-issuance.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2DifferentialScenarioId, Phase2ProfileRegistries } from '../profile.js';
import type { TokenStatusProjection } from '../projections/token-status.js';

export const tokenStatusScenarioIds = Object.freeze([
  'token-status.public-access-active',
  'token-status.public-refresh-active',
  'token-status.access-wrong-hint-active',
  'token-status.refresh-no-hint-active',
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
  token: string;
  proof: TokenStatusProof;
  expectedActive: boolean;
  tokenType?: 'Bearer';
  hint?: string;
}>;

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
          kind: 'introspection',
          token: plan.token,
          ...(plan.hint === undefined ? {} : { hint: plan.hint }),
          proof: plan.proof,
          subjectId: status.user.id,
          ownerClientId: status.client.id,
          grant: 'unchanged',
        },
        requestFetch
      );
      if (
        projection.status !== 200 ||
        projection.body?.active !== plan.expectedActive ||
        (plan.expectedActive && projection.body.token_type !== plan.tokenType)
      ) {
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
      expectedActive: true,
      tokenType: 'Bearer',
      hint: 'access_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[1],
      token: tokens.refresh,
      proof: publicProof,
      expectedActive: true,
      hint: 'refresh_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[2],
      token: tokens.access,
      proof: publicProof,
      expectedActive: true,
      tokenType: 'Bearer',
      hint: 'refresh_token',
    }),
    await observe({
      id: tokenStatusScenarioIds[3],
      token: tokens.refresh,
      proof: publicProof,
      expectedActive: true,
    }),
  ];
  return Object.freeze(publicResults);
};
