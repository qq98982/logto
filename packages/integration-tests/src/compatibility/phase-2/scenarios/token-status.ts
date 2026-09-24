import type { TargetConfig } from '../../model.js';
import { observeTokenStatus } from '../clients/token-status.js';
import { issuePublicUserTokens } from '../clients/user-token-issuance.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2DifferentialScenarioId, Phase2ProfileRegistries } from '../profile.js';
import type { TokenStatusProjection } from '../projections/token-status.js';

export const tokenStatusScenarioIds = Object.freeze([
  'token-status.public-access-active',
] as const satisfies readonly Phase2DifferentialScenarioId[]);

export type TokenStatusScenarioResult = Readonly<{
  id: (typeof tokenStatusScenarioIds)[number];
  projection: TokenStatusProjection;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 token status scenario');
};

export const runTokenStatusScenarios = async (
  profile: Phase2ProfileRegistries,
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  requestFetch: typeof fetch = fetch
): Promise<readonly TokenStatusScenarioResult[]> => {
  if (
    profile.differentialScenarios.length !==
      profile.differentialScenarios.indexOf(tokenStatusScenarioIds[0]) + 1 ||
    profile.differentialScenarios.at(-1) !== tokenStatusScenarioIds[0]
  ) {
    return fail();
  }
  const status = fixture.status ?? fail();
  const tokens = await issuePublicUserTokens(target, fixture, requestFetch);
  const projection = await observeTokenStatus(
    {
      target,
      kind: 'introspection',
      token: tokens.access,
      hint: 'access_token',
      proof: { method: 'public', clientId: status.client.id },
      subjectId: status.user.id,
      ownerClientId: status.client.id,
      grant: 'unchanged',
    },
    requestFetch
  );
  if (
    projection.status !== 200 ||
    projection.body?.active !== true ||
    projection.body.token_type !== 'Bearer'
  ) {
    return fail();
  }
  return Object.freeze([{ id: tokenStatusScenarioIds[0], projection }]);
};
