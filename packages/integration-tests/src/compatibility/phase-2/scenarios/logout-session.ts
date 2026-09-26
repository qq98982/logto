/* eslint-disable no-await-in-loop, @silverhand/fp/no-mutating-methods -- Ordered logout and Account observations share one fixture token lifecycle. */
import type { TargetConfig } from '../../model.js';
import { observeAccountSessionBoundary, observeLogoutSession } from '../clients/logout-session.js';
import { issuePublicUserTokens } from '../clients/user-token-issuance.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2DifferentialScenarioId, Phase2ProfileRegistries } from '../profile.js';
import type { LogoutSessionProjection } from '../projections/logout-session.js';

export const logoutSessionScenarioIds = Object.freeze([
  'logout.anonymous-get',
  'logout.anonymous-post',
  'logout.anonymous-confirmed',
  'logout.duplicate-client',
  'logout.unknown-client',
  'logout.unauthoritative-redirect',
  'logout.unregistered-redirect',
  'logout.success-page',
  'account-sessions.missing-verification',
  'account-sessions.wrong-password',
] as const satisfies readonly Phase2DifferentialScenarioId[]);

export type LogoutSessionScenarioResult = Readonly<{
  id: (typeof logoutSessionScenarioIds)[number];
  projection: LogoutSessionProjection;
}>;

export const runLogoutSessionScenarios = async (
  profile: Phase2ProfileRegistries,
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  requestFetch: typeof fetch = fetch
): Promise<readonly LogoutSessionScenarioResult[]> => {
  const tail = profile.differentialScenarios.slice(-logoutSessionScenarioIds.length);
  if (
    tail.length !== logoutSessionScenarioIds.length ||
    tail.some((id, index) => id !== logoutSessionScenarioIds[index])
  ) {
    throw new TypeError('Invalid Phase 2 logout session registry');
  }
  const clientId = fixture.status?.client.id;
  if (!clientId) {
    throw new TypeError('Invalid Phase 2 logout session fixture');
  }
  const observe = async (
    id: LogoutSessionScenarioResult['id'],
    operation: () => Promise<LogoutSessionProjection>
  ): Promise<LogoutSessionScenarioResult> => {
    try {
      return Object.freeze({ id, projection: await operation() });
    } catch {
      throw new Error(`Phase 2 scenario failed: ${target.label}/${id}`);
    }
  };
  const run = async (
    id: LogoutSessionScenarioResult['id'],
    input: Parameters<typeof observeLogoutSession>[0]
  ): Promise<LogoutSessionScenarioResult> =>
    observe(id, async () => observeLogoutSession(input, requestFetch));
  const results: LogoutSessionScenarioResult[] = [
    await run(logoutSessionScenarioIds[0], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
    }),
    await run(logoutSessionScenarioIds[1], {
      target,
      method: 'POST',
      path: '/oidc/session/end',
      form: [],
    }),
    await run(logoutSessionScenarioIds[2], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      confirm: true,
    }),
    await run(logoutSessionScenarioIds[3], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      form: [
        ['client_id', clientId],
        ['client_id', clientId],
      ],
    }),
    await run(logoutSessionScenarioIds[4], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      form: [['client_id', 'unknown-client']],
    }),
    await run(logoutSessionScenarioIds[5], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      form: [['post_logout_redirect_uri', 'https://untrusted.example/signed-out']],
    }),
    await run(logoutSessionScenarioIds[6], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      form: [
        ['client_id', clientId],
        ['post_logout_redirect_uri', 'https://untrusted.example/signed-out'],
      ],
    }),
    await run(logoutSessionScenarioIds[7], {
      target,
      method: 'GET',
      path: '/oidc/session/end/success',
    }),
  ];
  const tokens = await issuePublicUserTokens(target, fixture, requestFetch);
  for (const [id, kind] of [
    [logoutSessionScenarioIds[8], 'missing-verification'],
    [logoutSessionScenarioIds[9], 'wrong-password'],
  ] as const) {
    results.push(
      await observe(id, async () =>
        observeAccountSessionBoundary({ target, kind, bearer: tokens.access }, requestFetch)
      )
    );
  }
  return Object.freeze(results);
};

/* eslint-enable no-await-in-loop, @silverhand/fp/no-mutating-methods */
