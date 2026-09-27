/* eslint-disable no-await-in-loop, @silverhand/fp/no-mutating-methods -- Ordered logout and Account observations share one fixture token lifecycle. */
import type { TargetConfig } from '../../model.js';
import {
  observeAccountSessionBoundary,
  observeAccountSessionWorkflow,
  observeLogoutConfirmationBoundary,
  observeLogoutSession,
  observeRefreshActivity,
} from '../clients/logout-session.js';
import {
  issueConfidentialUserSession,
  issuePublicUserTokens,
} from '../clients/user-token-issuance.js';
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
  'logout.authenticated-get',
  'logout.authenticated-confirmed',
  'logout.offline-refresh-active',
  'logout.authenticated-declined',
  'logout.offline-refresh-active-after-decline',
  'logout.confirm-missing-session',
  'logout.confirm-xsrf-mismatch',
  'logout.confirm-replay',
  'logout.confirm-cross-cookie',
  'account-sessions.password-verification',
  'account-sessions.list-current',
  'account-sessions.delete-current',
  'account-sessions.list-zero-current',
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
  const start = profile.differentialScenarios.indexOf(logoutSessionScenarioIds[0]);
  const segment = profile.differentialScenarios.slice(
    start,
    start + logoutSessionScenarioIds.length
  );
  if (
    start < 0 ||
    segment.length !== logoutSessionScenarioIds.length ||
    segment.some((id, index) => id !== logoutSessionScenarioIds[index])
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
  const logoutSession = await issueConfidentialUserSession(target, fixture, requestFetch);
  results.push(
    await run(logoutSessionScenarioIds[10], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      initialCookieHeader: logoutSession.getCookieHeader(),
    }),
    await run(logoutSessionScenarioIds[11], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      confirm: true,
      initialCookieHeader: logoutSession.getCookieHeader(),
    })
  );
  const statusClient = fixture.status.confidentialClient;
  const statusSecret = await fixture.withSecretLease(async (lease) =>
    lease.getStatusClientSecret()
  );
  results.push(
    await observe(logoutSessionScenarioIds[12], async () =>
      observeRefreshActivity(
        {
          target,
          clientId: statusClient.id,
          clientSecret: statusSecret,
          refreshToken: logoutSession.refresh,
        },
        requestFetch
      )
    )
  );
  const declinedSession = await issueConfidentialUserSession(target, fixture, requestFetch);
  results.push(
    await run(logoutSessionScenarioIds[13], {
      target,
      method: 'GET',
      path: '/oidc/session/end',
      form: [['client_id', statusClient.id]],
      confirm: true,
      confirmLogout: false,
      initialCookieHeader: declinedSession.getCookieHeader(),
    }),
    await observe(logoutSessionScenarioIds[14], async () =>
      observeRefreshActivity(
        {
          target,
          clientId: statusClient.id,
          clientSecret: statusSecret,
          refreshToken: declinedSession.refresh,
        },
        requestFetch
      )
    ),
    await run(logoutSessionScenarioIds[15], {
      target,
      method: 'POST',
      path: '/oidc/session/end/confirm',
      form: [
        ['xsrf', 'missing-session-proof'],
        ['logout', 'yes'],
      ],
    })
  );
  const mismatchSession = await issueConfidentialUserSession(target, fixture, requestFetch);
  results.push(
    await observe(logoutSessionScenarioIds[16], async () =>
      observeLogoutConfirmationBoundary(
        {
          target,
          kind: 'mismatch',
          clientId: statusClient.id,
          cookieHeader: mismatchSession.getCookieHeader(),
        },
        requestFetch
      )
    )
  );
  const replaySession = await issueConfidentialUserSession(target, fixture, requestFetch);
  results.push(
    await observe(logoutSessionScenarioIds[17], async () =>
      observeLogoutConfirmationBoundary(
        {
          target,
          kind: 'replay',
          clientId: statusClient.id,
          cookieHeader: replaySession.getCookieHeader(),
        },
        requestFetch
      )
    )
  );
  const crossSession = await issueConfidentialUserSession(target, fixture, requestFetch);
  const otherSession = await issueConfidentialUserSession(target, fixture, requestFetch);
  results.push(
    await observe(logoutSessionScenarioIds[18], async () =>
      observeLogoutConfirmationBoundary(
        {
          target,
          kind: 'cross-cookie',
          clientId: statusClient.id,
          cookieHeader: crossSession.getCookieHeader(),
          otherCookieHeader: otherSession.getCookieHeader(),
        },
        requestFetch
      )
    )
  );
  const accountSession = await issueConfidentialUserSession(target, fixture, requestFetch);
  const password = await fixture.withSecretLease(async (lease) => lease.getSubjectPassword?.());
  if (!password) {
    throw new TypeError('Invalid Phase 2 logout session fixture');
  }
  const completeWorkflow = await observeAccountSessionWorkflow(
    { target, bearer: accountSession.access, password },
    requestFetch
  ).catch((error: unknown) => {
    const stage =
      error instanceof Error
        ? /^Invalid Phase 2 Account session workflow \((verification|list|delete|list-after-delete)\)$/u.exec(
            error.message
          )?.[1]
        : undefined;
    const index =
      stage === 'list' ? 20 : stage === 'delete' ? 21 : stage === 'list-after-delete' ? 22 : 19;
    throw new Error(`Phase 2 scenario failed: ${target.label}/${logoutSessionScenarioIds[index]}`);
  });
  results.push(
    Object.freeze({ id: logoutSessionScenarioIds[19], projection: completeWorkflow.verification }),
    Object.freeze({ id: logoutSessionScenarioIds[20], projection: completeWorkflow.sessions }),
    Object.freeze({ id: logoutSessionScenarioIds[21], projection: completeWorkflow.deletion }),
    Object.freeze({
      id: logoutSessionScenarioIds[22],
      projection: completeWorkflow.sessionsAfterDeletion,
    })
  );
  return Object.freeze(results);
};

/* eslint-enable no-await-in-loop, @silverhand/fp/no-mutating-methods */
