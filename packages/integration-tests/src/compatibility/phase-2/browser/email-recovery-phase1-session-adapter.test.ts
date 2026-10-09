/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/no-unsafe-assignment -- Focused adapter fakes exercise route guards without recreating the Phase 1 implementation. */
import type { Phase1BrowserSession } from '../../phase-1/browser/contracts.js';

import { adaptPhase1SessionForEmailRecovery } from './email-recovery-phase1-session-adapter.js';

const configuration = {
  storageKey: 'config',
  demo: {
    appId: 'app',
    prompt: 'consent',
    scope: 'openid offline_access profile email read:profile',
    resource: 'https://api.example',
  },
  expectedSubject: 'owner',
  expectedIssuer: 'https://core.example/oidc',
  canonicalEmail: 'owner@example.invalid',
  resource: 'https://api.example',
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid offline_access profile email',
  resourceScope: 'read:profile',
} as const;

test.each([
  ['forgot-password-email', 'input[name="identifier"]', '/forgot-password'],
  ['recovery-passcode-0', 'input[name="passcode_0"]', '/forgot-password/verification-code'],
  ['new-password', 'input[name="newPassword"]', '/forgot-password/reset'],
  ['fill-password', 'input[name="password"]', '/sign-in/password'],
] as const)('binds %s to its exact recovery route', async (step, selector, route) => {
  const observed: unknown[] = [];
  const session = {
    fill: async (_step: string, _selector: string, _value: string, guard: unknown) => {
      observed.push(guard);
    },
  } as unknown as Phase1BrowserSession;
  await adaptPhase1SessionForEmailRecovery(session, configuration).fill(step, selector, 'value');
  expect(observed).toEqual([{ endpoint: 'core', paths: expect.arrayContaining([route]) }]);
});

test('retains separate access and refresh assertions for the captured authority', async () => {
  const actions: string[] = [];
  let factReads = 0;
  const session = {
    click: async (_step: string, selector: string) => {
      actions.push(selector);
    },
    clickAndObserveObject: async (
      _step: string,
      selector: string,
      project: (body: Record<string, unknown>) => unknown
    ) => {
      actions.push(selector);
      return project(
        selector.includes('Fetch user info')
          ? { sub: 'owner', email: 'owner@example.invalid', email_verified: true }
          : { observed: true }
      );
    },
    fill: async () => {},
    waitForNetworkFacts: async () => ({
      exchanges:
        factReads++ === 0
          ? []
          : [
              {
                kind: 'management',
                authority: 'core',
                status: 200,
                requestShapeExact: true,
                requestCorrelationValid: true,
                clientId: 'app',
                redirectUri: null,
                initialRefreshPresent: false,
                replacementFresh: true,
                resource: 'https://api.example',
                organizationId: null,
                responseScope: 'read:profile',
                accessKind: 'compact',
                compactAccess: {
                  issuer: 'https://core.example/oidc',
                  subject: 'owner',
                  audience: 'https://api.example',
                  clientId: 'app',
                  scope: 'read:profile',
                  organizationIdPresent: false,
                },
              },
            ],
    }),
  } as unknown as Phase1BrowserSession;
  const authority = await adaptPhase1SessionForEmailRecovery(
    session,
    configuration
  ).captureAuthority();
  await authority.assertAccessUsable();
  await authority.assertRefreshUsable();
  expect(actions).toContain('role=button[name="Open dev panel"]');
  expect(actions).toContain('role=button[name="Request token"]');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function, @typescript-eslint/no-unsafe-assignment */
