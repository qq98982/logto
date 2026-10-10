/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The fake records ordered UI calls. */
import type { Phase1BrowserSession } from '../../phase-1/browser/contracts.js';

import { adaptPhase1SessionForPhoneCode } from './phone-code-phase1-session-adapter.js';

const configuration = {
  storageKey: 'configuration',
  demo: {
    appId: 'app',
    prompt: 'consent',
    scope: 'openid offline_access profile phone read:profile',
    resource: 'https://api.example',
  },
  expectedIssuer: 'https://core.example/oidc',
  resource: 'https://api.example',
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid offline_access profile phone',
  resourceScope: 'read:profile',
} as const;

test('selects China through the rendered country control and projects phone UserInfo claims', async () => {
  const actions: string[] = [];
  let factRead = 0;
  const phase1 = {
    preloadDemoConfiguration: async () => {},
    navigate: async () => {},
    waitForRoute: async () => {},
    click: async (_step: string, selector: string) => {
      actions.push(`click:${selector}`);
    },
    fill: async (_step: string, selector: string, value: string) => {
      actions.push(`fill:${selector}:${value}`);
    },
    clickAndObserveObject: async (
      _step: string,
      _selector: string,
      project: (value: Record<string, unknown>) => Record<string, unknown>
    ) =>
      project(
        _selector.includes('Fetch user info')
          ? {
              sub: 'owner',
              phone_number: '8613800138000',
              phone_number_verified: true,
            }
          : {}
      ),
    waitForNetworkFacts: async () => ({
      signIns: [],
      callbacks: [],
      endpointDiscoveries: [],
      accountReads: [],
      applicationReads: [],
      userReads: [],
      exchanges:
        factRead++ === 0
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
  const session = adaptPhase1SessionForPhoneCode(phase1, configuration, 'owner');
  await session.selectChinaCountryCode('country', '/sign-in');
  await session.fill('phone', 'input[name="identifier"]', '13800138000');
  await session.fill('code', 'input[name="passcode_0"]', '1');
  await expect(session.readProfile()).resolves.toEqual({
    sub: 'owner',
    phoneNumber: '8613800138000',
    phoneNumberVerified: true,
    emailAbsent: true,
  });
  await expect(session.refresh()).resolves.toEqual({
    subject: 'owner',
    rotated: true,
    phoneNumber: '8613800138000',
  });
  expect(
    actions.filter((value) => value === 'click:role=button[name="Open dev panel"]')
  ).toHaveLength(1);
  expect(actions).toEqual([
    'click:div[role="button"]:has-text("+1")',
    'fill:input[name="country-code-search"]:86',
    'click:[data-id="86"]',
    'fill:input[name="identifier"]:13800138000',
    'fill:input[name="passcode_0"]:1',
    'click:role=button[name="Open dev panel"]',
    'fill:form:has-text("Refresh token grant") input[name="resource"]:https://api.example',
  ]);
});

test('rejects selectors outside the phone identifier and six code cells', async () => {
  const phase1 = {
    preloadDemoConfiguration: async () => {},
    navigate: async () => {},
    waitForRoute: async () => {},
    click: async () => {},
    fill: async () => {},
  } as unknown as Phase1BrowserSession;
  const session = adaptPhase1SessionForPhoneCode(phase1, configuration, 'owner');
  await expect(session.fill('password', 'input[name="password"]', 'secret')).rejects.toThrow(
    'Invalid Common phone code browser adapter'
  );
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
