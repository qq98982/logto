/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The fake session enforces the real route contract for each ordered fill. */
import type {
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';

import { runCommonEmailCodeSignIn } from './common-email-code-sign-in.js';
import { adaptPhase1SessionForEmailCode } from './email-code-phase1-session-adapter.js';

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

const enforcingSession = (route: () => string, fills: string[]): Phase1BrowserSession =>
  ({
    fill: async (_step: string, selector: string, _value: string, guard: unknown) => {
      const paths = Reflect.get(guard as Record<string, unknown>, 'paths');
      if (!Array.isArray(paths) || !paths.includes(route())) {
        throw new Error('route rejected');
      }
      fills.push(selector);
    },
  }) as unknown as Phase1BrowserSession;

test('enforces identifier then six passcode fills on their exact routes', async () => {
  let route = '/sign-in';
  const fills: string[] = [];
  const adapter = adaptPhase1SessionForEmailCode(
    enforcingSession(() => route, fills),
    configuration
  );
  await adapter.fill('identifier', 'input[name="identifier"]', 'Owner@Example.Invalid');
  route = '/sign-in/verification-code';
  for (let index = 0; index < 6; index += 1) {
    await adapter.fill(`passcode-${index}`, `input[name="passcode_${index}"]`, String(index));
  }
  expect(fills).toEqual([
    'input[name="identifier"]',
    'input[name="passcode_0"]',
    'input[name="passcode_1"]',
    'input[name="passcode_2"]',
    'input[name="passcode_3"]',
    'input[name="passcode_4"]',
    'input[name="passcode_5"]',
  ]);
});

test.each([
  ['/sign-in/password', 'input[name="identifier"]'],
  ['/sign-in', 'input[name="passcode_0"]'],
  ['/sign-in/verification-code', 'input[name="password"]'],
] as const)('rejects selector %s on route %s', async (route, selector) => {
  const adapter = adaptPhase1SessionForEmailCode(
    enforcingSession(() => route, []),
    configuration
  );
  await expect(adapter.fill('invalid', selector, 'value')).rejects.toThrow();
});

test('runs the production Code flow with route-enforced fills and intact callback checks', async () => {
  let route = '/sign-in';
  let factReads = 0;
  const initial: Phase1BrowserNetworkFacts = {
    signIns: [
      {
        authority: 'core',
        status: 303,
        queryShapeExact: true,
        clientId: 'app',
        redirectUri: configuration.redirectUri,
        responseType: 'code',
        prompt: 'consent',
        scope: configuration.demo.scope,
        resources: [configuration.resource],
        pkceMethod: 'S256',
        stateFormatValid: true,
        challengeFormatValid: true,
      },
    ],
    callbacks: [
      {
        authority: 'core',
        path: '/demo-app',
        status: 200,
        queryShapeExact: true,
        stateMatches: true,
        issuer: configuration.expectedIssuer,
        codePresent: true,
        fragmentEmpty: true,
      },
    ],
    exchanges: [
      {
        kind: 'initial',
        authority: 'core',
        status: 200,
        requestShapeExact: true,
        requestCorrelationValid: true,
        clientId: 'app',
        redirectUri: configuration.redirectUri,
        initialRefreshPresent: true,
        replacementFresh: true,
        resource: null,
        organizationId: null,
        responseScope: configuration.initialResponseScope,
        accessKind: 'opaque',
      },
    ],
    endpointDiscoveries: [],
    accountReads: [],
    applicationReads: [],
    userReads: [],
  };
  const refreshed: Phase1BrowserNetworkFacts = {
    ...initial,
    exchanges: [
      ...initial.exchanges,
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
        resource: configuration.resource,
        organizationId: null,
        responseScope: configuration.resourceScope,
        accessKind: 'compact',
        compactAccess: {
          issuer: configuration.expectedIssuer,
          subject: 'owner',
          audience: configuration.resource,
          clientId: 'app',
          scope: configuration.resourceScope,
          organizationIdPresent: false,
        },
      },
    ],
  };
  const phase1 = {
    preloadDemoConfiguration: async () => {},
    navigate: async () => {
      route = '/sign-in';
    },
    waitForRoute: async (_step: string, _endpoint: string, paths: readonly string[]) => {
      if (!paths.includes(route)) {
        throw new Error('route rejected');
      }
    },
    waitForExactRoute: async () => {
      if (route !== '/demo-app') {
        throw new Error('route rejected');
      }
    },
    fill: async (
      _step: string,
      selector: string,
      _value: string,
      guard: { paths: readonly string[] }
    ) => {
      if (!guard.paths.includes(route)) {
        throw new Error('route rejected');
      }
      if (selector === 'input[name="passcode_5"]') {
        route = '/consent';
      }
    },
    click: async (_step: string, selector: string) => {
      if (selector === 'button[name="submit"]') {
        route = '/sign-in/verification-code';
      }
      if (selector.includes('Authorize')) {
        route = '/demo-app';
      }
    },
    waitForNetworkFacts: async () => (factReads++ < 2 ? initial : refreshed),
    clickAndObserveObject: async (
      _step: string,
      selector: string,
      project: (body: Record<string, unknown>) => Record<string, unknown>
    ) =>
      project(
        selector.includes('Fetch user info')
          ? { sub: 'owner', email: 'owner@example.invalid', email_verified: true }
          : { observed: true }
      ),
  } as unknown as Phase1BrowserSession;
  const controls = {
    recipientMismatch: { status: 400 as const, error: 'verification_code.email_mismatch' as const },
    ownerAfterRecipientMismatch: { status: 200 as const, outcome: 'verified' as const },
    consumedReplay: { status: 400 as const, error: 'verification_code.not_found' as const },
    expiry: { status: 400 as const, error: 'verification_code.expired' as const },
    foreignAccountSurface: {
      status: 400 as const,
      error: 'verification_record.not_found' as const,
    },
    ownerAfterForeignAccountSurface: { status: 200 as const, outcome: 'verified' as const },
    secondaryInteraction: {
      admissionStatus: 303 as const,
      interactionBound: true as const,
      initializationStatus: 204 as const,
    },
    secondaryVerify: {
      status: 404 as const,
      outcome: 'error' as const,
      error: 'session.verification_session_not_found' as const,
    },
    ownerAfterSecondaryVerify: { status: 200 as const, outcome: 'verified' as const },
  };
  await expect(
    runCommonEmailCodeSignIn({
      session: adaptPhase1SessionForEmailCode(phase1, configuration),
      email: 'Owner@Example.Invalid',
      canonicalEmail: 'owner@example.invalid',
      expectedSubject: 'owner',
      takePasscode: async () => '012345',
      runControls: async () => controls,
    })
  ).resolves.toMatchObject({ verificationOutcome: 'accepted', emailVerified: true });
});
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
