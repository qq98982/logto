/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions -- Counters and narrow structural fixtures prove capability ordering and lease lifetime. */
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  createScopedEmailCodeFixture,
  runCommonEmailCodeAdminBoundary,
  runCommonEmailCodeForTarget,
  runCommonEmailCodeForTargetTesting,
  runCommonEmailCodeInFreshContext,
} from './common-email-code-target-driver.js';

const admittedFixture = (onLease: () => void): ProvisionedPhase2Fixture =>
  ({
    public: { allocationId: 'allocation' },
    status: {
      user: { id: 'user', username: 'username' },
      client: { id: 'app', redirectUri: 'http://localhost:3001/demo-app' },
      confidentialClient: { id: 'confidential', redirectUri: 'https://core.example/secondary' },
      resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
    },
    withSecretLease: async () => {
      onLease();
      throw new Error('must not lease');
    },
  }) as unknown as ProvisionedPhase2Fixture;

const admittedBrowser = {
  storageKey: 'config',
  demo: {
    appId: 'app',
    prompt: 'consent',
    scope: 'openid offline_access profile email read:profile',
    resource: 'https://api.example',
  },
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid offline_access profile email',
  resourceScope: 'read:profile',
} as const;

const redactingObserver = {
  runInFreshContext: async (_group, _signal, _target, use) => {
    try {
      return await use({} as never);
    } catch {
      throw new Error('generic observer failure');
    }
  },
} as Phase1BrowserGroupObserver;

test.each([
  [
    'fixture stage',
    'Common email code fixture failed: primary-assign-role;cleanup-none',
    'Common email code target failed: fixture-assign-role',
  ],
  [
    'flow stage',
    'Common email code fixture failed: primary-use;cleanup-none;flow-initialization',
    'Common email code target failed: flow-initialization',
  ],
  [
    'passcode retrieval flow stage',
    'Common email code fixture failed: primary-use;cleanup-none;flow-passcode-retrieval',
    'Common email code target failed: flow-passcode-retrieval',
  ],
  [
    'passcode not-found flow stage',
    'Common email code fixture failed: primary-use;cleanup-none;flow-passcode-retrieval-not-found',
    'Common email code target failed: flow-passcode-retrieval-not-found',
  ],
  [
    'passcode format flow stage',
    'Common email code fixture failed: primary-use;cleanup-none;flow-passcode-format',
    'Common email code target failed: flow-passcode-format',
  ],
  [
    'control group flow stage',
    'Common email code fixture failed: primary-use;cleanup-none;flow-controls-secondary-client',
    'Common email code target failed: flow-controls-secondary-client',
  ],
])('preserves a closed %s across generic observer redaction', async (_name, source, expected) => {
  await expect(
    runCommonEmailCodeInFreshContext(
      redactingObserver,
      new AbortController().signal,
      { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
      async () => {
        throw new TypeError(source);
      }
    )
  ).rejects.toThrow(expected);
});

test('maps an unknown redacted context failure to the closed browser boundary', async () => {
  await expect(
    runCommonEmailCodeInFreshContext(
      redactingObserver,
      new AbortController().signal,
      { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
      async () => {
        throw new Error('private callback detail');
      }
    )
  ).rejects.toThrow('Common email code target failed: browser');
});

test.each([
  [
    'known consumer flow',
    'Common email code target failed: flow-passcode-retrieval-not-found',
    'Common email code target failed: admin-consumer-flow-passcode-retrieval-not-found',
  ],
  [
    'known consumer fixture request',
    'Common email code target failed: fixture-patch-sie-request',
    'Common email code target failed: admin-consumer-fixture-patch-sie-request',
  ],
  [
    'known consumer control group',
    'Common email code target failed: flow-controls-foreign-account',
    'Common email code target failed: admin-consumer-flow-controls-foreign-account',
  ],
  [
    'unknown consumer detail',
    'private consumer detail',
    'Common email code target failed: admin-consumer',
  ],
])(
  'preserves only the closed %s across Admin consumer redaction',
  async (_name, source, expected) => {
    await expect(
      runCommonEmailCodeAdminBoundary(async (capture) => {
        try {
          return await capture(async () => {
            throw new Error(source);
          });
        } catch {
          throw new TypeError('Invalid Phase 2 Admin Management bearer flow (consumer)');
        }
      })
    ).rejects.toThrow(expected);
  }
);

test('preserves a fixed Admin authentication stage without consumer details', async () => {
  await expect(
    runCommonEmailCodeAdminBoundary(async () => {
      throw new TypeError('Invalid Phase 2 Admin Management bearer flow (jwks)');
    })
  ).rejects.toThrow('Common email code target failed: admin-jwks');
});

test('rejects an unregistered observer before discovery or lease use', async () => {
  let fetches = 0;
  let leases = 0;
  await expect(
    runCommonEmailCodeForTarget({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: {
        public: { allocationId: 'allocation' },
        withSecretLease: async () => {
          leases += 1;
          throw new Error('must not open');
        },
      } as unknown as ProvisionedPhase2Fixture,
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser: {
        storageKey: 'config',
        demo: { appId: 'app', prompt: 'consent', scope: 'openid', resource: 'resource' },
        redirectUri: 'https://core.example/demo-app',
        initialResponseScope: 'openid',
        resourceScope: 'read',
      },
      fetch: async () => {
        fetches += 1;
        throw new Error('must not fetch');
      },
    })
  ).rejects.toThrow('Common email code target failed: capability');
  expect({ fetches, leases }).toEqual({ fetches: 0, leases: 0 });
});

test('delegates one active outer lease sequentially and rejects reentrancy and use after revoke', async () => {
  const lease = {
    toJSON: () => {
      throw new Error('private');
    },
  } as Phase2FixtureSecretLease;
  const fixture = {
    public: { allocationId: 'allocation' },
    status: {
      user: { id: 'user', username: 'username' },
      client: { id: 'app', redirectUri: 'http://localhost:3001/demo-app' },
      confidentialClient: { id: 'confidential', redirectUri: 'https://core.example/secondary' },
      resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read' },
    },
    withSecretLease: async () => {
      throw new Error('outer fixture must not be reacquired');
    },
  } as unknown as ProvisionedPhase2Fixture;
  const scope = createScopedEmailCodeFixture(fixture, lease, 'https://core.example/demo-app');
  expect(scope.fixture.status?.client.redirectUri).toBe('https://core.example/demo-app');
  await expect(scope.fixture.withSecretLease(async (value) => value === lease)).resolves.toBe(true);
  await expect(
    scope.fixture.withSecretLease(async () => scope.fixture.withSecretLease(async () => true))
  ).rejects.toThrow('Common email code target failed: lease');
  await expect(scope.fixture.withSecretLease(async () => true)).resolves.toBe(true);
  scope.revoke();
  await expect(scope.fixture.withSecretLease(async () => true)).rejects.toThrow(
    'Common email code target failed: lease'
  );
});

test.each([
  {
    name: 'wrong prompt',
    browser: { ...admittedBrowser, demo: { ...admittedBrowser.demo, prompt: 'login' } },
  },
  {
    name: 'duplicate scope',
    browser: {
      ...admittedBrowser,
      demo: { ...admittedBrowser.demo, scope: `${admittedBrowser.demo.scope} email` },
    },
  },
  {
    name: 'wrong initial scope',
    browser: { ...admittedBrowser, initialResponseScope: 'openid profile email' },
  },
])('rejects $name before discovery and lease use', async ({ browser }) => {
  let fetches = 0;
  let leases = 0;
  await expect(
    runCommonEmailCodeForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: admittedFixture(() => {
        leases += 1;
      }),
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser,
      fetch: async () => {
        fetches += 1;
        throw new Error('must not fetch');
      },
    })
  ).rejects.toThrow('Common email code target failed: admission');
  expect({ fetches, leases }).toEqual({ fetches: 0, leases: 0 });
});

test.each([
  { name: 'issuer user info', issuer: 'https://user:private@core.example/oidc', length: undefined },
  { name: 'negative length', issuer: 'https://core.example/oidc', length: '-1' },
  { name: 'non-numeric length', issuer: 'https://core.example/oidc', length: 'NaN' },
])('rejects $name during bounded discovery before lease use', async ({ issuer, length }) => {
  let leases = 0;
  await expect(
    runCommonEmailCodeForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: admittedFixture(() => {
        leases += 1;
      }),
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser: admittedBrowser,
      fetch: async () =>
        new Response(JSON.stringify({ issuer }), {
          status: 200,
          ...(length === undefined ? {} : { headers: { 'content-length': length } }),
        }),
    })
  ).rejects.toThrow('Common email code target failed: discovery');
  expect(leases).toBe(0);
});

test('cancels overflow discovery and releases the reader without leasing', async () => {
  let cancelled = false;
  let leases = 0;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(65_537));
    },
    cancel() {
      cancelled = true;
    },
  });
  await expect(
    runCommonEmailCodeForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: admittedFixture(() => {
        leases += 1;
      }),
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser: admittedBrowser,
      fetch: async () => new Response(stream, { status: 200 }),
    })
  ).rejects.toThrow('Common email code target failed: discovery');
  expect({ cancelled, locked: stream.locked, leases }).toEqual({
    cancelled: true,
    locked: false,
    leases: 0,
  });
});

test('maps a throwing discovery stream to the fixed stage and releases its reader', async () => {
  let leases = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull() {
      throw new Error('private transport detail');
    },
  });
  await expect(
    runCommonEmailCodeForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture: admittedFixture(() => {
        leases += 1;
      }),
      observer: { runInFreshContext: async () => null } as Phase1BrowserGroupObserver,
      signal: new AbortController().signal,
      browser: admittedBrowser,
      fetch: async () => new Response(stream, { status: 200 }),
    })
  ).rejects.toThrow('Common email code target failed: discovery');
  expect({ locked: stream.locked, leases }).toEqual({ locked: false, leases: 0 });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions */
