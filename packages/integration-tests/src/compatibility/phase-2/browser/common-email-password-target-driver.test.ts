/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function, unicorn/consistent-function-scoping -- Stateful closed fakes expose lease, transport, real observer rewriting, and fresh-context ordering. */
import type { Browser, BrowserContext, BrowserType } from '@playwright/test';

import type {
  Phase1BrowserGroupObserver,
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
} from '../../phase-1/browser/contracts.js';
import { createPlaywrightObserver } from '../../phase-1/browser/playwright-observer.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  preserveCommonEmailPasswordContextStage,
  runCommonEmailPasswordForTarget,
  runCommonEmailPasswordForTargetTesting,
  withCandidateEmailPasswordStageLatch,
} from './common-email-password-target-driver.js';

test('restores a known candidate consumer stage only after its lease closes', async () => {
  let active = false;
  const lease = {} as never;
  await expect(
    withCandidateEmailPasswordStageLatch(
      async (use) => {
        active = true;
        try {
          return await use('bounded-bearer', lease);
        } catch {
          throw new Error('Invalid Phase 2 Admin Management bearer flow (consumer)');
        } finally {
          active = false;
        }
      },
      async () => {
        expect(active).toBe(true);
        throw new TypeError('Common email password stage failed: controls-username');
      }
    )
  ).rejects.toThrow('Common email password stage failed: controls-username');
  expect(active).toBe(false);
});

test('does not preserve an unknown candidate consumer error', async () => {
  await expect(
    withCandidateEmailPasswordStageLatch(
      async (use) => {
        try {
          return await use('bounded-bearer', {} as never);
        } catch {
          throw new Error('Invalid Phase 2 Admin Management bearer flow (consumer)');
        }
      },
      async () => {
        throw new Error('private consumer detail');
      }
    )
  ).rejects.toThrow('Invalid Phase 2 Admin Management bearer flow (consumer)');
});

test.each([false, true])(
  'restores a latched stage after the real observer rewrites callback error (cleanup=%s)',
  async (cleanupFails) => {
    const latched = new TypeError(
      'Common email password fixture failed: primary-use;cleanup-none;flow-credentials'
    );
    const events: string[] = [];
    const context = {
      close: async () => {
        events.push('context-close');
        if (cleanupFails) {
          throw new Error('private cleanup detail');
        }
      },
    } as unknown as BrowserContext;
    const browser = {
      newContext: async () => {
        events.push('context-open');
        return context;
      },
      close: async () => {
        events.push('browser-close');
      },
    } as unknown as Browser;
    const browserType = {
      launch: async () => {
        events.push('browser-launch');
        return browser;
      },
    } as Pick<BrowserType<Browser>, 'launch'>;
    const observer = createPlaywrightObserver({
      scenarioId: 'browser.experience',
      browserType,
    });
    let observerError: unknown;
    try {
      await observer.withContext('experience', async () => {
        events.push('callback');
        throw new Error('private body detail');
      });
    } catch (error: unknown) {
      observerError = error;
    }
    expect(events).toEqual([
      'browser-launch',
      'context-open',
      'callback',
      'context-close',
      'browser-close',
    ]);
    expect(() => preserveCommonEmailPasswordContextStage(latched, observerError)).toThrow(
      cleanupFails ? 'Common email password target failed: context-cleanup' : latched.message
    );
  }
);

const fixture = {
  public: { allocationId: 'allocation' },
  status: {
    user: { id: 'baseline-user', username: 'baseline-name' },
    client: { id: 'browser-app', redirectUri: 'https://core.example/demo-app' },
    confidentialClient: { id: 'confidential', redirectUri: 'https://core.example/confidential' },
    resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
  },
  withSecretLease: async () => {
    throw new Error('lease must not open');
  },
} as unknown as ProvisionedPhase2Fixture;

const observer: Phase1BrowserGroupObserver = {
  runInFreshContext: async () => {
    throw new Error('browser must not open');
  },
};

const browser = {
  storageKey: 'config',
  demo: {
    appId: 'browser-app',
    prompt: 'consent',
    scope: 'openid profile offline_access email read:profile',
    resource: 'https://api.example',
  },
  redirectUri: 'https://core.example/demo-app',
  initialResponseScope: 'openid offline_access profile email',
  resourceScope: 'read:profile',
} as const;

test('production entrypoint rejects a structural observer before fetch, lease, or browser use', async () => {
  let fetches = 0;
  await expect(
    runCommonEmailPasswordForTarget({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture,
      observer,
      signal: new AbortController().signal,
      browser,
      fetch: async () => {
        fetches += 1;
        throw new Error('fetch must not run');
      },
    })
  ).rejects.toThrow('Common email password target failed: capability');
  expect(fetches).toBe(0);
});

test('test executor rejects browser metadata that is not bound to the provisioned fixture', async () => {
  let fetches = 0;
  await expect(
    runCommonEmailPasswordForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture,
      observer,
      signal: new AbortController().signal,
      browser: { ...browser, demo: { ...browser.demo, appId: 'foreign-app' } },
      fetch: async () => {
        fetches += 1;
        throw new Error('fetch must not run');
      },
    })
  ).rejects.toThrow('Common email password target failed: admission');
  expect(fetches).toBe(0);
});

test('rejects a discovery issuer from a foreign target before opening a lease or browser', async () => {
  await expect(
    runCommonEmailPasswordForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture,
      observer,
      signal: new AbortController().signal,
      browser,
      fetch: async () =>
        new Response(JSON.stringify({ issuer: 'https://foreign.example/oidc' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    })
  ).rejects.toThrow('Common email password target failed: discovery');
});

test('stream-cancels oversized discovery before opening a lease or browser', async () => {
  let cancelled = false;
  const oversized = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(64 * 1024 + 1));
    },
    cancel() {
      cancelled = true;
    },
  });
  await expect(
    runCommonEmailPasswordForTargetTesting({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      fixture,
      observer,
      signal: new AbortController().signal,
      browser,
      fetch: async () => new Response(oversized, { status: 200 }),
    })
  ).rejects.toThrow('Common email password target failed: discovery');
  expect(cancelled).toBe(true);
});

test('binds reference Management, one active lease, and four fresh browser contexts', async () => {
  const calls: string[] = [];
  let methods: unknown = [{ identifier: 'username' }];
  let branding: unknown = {};
  let applicationMetadata = {
    redirectUris: ['http://localhost:3001/demo-app'],
    postLogoutRedirectUris: [] as string[],
  };
  let leaseActive = false;
  const boundFixture = {
    ...fixture,
    withSecretLease: async <Result>(
      use: (lease: {
        getSelectedEmailPassword(): string;
        getInvalidEmailPassword(): string;
        getSubjectPassword(): string;
        toJSON(): never;
      }) => Promise<Result>
    ) => {
      if (leaseActive) {
        throw new Error('nested lease');
      }
      leaseActive = true;
      try {
        return await use({
          getSelectedEmailPassword: () => (leaseActive ? 'selected-secret' : ''),
          getInvalidEmailPassword: () => (leaseActive ? 'independent-wrong-secret' : ''),
          getSubjectPassword: () => (leaseActive ? 'baseline-secret' : ''),
          toJSON: () => {
            throw new TypeError('private');
          },
        });
      } finally {
        leaseActive = false;
      }
    },
  } as unknown as ProvisionedPhase2Fixture;
  const requestFetch: typeof fetch = async (request, init) => {
    const url = new URL(
      typeof request === 'string' ? request : request instanceof URL ? request : request.url
    );
    calls.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (url.pathname === '/oidc/.well-known/openid-configuration') {
      return new Response(JSON.stringify({ issuer: 'https://core.example/oidc' }), { status: 200 });
    }
    const body =
      init?.body && typeof init.body === 'string'
        ? (JSON.parse(init.body) as Record<string, unknown>)
        : undefined;
    if (url.pathname === '/api/applications/browser-app' && init?.method === 'GET') {
      return new Response(
        JSON.stringify({ id: 'browser-app', type: 'SPA', oidcClientMetadata: applicationMetadata }),
        { status: 200 }
      );
    }
    if (url.pathname === '/api/applications/browser-app') {
      applicationMetadata = (body as { oidcClientMetadata: typeof applicationMetadata })
        .oidcClientMetadata;
      return new Response(
        JSON.stringify({ id: 'browser-app', type: 'SPA', oidcClientMetadata: applicationMetadata }),
        { status: 200 }
      );
    }
    if (url.pathname === '/api/sign-in-exp' && init?.method === 'GET') {
      return new Response(JSON.stringify({ signIn: { methods }, branding }), { status: 200 });
    }
    if (url.pathname === '/api/sign-in-exp') {
      methods = (body as { signIn: { methods: unknown } }).signIn.methods;
      branding = (body as { branding: unknown }).branding;
      return new Response(JSON.stringify({ signIn: { methods }, branding }), { status: 200 });
    }
    if (url.pathname === '/api/resources' && url.searchParams.get('includeScopes') === 'true') {
      return new Response(
        JSON.stringify([{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }]),
        { status: 200 }
      );
    }
    if (url.pathname === '/api/roles' && init?.method === 'POST') {
      return new Response(
        JSON.stringify({
          id: 'email-role',
          name: 'common-email-allocation',
          type: 'User',
          isDefault: false,
        }),
        { status: 200 }
      );
    }
    if (url.pathname === '/api/roles/email-role/scopes') {
      return new Response(
        JSON.stringify([{ id: 'scope', name: 'read:profile', resourceId: 'resource' }]),
        { status: 200 }
      );
    }
    if (url.pathname === '/api/roles/email-role/users') {
      return new Response(null, { status: 201 });
    }
    if (url.pathname === '/api/users/email-user/roles') {
      return new Response(JSON.stringify([{ id: 'email-role', type: 'User' }]), { status: 200 });
    }
    if (url.pathname === '/api/users' && init?.method === 'POST') {
      return new Response(
        JSON.stringify({
          id: 'email-user',
          primaryEmail: 'common-email-allocation@example.invalid',
          hasPassword: true,
          isSuspended: false,
        }),
        { status: 200 }
      );
    }
    if (url.pathname === '/api/users/email-user/is-suspended') {
      return new Response(JSON.stringify({ id: 'email-user', isSuspended: body?.isSuspended }), {
        status: 200,
      });
    }
    return new Response(null, { status: 204 });
  };
  const initial = (subject: string): Phase1BrowserNetworkFacts => ({
    signIns: [
      {
        authority: 'core',
        status: 303,
        queryShapeExact: true,
        clientId: 'browser-app',
        redirectUri: 'https://core.example/demo-app',
        responseType: 'code',
        prompt: 'consent',
        scope: 'openid profile offline_access email read:profile',
        resources: ['https://api.example'],
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
        issuer: 'https://core.example/oidc',
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
        clientId: 'browser-app',
        redirectUri: 'https://core.example/demo-app',
        initialRefreshPresent: true,
        replacementFresh: true,
        resource: null,
        organizationId: null,
        responseScope: 'openid offline_access profile email',
        accessKind: 'opaque',
      },
    ],
    endpointDiscoveries: [],
    accountReads: [],
    applicationReads: [],
    userReads: [],
  });
  let contexts = 0;
  const liveObserver: Phase1BrowserGroupObserver = {
    runInFreshContext: async (_group, _signal, _target, use) => {
      contexts += 1;
      const contextId = contexts;
      let reads = 0;
      const subject = contextId === 1 ? 'email-user' : 'baseline-user';
      const first = initial(subject);
      const refreshed: Phase1BrowserNetworkFacts = {
        ...first,
        exchanges: [
          ...first.exchanges,
          {
            kind: 'management',
            authority: 'core',
            status: 200,
            requestShapeExact: true,
            requestCorrelationValid: true,
            clientId: 'browser-app',
            redirectUri: null,
            initialRefreshPresent: false,
            replacementFresh: true,
            resource: 'https://api.example',
            organizationId: null,
            responseScope: 'read:profile',
            accessKind: 'compact',
            compactAccess: {
              issuer: 'https://core.example/oidc',
              subject: 'email-user',
              audience: 'https://api.example',
              clientId: 'browser-app',
              scope: 'read:profile',
              organizationIdPresent: false,
            },
          },
        ],
      };
      const session = {
        preloadDemoConfiguration: async () => {},
        navigate: async () => {},
        waitForRoute: async () => {},
        waitForExactRoute: async () => {},
        assertRoute: async () => {},
        assertExactRoute: async () => {},
        fill: async () => {},
        click: async () => {},
        expectText: async () => {},
        expectCount: async () => {},
        waitForNetworkFacts: async () => (contextId === 1 && reads++ >= 2 ? refreshed : first),
        clickAndObserveObject: async (
          _step: string,
          _selector: string,
          project: (body: Record<string, unknown>) => Record<string, unknown>
        ) =>
          project({
            sub: subject,
            email:
              contextId === 1
                ? 'common-email-allocation@example.invalid'
                : 'baseline@example.invalid',
            email_verified: true,
          }),
      } as Phase1BrowserSession;
      return use(session);
    },
  };
  const result = await runCommonEmailPasswordForTargetTesting({
    target: { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
    fixture: boundFixture,
    observer: liveObserver,
    signal: new AbortController().signal,
    browser,
    fetch: requestFetch,
  });
  expect(result).toMatchObject({
    identifier: 'email',
    usernamePreserved: true,
    refreshRotated: true,
  });
  expect(contexts).toBe(4);
  expect(calls.filter((call) => call === 'PATCH /api/users/email-user/is-suspended')).toHaveLength(
    2
  );
  expect(calls).toContain('DELETE /api/users/email-user');
  expect(applicationMetadata.redirectUris).toEqual(['http://localhost:3001/demo-app']);
  expect(leaseActive).toBe(false);
});
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function, unicorn/consistent-function-scoping */
