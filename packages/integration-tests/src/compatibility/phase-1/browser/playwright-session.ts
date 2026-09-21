/* eslint-disable complexity, max-lines, max-params, no-restricted-syntax, no-control-regex, no-await-in-loop, promise/prefer-await-to-then, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/no-throw-literal, unicorn/no-array-callback-reference, unicorn/no-await-expression-member, unicorn/no-useless-spread, prefer-destructuring -- The adapter owns raw Playwright pages, response bodies, credential-bearing request fields, sequential listener drainage, and fixed diagnostics; browser flows receive only closed safe facts. */
import { createHash } from 'node:crypto';

import type { Browser, BrowserContext, BrowserType, Page, Response } from '@playwright/test';
import { decodeJwt } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { JsonObject } from '../../normalize.js';

import type {
  Phase1BrowserAccountFact,
  Phase1BrowserApplicationReadFact,
  Phase1BrowserAuthority,
  Phase1BrowserCallbackFact,
  Phase1BrowserCompactAccess,
  Phase1BrowserEndpoint,
  Phase1BrowserEndpointDiscoveryFact,
  Phase1BrowserExchangeFact,
  Phase1BrowserGroupId,
  Phase1BrowserGroupObserver,
  Phase1BrowserNetworkFacts,
  Phase1BrowserSession,
  Phase1BrowserSignInFact,
  Phase1BrowserUserReadFact,
  Phase1LastSignInState,
  Phase1ProfiledDemoConfiguration,
} from './contracts.js';
import { createPlaywrightObserver, type PlaywrightFailureContext } from './playwright-observer.js';

const networkWaitAttempts = 200;
const networkWaitIntervalMs = 25;
const maximumSafeTextLength = 4096;
const base64UrlPattern = /^[A-Za-z0-9_-]+$/u;
const browserGroupObserverCapabilities = new WeakSet<object>();

type ContextNetworkGuard = Readonly<{
  hasViolation(): boolean;
  watchPrimaryPage(page: Page): void;
  close(): void;
}>;

const fixedContext = (stepId: string, errorClass: PlaywrightFailureContext['errorClass']) =>
  Object.freeze({
    stepId,
    errorClass,
    projectionPointer: `/steps/${stepId}/value`,
  } satisfies PlaywrightFailureContext);

const safeTextAllowEmpty = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length > maximumSafeTextLength ||
    /[\u0000-\u001F\u007F]/u.test(value)
  ) {
    throw new TypeError('Invalid browser network observation');
  }

  return value;
};

const safeText = (value: unknown): string => {
  const result = safeTextAllowEmpty(value);

  if (result.length === 0) {
    throw new TypeError('Invalid browser network observation');
  }

  return result;
};

const safeOptionalText = (value: unknown): string | null =>
  value === undefined || value === null ? null : safeText(value);

const safeStatus = (value: number): number => {
  if (!Number.isSafeInteger(value) || value < 100 || value > 599) {
    throw new TypeError('Invalid browser network observation');
  }

  return value;
};

const record = (value: unknown): Readonly<Record<string, unknown>> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('Invalid browser network observation');
  }

  return value as Readonly<Record<string, unknown>>;
};

const list = (value: unknown): readonly unknown[] => {
  if (!Array.isArray(value) || value.length > 256) {
    throw new TypeError('Invalid browser network observation');
  }

  return value;
};

const safeTotal = (value: string | undefined): number => {
  if (!value || !/^(?:0|[1-9]\d*)$/u.test(value)) {
    throw new TypeError('Invalid browser network observation');
  }
  const total = Number(value);

  if (!Number.isSafeInteger(total)) {
    throw new TypeError('Invalid browser network observation');
  }

  return total;
};

const endpointUrl = (target: TargetConfig, endpoint: Phase1BrowserEndpoint): URL =>
  new URL(endpoint === 'core' ? target.coreUrl : target.adminUrl);

const absoluteProfiledUrl = (
  target: TargetConfig,
  endpoint: Phase1BrowserEndpoint,
  path: string
): URL => {
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new TypeError('Invalid browser route');
  }
  const base = endpointUrl(target, endpoint);
  const url = new URL(path, base);

  if (url.origin !== base.origin || url.username || url.password) {
    throw new TypeError('Invalid browser route');
  }

  return url;
};

const authorityFor = (target: TargetConfig, url: URL): Phase1BrowserAuthority => {
  if (url.origin === new URL(target.adminUrl).origin) {
    return 'admin';
  }
  if (url.origin === new URL(target.coreUrl).origin) {
    return 'core';
  }

  throw new TypeError('Invalid browser network observation');
};

const exactEntries = (
  parameters: URLSearchParams,
  expected: ReadonlyArray<readonly [string, string]>
): boolean => {
  const actual = [...parameters.entries()];

  return (
    actual.length === expected.length &&
    actual.every(
      ([key, value], index) => key === expected[index]?.[0] && value === expected[index]?.[1]
    )
  );
};

const exactKeys = (parameters: URLSearchParams, expected: readonly string[]): boolean => {
  const actual = [...parameters.keys()];

  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};

const suppressedPassiveExternalGetUrls = new Set(['https://numbers.logto.io/pull.json']);

const matchesBase64UrlLength = (value: string | null, length: number): boolean =>
  value?.length === length && base64UrlPattern.test(value);

const installContextNetworkGuard = async (
  observer: Observer,
  context: BrowserContext,
  target: TargetConfig,
  groupId: Phase1BrowserGroupId
): Promise<ContextNetworkGuard> => {
  const allowedOrigins = new Set([new URL(target.coreUrl).origin, new URL(target.adminUrl).origin]);
  let violated = false;
  let primaryPage: Page | undefined;
  const reject = () => {
    violated = true;
  };
  const onPage = (page: Page) => {
    if (primaryPage && page !== primaryPage) {
      reject();
      void page.close().catch(() => null);
    }
  };

  await observer.run(fixedContext('origin-guard', 'evaluation'), async () => {
    await context.route('**/*', async (route) => {
      try {
        const url = new URL(route.request().url());

        if (allowedOrigins.has(url.origin) || ['data:', 'blob:'].includes(url.protocol)) {
          await route.continue();
          return;
        }
        if (
          groupId === 'console' &&
          route.request().method() === 'GET' &&
          suppressedPassiveExternalGetUrls.has(url.href)
        ) {
          // The OSS Console performs a passive version check. Abort it deterministically without
          // granting external network authority or failing the business-flow network boundary.
          await route.abort('blockedbyclient');
          return;
        }
      } catch {
        // The request is rejected below with the same closed guard state.
      }
      reject();
      await route.abort('blockedbyclient');
    });
    await context.routeWebSocket('**/*', async (webSocket) => {
      reject();
      await webSocket.close({ code: 1008 });
    });
  });

  return Object.freeze({
    hasViolation: () => violated,
    watchPrimaryPage: (page: Page) => {
      if (
        primaryPage !== undefined ||
        context.pages().length !== 1 ||
        context.pages()[0] !== page
      ) {
        reject();
        throw new Error('Browser context page boundary failed');
      }
      primaryPage = page;
      context.on('page', onPage);
    },
    close: () => {
      context.removeListener('page', onPage);
    },
  });
};

const claimsProjection = (value: string): Phase1BrowserCompactAccess | undefined => {
  try {
    const claims = decodeJwt(value);
    const issuer = safeText(claims.iss);
    const subject = safeText(claims.sub);
    const clientId = safeText(claims.client_id);
    const scope = safeTextAllowEmpty(claims.scope ?? '');
    const audience = Array.isArray(claims.aud)
      ? Object.freeze(claims.aud.map(safeText))
      : safeText(claims.aud);

    return Object.freeze({
      issuer,
      subject,
      audience,
      clientId,
      scope,
      organizationIdPresent: Object.hasOwn(claims, 'organization_id'),
    });
  } catch {
    return undefined;
  }
};

const applicationRows = (value: unknown) =>
  Object.freeze(
    list(value).map((candidate) => {
      const row = record(candidate);

      return Object.freeze({ id: safeText(row.id), name: safeText(row.name) });
    })
  );

const userRows = (value: unknown) =>
  Object.freeze(
    list(value).map((candidate) => {
      const row = record(candidate);
      const lastSignInAt = row.lastSignInAt;
      const lastSignInState: Phase1LastSignInState =
        lastSignInAt === null
          ? 'never'
          : typeof lastSignInAt === 'number' &&
              Number.isSafeInteger(lastSignInAt) &&
              lastSignInAt > 0
            ? 'present'
            : (() => {
                throw new TypeError('Invalid browser network observation');
              })();

      return Object.freeze({
        id: safeText(row.id),
        name: safeOptionalText(row.name),
        username: safeOptionalText(row.username),
        primaryEmail: safeOptionalText(row.primaryEmail),
        lastSignInState,
      });
    })
  );

type Observer = ReturnType<typeof createPlaywrightObserver>;

class PlaywrightBrowserSession implements Phase1BrowserSession {
  readonly #observer: Observer;
  readonly #page: Page;
  readonly #target: TargetConfig;
  readonly #signal: AbortSignal;
  readonly #networkGuard: ContextNetworkGuard;
  readonly #signIns: Phase1BrowserSignInFact[] = [];
  readonly #callbacks: Phase1BrowserCallbackFact[] = [];
  readonly #endpointDiscoveries: Phase1BrowserEndpointDiscoveryFact[] = [];
  readonly #exchanges: Phase1BrowserExchangeFact[] = [];
  readonly #accountReads: Phase1BrowserAccountFact[] = [];
  readonly #applicationReads: Phase1BrowserApplicationReadFact[] = [];
  readonly #userReads: Phase1BrowserUserReadFact[] = [];
  readonly #pending = new Set<Promise<void>>();
  readonly #refreshLineage = new Set<string>();
  readonly #issuedCredentials = new Set<string>();
  #authorizationState: string | undefined;
  #authorizationChallenge: string | undefined;
  #callbackCode: string | undefined;
  #initialAccess: string | undefined;
  #managementAccess: string | undefined;
  #networkFailed = false;
  #closed = false;

  constructor(
    observer: Observer,
    page: Page,
    target: TargetConfig,
    signal: AbortSignal,
    networkGuard: ContextNetworkGuard
  ) {
    this.#observer = observer;
    this.#page = page;
    this.#target = target;
    this.#signal = signal;
    this.#networkGuard = networkGuard;
    this.#page.on('response', this.#onResponse);
  }

  async preloadDemoConfiguration(
    stepId: string,
    storageKey: string,
    value: Phase1ProfiledDemoConfiguration
  ): Promise<void> {
    const key = safeText(storageKey);
    const configuration = Object.freeze({
      appId: safeText(value.appId),
      prompt: safeText(value.prompt),
      scope: safeText(value.scope),
      resource: safeText(value.resource),
    });

    await this.#observer.run(fixedContext(stepId, 'evaluation'), async () => {
      await this.#page.addInitScript(
        ({ key, configuration }) => {
          localStorage.setItem(key, JSON.stringify(configuration));
        },
        { key, configuration }
      );
    });
  }

  async navigate(stepId: string, endpoint: Phase1BrowserEndpoint, path: string): Promise<void> {
    const url = absoluteProfiledUrl(this.#target, endpoint, path);
    await this.#observer.navigate(this.#page, stepId, url.href, `/steps/${stepId}/value`);
  }

  async waitForRoute(
    stepId: string,
    endpoint: Phase1BrowserEndpoint,
    paths: readonly string[]
  ): Promise<void> {
    const origin = endpointUrl(this.#target, endpoint).origin;
    const allowed = new Set(
      paths.map((path) => absoluteProfiledUrl(this.#target, endpoint, path).pathname)
    );

    await this.#observer.run(fixedContext(stepId, 'navigation'), async () => {
      await this.#page.waitForURL((url) => url.origin === origin && allowed.has(url.pathname), {
        waitUntil: 'load',
      });
    });
  }

  async waitForExactRoute(
    stepId: string,
    endpoint: Phase1BrowserEndpoint,
    path: string
  ): Promise<void> {
    const expected = absoluteProfiledUrl(this.#target, endpoint, path);

    await this.#observer.run(fixedContext(stepId, 'navigation'), async () => {
      await this.#page.waitForURL((url) => url.href === expected.href, { waitUntil: 'load' });
    });
  }

  async assertRoute(
    stepId: string,
    endpoint: Phase1BrowserEndpoint,
    paths: readonly string[]
  ): Promise<void> {
    const origin = endpointUrl(this.#target, endpoint).origin;
    const allowed = new Set(
      paths.map((path) => absoluteProfiledUrl(this.#target, endpoint, path).pathname)
    );

    await this.#observer.run(fixedContext(stepId, 'evaluation'), async () => {
      const current = new URL(this.#page.url());

      if (current.origin !== origin || !allowed.has(current.pathname)) {
        throw new Error('Unexpected browser route');
      }
    });
  }

  async assertExactRoute(
    stepId: string,
    endpoint: Phase1BrowserEndpoint,
    path: string
  ): Promise<void> {
    const expected = absoluteProfiledUrl(this.#target, endpoint, path);

    await this.#observer.run(fixedContext(stepId, 'evaluation'), async () => {
      if (this.#page.url() !== expected.href) {
        throw new Error('Unexpected browser route');
      }
    });
  }

  async fill(
    stepId: string,
    selector: string,
    value: string,
    route: Readonly<{ endpoint: Phase1BrowserEndpoint; paths: readonly string[] }>
  ): Promise<void> {
    await this.assertRoute(stepId, route.endpoint, route.paths);
    await this.#observer.locate(
      this.#page,
      stepId,
      selector,
      `/steps/${stepId}/value`,
      async (locator) => locator.fill(value)
    );
  }

  async click(
    stepId: string,
    selector: string,
    route?: Readonly<{ endpoint: Phase1BrowserEndpoint; paths: readonly string[] }>
  ): Promise<void> {
    if (route) {
      await this.assertRoute(stepId, route.endpoint, route.paths);
    }
    await this.#observer.locate(
      this.#page,
      stepId,
      selector,
      `/steps/${stepId}/value`,
      async (locator) => locator.click()
    );
  }

  async expectText(stepId: string, selector: string, expected: string): Promise<void> {
    const value = safeText(expected);
    await this.#observer.locate(
      this.#page,
      stepId,
      selector,
      `/steps/${stepId}/value`,
      async (locator) => {
        const observed = (await locator.textContent())?.trim();

        if (observed !== value) {
          throw new Error('Unexpected browser text');
        }
      }
    );
  }

  async expectCount(stepId: string, selector: string, expected: number): Promise<void> {
    if (!Number.isSafeInteger(expected) || expected < 0) {
      throw new TypeError('Invalid browser count');
    }
    await this.#observer.locate(
      this.#page,
      stepId,
      selector,
      `/steps/${stepId}/value`,
      async (locator) => {
        if (expected > 0) {
          await locator.first().waitFor({ state: 'visible' });
        }
        if ((await locator.count()) !== expected) {
          throw new Error('Unexpected browser count');
        }
      }
    );
  }

  async clickAndObserveObject<Projection extends JsonObject>(
    stepId: string,
    selector: string,
    project: (value: JsonObject) => Projection
  ): Promise<Readonly<Projection>> {
    return this.#observer.observeConsoleProjection(
      this.#page,
      stepId,
      `/steps/${stepId}/value`,
      project,
      async () => {
        await this.#page.locator(selector).click();
      }
    );
  }

  async waitForNetworkFacts(
    stepId: string,
    accept: (facts: Phase1BrowserNetworkFacts) => boolean
  ): Promise<Phase1BrowserNetworkFacts> {
    return this.#observer.run(fixedContext(stepId, 'evaluation'), async () => {
      for (let attempt = 0; attempt < networkWaitAttempts; attempt += 1) {
        if (this.#signal.aborted || this.#networkFailed || this.#networkGuard.hasViolation()) {
          throw new Error('Browser network observation failed');
        }
        await Promise.all([...this.#pending]);
        const facts = this.#snapshotFacts();

        if (accept(facts)) {
          return facts;
        }
        await new Promise<void>((resolve) => {
          setTimeout(resolve, networkWaitIntervalMs);
        });
      }

      throw new Error('Browser network observation timed out');
    });
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#page.removeListener('response', this.#onResponse);
    await Promise.all([...this.#pending]);
    if (this.#networkFailed || this.#networkGuard.hasViolation()) {
      throw new Error('Browser network observation failed');
    }
    await this.#observer.run(fixedContext('session-cleanup', 'evaluation'), async () => {
      await this.#page.close();
    });
    if (this.#networkGuard.hasViolation()) {
      throw new Error('Browser network observation failed');
    }
    this.#networkGuard.close();
  }

  #snapshotFacts(): Phase1BrowserNetworkFacts {
    return Object.freeze({
      signIns: Object.freeze([...this.#signIns]),
      callbacks: Object.freeze([...this.#callbacks]),
      endpointDiscoveries: Object.freeze([...this.#endpointDiscoveries]),
      exchanges: Object.freeze([...this.#exchanges]),
      accountReads: Object.freeze([...this.#accountReads]),
      applicationReads: Object.freeze([...this.#applicationReads]),
      userReads: Object.freeze([...this.#userReads]),
    });
  }

  readonly #onResponse = (response: Response) => {
    const prior = Promise.all(this.#pending);
    const pending = prior
      .then(async () => this.#observeResponse(response))
      .catch(() => {
        this.#networkFailed = true;
      })
      .finally(() => {
        this.#pending.delete(pending);
      });
    this.#pending.add(pending);
  };

  async #observeResponse(response: Response): Promise<void> {
    const url = new URL(response.url());

    if (
      ![new URL(this.#target.coreUrl).origin, new URL(this.#target.adminUrl).origin].includes(
        url.origin
      )
    ) {
      return;
    }
    const request = response.request();
    const method = request.method().toUpperCase();
    const authority = authorityFor(this.#target, url);

    if (url.pathname === '/oidc/auth') {
      if (method !== 'GET') {
        throw new TypeError('Invalid browser network observation');
      }
      const state = url.searchParams.get('state');
      const challenge = url.searchParams.get('code_challenge');
      const resources = url.searchParams.getAll('resource');
      const stateFormatValid = matchesBase64UrlLength(state, 86);
      const challengeFormatValid = matchesBase64UrlLength(challenge, 43);

      if (stateFormatValid && state) {
        this.#authorizationState = state;
      }
      if (challengeFormatValid && challenge) {
        this.#authorizationChallenge = challenge;
      }
      this.#signIns.push(
        Object.freeze({
          authority,
          status: safeStatus(response.status()),
          queryShapeExact: exactKeys(url.searchParams, [
            'client_id',
            'redirect_uri',
            'code_challenge',
            'code_challenge_method',
            'state',
            'response_type',
            'prompt',
            'scope',
            ...resources.map(() => 'resource'),
          ]),
          clientId: safeOptionalText(url.searchParams.get('client_id')),
          redirectUri: safeOptionalText(url.searchParams.get('redirect_uri')),
          responseType: safeOptionalText(url.searchParams.get('response_type')),
          prompt: safeOptionalText(url.searchParams.get('prompt')),
          scope: safeOptionalText(url.searchParams.get('scope')),
          resources: Object.freeze(resources.map(safeText)),
          pkceMethod: safeOptionalText(url.searchParams.get('code_challenge_method')),
          stateFormatValid,
          challengeFormatValid,
        })
      );
      return;
    }
    if (
      (url.pathname === '/console/callback' || url.pathname === '/demo-app') &&
      ['code', 'state', 'iss'].some((key) => url.searchParams.has(key))
    ) {
      if (method !== 'GET') {
        throw new TypeError('Invalid browser network observation');
      }
      const code = url.searchParams.get('code');

      if (code) {
        this.#callbackCode = safeText(code);
      }
      this.#callbacks.push(
        Object.freeze({
          authority,
          path: url.pathname,
          status: safeStatus(response.status()),
          queryShapeExact: exactKeys(url.searchParams, ['code', 'state', 'iss']),
          stateMatches: Boolean(
            this.#authorizationState && url.searchParams.get('state') === this.#authorizationState
          ),
          issuer: safeOptionalText(url.searchParams.get('iss')),
          codePresent: Boolean(code),
          fragmentEmpty: url.hash === '',
        })
      );
      return;
    }
    if (url.pathname === '/api/.well-known/endpoints/default') {
      if (method !== 'GET') {
        throw new TypeError('Invalid browser network observation');
      }
      const body = record(await response.json());
      const user = new URL(safeText(body.user));
      const access = await request.headerValue('authorization');

      this.#endpointDiscoveries.push(
        Object.freeze({
          authority,
          status: safeStatus(response.status()),
          queryShapeExact: [...url.searchParams].length === 0 && url.hash === '',
          accessAbsent: access === null,
          userOriginMatchesCore: user.href === new URL(this.#target.coreUrl).href,
        })
      );
      return;
    }
    if (url.pathname === '/oidc/token') {
      if (method !== 'POST') {
        throw new TypeError('Invalid browser network observation');
      }
      const form = new URLSearchParams(request.postData() ?? '');
      const grantType = form.get('grant_type');
      const resource = form.get('resource');
      const organizationId = form.get('organization_id');
      const body = record(await response.json());
      const access = typeof body.access_token === 'string' ? body.access_token : undefined;
      const id = typeof body.id_token === 'string' ? safeText(body.id_token) : undefined;
      const compactAccess = access?.split('.').length === 3 ? claimsProjection(access) : undefined;
      const accessKind = access ? (compactAccess ? 'compact' : 'opaque') : 'missing';
      const kind =
        grantType === 'authorization_code'
          ? 'initial'
          : grantType === 'refresh_token' && organizationId
            ? 'organization'
            : grantType === 'refresh_token' && resource
              ? 'management'
              : 'other';
      const contentType = await request.headerValue('content-type');
      const commonShape =
        authority === (this.#signIns[0]?.authority ?? authority) &&
        url.search === '' &&
        url.hash === '' &&
        contentType?.split(';', 1)[0]?.trim().toLowerCase() === 'application/x-www-form-urlencoded';
      const requestShapeExact =
        commonShape &&
        (kind === 'initial'
          ? exactKeys(form, ['client_id', 'code', 'code_verifier', 'redirect_uri', 'grant_type'])
          : kind === 'management'
            ? exactKeys(form, ['client_id', 'refresh_token', 'grant_type', 'resource'])
            : kind === 'organization'
              ? exactKeys(form, ['client_id', 'refresh_token', 'grant_type', 'organization_id'])
              : false);
      const responseRefresh =
        typeof body.refresh_token === 'string' ? safeText(body.refresh_token) : undefined;
      const requestRefresh = form.get('refresh_token');
      const verifier = form.get('code_verifier');
      const replacementFresh = Boolean(
        responseRefresh &&
          responseRefresh !== access &&
          responseRefresh !== id &&
          !this.#issuedCredentials.has(responseRefresh)
      );
      const requestCorrelationValid =
        kind === 'initial'
          ? Boolean(
              this.#callbackCode &&
                form.get('code') === this.#callbackCode &&
                this.#authorizationChallenge &&
                verifier &&
                createHash('sha256').update(verifier).digest('base64url') ===
                  this.#authorizationChallenge
            )
          : Boolean(requestRefresh && this.#refreshLineage.has(requestRefresh));

      if (kind === 'initial') {
        if (access) {
          this.#initialAccess = access;
        }
        if (responseRefresh && replacementFresh) {
          this.#refreshLineage.add(responseRefresh);
        }
      } else if (responseRefresh && replacementFresh && requestCorrelationValid) {
        this.#refreshLineage.add(responseRefresh);
      }
      for (const credential of [access, id, responseRefresh]) {
        if (credential) {
          this.#issuedCredentials.add(credential);
        }
      }
      if (kind === 'management' && access) {
        this.#managementAccess = access;
      }
      this.#exchanges.push(
        Object.freeze({
          kind,
          authority,
          status: safeStatus(response.status()),
          requestShapeExact,
          requestCorrelationValid,
          clientId: safeOptionalText(form.get('client_id')),
          redirectUri: safeOptionalText(form.get('redirect_uri')),
          initialRefreshPresent: kind === 'initial' && Boolean(responseRefresh),
          replacementFresh,
          resource: safeOptionalText(resource),
          organizationId: safeOptionalText(organizationId),
          responseScope:
            body.scope === undefined || body.scope === null ? null : safeTextAllowEmpty(body.scope),
          accessKind,
          ...(compactAccess ? { compactAccess } : {}),
        })
      );
      return;
    }
    if (url.pathname === '/api/my-account/') {
      if (method !== 'GET') {
        throw new TypeError('Invalid browser network observation');
      }
      const body = record(await response.json());
      const header = await request.headerValue('authorization');
      this.#accountReads.push(
        Object.freeze({
          authority,
          status: safeStatus(response.status()),
          queryShapeExact: [...url.searchParams].length === 0 && url.hash === '',
          accessMatchesInitial: Boolean(
            this.#initialAccess && header === `Bearer ${this.#initialAccess}`
          ),
          id: safeText(body.id),
          username: safeText(body.username),
          primaryEmail: safeText(body.primaryEmail),
        })
      );
      return;
    }
    if (url.pathname === '/api/applications') {
      if (method !== 'GET') {
        throw new TypeError('Invalid browser network observation');
      }
      const isSamlProbe = url.searchParams.get('types') === 'SAML';
      const isThirdParty = url.searchParams.get('isThirdParty') === 'true';
      const expectedEntries = isSamlProbe
        ? ([
            ['page', '1'],
            ['page_size', '1'],
            ['isThirdParty', 'false'],
            ['types', 'SAML'],
          ] as const)
        : ([
            ['page', '1'],
            ['page_size', '20'],
            ['isThirdParty', isThirdParty ? 'true' : 'false'],
          ] as const);
      const authorization = await request.headerValue('authorization');
      const language = await request.headerValue('accept-language');
      const origin = await request.headerValue('origin');

      this.#applicationReads.push(
        Object.freeze({
          authority,
          status: safeStatus(response.status()),
          queryShapeExact: exactEntries(url.searchParams, expectedEntries) && url.hash === '',
          originMatches: origin === new URL(this.#target.adminUrl).origin,
          languageMatches: language === 'en',
          accessMatchesManagement: Boolean(
            this.#managementAccess && authorization === `Bearer ${this.#managementAccess}`
          ),
          isThirdParty,
          isSamlProbe,
          total: safeTotal(response.headers()['total-number']),
          rows: applicationRows(await response.json()),
        })
      );
      return;
    }
    if (url.pathname === '/api/users') {
      if (method !== 'GET') {
        throw new TypeError('Invalid browser network observation');
      }
      const authorization = await request.headerValue('authorization');
      const language = await request.headerValue('accept-language');
      const origin = await request.headerValue('origin');

      this.#userReads.push(
        Object.freeze({
          authority,
          status: safeStatus(response.status()),
          queryShapeExact:
            exactEntries(url.searchParams, [
              ['page', '1'],
              ['page_size', '20'],
            ]) && url.hash === '',
          originMatches: origin === new URL(this.#target.adminUrl).origin,
          languageMatches: language === 'en',
          accessMatchesManagement: Boolean(
            this.#managementAccess && authorization === `Bearer ${this.#managementAccess}`
          ),
          total: safeTotal(response.headers()['total-number']),
          rows: userRows(await response.json()),
        })
      );
    }
  }
}

const closeSession = async <Result>(
  session: PlaywrightBrowserSession,
  use: () => Promise<Result>
): Promise<Result> => {
  let result: Result | undefined;
  let primaryError: unknown;
  let cleanupError: unknown;

  try {
    result = await use();
  } catch (error: unknown) {
    primaryError = error;
  }
  try {
    await session.close();
  } catch (error: unknown) {
    cleanupError = error;
  }
  if (primaryError !== undefined && cleanupError !== undefined) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Browser flow and session cleanup failed',
      { cause: primaryError }
    );
  }
  if (primaryError !== undefined) {
    throw primaryError;
  }
  if (cleanupError !== undefined) {
    throw cleanupError;
  }

  return result as Result;
};

export const createPlaywrightBrowserGroupObserver = (
  browserType: Pick<BrowserType<Browser>, 'launch'>
): Phase1BrowserGroupObserver => {
  const capability = Object.freeze({
    runInFreshContext: async <Result>(
      groupId: Phase1BrowserGroupId,
      signal: AbortSignal,
      target: TargetConfig,
      use: (session: Phase1BrowserSession) => Promise<Result>
    ): Promise<Result> => {
      const observer = createPlaywrightObserver({
        scenarioId: `browser.${groupId}`,
        browserType,
        signal,
      });

      return observer.withContext(groupId, async (context) => {
        await observer.run(fixedContext('fresh-context', 'evaluation'), async () => {
          if ((await context.cookies()).length > 0 || context.pages().length > 0) {
            throw new Error('Browser context is not fresh');
          }
        });
        const networkGuard = await installContextNetworkGuard(observer, context, target, groupId);
        const page = await observer.run(fixedContext('page-create', 'browser-process'), async () =>
          context.newPage()
        );
        networkGuard.watchPrimaryPage(page);
        const session = new PlaywrightBrowserSession(observer, page, target, signal, networkGuard);

        return closeSession(session, async () => use(session));
      });
    },
  });

  browserGroupObserverCapabilities.add(capability);
  return capability;
};

export const isPlaywrightBrowserGroupObserver = (value: Phase1BrowserGroupObserver): boolean =>
  browserGroupObserverCapabilities.has(value);

/* eslint-enable complexity, max-lines, max-params, no-restricted-syntax, no-control-regex, no-await-in-loop, promise/prefer-await-to-then, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, @typescript-eslint/no-throw-literal, unicorn/no-array-callback-reference, unicorn/no-await-expression-member, unicorn/no-useless-spread, prefer-destructuring */
