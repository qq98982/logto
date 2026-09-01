/* eslint-disable max-lines, max-params, complexity, no-restricted-syntax, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This browser boundary keeps two same-host tenant interactions, bounded secret variants, fixed Playwright failures, and ordered projections together so port-isolated jars cannot satisfy the scenario. */
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';

import type {
  Browser,
  BrowserContext,
  BrowserType,
  Page,
  Route,
  Response as PlaywrightResponse,
} from '@playwright/test';

import type { JsonObject, JsonValue, NormalizationContext } from '../../normalize.js';
import {
  createPlaywrightObserver,
  PlaywrightObservationError,
} from '../browser/playwright-observer.js';
import { MemoryProtocolSecretStore } from '../clients/oidc.js';
import { getPhase1FixtureRuntimeId, getPhase1FixtureRuntimeUsername } from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import {
  projectCookieObservation,
  projectSemanticStateObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from '../projections/index.js';

const scenarioId = 'cookie.localhost-port-interleaving';
const jsonContentType = 'application/json';
const rootCookieNames = Object.freeze(['_interaction', '_interaction.sig', '_logto'] as const);
const maximumCredentialTransformDepth = 6;
const maximumCredentialVariantLength = 64 * 1024;

type TenantRole = 'admin' | 'data';

type CookieScenarioDependencies = Readonly<{
  browserType?: Pick<BrowserType<Browser>, 'launch'>;
}>;

type BrowserHttpResponse = Readonly<{
  status: number;
  headers: ReadonlyArray<readonly [string, string]>;
  body: string;
}>;

type BrowserCookie = Readonly<{
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}>;

const normalizePercentEscapes = (value: string): string =>
  value.replaceAll(/%[\da-f]{2}/giu, (encoded) => encoded.toUpperCase());

const credentialVariants = (value: string): readonly string[] => {
  const variants = new Set<string>([value]);
  let frontier = [value];

  for (let depth = 0; depth < maximumCredentialTransformDepth; depth += 1) {
    const next: string[] = [];

    for (const candidate of frontier) {
      const transformed = [
        encodeURIComponent(candidate),
        (() => {
          try {
            return decodeURIComponent(candidate);
          } catch {
            return candidate;
          }
        })(),
      ];

      for (const item of transformed) {
        if (
          item.length > 0 &&
          item.length <= maximumCredentialVariantLength &&
          !variants.has(item)
        ) {
          variants.add(item);
          next.push(item);
        }
      }
    }
    if (next.length === 0) {
      break;
    }
    frontier = next;
  }

  return Object.freeze([...variants]);
};

class BrowserScenarioSecretAuthority {
  readonly #store = new MemoryProtocolSecretStore();
  readonly #variants = new Set<string>();

  registerSecret(value: string): void {
    if (value.length === 0 || value.length > maximumCredentialVariantLength) {
      throw new Error('Phase 1 browser credential is invalid');
    }
    this.#store.registerSecret(value);
    for (const variant of credentialVariants(value)) {
      this.#variants.add(variant);
      this.#variants.add(normalizePercentEscapes(variant));
    }
  }

  registerSetCookieHeaders(headers: ReadonlyArray<readonly [string, string]>): void {
    for (const [name, header] of headers) {
      if (name.toLowerCase() !== 'set-cookie') {
        continue;
      }
      const pair = header.split(';', 1)[0] ?? '';
      const separator = pair.indexOf('=');
      const raw = separator < 0 ? '' : pair.slice(separator + 1).trim();
      const unquoted = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;

      for (const value of [raw, unquoted]) {
        if (value.length > 0) {
          this.registerSecret(value);
        }
      }
    }
  }

  assertNoCredentialMaterial(value: unknown): void {
    this.#store.assertNoCredentialMaterial(value);
    let serialized: string;

    try {
      serialized = JSON.stringify(value);
    } catch {
      throw new Error('Phase 1 browser projection contains credential material');
    }
    const normalized = normalizePercentEscapes(serialized);

    if (
      [...this.#variants].some(
        (credential) => serialized.includes(credential) || normalized.includes(credential)
      )
    ) {
      throw new Error('Phase 1 browser projection contains credential material');
    }
  }

  toJSON(): never {
    throw new TypeError('Phase 1 browser secret authority is not serializable');
  }
}

const loadChromium = (): BrowserType<Browser> =>
  (
    createRequire(import.meta.url)('@playwright/test') as {
      chromium: BrowserType<Browser>;
    }
  ).chromium;

type PreparedInteraction = Readonly<{
  role: TenantRole;
  applicationId: string;
  interactionId: string;
  startRedirect: string;
  page: Page;
  allowedOrigin: string;
  projectionContext: NormalizationContext;
}>;

const requireText = (value: unknown, diagnostic: string): string => {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new Error(diagnostic);
  }

  return value;
};

const requireJsonObject = (value: string, diagnostic: string): JsonObject => {
  try {
    const parsed: unknown = JSON.parse(value);

    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new TypeError('invalid JSON object');
    }

    return parsed as JsonObject;
  } catch {
    throw new Error(diagnostic);
  }
};

const headerValues = (
  headers: ReadonlyArray<readonly [string, string]>,
  name: string
): readonly string[] =>
  headers.filter(([candidate]) => candidate.toLowerCase() === name).map(([, value]) => value);

const requireLocation = (
  headers: ReadonlyArray<readonly [string, string]>,
  baseUrl: string,
  diagnostic: string
): string => {
  const locations = headerValues(headers, 'location');

  if (locations.length !== 1 || !locations[0]) {
    throw new Error(diagnostic);
  }
  try {
    return new URL(locations[0], baseUrl).href;
  } catch {
    throw new Error(diagnostic);
  }
};

const absoluteLocationHeaders = (
  headers: ReadonlyArray<readonly [string, string]>,
  location: string
): ReadonlyArray<readonly [string, string]> =>
  Object.freeze(
    headers.map(([name, value]) =>
      Object.freeze([name, name.toLowerCase() === 'location' ? location : value] as const)
    )
  );

const sanitizeSetCookieHeaders = (
  headers: ReadonlyArray<readonly [string, string]>,
  secretAuthority: BrowserScenarioSecretAuthority
): ReadonlyArray<readonly [string, string]> => {
  secretAuthority.registerSetCookieHeaders(headers);
  const cookieValues = headers.flatMap(([name, header]) => {
    if (name.toLowerCase() !== 'set-cookie') {
      return [];
    }
    const pair = header.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    const raw = separator < 0 ? '' : pair.slice(separator + 1).trim();
    const unquoted = raw.startsWith('"') && raw.endsWith('"') ? raw.slice(1, -1) : raw;

    return [raw, unquoted];
  });
  const candidates = cookieValues
    .flatMap((value) => credentialVariants(value))
    .flatMap((value) => [value, normalizePercentEscapes(value)])
    .filter((value, index, values) => value.length > 0 && values.indexOf(value) === index)
    .toSorted((left, right) => right.length - left.length);

  const sanitized = Object.freeze(
    headers.map(([name, header]) => {
      if (name.toLowerCase() !== 'set-cookie') {
        return Object.freeze([name, header] as const);
      }
      const attributeOffset = header.indexOf(';');
      const pair = attributeOffset < 0 ? header : header.slice(0, attributeOffset);
      const attributes = attributeOffset < 0 ? '' : header.slice(attributeOffset);
      const separator = pair.indexOf('=');

      if (separator < 1) {
        throw new Error('Phase 1 localhost cookie response is invalid');
      }
      const safeAttributes = candidates.reduce(
        (value, candidate) => value.replaceAll(candidate, 'aster-cookie-attribute-value'),
        attributes
      );

      return Object.freeze([
        name,
        `${pair.slice(0, separator)}=aster-cookie-pair-value${safeAttributes}`,
      ] as const);
    })
  );
  secretAuthority.assertNoCredentialMaterial(sanitized);

  return sanitized;
};

const allocationFor = (context: Phase1ScenarioRunContext, role: TenantRole) => {
  const allocation = context.fixture.public.allocations.find(
    (candidate) => candidate.role === role
  );

  if (!allocation) {
    throw new Error('Phase 1 localhost cookie allocation is unavailable');
  }

  return allocation;
};

const applicationFor = (context: Phase1ScenarioRunContext, role: TenantRole): string => {
  if (role === 'admin') {
    return context.profile.consoleAuthentication.applicationId;
  }
  const logicalId =
    context.profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.appId;

  return getPhase1FixtureRuntimeId(
    context.fixture.public,
    allocationFor(context, 'data').allocationId,
    'application',
    logicalId
  );
};

const redirectUriFor = (context: Phase1ScenarioRunContext, role: TenantRole): string => {
  const baseUrl = role === 'admin' ? context.target.adminUrl : context.target.coreUrl;
  const configured =
    role === 'admin'
      ? context.profile.consoleAuthentication.redirectUri
      : context.profile.fixtures.dataTenant.applications.find(
          ({ id }) =>
            id ===
            context.profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.appId
        )?.oidcClientMetadata.redirectUris[0];

  if (!configured) {
    throw new Error('Phase 1 localhost cookie redirect URI is unavailable');
  }
  const url = new URL(configured);

  return new URL(`${url.pathname}${url.search}${url.hash}`, baseUrl).href;
};

const authorizationUrl = (
  context: Phase1ScenarioRunContext,
  role: TenantRole,
  applicationId: string,
  secretAuthority: BrowserScenarioSecretAuthority
): string => {
  const baseUrl = role === 'admin' ? context.target.adminUrl : context.target.coreUrl;
  const path = context.profile.oidc.authorizationPath;

  if (!path.startsWith('/') || path.slice(1).startsWith('/')) {
    throw new Error('Phase 1 localhost cookie authorization path is invalid');
  }
  const verifier = randomBytes(48).toString('base64url');
  const state = randomBytes(32).toString('base64url');
  secretAuthority.registerSecret(verifier);
  secretAuthority.registerSecret(state);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({
    client_id: applicationId,
    redirect_uri: redirectUriFor(context, role),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
    response_type: 'code',
    prompt:
      role === 'admin'
        ? context.profile.consoleAuthentication.prompt.join(' ')
        : context.profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.prompt,
    scope:
      role === 'admin'
        ? context.profile.consoleAuthentication.effectiveScopes.join(' ')
        : [
            'openid',
            'offline_access',
            ...context.profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.scope
              .split(/\s+/u)
              .filter(Boolean)
              .filter(
                (scope) =>
                  !context.profile.fixtures.dataTenant.resource.scopes.some(
                    ({ name }) => name === scope
                  )
              ),
          ].join(' '),
  });

  if (role === 'admin') {
    for (const resource of context.profile.consoleAuthentication.effectiveResources) {
      query.append('resource', resource);
    }
  }

  return new URL(`${path}?${query.toString()}`, baseUrl).href;
};

const fixedObservationError = (
  stepId: string,
  errorClass: 'navigation' | 'evaluation',
  pointer = `/steps/${stepId}/value`
): PlaywrightObservationError =>
  new PlaywrightObservationError(scenarioId, { stepId, errorClass, projectionPointer: pointer });

const httpOrigin = (value: string): string | undefined => {
  try {
    const url = new URL(value);

    return ['http:', 'https:'].includes(url.protocol) ? url.origin : undefined;
  } catch {
    return undefined;
  }
};

const installAllowedOriginGuard = async (
  page: Page,
  stepId: string,
  allowedOrigin: string
): Promise<void> => {
  try {
    await page.route('**/*', async (route: Route) => {
      if (httpOrigin(route.request().url()) !== allowedOrigin) {
        await route.abort('blockedbyclient');
        return;
      }
      await route.continue();
    });
  } catch {
    throw fixedObservationError(stepId, 'navigation');
  }
};

const capturedResponseBody = async (
  response: PlaywrightResponse,
  headers: ReadonlyArray<readonly [string, string]>
): Promise<string> => {
  try {
    const body = await response.body();

    return body.toString('utf8');
  } catch {
    const contentLengths = headerValues(headers, 'content-length');
    const status = response.status();

    if (
      [204, 205, 304].includes(status) ||
      (status >= 300 &&
        status < 400 &&
        (contentLengths.length === 0 || (contentLengths.length === 1 && contentLengths[0] === '0')))
    ) {
      return '';
    }

    throw new Error('Phase 1 captured browser response body is unavailable');
  }
};

const captureAuthorizationResponse = async (
  page: Page,
  stepId: string,
  url: string,
  allowedOrigin: string,
  secretAuthority: BrowserScenarioSecretAuthority,
  navigate: (page: Page, stepId: string, url: string, pointer: string) => Promise<unknown>
): Promise<BrowserHttpResponse> => {
  let response: PlaywrightResponse | undefined;
  let forbiddenResponse: PlaywrightResponse | undefined;
  const onResponse = (candidate: PlaywrightResponse) => {
    const origin = httpOrigin(candidate.url());

    if (origin !== undefined && origin !== allowedOrigin) {
      forbiddenResponse = candidate;
      return;
    }
    if (candidate.url() === url && candidate.request().method() === 'GET') {
      response = candidate;
    }
  };

  page.on('response', onResponse);
  try {
    await navigate(page, stepId, url, `/steps/${stepId}/value/redirect`);
    if (
      forbiddenResponse !== undefined ||
      !response ||
      httpOrigin(response.url()) !== allowedOrigin
    ) {
      throw fixedObservationError(stepId, 'navigation');
    }
    const captured = response;
    const rawHeaders = await captured.headersArray();
    const headers = Object.freeze(
      rawHeaders.map(({ name, value }) => Object.freeze([name, value] as const))
    );
    secretAuthority.registerSetCookieHeaders(headers);

    return Object.freeze({
      status: captured.status(),
      headers,
      body: await capturedResponseBody(captured, headers),
    });
  } catch (error: unknown) {
    if (error instanceof PlaywrightObservationError) {
      throw error;
    }
    throw fixedObservationError(stepId, 'navigation');
  } finally {
    page.removeListener('response', onResponse);
  }
};

const browserFetch = async (
  page: Page,
  stepId: string,
  allowedOrigin: string,
  secretAuthority: BrowserScenarioSecretAuthority,
  input: Readonly<{
    path: string;
    method: string;
    applicationId: string;
    body?: JsonValue;
  }>
): Promise<BrowserHttpResponse> => {
  let observedResponse: PlaywrightResponse | undefined;
  let forbiddenResponse: PlaywrightResponse | undefined;
  const currentPage = new URL(page.url());

  if (currentPage.origin !== allowedOrigin || currentPage.pathname !== '/sign-in') {
    throw fixedObservationError(stepId, 'evaluation', `/steps/${stepId}/value/redirect`);
  }
  const requestUrl = new URL(input.path, `${allowedOrigin}/`).href;
  const onResponse = (candidate: PlaywrightResponse) => {
    const origin = httpOrigin(candidate.url());

    if (origin !== undefined && origin !== allowedOrigin) {
      forbiddenResponse = candidate;
      return;
    }
    if (candidate.url() === requestUrl && candidate.request().method() === input.method) {
      observedResponse = candidate;
    }
  };

  page.on('response', onResponse);
  try {
    const request = {
      path: input.path,
      method: input.method,
      applicationId: input.applicationId,
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    };
    await page.evaluate(async ({ path, method, applicationId, body }) => {
      const response = await fetch(path, {
        method,
        headers: {
          'content-type': 'application/json',
          'Logto-App-Id': applicationId,
        },
        body,
      });
      await response.arrayBuffer();
    }, request);

    if (
      forbiddenResponse !== undefined ||
      !observedResponse ||
      observedResponse.url() !== requestUrl ||
      httpOrigin(observedResponse.url()) !== allowedOrigin
    ) {
      throw fixedObservationError(stepId, 'evaluation');
    }
    const captured = observedResponse;
    const rawHeaders = await captured.headersArray();
    const headers = Object.freeze(
      rawHeaders.map(({ name, value }) => Object.freeze([name, value] as const))
    );
    secretAuthority.registerSetCookieHeaders(headers);

    return Object.freeze({
      status: captured.status(),
      headers,
      body: await capturedResponseBody(captured, headers),
    });
  } catch (error: unknown) {
    if (error instanceof PlaywrightObservationError) {
      throw error;
    }
    throw fixedObservationError(stepId, 'evaluation');
  } finally {
    page.removeListener('response', onResponse);
  }
};

const browserCookies = async (
  context: BrowserContext,
  stepId: string,
  secretAuthority: BrowserScenarioSecretAuthority
): Promise<readonly BrowserCookie[]> => {
  try {
    const cookies = await context.cookies();

    const snapshot = Object.freeze(
      cookies.map(({ name, value, domain, path, expires, httpOnly, secure, sameSite }) =>
        Object.freeze({ name, value, domain, path, expires, httpOnly, secure, sameSite })
      )
    );
    for (const { value } of snapshot) {
      if (value.length > 0) {
        secretAuthority.registerSecret(value);
      }
    }

    return snapshot;
  } catch {
    throw fixedObservationError(stepId, 'evaluation', `/steps/${stepId}/value/cookies`);
  }
};

const restoreCookies = async (
  context: BrowserContext,
  stepId: string,
  cookies: readonly BrowserCookie[]
): Promise<void> => {
  try {
    await context.addCookies(cookies.map((cookie) => ({ ...cookie })));
  } catch {
    throw fixedObservationError(stepId, 'evaluation', `/steps/${stepId}/value/cookies`);
  }
};

const cookieKey = ({ name, domain, path }: BrowserCookie): string => `${name}|${domain}|${path}`;

const assertRootCookiesWereOverwritten = (
  stepId: string,
  before: readonly BrowserCookie[],
  after: readonly BrowserCookie[]
): void => {
  const beforeByKey = new Map(before.map((cookie) => [cookieKey(cookie), cookie]));
  const afterByKey = new Map(after.map((cookie) => [cookieKey(cookie), cookie]));

  for (const name of rootCookieNames) {
    const candidates = before.filter((cookie) => cookie.name === name && cookie.path === '/');
    const previous = candidates.length === 1 ? candidates[0] : undefined;
    const current = previous && afterByKey.get(cookieKey(previous));

    if (!previous || !current || beforeByKey.get(cookieKey(previous))?.value === current.value) {
      throw fixedObservationError(
        stepId,
        'evaluation',
        `/steps/${stepId}/value/cookies/${name.replaceAll('.', '-')}`
      );
    }
  }
  const retainedResume = before.filter(
    ({ name, path }) => name.startsWith('_interaction_resume') && path.startsWith('/oidc/auth/')
  );

  if (
    retainedResume.length === 0 ||
    retainedResume.some(
      ({ value, ...metadata }) => afterByKey.get(cookieKey({ ...metadata, value }))?.value !== value
    )
  ) {
    throw fixedObservationError(stepId, 'evaluation', `/steps/${stepId}/value/cookies/resume`);
  }
};

const interactionIdFrom = (
  cookies: readonly BrowserCookie[],
  applicationId: string,
  diagnostic: string
): string => {
  const cookie = cookies.find(({ name, path }) => name === '_interaction' && path === '/');

  try {
    if (!cookie) {
      throw new TypeError('missing interaction cookie');
    }
    const mapping: unknown = JSON.parse(decodeURIComponent(cookie.value));
    const value: unknown =
      typeof mapping === 'object' && mapping !== null && !Array.isArray(mapping)
        ? (mapping as Record<string, unknown>)[applicationId]
        : undefined;

    return requireText(value, diagnostic);
  } catch {
    throw new Error(diagnostic);
  }
};

const stateInput = async (context: Phase1ScenarioRunContext, stepId: string) =>
  context.projectScenarioState({ scenarioId, stepId, fixture: context.fixture });

const rawObservation = (
  response: Pick<BrowserHttpResponse, 'status' | 'headers'>,
  body: JsonValue,
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>,
  overrides: Partial<RawHttpObservation> = {}
): RawHttpObservation => ({
  ...state,
  status: response.status,
  headers: response.headers,
  body,
  ...overrides,
});

const step = (stepId: string, value: Phase1HttpProjection): Phase1ScenarioStepResult =>
  Object.freeze({ stepId, value });

const securedStep = (
  secretAuthority: BrowserScenarioSecretAuthority,
  stepId: string,
  value: Phase1HttpProjection
): Phase1ScenarioStepResult => {
  const result = step(stepId, value);
  secretAuthority.assertNoCredentialMaterial(result);

  return result;
};

const startInteraction = async (
  context: Phase1ScenarioRunContext,
  browserContext: BrowserContext,
  role: TenantRole,
  stepId: string,
  occurrence: string,
  secretAuthority: BrowserScenarioSecretAuthority,
  navigate: (page: Page, stepId: string, url: string, pointer: string) => Promise<unknown>
): Promise<
  Readonly<{
    prepared: PreparedInteraction;
    evidence: Phase1ScenarioStepResult;
    cookies: readonly BrowserCookie[];
  }>
> => {
  try {
    const page = await browserContext.newPage();
    const applicationId = applicationFor(context, role);
    const baseUrl = role === 'admin' ? context.target.adminUrl : context.target.coreUrl;
    const allowedOrigin = new URL(baseUrl).origin;
    await installAllowedOriginGuard(page, stepId, allowedOrigin);
    const response = await captureAuthorizationResponse(
      page,
      stepId,
      authorizationUrl(context, role, applicationId, secretAuthority),
      allowedOrigin,
      secretAuthority,
      navigate
    );

    if (response.status !== 303) {
      throw new Error('Phase 1 localhost cookie authorization start failed');
    }
    const location = requireLocation(
      response.headers,
      baseUrl,
      'Phase 1 localhost cookie authorization redirect is invalid'
    );
    const locationUrl = new URL(location);

    if (locationUrl.origin !== new URL(baseUrl).origin || locationUrl.pathname !== '/sign-in') {
      throw new Error('Phase 1 localhost cookie authorization redirect is invalid');
    }
    const prepare = await browserFetch(page, stepId, allowedOrigin, secretAuthority, {
      path: '/api/experience',
      method: 'PUT',
      applicationId,
      body: { interactionEvent: 'SignIn' },
    });

    if (prepare.status !== 204) {
      throw new Error('Phase 1 localhost cookie interaction preparation failed');
    }
    const cookies = await browserCookies(browserContext, stepId, secretAuthority);
    const interactionId = interactionIdFrom(
      cookies,
      applicationId,
      'Phase 1 localhost cookie interaction identifier is invalid'
    );
    secretAuthority.registerSecret(interactionId);
    const allocation = allocationFor(context, role);
    const symbols = context.protocol.symbolsFor(allocation.allocationId);

    if (!symbols) {
      throw new Error('Phase 1 localhost cookie symbols are unavailable');
    }
    symbols.bindOccurrence(`interaction.${role}.${occurrence}`, interactionId);
    const projectionContext = { target: context.target, symbols };
    const state = await stateInput(context, stepId);
    const safeHeaders = sanitizeSetCookieHeaders(
      absoluteLocationHeaders(response.headers, location),
      secretAuthority
    );
    const evidence = securedStep(
      secretAuthority,
      stepId,
      projectCookieObservation(
        rawObservation(
          { ...response, headers: safeHeaders },
          [...headerValues(safeHeaders, 'set-cookie')],
          { ...state, generatedIds: { interaction: interactionId } },
          { redirect: location, outcomes: [{ authority: 'prepared' }] }
        ),
        projectionContext
      )
    );

    return Object.freeze({
      prepared: Object.freeze({
        role,
        applicationId,
        interactionId,
        startRedirect: location,
        page,
        allowedOrigin,
        projectionContext,
      }),
      evidence,
      cookies,
    });
  } catch (error: unknown) {
    if (error instanceof PlaywrightObservationError) {
      throw error;
    }
    throw fixedObservationError(stepId, 'evaluation');
  }
};

const finishInteraction = async (
  context: Phase1ScenarioRunContext,
  prepared: PreparedInteraction,
  stepId: string,
  password: string,
  username: string,
  secretAuthority: BrowserScenarioSecretAuthority,
  expected: 'rejected' | 'accepted'
): Promise<Phase1ScenarioStepResult> => {
  try {
    const passwordResponse = await browserFetch(
      prepared.page,
      stepId,
      prepared.allowedOrigin,
      secretAuthority,
      {
        path: '/api/experience/verification/password',
        method: 'POST',
        applicationId: prepared.applicationId,
        body: { identifier: { type: 'username', value: username }, password },
      }
    );
    const state = await stateInput(context, stepId);

    if (expected === 'rejected') {
      const body = requireJsonObject(
        passwordResponse.body,
        'Phase 1 localhost cookie rejection response is invalid'
      );

      if (passwordResponse.status !== 400 || body.code !== 'session.not_found') {
        throw new Error('Phase 1 localhost cookie cross-tenant authority was not rejected');
      }

      const safeHeaders = sanitizeSetCookieHeaders(passwordResponse.headers, secretAuthority);

      return securedStep(
        secretAuthority,
        stepId,
        projectCookieObservation(
          rawObservation(
            { ...passwordResponse, headers: safeHeaders },
            [...headerValues(safeHeaders, 'set-cookie')],
            { ...state, generatedIds: { interaction: prepared.interactionId } },
            {
              redirect: prepared.startRedirect,
              error: { error: 'invalid_request' },
              outcomes: [{ authority: 'rejected' }],
            }
          ),
          prepared.projectionContext
        )
      );
    }

    if (passwordResponse.status !== 200) {
      throw new Error('Phase 1 localhost cookie current interaction was rejected');
    }
    const verificationId = requireText(
      requireJsonObject(
        passwordResponse.body,
        'Phase 1 localhost cookie password response is invalid'
      ).verificationId,
      'Phase 1 localhost cookie password response is invalid'
    );
    context.protocol.forAllocation(prepared.role).oidc.store.registerSecret(verificationId);
    secretAuthority.registerSecret(verificationId);
    const identifyResponse = await browserFetch(
      prepared.page,
      stepId,
      prepared.allowedOrigin,
      secretAuthority,
      {
        path: '/api/experience/identification',
        method: 'POST',
        applicationId: prepared.applicationId,
        body: { verificationId },
      }
    );

    if (identifyResponse.status !== 204) {
      throw new Error('Phase 1 localhost cookie identification failed');
    }
    const submitResponse = await browserFetch(
      prepared.page,
      stepId,
      prepared.allowedOrigin,
      secretAuthority,
      {
        path: '/api/experience/submit',
        method: 'POST',
        applicationId: prepared.applicationId,
      }
    );
    const redirectTo = requireText(
      requireJsonObject(
        submitResponse.body,
        'Phase 1 localhost cookie submission response is invalid'
      ).redirectTo,
      'Phase 1 localhost cookie submission response is invalid'
    );

    if (submitResponse.status !== 200 || new URL(redirectTo).origin !== prepared.allowedOrigin) {
      throw new Error('Phase 1 localhost cookie submission redirect is invalid');
    }
    const redirectUrl = new URL(redirectTo);
    const resumeCredential = decodeURIComponent(redirectUrl.pathname.split('/').at(-1) ?? '');

    if (resumeCredential.length > 0) {
      secretAuthority.registerSecret(resumeCredential);
    }
    const safeHeaders = sanitizeSetCookieHeaders(submitResponse.headers, secretAuthority);

    return securedStep(
      secretAuthority,
      stepId,
      projectCookieObservation(
        rawObservation(
          { ...submitResponse, headers: safeHeaders },
          [...headerValues(safeHeaders, 'set-cookie')],
          { ...state, generatedIds: { interaction: prepared.interactionId } },
          { redirect: redirectTo, outcomes: [{ authority: 'accepted' }] }
        ),
        prepared.projectionContext
      )
    );
  } catch (error: unknown) {
    if (error instanceof PlaywrightObservationError) {
      throw error;
    }
    throw fixedObservationError(stepId, 'evaluation');
  }
};

const usernameFor = (context: Phase1ScenarioRunContext, role: TenantRole): string => {
  const allocation = allocationFor(context, role);
  const username =
    role === 'admin'
      ? context.profile.fixtures.adminTenant.operator.username
      : context.profile.fixtures.dataTenant.subject.username;

  return getPhase1FixtureRuntimeUsername(username, allocation.allocationId);
};

export const runCookieLocalhostPortInterleaving = async (
  context: Phase1ScenarioRunContext,
  dependencies: CookieScenarioDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const core = new URL(context.target.coreUrl);
  const admin = new URL(context.target.adminUrl);

  if (
    core.hostname !== 'localhost' ||
    admin.hostname !== 'localhost' ||
    core.port.length === 0 ||
    admin.port.length === 0 ||
    core.port === admin.port
  ) {
    throw new Error('Phase 1 localhost cookie target topology is invalid');
  }
  const browserType = dependencies.browserType ?? loadChromium();
  const observer = createPlaywrightObserver({
    scenarioId,
    browserType,
    signal: context.signal,
  });

  return context.fixture.withSecretLease(async (lease) =>
    observer.withContext('admin-start', async (browserContext) => {
      const adminPassword = lease.getPassword(context.profile.fixtures.adminTenant.operator.id);
      const dataPassword = lease.getPassword(context.profile.fixtures.dataTenant.subject.id);
      const secretAuthority = new BrowserScenarioSecretAuthority();
      secretAuthority.registerSecret(adminPassword);
      secretAuthority.registerSecret(dataPassword);
      const firstAdmin = await startInteraction(
        context,
        browserContext,
        'admin',
        'admin-start',
        'first',
        secretAuthority,
        observer.navigate
      );
      const firstData = await startInteraction(
        context,
        browserContext,
        'data',
        'data-start',
        'first',
        secretAuthority,
        observer.navigate
      );
      assertRootCookiesWereOverwritten('data-start', firstAdmin.cookies, firstData.cookies);
      const adminFinish = await finishInteraction(
        context,
        firstAdmin.prepared,
        'admin-finish',
        adminPassword,
        usernameFor(context, 'admin'),
        secretAuthority,
        'rejected'
      );
      await restoreCookies(browserContext, 'data-finish', firstData.cookies);
      const dataFinish = await finishInteraction(
        context,
        firstData.prepared,
        'data-finish',
        dataPassword,
        usernameFor(context, 'data'),
        secretAuthority,
        'accepted'
      );

      try {
        await browserContext.clearCookies();
      } catch {
        throw fixedObservationError(
          'data-start-reverse',
          'evaluation',
          '/steps/data-start-reverse/value/cookies'
        );
      }
      const reverseData = await startInteraction(
        context,
        browserContext,
        'data',
        'data-start-reverse',
        'reverse',
        secretAuthority,
        observer.navigate
      );
      const reverseAdmin = await startInteraction(
        context,
        browserContext,
        'admin',
        'admin-start-reverse',
        'reverse',
        secretAuthority,
        observer.navigate
      );
      assertRootCookiesWereOverwritten(
        'admin-start-reverse',
        reverseData.cookies,
        reverseAdmin.cookies
      );
      const dataFinishReverse = await finishInteraction(
        context,
        reverseData.prepared,
        'data-finish-reverse',
        dataPassword,
        usernameFor(context, 'data'),
        secretAuthority,
        'rejected'
      );
      await restoreCookies(browserContext, 'admin-finish-reverse', reverseAdmin.cookies);
      const adminFinishReverse = await finishInteraction(
        context,
        reverseAdmin.prepared,
        'admin-finish-reverse',
        adminPassword,
        usernameFor(context, 'admin'),
        secretAuthority,
        'accepted'
      );
      const finalState = await stateInput(context, 'state');
      const stateStep = securedStep(
        secretAuthority,
        'state',
        projectSemanticStateObservation(
          { ...finalState, status: 200, headers: [] },
          firstData.prepared.projectionContext,
          { scenarioId, stepId: 'state' }
        )
      );
      const steps = Object.freeze([
        firstAdmin.evidence,
        firstData.evidence,
        adminFinish,
        dataFinish,
        reverseData.evidence,
        reverseAdmin.evidence,
        dataFinishReverse,
        adminFinishReverse,
        stateStep,
      ]);

      context.protocol.forAllocation('admin').oidc.store.assertNoCredentialMaterial(steps);
      context.protocol.forAllocation('data').oidc.store.assertNoCredentialMaterial(steps);
      secretAuthority.assertNoCredentialMaterial(steps);

      return steps;
    })
  );
};

/* eslint-enable max-lines, max-params, complexity, no-restricted-syntax, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
