/* eslint-disable max-lines, complexity, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types, @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-return -- Twenty oracle-locked requests, raw-form controls, exact outcome contracts, and field-specific comparator controls intentionally live together as one closed registry. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import {
  observeClientCredentialsToken,
  type ClientCredentialsRequest,
  type SanitizedTokenObservation,
} from '../clients/client-credentials.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2DifferentialScenarioId, Phase2ProfileRegistries } from '../profile.js';
import {
  projectClientCredentialsObservation,
  type ClientCredentialsProjection,
  type Phase2JwtAudit,
  type Phase2EffectiveAuthorityFacts,
  type Phase2SideEffectFacts,
  type Phase2SigningUseFacts,
} from '../projections/client-credentials.js';

export const clientCredentialsScenarioIds = Object.freeze([
  'client-credentials.basic-explicit-resource',
  'client-credentials.post-explicit-resource',
  'client-credentials.default-resource',
  'client-credentials.resource-no-scope',
  'client-credentials.resource-partial-scope',
  'client-credentials.organization-empty-scope',
  'client-credentials.organization-scope',
  'client-credentials.organization-resource-scope',
  'client-credentials.unknown-client-basic',
  'client-credentials.unknown-client-post',
  'client-credentials.wrong-secret-basic',
  'client-credentials.wrong-secret-post',
  'client-credentials.mixed-authentication',
  'client-credentials.missing-target',
  'client-credentials.unknown-resource',
  'client-credentials.unassociated-organization',
  'client-credentials.duplicate-resource',
  'client-credentials.duplicate-scope-name',
  'client-credentials.malformed-scope-whitespace',
  'client-credentials.unsupported-parameter',
] as const satisfies readonly Phase2DifferentialScenarioId[]);

type ScenarioName = Phase2DifferentialScenarioId extends `client-credentials.${infer Name}`
  ? Name
  : never;

export type Phase2ScenarioStateObservation = Readonly<{
  response: SanitizedTokenObservation;
  authority: Phase2EffectiveAuthorityFacts;
  signingUse: Phase2SigningUseFacts;
  sideEffects: Phase2SideEffectFacts;
}>;

export type Phase2ScenarioStateDriver = Readonly<{
  observe(
    scenarioId: Phase2DifferentialScenarioId,
    fixture: ProvisionedPhase2Fixture,
    execute: () => Promise<SanitizedTokenObservation>
  ): Promise<Phase2ScenarioStateObservation>;
  setDefaultResource(fixture: ProvisionedPhase2Fixture, enabled: boolean): Promise<void>;
}>;

export type ClientCredentialsScenarioRuntime = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  jwks: Readonly<JSONWebKeySet>;
  state: Phase2ScenarioStateDriver;
  jwtAudit: Phase2JwtAudit;
  fetch?: typeof fetch;
  requestTimeoutMs?: number;
}>;

export type ClientCredentialsScenarioResult = Readonly<{
  id: Phase2DifferentialScenarioId;
  projection: ClientCredentialsProjection;
}>;

export type ClientCredentialsScenario = Readonly<{
  id: Phase2DifferentialScenarioId;
  run(runtime: ClientCredentialsScenarioRuntime): Promise<ClientCredentialsScenarioResult>;
}>;

export type ClientCredentialsDifference = Readonly<{
  path: string;
  expected?: unknown;
  actual?: unknown;
}>;

export type ClientCredentialsControlResult = Readonly<{
  name:
    | 'status'
    | 'challenge'
    | 'error'
    | 'audience'
    | 'scope'
    | 'client-id'
    | 'organization-id'
    | 'typ'
    | 'alg'
    | 'kid'
    | 'discovery-grant-order'
    | 'unexpected-field';
  pointer: string;
  detected: true;
}>;

type RawEntries = ReadonlyArray<readonly [string, string]>;

type ScenarioContract = Readonly<{
  status: number;
  error?: string;
  errorDescription?: string;
  challenge: 'basic' | 'absent';
  audience?: '<resource.primary>' | '<resource.default>' | 'organization';
  scope?: string | null;
  client?: '<client.basic>' | '<client.post>';
  organizationId?: '<organization.primary>';
}>;

type ScenarioRequestPlan = Readonly<{
  contract: ScenarioContract;
  disableDefaultResource?: true;
  rawEntries?: (
    lease: Readonly<{ basic: string; post: string }>,
    fixture: ProvisionedPhase2Fixture
  ) => RawEntries;
  request(
    lease: Readonly<{ basic: string; post: string }>,
    fixture: ProvisionedPhase2Fixture
  ): ClientCredentialsRequest;
}>;

const diagnostic = 'Invalid Phase 2 client credentials scenario';
const wrongBasicSecret = 'W'.repeat(32);
const wrongPostSecret = 'X'.repeat(32);
const unknownBasicSecret = 'Y'.repeat(32);
const unknownPostSecret = 'Z'.repeat(32);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const scenarioId = (name: ScenarioName): Phase2DifferentialScenarioId =>
  `client-credentials.${name}`;

const errorBody = (error: string, errorDescription: string) => ({
  error,
  errorDescription,
  challenge: 'absent' as const,
});

const plans: Readonly<Record<ScenarioName, ScenarioRequestPlan>> = Object.freeze({
  'basic-explicit-resource': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: null,
      client: '<client.basic>',
    },
  },
  'post-explicit-resource': {
    request: (lease, fixture) => ({
      method: 'client_secret_post',
      clientId: fixture.public.clients.post.id,
      clientSecret: lease.post,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: null,
      client: '<client.post>',
    },
  },
  'default-resource': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.default>',
      scope: null,
      client: '<client.basic>',
    },
  },
  'resource-no-scope': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: null,
      client: '<client.basic>',
    },
  },
  'resource-partial-scope': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
      scope: 'read unavailable',
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: 'read',
      client: '<client.basic>',
    },
  },
  'organization-empty-scope': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      organizationId: fixture.public.organization.id,
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: 'organization',
      scope: '',
      client: '<client.basic>',
    },
  },
  'organization-scope': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      organizationId: fixture.public.organization.id,
      scope: 'organization:read unavailable',
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: 'organization',
      scope: 'organization:read',
      client: '<client.basic>',
    },
  },
  'organization-resource-scope': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
      organizationId: fixture.public.organization.id,
      scope: 'read write unassigned',
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: 'read write',
      client: '<client.basic>',
      organizationId: '<organization.primary>',
    },
  },
  'unknown-client-basic': {
    request: (_lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: 'phase2-unknown-client-basic',
      clientSecret: unknownBasicSecret,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: {
      status: 400,
      ...errorBody('invalid_client', 'invalid client phase2-unknown-client-basic'),
    },
  },
  'unknown-client-post': {
    request: (_lease, fixture) => ({
      method: 'client_secret_post',
      clientId: 'phase2-unknown-client-post',
      clientSecret: unknownPostSecret,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: {
      status: 400,
      ...errorBody('invalid_client', 'invalid client phase2-unknown-client-post'),
    },
  },
  'wrong-secret-basic': {
    request: (_lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: wrongBasicSecret,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: {
      status: 401,
      error: 'invalid_client',
      errorDescription: 'client authentication failed',
      challenge: 'basic',
    },
  },
  'wrong-secret-post': {
    request: (_lease, fixture) => ({
      method: 'client_secret_post',
      clientId: fixture.public.clients.post.id,
      clientSecret: wrongPostSecret,
      resource: fixture.public.resources.primary.indicator,
    }),
    contract: { status: 401, ...errorBody('invalid_client', 'client authentication failed') },
  },
  'mixed-authentication': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
    }),
    rawEntries: (lease, fixture) => [
      ['grant_type', 'client_credentials'],
      ['resource', fixture.public.resources.primary.indicator],
      ['client_id', fixture.public.clients.post.id],
      ['client_secret', lease.post],
    ],
    contract: {
      status: 400,
      ...errorBody(
        'invalid_request',
        'client authentication must only be provided using one mechanism'
      ),
    },
  },
  'missing-target': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
    }),
    disableDefaultResource: true,
    contract: {
      status: 400,
      ...errorBody('invalid_target', 'both `resource` and `organization_id` are not provided'),
    },
  },
  'unknown-resource': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: 'https://phase2.example.invalid/unknown',
    }),
    contract: {
      status: 400,
      ...errorBody('invalid_target', 'resource indicator is missing, or unknown'),
    },
  },
  'unassociated-organization': {
    request: (lease, fixture) => ({
      method: 'client_secret_post',
      clientId: fixture.public.clients.post.id,
      clientSecret: lease.post,
      organizationId: fixture.public.organization.id,
    }),
    contract: {
      status: 403,
      ...errorBody('access_denied', 'app has not associated with the organization'),
    },
  },
  'duplicate-resource': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
    }),
    rawEntries: (_lease, fixture) => [
      ['grant_type', 'client_credentials'],
      ['resource', fixture.public.resources.primary.indicator],
      ['resource', fixture.public.resources.default.indicator],
    ],
    contract: {
      status: 400,
      ...errorBody(
        'invalid_target',
        'only a single resource indicator value is supported for this grant type'
      ),
    },
  },
  'duplicate-scope-name': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
      scope: 'read read write',
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: 'read write',
      client: '<client.basic>',
    },
  },
  'malformed-scope-whitespace': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
      scope: ' read  write ',
    }),
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: 'read write',
      client: '<client.basic>',
    },
  },
  'unsupported-parameter': {
    request: (lease, fixture) => ({
      method: 'client_secret_basic',
      clientId: fixture.public.clients.basic.id,
      clientSecret: lease.basic,
      resource: fixture.public.resources.primary.indicator,
    }),
    rawEntries: (_lease, fixture) => [
      ['grant_type', 'client_credentials'],
      ['resource', fixture.public.resources.primary.indicator],
      ['unsupported_parameter', 'rejected'],
    ],
    contract: {
      status: 200,
      challenge: 'absent',
      audience: '<resource.primary>',
      scope: null,
      client: '<client.basic>',
    },
  },
});

const scenarioName = (id: Phase2DifferentialScenarioId): ScenarioName => {
  const prefix = 'client-credentials.';
  if (!id.startsWith(prefix)) {
    return fail();
  }
  const name = id.slice(prefix.length) as ScenarioName;
  return Object.hasOwn(plans, name) ? name : fail();
};

const rawFetch = (requestFetch: typeof fetch, rawEntries: RawEntries | undefined): typeof fetch => {
  return async (input, init = {}) => {
    const response = await requestFetch(input, {
      ...init,
      ...(rawEntries === undefined
        ? {}
        : { body: new URLSearchParams(rawEntries.map(([name, value]) => [name, value])) }),
    });
    if (
      ['authorization', 'proxy-authorization', 'cookie', 'set-cookie'].some((name) =>
        response.headers.has(name)
      )
    ) {
      return fail();
    }
    return response;
  };
};

const assertScenarioContract = (
  projection: ClientCredentialsProjection,
  contract: ScenarioContract
): void => {
  if (projection.http.status !== contract.status) {
    return fail();
  }
  const challenge = projection.http.headers['www-authenticate'];
  if (
    (contract.challenge === 'basic' &&
      challenge !==
        'Basic realm="<target-issuer>", error="invalid_client", error_description="client authentication failed"') ||
    (contract.challenge === 'absent' && challenge !== undefined)
  ) {
    return fail();
  }
  if (contract.error !== undefined) {
    if (
      projection.jwt !== null ||
      projection.http.body.error !== contract.error ||
      projection.http.body.error_description !== contract.errorDescription
    ) {
      return fail();
    }
    return;
  }
  const claims = projection.jwt?.claims;
  if (
    !claims ||
    claims.client_id !== contract.client ||
    claims.sub !== contract.client ||
    (contract.audience === 'organization'
      ? claims.aud !== 'urn:aster:organization:<organization.primary>'
      : claims.aud !== contract.audience) ||
    (contract.scope === null
      ? Object.hasOwn(claims, 'scope') || Object.hasOwn(projection.http.body, 'scope')
      : claims.scope !== contract.scope || projection.http.body.scope !== contract.scope) ||
    (contract.organizationId === undefined
      ? Object.hasOwn(claims, 'organization_id')
      : claims.organization_id !== contract.organizationId)
  ) {
    return fail();
  }
};

const runScenario = async (
  id: Phase2DifferentialScenarioId,
  runtime: ClientCredentialsScenarioRuntime
): Promise<ClientCredentialsScenarioResult> => {
  const plan = plans[scenarioName(id)];
  const auditState: { jwtProof?: ReturnType<Phase2JwtAudit['verify']> } = {};
  const execute = async (): Promise<SanitizedTokenObservation> =>
    runtime.fixture.withSecretLease(async (secretLease) => {
      const lease = Object.freeze({
        basic: secretLease.getClientSecret('basic'),
        post: secretLease.getClientSecret('post'),
      });
      const request = plan.request(lease, runtime.fixture);
      const entries = plan.rawEntries?.(lease, runtime.fixture);
      const requestStartedAtMilliseconds = Date.now();
      const response = await observeClientCredentialsToken(
        new URL('/oidc/token', runtime.target.coreUrl),
        runtime.jwks,
        request,
        {
          fetch: rawFetch(runtime.fetch ?? fetch, entries),
          ...(runtime.requestTimeoutMs === undefined
            ? {}
            : { timeoutMs: runtime.requestTimeoutMs }),
        }
      );
      const responseObservedAtMilliseconds = Date.now();
      auditState.jwtProof = runtime.jwtAudit.verify(
        response,
        requestStartedAtMilliseconds,
        responseObservedAtMilliseconds
      );
      return response;
    });

  let observation: Phase2ScenarioStateObservation;
  if (plan.disableDefaultResource) {
    await runtime.state.setDefaultResource(runtime.fixture, false);
    try {
      observation = await runtime.state.observe(id, runtime.fixture, execute);
    } finally {
      await runtime.state.setDefaultResource(runtime.fixture, true);
    }
  } else {
    observation = await runtime.state.observe(id, runtime.fixture, execute);
  }
  const projection = projectClientCredentialsObservation({
    target: runtime.target,
    fixture: runtime.fixture.public,
    jwtProof: auditState.jwtProof,
    ...observation,
  });
  assertScenarioContract(projection, plan.contract);
  return Object.freeze({ id, projection });
};

export const createClientCredentialsScenarioRegistry = (
  profile: Phase2ProfileRegistries
): readonly ClientCredentialsScenario[] => {
  if (
    profile.differentialScenarios.length !== clientCredentialsScenarioIds.length ||
    profile.differentialScenarios.some((id, index) => id !== clientCredentialsScenarioIds[index])
  ) {
    return fail();
  }
  return Object.freeze(
    clientCredentialsScenarioIds.map((id) =>
      Object.freeze({
        id,
        run: async (runtime: ClientCredentialsScenarioRuntime) => runScenario(id, runtime),
      })
    )
  );
};

const plain = (value: unknown): value is Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.prototype.toString.call(value) !== '[object Object]'
  ) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype === null) {
    return true;
  }
  const constructor = Object.getOwnPropertyDescriptor(prototype, 'constructor');
  return (
    constructor !== undefined &&
    Object.hasOwn(constructor, 'value') &&
    typeof constructor.value === 'function' &&
    constructor.value.name === 'Object'
  );
};

const differences = (
  expected: unknown,
  actual: unknown,
  pointer = ''
): readonly ClientCredentialsDifference[] => {
  if (isDeepStrictEqual(expected, actual)) {
    return Object.freeze([]);
  }
  if (Array.isArray(expected) && Array.isArray(actual)) {
    const length = Math.max(expected.length, actual.length);
    return Object.freeze(
      Array.from({ length }, (_, index) =>
        differences(expected[index], actual[index], `${pointer}/${index}`)
      ).flat()
    );
  }
  if (plain(expected) && plain(actual)) {
    const keys = [...new Set([...Object.keys(expected), ...Object.keys(actual)])].toSorted();
    return Object.freeze(
      keys.flatMap((key) =>
        differences(
          expected[key],
          actual[key],
          `${pointer}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`
        )
      )
    );
  }
  return Object.freeze([{ path: pointer || '/', expected, actual }]);
};

export const compareClientCredentialsProjections = (
  expected: ClientCredentialsProjection,
  actual: ClientCredentialsProjection
): readonly ClientCredentialsDifference[] => differences(expected, actual);

const clone = <Value>(value: Value): Value => {
  if (Array.isArray(value)) {
    return value.map((entry) => clone(entry)) as Value;
  }
  if (plain(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, clone(nested)])
    ) as Value;
  }
  return value;
};

const requireDifference = (
  name: ClientCredentialsControlResult['name'],
  expectedPointer: string,
  expected: unknown,
  actual: unknown
): ClientCredentialsControlResult => {
  const found = differences(expected, actual);
  if (!found.some(({ path }) => path === expectedPointer)) {
    return fail();
  }
  return Object.freeze({ name, pointer: expectedPointer, detected: true });
};

const requireDiscoveryOrderDifference = (
  expected: readonly string[],
  actual: readonly string[]
): ClientCredentialsControlResult => {
  const found = differences(expected, actual);
  if (
    found.length !== 2 ||
    found[0]?.path !== '/0' ||
    found[1]?.path !== '/1' ||
    [...expected].toSorted().some((value, index) => value !== [...actual].toSorted()[index])
  ) {
    return fail();
  }
  return Object.freeze({
    name: 'discovery-grant-order',
    pointer: '/0',
    detected: true,
  });
};

export const runClientCredentialsNegativeControls = (
  input: Readonly<{
    success: ClientCredentialsProjection;
    authenticationError: ClientCredentialsProjection;
    discoveryGrantTypes: readonly string[];
  }>
): readonly ClientCredentialsControlResult[] => {
  if (
    input.success.jwt === null ||
    input.authenticationError.jwt !== null ||
    input.discoveryGrantTypes.length < 2 ||
    !input.discoveryGrantTypes.includes('client_credentials')
  ) {
    return fail();
  }
  const mutate = (
    source: ClientCredentialsProjection,
    apply: (copy: any) => void
  ): ClientCredentialsProjection => {
    const copy = clone(source);
    apply(copy);
    return copy;
  };
  const controls = [
    requireDifference(
      'status',
      '/http/status',
      input.success,
      mutate(input.success, (copy) => {
        copy.http.status = 201;
      })
    ),
    requireDifference(
      'challenge',
      '/http/headers/www-authenticate',
      input.authenticationError,
      mutate(input.authenticationError, (copy) => {
        copy.http.headers['www-authenticate'] = 'Basic realm="changed"';
      })
    ),
    requireDifference(
      'error',
      '/http/body/error',
      input.authenticationError,
      mutate(input.authenticationError, (copy) => {
        copy.http.body.error = 'changed';
      })
    ),
    requireDifference(
      'audience',
      '/jwt/claims/aud',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.claims.aud = '<resource.default>';
      })
    ),
    requireDifference(
      'scope',
      '/jwt/claims/scope',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.claims.scope = 'changed';
      })
    ),
    requireDifference(
      'client-id',
      '/jwt/claims/client_id',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.claims.client_id = '<client.post>';
      })
    ),
    requireDifference(
      'organization-id',
      '/jwt/claims/organization_id',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.claims.organization_id = '<organization.changed>';
      })
    ),
    requireDifference(
      'typ',
      '/jwt/header/typ',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.header.typ = 'JWT';
      })
    ),
    requireDifference(
      'alg',
      '/jwt/header/alg',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.header.alg = 'RS256';
      })
    ),
    requireDifference(
      'kid',
      '/jwt/header/kid',
      input.success,
      mutate(input.success, (copy) => {
        copy.jwt.header.kid = '<changed-key>';
      })
    ),
    requireDiscoveryOrderDifference(input.discoveryGrantTypes, [
      input.discoveryGrantTypes[1]!,
      input.discoveryGrantTypes[0]!,
      ...input.discoveryGrantTypes.slice(2),
    ]),
    requireDifference(
      'unexpected-field',
      '/unexpected',
      input.success,
      (() => {
        const copy = clone(input.success) as any;
        copy.unexpected = true;
        return copy;
      })()
    ),
  ];
  return Object.freeze(controls);
};

export const assertDiscoveryGrantContract = (
  grantTypes: unknown,
  expectedAppend: readonly ['client_credentials'],
  target: TargetConfig['label']
): readonly string[] => {
  const expected = Object.freeze(['authorization_code', 'refresh_token', expectedAppend[0]]);
  if (
    !Array.isArray(grantTypes) ||
    grantTypes.some((value) => typeof value !== 'string') ||
    new Set(grantTypes).size !== grantTypes.length
  ) {
    return fail();
  }
  const values = grantTypes as string[];
  const selected = values.filter((value) => expected.includes(value));
  if (
    !isDeepStrictEqual(selected, expected) ||
    (target === 'candidate' && !isDeepStrictEqual(values, expected))
  ) {
    return fail();
  }
  return expected;
};

export const assertDiscoveryAbsentFieldsContract = (
  discovery: Readonly<Record<string, unknown>>,
  expectedAbsent: readonly string[],
  target: TargetConfig['label']
): readonly string[] => {
  if (target === 'candidate' && expectedAbsent.some((field) => Object.hasOwn(discovery, field))) {
    return fail();
  }
  return Object.freeze([...expectedAbsent]);
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types, @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-return */
