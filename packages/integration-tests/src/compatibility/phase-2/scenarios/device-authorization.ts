/* eslint-disable complexity, max-lines, no-restricted-syntax, no-await-in-loop, unicorn/no-object-as-default-parameter, @silverhand/fp/no-mutating-methods, unicorn/no-array-callback-reference, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-delete, @typescript-eslint/require-array-sort-compare, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unnecessary-condition -- The registry is intentionally explicit: every closed profile ID owns one real wire/state plan. */
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import {
  createDeviceAuthorizationTransportLease,
  type DeviceAuthorizationProjection,
  type DeviceAuthorizationRequest,
  type DeviceAuthorizationTransportLease,
  type DeviceLifecycleProjection,
} from '../clients/device-authorization.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2DifferentialScenarioId, Phase2ProfileRegistries } from '../profile.js';
import {
  assertDeviceAuthorizationEvidenceIsSanitized,
  compareDeviceAuthorizationProjections,
  projectDeviceCredentials,
  type DeviceCredentialProjection,
  type DeviceCredentialProjectionInput,
} from '../projections/device-authorization.js';

export const deviceAuthorizationScenarioIds = Object.freeze([
  'device-authorization.urlencoded-success',
  'device-authorization.json-object-success',
  'device-authorization.missing-client',
  'device-authorization.unknown-client',
  'device-authorization.ineligible-web-client',
  'device-authorization.confidential-client',
  'device-authorization.public-client-basic-rejected',
  'device-authorization.public-client-secret-post-rejected',
  'device-authorization.missing-device-grant',
  'device-authorization.explicit-resource',
  'device-authorization.unknown-resource',
  'device-authorization.organization',
  'device-authorization.unassociated-organization',
  'device-authorization.absent-scope',
  'device-authorization.empty-scope',
  'device-authorization.unknown-scope',
  'device-authorization.duplicate-client',
  'device-authorization.duplicate-resource',
  'device-authorization.duplicate-scope',
  'device-authorization.malformed-form',
  'device-authorization.malformed-json',
  'device-authorization.unsupported-parameter',
  'device-authorization.unknown-extension',
  'device-authorization.ui-locales',
  'device-authorization.json-array-rejected',
  'device-authorization.text-body-rejected',
  'device-authorization.query-only-rejected',
  'device-verification.shortcut-redirect',
  'device-verification.manual-entry',
  'device-verification.complete-url-entry',
  'device-verification.missing-code',
  'device-verification.malformed-code',
  'device-verification.unknown-code',
  'device-verification.expired-code',
  'device-verification.already-used-code',
  'device-verification.invalid-xsrf',
  'device-verification.cross-cookie-xsrf',
  'device-verification.abort',
  'device-verification.confirmation',
  'device-verification.confirmed-sign-in-redirect',
  'device-token.pending-poll',
  'device-token.in-flight-poll',
  'device-consent.first-party-matching-grant-required',
  'device-consent.third-party-redirect-absent',
  'device-token.denied-poll',
  'device-consent.approval',
  'device-verification.success-page',
  'device-verification.completed-cookie-cleanup',
  'device-token.openid-issuance',
  'device-token.id-token-signature-and-claims',
  'device-token.userinfo',
  'device-token.offline-refresh-rotation',
  'device-token.offline-refresh-after-logout',
  'device-token.resource-authority',
  'device-token.organization-authority',
  'device-token.refresh-resource-selection',
  'device-token.refresh-organization-selection',
  'device-token.session-bound-expiry',
  'device-token.client-mismatch',
  'device-token.unknown-code',
  'device-token.expired-code',
  'device-token.consumed-replay',
  'device-token.concurrent-reference-multi-winner',
  'device-token-status.access-introspection',
  'device-token-status.access-revocation',
  'device-token-status.refresh-introspection',
  'device-token-status.refresh-revocation',
  'device-discovery.oidc',
  'device-discovery.oauth',
] as const satisfies readonly Phase2DifferentialScenarioId[]);

export type DeviceAuthorizationScenarioId = (typeof deviceAuthorizationScenarioIds)[number];
export type DeviceScenarioProjection =
  | DeviceAuthorizationProjection
  | DeviceLifecycleProjection
  | DeviceCredentialProjection
  | DeviceVerificationFollowProjection
  | DeviceConsentSequenceProjection
  | DeviceConcurrencyProjection
  | DeviceTokenLifecycleProjection;

export type DeviceConsentSequenceProjection = Readonly<{
  kind: 'device-consent-sequence';
  mode: 'first-party-matching-grant' | 'third-party';
  firstIssued?: DeviceAuthorizationProjection;
  consent: DeviceLifecycleProjection;
  completion: DeviceLifecycleProjection;
}>;

export type DeviceVerificationFollowProjection = Readonly<{
  kind: 'device-verification-follow';
  redirect: DeviceAuthorizationProjection;
  terminal: DeviceAuthorizationProjection;
}>;

export type DeviceConcurrencyProjection = Readonly<{
  kind: 'device-concurrency';
  target: 'oracle' | 'candidate';
  referenceExpectedMultiWinner: true;
  trials: readonly [DeviceConcurrencyTrial, DeviceConcurrencyTrial, DeviceConcurrencyTrial];
}>;

type DeviceConcurrencyTrial = Readonly<{
  winnerCount: number;
  responses: readonly [DeviceAuthorizationProjection, DeviceAuthorizationProjection];
}>;

export type DeviceTokenLifecycleProjection = Readonly<{
  kind: 'device-token-lifecycle';
  mode: 'access-revocation' | 'refresh-revocation' | 'session-expiry';
  before: DeviceLifecycleProjection;
  action?: DeviceLifecycleProjection;
  after: DeviceLifecycleProjection;
  siblingBefore?: DeviceLifecycleProjection;
  siblingAfter?: DeviceLifecycleProjection;
  stateTransition?: 'session-expired';
}>;

export type DeviceScenarioStateAction = 'expire' | 'consume' | 'expire-session';

export type DeviceScenarioHandle = Readonly<{
  capture(): Promise<void>;
  transition(action: DeviceScenarioStateAction): Promise<void>;
}>;

export type DeviceScenarioStateDriver = Readonly<{
  withDeviceHandle<Result>(
    scenarioId: DeviceAuthorizationScenarioId,
    fixture: ProvisionedPhase2Fixture,
    use: (handle: DeviceScenarioHandle) => Result | Promise<Result>
  ): Promise<Result>;
}>;

export type DeviceAuthorizationScenarioRuntime = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  jwks: Readonly<JSONWebKeySet>;
  state: DeviceScenarioStateDriver;
  fetch?: typeof fetch;
  createTransport?: typeof createDeviceAuthorizationTransportLease;
  projectCredentials?: (
    input: DeviceCredentialProjectionInput
  ) => Promise<DeviceCredentialProjection>;
  concurrencyBarrierTimeoutMs?: number;
}>;

export type DeviceAuthorizationScenarioResult = Readonly<{
  id: DeviceAuthorizationScenarioId;
  projection: DeviceScenarioProjection;
}>;

export type DeviceAuthorizationScenario = Readonly<{
  id: DeviceAuthorizationScenarioId;
  run(runtime: DeviceAuthorizationScenarioRuntime): Promise<DeviceAuthorizationScenarioResult>;
}>;

export type UsedCodeStep =
  | 'approval'
  | 'approval-authorize'
  | 'approval-capture'
  | 'approval-verify'
  | 'approval-experience-open'
  | 'approval-password'
  | 'approval-identification'
  | 'approval-experience-submit'
  | 'approval-resume-initial'
  | 'approval-consent-read'
  | 'approval-consent-write'
  | 'approval-resume-final'
  | 'transition'
  | 'verification-get'
  | 'verification-post';

const usedCodeApprovalFailurePattern =
  /^Invalid Phase 2 device already-used-code step \(approval-(?:authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final)\)$/u;

export const runUsedCodeStep = async <Result>(
  step: UsedCodeStep,
  operation: () => Result | Promise<Result>
): Promise<Result> => {
  try {
    return await operation();
  } catch (error) {
    if (
      step === 'approval' &&
      error instanceof Error &&
      usedCodeApprovalFailurePattern.test(error.message)
    ) {
      throw error;
    }
    throw new TypeError(`Invalid Phase 2 device already-used-code step (${step})`);
  }
};

const runApprovalStep = async <Result>(
  trace: boolean,
  step: Extract<UsedCodeStep, `approval-${string}`>,
  operation: () => Result | Promise<Result>
): Promise<Result> => (trace ? runUsedCodeStep(step, operation) : operation());

export type DeviceAuthorizationControlResult = Readonly<{
  name: 'status' | 'path' | 'cookie-clearing' | 'oauth' | 'claimKeys' | 'discovery-fields';
  pointer: string;
  detected: true;
}>;

export type DeviceFlowOptions = Readonly<{
  client: 'firstParty' | 'thirdParty';
  scope?: string;
  traceUsedCodeApproval?: boolean;
  resource?: string;
  organizationId?: string;
}>;

const diagnostic = 'Invalid Phase 2 device authorization scenario';
const devicePrefixes = [
  'device-authorization.',
  'device-verification.',
  'device-consent.',
  'device-token.',
  'device-token-status.',
  'device-discovery.',
];

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const isDeviceScenario = (value: string): boolean =>
  devicePrefixes.some((prefix) => value.startsWith(prefix));

const clientId = (
  runtime: DeviceAuthorizationScenarioRuntime,
  client: DeviceFlowOptions['client']
) => runtime.fixture.public.deviceClients[client].id;

const authorizationRequest = (
  runtime: DeviceAuthorizationScenarioRuntime,
  id: DeviceAuthorizationScenarioId,
  confidentialSecret?: string
): DeviceAuthorizationRequest => {
  const fixture = runtime.fixture.public;
  const first = fixture.deviceClients.firstParty.id;
  switch (id) {
    case 'device-authorization.json-object-success': {
      return { encoding: 'json', fields: { client_id: first, scope: 'openid' } };
    }
    case 'device-authorization.missing-client': {
      return { encoding: 'form', fields: [['scope', 'openid']] };
    }
    case 'device-authorization.unknown-client': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', 'unknown-device-client'],
          ['scope', 'openid'],
        ],
      };
    }
    case 'device-authorization.ineligible-web-client': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', fixture.deviceClients.ineligibleWeb.id],
          ['scope', 'openid'],
        ],
      };
    }
    case 'device-authorization.confidential-client': {
      if (!runtime.fixture.status || confidentialSecret === undefined) {
        return fail();
      }
      return {
        encoding: 'form',
        fields: [
          ['client_id', runtime.fixture.status.confidentialClient.id],
          ['scope', 'openid'],
        ],
        transport: {
          proof: {
            method: 'basic',
            clientId: runtime.fixture.status.confidentialClient.id,
            clientSecret: confidentialSecret,
          },
        },
      };
    }
    case 'device-authorization.public-client-basic-rejected': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['scope', 'openid'],
        ],
        transport: { proof: { method: 'basic', clientId: first, clientSecret: '' } },
      };
    }
    case 'device-authorization.public-client-secret-post-rejected': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['client_secret', 'incorrect-secret'],
          ['scope', 'openid'],
        ],
      };
    }
    case 'device-authorization.missing-device-grant': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', fixture.deviceClients.missingGrant.id],
          ['scope', 'openid'],
        ],
      };
    }
    case 'device-authorization.explicit-resource': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['resource', fixture.resources.primary.indicator],
          ['scope', 'openid read'],
        ],
      };
    }
    case 'device-authorization.unknown-resource': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['resource', 'https://unknown.invalid/api'],
        ],
      };
    }
    case 'device-authorization.organization': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['organization_id', fixture.organization.id],
          ['scope', `openid ${fixture.organization.scopeName}`],
        ],
      };
    }
    case 'device-authorization.unassociated-organization': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', fixture.deviceClients.thirdParty.id],
          ['organization_id', fixture.organization.id],
        ],
      };
    }
    case 'device-authorization.absent-scope': {
      return { encoding: 'form', fields: [['client_id', first]] };
    }
    case 'device-authorization.empty-scope': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['scope', ''],
        ],
      };
    }
    case 'device-authorization.unknown-scope': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['scope', 'unknown_scope'],
        ],
      };
    }
    case 'device-authorization.duplicate-client': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['client_id', first],
          ['scope', 'openid'],
        ],
      };
    }
    case 'device-authorization.duplicate-resource': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['resource', fixture.resources.primary.indicator],
          ['resource', fixture.resources.primary.indicator],
        ],
      };
    }
    case 'device-authorization.duplicate-scope': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['scope', 'openid'],
          ['scope', 'profile'],
        ],
      };
    }
    case 'device-authorization.malformed-form': {
      return {
        encoding: 'raw',
        mediaType: 'application/x-www-form-urlencoded',
        body: 'client_id=%E0%A4%A&scope=openid',
        sensitiveFragments: [],
      };
    }
    case 'device-authorization.malformed-json': {
      return {
        encoding: 'raw',
        mediaType: 'application/json',
        body: '{"client_id":',
        sensitiveFragments: [],
      };
    }
    case 'device-authorization.unsupported-parameter': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['request_uri', 'x'],
        ],
      };
    }
    case 'device-authorization.unknown-extension': {
      return {
        encoding: 'raw',
        mediaType: 'application/x-www-form-urlencoded',
        body: `client_id=${encodeURIComponent(first)}&phase2_extension=x`,
        sensitiveFragments: [],
      };
    }
    case 'device-authorization.ui-locales': {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['ui_locales', 'ja en'],
        ],
      };
    }
    case 'device-authorization.json-array-rejected': {
      return {
        encoding: 'raw',
        mediaType: 'application/json',
        body: `[{"client_id":"${first}"}]`,
        sensitiveFragments: [],
      };
    }
    case 'device-authorization.text-body-rejected': {
      return {
        encoding: 'raw',
        mediaType: 'text/plain',
        body: `client_id=${first}`,
        sensitiveFragments: [],
      };
    }
    case 'device-authorization.query-only-rejected': {
      return {
        encoding: 'form',
        fields: [],
        transport: {
          query: [
            ['client_id', first],
            ['scope', 'openid'],
          ],
        },
      };
    }
    default: {
      return {
        encoding: 'form',
        fields: [
          ['client_id', first],
          ['scope', 'openid profile'],
        ],
      };
    }
  }
};

export const startDeviceAuthorization = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime,
  options: DeviceFlowOptions = { client: 'firstParty' }
): Promise<DeviceAuthorizationProjection> => {
  const fields: Array<readonly ['client_id' | 'scope' | 'resource' | 'organization_id', string]> = [
    ['client_id', clientId(runtime, options.client)],
  ];
  if (options.scope !== undefined) {
    fields.push(['scope', options.scope]);
  }
  if (options.resource !== undefined) {
    fields.push(['resource', options.resource]);
  }
  if (options.organizationId !== undefined) {
    fields.push(['organization_id', options.organizationId]);
  }
  return lease.requestAuthorization({ encoding: 'form', fields });
};

const confirmVerification = async (
  lease: DeviceAuthorizationTransportLease
): Promise<DeviceAuthorizationProjection> => {
  await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
  return lease.requestVerification({
    method: 'POST',
    path: '/oidc/device',
    fields: { xsrf: { stored: 'xsrf' }, user_code: { stored: 'user-code' }, confirm: 'yes' },
  });
};

export const completeDeviceApproval = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime,
  traceUsedCodeApproval = false
): Promise<
  Readonly<{
    consentRead: DeviceLifecycleProjection;
    consent: DeviceLifecycleProjection;
    resume: DeviceLifecycleProjection;
  }>
> => {
  await runApprovalStep(traceUsedCodeApproval, 'approval-verify', async () =>
    confirmVerification(lease)
  );
  if (!runtime.fixture.status) {
    return fail();
  }
  await runApprovalStep(traceUsedCodeApproval, 'approval-experience-open', async () =>
    lease.requestLifecycle({ kind: 'experience-open', method: 'PUT' })
  );
  await runApprovalStep(traceUsedCodeApproval, 'approval-password', async () =>
    runtime.fixture.withSecretLease(async (secret) => {
      const password = secret.getSubjectPassword?.() ?? fail();
      return lease.requestLifecycle({
        kind: 'password-verification',
        method: 'POST',
        username: runtime.fixture.status?.user.username ?? fail(),
        password,
      });
    })
  );
  await runApprovalStep(traceUsedCodeApproval, 'approval-identification', async () =>
    lease.requestLifecycle({ kind: 'identification', method: 'POST' })
  );
  await runApprovalStep(traceUsedCodeApproval, 'approval-experience-submit', async () =>
    lease.requestLifecycle({ kind: 'experience-submit', method: 'POST' })
  );
  await runApprovalStep(traceUsedCodeApproval, 'approval-resume-initial', async () =>
    lease.requestLifecycle({ kind: 'resume', method: 'GET' })
  );
  const consentRead = await runApprovalStep(
    traceUsedCodeApproval,
    'approval-consent-read',
    async () => lease.requestLifecycle({ kind: 'consent-read', method: 'GET' })
  );
  const consent = await runApprovalStep(traceUsedCodeApproval, 'approval-consent-write', async () =>
    lease.requestLifecycle({ kind: 'consent-write', method: 'POST' })
  );
  const resume = await runApprovalStep(traceUsedCodeApproval, 'approval-resume-final', async () =>
    lease.requestLifecycle({ kind: 'resume', method: 'GET' })
  );
  return Object.freeze({ consentRead, consent, resume });
};

export const approveDeviceAuthorization = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime,
  options: DeviceFlowOptions,
  afterAuthorization?: () => Promise<void>
): Promise<
  Readonly<{
    consentRead: DeviceLifecycleProjection;
    consent: DeviceLifecycleProjection;
    resume: DeviceLifecycleProjection;
  }>
> => {
  const traceUsedCodeApproval = options.traceUsedCodeApproval ?? false;
  await runApprovalStep(traceUsedCodeApproval, 'approval-authorize', async () =>
    startDeviceAuthorization(lease, runtime, options)
  );
  await runApprovalStep(traceUsedCodeApproval, 'approval-capture', async () =>
    afterAuthorization?.()
  );
  return completeDeviceApproval(lease, runtime, traceUsedCodeApproval);
};

export const issueDeviceAuthorization = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime,
  options: DeviceFlowOptions,
  afterAuthorization?: () => Promise<void>
): Promise<DeviceAuthorizationProjection> => {
  await approveDeviceAuthorization(lease, runtime, options, afterAuthorization);
  return lease.pollToken({
    proof: { method: 'public', clientId: clientId(runtime, options.client) },
  });
};

const introspect = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime,
  token: 'access' | 'refresh'
): Promise<DeviceLifecycleProjection> =>
  lease.requestLifecycle({
    kind: 'introspection',
    method: 'POST',
    proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
    token,
    expectedSubjectId: runtime.fixture.status?.user.id ?? fail(),
    expectedClientId: clientId(runtime, 'firstParty'),
  });

export const createDeviceConcurrencyBarrierFetch = (
  source: typeof fetch | undefined,
  timeoutMs = 10_000
): Readonly<{ fetch: typeof fetch; abort(error: unknown): void }> => {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) {
    return fail();
  }
  const requestFetch = source ?? fetch;
  let waiting = 0;
  let gateOpen = true;
  let releaseGate: (() => void) | undefined;
  let rejectGate: ((error: unknown) => void) | undefined;
  const shared = new AbortController();
  const gate = new Promise<void>((resolve, reject) => {
    releaseGate = resolve;
    rejectGate = reject;
  });
  const consumeRejectedGate = async () => {
    try {
      await gate;
    } catch {}
  };
  void consumeRejectedGate();
  const timer = setTimeout(() => {
    reject(new TypeError(diagnostic));
  }, timeoutMs);
  const release = () => {
    if (gateOpen) {
      gateOpen = false;
      clearTimeout(timer);
      releaseGate?.();
    }
  };
  const reject = (error: unknown) => {
    if (!shared.signal.aborted) {
      shared.abort(error);
    }
    if (gateOpen) {
      gateOpen = false;
      clearTimeout(timer);
      rejectGate?.(error);
    }
  };
  return Object.freeze({
    fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
      waiting += 1;
      if (waiting > 2) {
        const error = new TypeError(diagnostic);
        reject(error);
        throw error;
      }
      const participant = init?.signal;
      const onAbort = () => {
        reject(participant?.reason ?? new TypeError(diagnostic));
      };
      participant?.addEventListener('abort', onAbort, { once: true });
      if (waiting === 2) {
        release();
      }
      try {
        await gate;
        return await requestFetch(input, {
          ...init,
          signal: participant ? AbortSignal.any([participant, shared.signal]) : shared.signal,
        });
      } catch (error: unknown) {
        reject(error);
        throw error;
      } finally {
        participant?.removeEventListener('abort', onAbort);
      }
    },
    abort: reject,
  });
};

export const executeDeviceConcurrencyTrial = async (
  runtime: DeviceAuthorizationScenarioRuntime,
  createTransport: typeof createDeviceAuthorizationTransportLease
): Promise<DeviceConcurrencyTrial> => {
  const flow = createTransport({ target: runtime.target, fetch: runtime.fetch });
  try {
    await approveDeviceAuthorization(flow, runtime, {
      client: 'firstParty',
      scope: 'openid profile',
    });
    return await flow.withDeviceCodeLease(async (secret) => {
      const barrier = createDeviceConcurrencyBarrierFetch(
        runtime.fetch,
        runtime.concurrencyBarrierTimeoutMs
      );
      const first = createTransport({ target: runtime.target, fetch: barrier.fetch });
      const second = createTransport({ target: runtime.target, fetch: barrier.fetch });
      try {
        const request = {
          proof: { method: 'public' as const, clientId: clientId(runtime, 'firstParty') },
          deviceCode: secret.getDeviceCode(),
        };
        let responses: DeviceAuthorizationProjection[];
        try {
          responses = await Promise.all([first.pollToken(request), second.pollToken(request)]);
        } catch (error: unknown) {
          barrier.abort(error);
          throw error;
        }
        const pair = responses as [DeviceAuthorizationProjection, DeviceAuthorizationProjection];
        return Object.freeze({
          winnerCount: pair.filter(({ status }) => status === 200).length,
          responses: Object.freeze(pair),
        });
      } finally {
        barrier.abort(new TypeError(diagnostic));
        first.clear();
        second.clear();
      }
    });
  } finally {
    flow.clear();
  }
};

const projectIssuedCredentials = async (
  lease: DeviceAuthorizationTransportLease,
  runtime: DeviceAuthorizationScenarioRuntime,
  options: DeviceFlowOptions,
  expected: Readonly<{
    accessFormat?: 'opaque' | 'verified-jwt';
    audience?: string;
    scopes?: readonly string[];
    accessOrganizationIdRequired?: boolean;
  }> = {}
): Promise<DeviceCredentialProjection> => {
  const { status } = runtime.fixture;
  if (!status) {
    return fail();
  }
  const project = runtime.projectCredentials ?? projectDeviceCredentials;
  return lease.withCredentialLease(async (credentials) => {
    const accessToken = credentials.getAccessToken();
    if (!accessToken) {
      return fail();
    }
    return project({
      target: runtime.target,
      jwks: runtime.jwks,
      accessToken,
      refreshToken: credentials.getRefreshToken(),
      idToken: credentials.getIdToken(),
      previousRefreshToken: credentials.getPreviousRefreshToken(),
      expected: {
        clientId: clientId(runtime, options.client),
        subjectId: status.user.id,
        audience: expected.audience ?? options.resource ?? clientId(runtime, options.client),
        ...(expected.accessFormat === undefined ? {} : { accessFormat: expected.accessFormat }),
        ...(expected.scopes === undefined
          ? options.scope === undefined
            ? {}
            : { scopes: options.scope.split(' ').sort() }
          : { scopes: expected.scopes }),
        ...(options.resource === undefined ? {} : { resource: options.resource }),
        ...(options.organizationId === undefined ? {} : { organizationId: options.organizationId }),
        ...(expected.accessOrganizationIdRequired === undefined
          ? {}
          : { accessOrganizationIdRequired: expected.accessOrganizationIdRequired }),
      },
    });
  });
};

const execute = async (
  id: DeviceAuthorizationScenarioId,
  runtime: DeviceAuthorizationScenarioRuntime,
  lease: DeviceAuthorizationTransportLease,
  createTransport: typeof createDeviceAuthorizationTransportLease
): Promise<DeviceScenarioProjection> => {
  if (id.startsWith('device-authorization.')) {
    if (id === 'device-authorization.confidential-client') {
      return runtime.fixture.withSecretLease(async (secret) =>
        lease.requestAuthorization(
          authorizationRequest(runtime, id, secret.getStatusClientSecret())
        )
      );
    }
    return lease.requestAuthorization(authorizationRequest(runtime, id));
  }
  if (id === 'device-verification.shortcut-redirect') {
    return lease.requestVerification({ method: 'GET', path: '/device' });
  }
  if (id === 'device-verification.manual-entry') {
    await startDeviceAuthorization(lease, runtime);
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    return lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: { xsrf: { stored: 'xsrf' }, user_code: { stored: 'user-code' } },
    });
  }
  if (id === 'device-verification.complete-url-entry') {
    await startDeviceAuthorization(lease, runtime);
    const redirect = await lease.requestVerification({
      method: 'GET',
      path: '/device',
      userCode: { stored: 'user-code' },
    });
    const terminal = await lease.requestVerification({ method: 'FOLLOW_PROJECTED_LOCATION' });
    return Object.freeze({ kind: 'device-verification-follow', redirect, terminal });
  }
  if (id === 'device-verification.missing-code') {
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    return lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: { xsrf: { stored: 'xsrf' } },
    });
  }
  if (id === 'device-verification.malformed-code' || id === 'device-verification.unknown-code') {
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    return lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: {
        xsrf: { stored: 'xsrf' },
        user_code: id.endsWith('malformed-code') ? 'bad' : 'ZZZZ-ZZZZ',
      },
    });
  }
  if (id === 'device-verification.expired-code' || id === 'device-verification.already-used-code') {
    return runtime.state.withDeviceHandle(id, runtime.fixture, async (handle) => {
      if (id.endsWith('already-used-code')) {
        await runUsedCodeStep('approval', async () =>
          approveDeviceAuthorization(
            lease,
            runtime,
            { client: 'firstParty', scope: 'openid profile', traceUsedCodeApproval: true },
            handle.capture
          )
        );
        await runUsedCodeStep('transition', async () => handle.transition('consume'));
        await runUsedCodeStep('verification-get', async () =>
          lease.requestVerification({ method: 'GET', path: '/oidc/device' })
        );
        return runUsedCodeStep('verification-post', async () =>
          lease.requestVerification({
            method: 'POST',
            path: '/oidc/device',
            fields: {
              xsrf: { stored: 'xsrf' },
              user_code: { stored: 'user-code' },
              confirm: 'yes',
            },
          })
        );
      }
      await startDeviceAuthorization(lease, runtime);
      await handle.capture();
      await handle.transition('expire');
      await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
      return lease.requestVerification({
        method: 'POST',
        path: '/oidc/device',
        fields: {
          xsrf: { stored: 'xsrf' },
          user_code: { stored: 'user-code' },
          confirm: 'yes',
        },
      });
    });
  }
  if (id === 'device-verification.invalid-xsrf') {
    await startDeviceAuthorization(lease, runtime);
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    return lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: { xsrf: 'phase2-invalid-xsrf', user_code: { stored: 'user-code' }, confirm: 'yes' },
    });
  }
  if (id === 'device-verification.cross-cookie-xsrf') {
    await startDeviceAuthorization(lease, runtime);
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    const other = createTransport({ target: runtime.target, fetch: runtime.fetch });
    try {
      await other.requestVerification({ method: 'GET', path: '/oidc/device' });
      return await lease.withVerificationUserCodeLease(async (secrets) =>
        other.requestVerification({
          method: 'POST',
          path: '/oidc/device',
          fields: {
            xsrf: secrets.getXsrf(),
            user_code: secrets.getUserCode(),
            confirm: 'yes',
          },
        })
      );
    } finally {
      other.clear();
    }
  }
  if (id === 'device-verification.abort' || id === 'device-token.denied-poll') {
    await startDeviceAuthorization(lease, runtime);
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    const denied = await lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: { xsrf: { stored: 'xsrf' }, user_code: { stored: 'user-code' }, abort: 'yes' },
    });
    return id === 'device-verification.abort'
      ? denied
      : lease.pollToken({ proof: { method: 'public', clientId: clientId(runtime, 'firstParty') } });
  }
  if (
    id === 'device-verification.confirmation' ||
    id === 'device-verification.confirmed-sign-in-redirect'
  ) {
    await startDeviceAuthorization(lease, runtime);
    await lease.requestVerification({ method: 'GET', path: '/oidc/device' });
    return lease.requestVerification({
      method: 'POST',
      path: '/oidc/device',
      fields: {
        xsrf: { stored: 'xsrf' },
        user_code: { stored: 'user-code' },
        ...(id === 'device-verification.confirmed-sign-in-redirect' ? { confirm: 'yes' } : {}),
      },
    });
  }
  if (id === 'device-token.pending-poll' || id === 'device-token.in-flight-poll') {
    await startDeviceAuthorization(lease, runtime);
    if (id.endsWith('in-flight-poll')) {
      await confirmVerification(lease);
    }
    return lease.pollToken({
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
    });
  }
  if (id.startsWith('device-consent.')) {
    if (id === 'device-consent.first-party-matching-grant-required') {
      const flow = {
        client: 'firstParty' as const,
        scope: 'openid offline_access profile',
      };
      const firstIssued = await issueDeviceAuthorization(lease, runtime, flow);
      const second = await approveDeviceAuthorization(lease, runtime, flow);
      return publishDeviceScenarioProjection(
        Object.freeze({
          kind: 'device-consent-sequence' as const,
          mode: 'first-party-matching-grant' as const,
          firstIssued,
          consent: second.consentRead,
          completion: second.resume,
        })
      );
    }
    const flow =
      id === 'device-consent.third-party-redirect-absent'
        ? { client: 'thirdParty' as const, scope: 'openid profile' }
        : { client: 'firstParty' as const, scope: 'openid profile' };
    const approved = await approveDeviceAuthorization(lease, runtime, flow);
    return id === 'device-consent.third-party-redirect-absent'
      ? publishDeviceScenarioProjection(
          Object.freeze({
            kind: 'device-consent-sequence' as const,
            mode: 'third-party' as const,
            consent: approved.consentRead,
            completion: approved.resume,
          })
        )
      : approved.resume;
  }
  if (
    id === 'device-verification.success-page' ||
    id === 'device-verification.completed-cookie-cleanup'
  ) {
    const approved = await approveDeviceAuthorization(lease, runtime, {
      client: 'firstParty',
      scope: 'openid profile',
    });
    return id.endsWith('success-page')
      ? lease.requestLifecycle({ kind: 'verification-success', method: 'GET' })
      : approved.resume;
  }
  if (id === 'device-token.unknown-code') {
    return lease.pollToken({
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
      deviceCode: 'phase2-unknown-device-code',
    });
  }
  if (id === 'device-token.expired-code') {
    return runtime.state.withDeviceHandle(id, runtime.fixture, async (handle) => {
      await startDeviceAuthorization(lease, runtime);
      await handle.capture();
      await handle.transition('expire');
      return lease.pollToken({
        proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
      });
    });
  }
  if (id === 'device-token.client-mismatch') {
    await startDeviceAuthorization(lease, runtime);
    return lease.pollToken({
      proof: { method: 'public', clientId: clientId(runtime, 'thirdParty') },
    });
  }
  if (id === 'device-token.consumed-replay') {
    await issueDeviceAuthorization(lease, runtime, {
      client: 'firstParty',
      scope: 'openid profile',
    });
    return lease.pollToken({
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
    });
  }
  if (id === 'device-token.concurrent-reference-multi-winner') {
    const trials: DeviceConcurrencyTrial[] = [];
    for (let index = 0; index < 3; index += 1) {
      trials.push(await executeDeviceConcurrencyTrial(runtime, createTransport));
    }
    return publishDeviceScenarioProjection(
      Object.freeze({
        kind: 'device-concurrency',
        target: runtime.target.label,
        referenceExpectedMultiWinner: true,
        trials: Object.freeze(trials) as unknown as DeviceConcurrencyProjection['trials'],
      })
    );
  }
  if (id === 'device-token.session-bound-expiry') {
    return runtime.state.withDeviceHandle(id, runtime.fixture, async (handle) => {
      await issueDeviceAuthorization(
        lease,
        runtime,
        { client: 'firstParty', scope: 'openid profile' },
        handle.capture
      );
      const before = await lease.requestLifecycle({
        kind: 'userinfo',
        method: 'GET',
        expectedSubjectId: runtime.fixture.status?.user.id ?? fail(),
      });
      const siblingBefore = await introspect(lease, runtime, 'access');
      await handle.transition('expire-session');
      const after = await lease.requestLifecycle({
        kind: 'userinfo',
        method: 'GET',
        expectedSubjectId: runtime.fixture.status?.user.id ?? fail(),
      });
      const siblingAfter = await introspect(lease, runtime, 'access');
      return publishDeviceScenarioProjection(
        Object.freeze({
          kind: 'device-token-lifecycle',
          mode: 'session-expiry',
          before,
          after,
          siblingBefore,
          siblingAfter,
          stateTransition: 'session-expired',
        })
      );
    });
  }
  if (id === 'device-discovery.oidc') {
    return lease.requestLifecycle({ kind: 'oidc-discovery', method: 'GET' });
  }
  if (id === 'device-discovery.oauth') {
    return lease.requestLifecycle({ kind: 'oauth-discovery', method: 'GET' });
  }
  const resource = runtime.fixture.public.resources.primary.indicator;
  const organizationId = runtime.fixture.public.organization.id;
  const organizationScope =
    runtime.target.label === 'oracle'
      ? 'urn:logto:scope:organizations'
      : 'urn:aster:scope:organizations';
  const flow: DeviceFlowOptions = id.includes('organization')
    ? {
        client: 'firstParty',
        scope: `openid offline_access ${organizationScope}`,
        organizationId,
      }
    : id.includes('resource')
      ? { client: 'firstParty', scope: 'openid offline_access read', resource }
      : { client: 'firstParty', scope: 'openid offline_access profile email' };
  const issued = await issueDeviceAuthorization(lease, runtime, flow);
  if (id === 'device-token.openid-issuance') {
    return issued;
  }
  if (
    id === 'device-token.id-token-signature-and-claims' ||
    id === 'device-token.organization-authority'
  ) {
    return projectIssuedCredentials(lease, runtime, flow);
  }
  if (id === 'device-token.resource-authority') {
    return projectIssuedCredentials(lease, runtime, flow, { accessFormat: 'opaque' });
  }
  if (id === 'device-token.userinfo') {
    return lease.requestLifecycle({
      kind: 'userinfo',
      method: 'GET',
      expectedSubjectId: runtime.fixture.status?.user.id ?? fail(),
    });
  }
  if (id === 'device-token.offline-refresh-rotation') {
    return lease.requestLifecycle({
      kind: 'refresh',
      method: 'POST',
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
    });
  }
  if (id === 'device-token.refresh-resource-selection') {
    await lease.requestLifecycle({
      kind: 'refresh',
      method: 'POST',
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
      resource,
      scope: 'read',
    });
    return projectIssuedCredentials(
      lease,
      runtime,
      { client: 'firstParty' },
      { accessFormat: 'verified-jwt', audience: resource, scopes: ['read'] }
    );
  }
  if (id === 'device-token.refresh-organization-selection') {
    const refreshed = await lease.requestLifecycle({
      kind: 'refresh',
      method: 'POST',
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
      organizationId,
    });
    if (
      refreshed.kind !== 'refresh' ||
      refreshed.facts.marker !== 'tokens-refreshed' ||
      !refreshed.facts.idTokenIssued
    ) {
      return fail();
    }
    const organizationAudience = `${
      runtime.target.label === 'oracle' ? 'urn:logto:organization:' : 'urn:aster:organization:'
    }${organizationId}`;
    return projectIssuedCredentials(
      lease,
      runtime,
      { client: 'firstParty', organizationId },
      {
        accessFormat: 'verified-jwt',
        audience: organizationAudience,
        scopes: [],
        accessOrganizationIdRequired: false,
      }
    );
  }
  if (id === 'device-token.offline-refresh-after-logout') {
    await lease.requestLifecycle({
      kind: 'logout-open',
      method: 'GET',
      clientId: clientId(runtime, 'firstParty'),
    });
    await lease.requestLifecycle({ kind: 'logout-confirm', method: 'POST', confirm: true });
    return lease.requestLifecycle({
      kind: 'refresh',
      method: 'POST',
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
    });
  }
  if (id.startsWith('device-token-status.')) {
    const token = id.includes('refresh') ? 'refresh' : 'access';
    if (id.endsWith('revocation')) {
      const before = await introspect(lease, runtime, token);
      const siblingBefore = await introspect(
        lease,
        runtime,
        token === 'access' ? 'refresh' : 'access'
      );
      const action = await lease.requestLifecycle({
        kind: 'revocation',
        method: 'POST',
        proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
        token,
      });
      const after = await introspect(lease, runtime, token);
      const siblingAfter =
        token === 'access'
          ? await lease.requestLifecycle({
              kind: 'refresh',
              method: 'POST',
              proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
            })
          : await introspect(lease, runtime, 'access');
      return publishDeviceScenarioProjection(
        Object.freeze({
          kind: 'device-token-lifecycle',
          mode: token === 'access' ? 'access-revocation' : 'refresh-revocation',
          before,
          action,
          after,
          siblingBefore,
          siblingAfter,
        })
      );
    }
    return lease.requestLifecycle({
      kind: 'introspection',
      method: 'POST',
      proof: { method: 'public', clientId: clientId(runtime, 'firstParty') },
      token,
      expectedSubjectId: runtime.fixture.status?.user.id ?? fail(),
      expectedClientId: clientId(runtime, 'firstParty'),
    });
  }
  return fail();
};

export const createDeviceAuthorizationScenarioRegistry = (
  profile: Phase2ProfileRegistries
): readonly DeviceAuthorizationScenario[] => {
  const actual = profile.differentialScenarios.filter(isDeviceScenario);
  if (
    actual.length !== deviceAuthorizationScenarioIds.length ||
    actual.some((id, index) => id !== deviceAuthorizationScenarioIds[index])
  ) {
    return fail();
  }
  return Object.freeze(
    deviceAuthorizationScenarioIds.map((id) =>
      Object.freeze({
        id,
        run: async (runtime: DeviceAuthorizationScenarioRuntime) => {
          const createTransport =
            runtime.createTransport ?? createDeviceAuthorizationTransportLease;
          const lease = createTransport({ target: runtime.target, fetch: runtime.fetch });
          try {
            const projection = publishDeviceScenarioProjection(
              await execute(id, runtime, lease, createTransport),
              id
            );
            return Object.freeze({ id, projection });
          } finally {
            lease.clear();
          }
        },
      })
    )
  );
};

const exactProjectionKeys = (
  value: unknown,
  keys: readonly string[]
): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Reflect.ownKeys(value).length === keys.length &&
  Reflect.ownKeys(value).every((key) => typeof key === 'string' && keys.includes(key));

const validatePrimitiveProjection = (
  value: DeviceAuthorizationProjection | DeviceLifecycleProjection | DeviceCredentialProjection
): void => {
  compareDeviceAuthorizationProjections(value, value);
};

const cloneJsonProjection = (value: unknown): unknown => {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== value.length + 1 ||
      !keys.every(
        (key) =>
          key === 'length' ||
          (typeof key === 'string' &&
            Number.isSafeInteger(Number(key)) &&
            String(Number(key)) === key &&
            Number(key) < value.length)
      )
    ) {
      return fail();
    }
    return value.map((entry) => cloneJsonProjection(entry));
  }
  if (
    typeof value !== 'object' ||
    value === null ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  ) {
    return fail();
  }
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== 'string' ||
      descriptor === undefined ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, 'value') ||
      descriptor.value === undefined
    ) {
      return fail();
    }
    result[key] = cloneJsonProjection(descriptor.value);
  }
  return result;
};

const restoreUndefined = (value: Record<string, unknown>, keys: readonly string[]): void => {
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) {
      value[key] = undefined;
    }
  }
};

const projectionRecord = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

const restoreAuthorizationProjection = (projection: Record<string, unknown>): void => {
  restoreUndefined(projection, [
    'contentType',
    'challenge',
    'location',
    'userCodeShape',
    'deviceCodeShape',
    'expiresIn',
    'interval',
    'tokenType',
    'verificationUri',
    'verificationUriComplete',
    'experience',
  ]);
  const oauthError = projectionRecord(projection.oauthError);
  if (oauthError !== undefined) {
    restoreUndefined(oauthError, ['category', 'description']);
  }
  const userCodeShape = projectionRecord(projection.userCodeShape);
  if (userCodeShape !== undefined) {
    restoreUndefined(userCodeShape, ['separator']);
  }
  const experience = projectionRecord(projection.experience);
  if (experience !== undefined) {
    restoreUndefined(experience, ['title', 'formAction']);
  }
};

const restoreLifecycleProjection = (projection: Record<string, unknown>): void => {
  restoreUndefined(projection, ['contentType', 'challenge', 'location']);
  const oauthError = projectionRecord(projection.oauthError);
  if (oauthError !== undefined) {
    restoreUndefined(oauthError, ['category', 'description']);
  }
  const facts = projectionRecord(projection.facts);
  if (projection.kind === 'logout-open' && facts?.marker === 'logout-confirmation') {
    restoreUndefined(facts, ['title']);
  }
};

const restoreCredentialProjection = (projection: Record<string, unknown>): void => {
  restoreUndefined(projection, ['id', 'refresh']);
  const refresh = projectionRecord(projection.refresh);
  if (refresh !== undefined) {
    restoreUndefined(refresh, ['rotated']);
  }
};

const restorePrimitiveProjection = (projection: Record<string, unknown>): void => {
  if (Object.hasOwn(projection, 'kind')) {
    restoreLifecycleProjection(projection);
  } else if (Object.hasOwn(projection, 'keys')) {
    restoreAuthorizationProjection(projection);
  } else {
    restoreCredentialProjection(projection);
  }
};

const restoreConcurrencyProjection = (projection: Record<string, unknown>): void => {
  if (!Array.isArray(projection.trials)) {
    return;
  }
  for (const trialValue of projection.trials) {
    const trial = projectionRecord(trialValue);
    if (!Array.isArray(trial?.responses)) {
      continue;
    }
    for (const response of trial.responses) {
      const nested = projectionRecord(response);
      if (nested !== undefined) {
        restoreAuthorizationProjection(nested);
      }
    }
  }
};

const restoreProjectionGraph = (projection: Record<string, unknown>): void => {
  switch (projection.kind) {
    case 'device-verification-follow': {
      for (const key of ['redirect', 'terminal']) {
        const nested = projectionRecord(projection[key]);
        if (nested !== undefined) {
          restoreAuthorizationProjection(nested);
        }
      }
      return;
    }
    case 'device-consent-sequence': {
      const firstIssued = projectionRecord(projection.firstIssued);
      if (firstIssued !== undefined) {
        restoreAuthorizationProjection(firstIssued);
      }
      for (const key of ['consent', 'completion']) {
        const nested = projectionRecord(projection[key]);
        if (nested !== undefined) {
          restoreLifecycleProjection(nested);
        }
      }
      return;
    }
    case 'device-concurrency': {
      restoreConcurrencyProjection(projection);
      return;
    }
    case 'device-token-lifecycle': {
      for (const key of ['before', 'action', 'after', 'siblingBefore', 'siblingAfter']) {
        const nested = projectionRecord(projection[key]);
        if (nested !== undefined) {
          restoreLifecycleProjection(nested);
        }
      }
      return;
    }
    default: {
      restorePrimitiveProjection(projection);
    }
  }
};

export const restoreDeviceScenarioProjectionFromJson = (
  value: unknown,
  scenarioId: DeviceAuthorizationScenarioId
): DeviceScenarioProjection => {
  const projection = projectionRecord(cloneJsonProjection(value));
  if (projection === undefined) {
    return fail();
  }
  restoreProjectionGraph(projection);
  return publishDeviceScenarioProjection(projection as DeviceScenarioProjection, scenarioId);
};

const concurrencyHeaders = Object.freeze({
  'access-control-allow-origin': '*',
  'access-control-expose-headers': 'WWW-Authenticate',
  'cache-control': 'no-store',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-content-type-options': 'nosniff',
});
const concurrencyWinnerKeys = Object.freeze([
  'access_token',
  'expires_in',
  'id_token',
  'scope',
  'token_type',
]);
const concurrencyLoserKeys = Object.freeze([
  'code',
  'error',
  'error_description',
  'error_uri',
  'message',
]);

const isConcurrencyWinner = (response: DeviceAuthorizationProjection): boolean =>
  response.status === 200 &&
  response.contentType === 'application/json' &&
  JSON.stringify(response.headers) === JSON.stringify(concurrencyHeaders) &&
  JSON.stringify(response.keys) === JSON.stringify(concurrencyWinnerKeys) &&
  response.oauthError.category === undefined &&
  response.oauthError.description === undefined &&
  response.tokenType === 'Bearer' &&
  response.expiresIn === 3600;

const isConcurrencyLoser = (response: DeviceAuthorizationProjection): boolean =>
  response.status === 400 &&
  response.contentType === 'application/json' &&
  JSON.stringify(response.headers) === JSON.stringify(concurrencyHeaders) &&
  JSON.stringify(response.keys) === JSON.stringify(concurrencyLoserKeys) &&
  response.oauthError.category === 'invalid_grant' &&
  response.oauthError.description === 'grant request is invalid' &&
  response.tokenType === undefined &&
  response.expiresIn === undefined;

export const publishDeviceScenarioProjection = (
  value: DeviceScenarioProjection,
  scenarioId?: DeviceAuthorizationScenarioId
): DeviceScenarioProjection => {
  if (!exactProjectionKeys(value, Reflect.ownKeys(value) as string[])) {
    return fail();
  }
  const kind = Object.hasOwn(value, 'kind') ? (value as { kind: string }).kind : undefined;
  const expectedCompositeKind =
    scenarioId === 'device-verification.complete-url-entry'
      ? 'device-verification-follow'
      : scenarioId === 'device-consent.first-party-matching-grant-required' ||
          scenarioId === 'device-consent.third-party-redirect-absent'
        ? 'device-consent-sequence'
        : scenarioId === 'device-token.concurrent-reference-multi-winner'
          ? 'device-concurrency'
          : scenarioId === 'device-token.session-bound-expiry' ||
              scenarioId === 'device-token-status.access-revocation' ||
              scenarioId === 'device-token-status.refresh-revocation'
            ? 'device-token-lifecycle'
            : undefined;
  const compositeKinds = new Set([
    'device-consent-sequence',
    'device-verification-follow',
    'device-concurrency',
    'device-token-lifecycle',
  ]);
  if (
    scenarioId !== undefined &&
    kind !== expectedCompositeKind &&
    (expectedCompositeKind !== undefined || compositeKinds.has(kind ?? ''))
  ) {
    return fail();
  }
  switch (kind) {
    case 'device-verification-follow': {
      const sequence = value as DeviceVerificationFollowProjection;
      if (!exactProjectionKeys(sequence, ['kind', 'redirect', 'terminal'])) {
        return fail();
      }
      validatePrimitiveProjection(sequence.redirect);
      validatePrimitiveProjection(sequence.terminal);
      if (
        ![302, 303].includes(sequence.redirect.status) ||
        sequence.redirect.location?.path !== '/oidc/device' ||
        JSON.stringify(sequence.redirect.location.queryKeys) !== JSON.stringify(['user_code']) ||
        sequence.terminal.status !== 200 ||
        sequence.terminal.contentType !== 'text/html'
      ) {
        return fail();
      }
      break;
    }
    case 'device-consent-sequence': {
      const sequence = value as DeviceConsentSequenceProjection;
      const expectedKeys =
        sequence.mode === 'first-party-matching-grant'
          ? ['kind', 'mode', 'firstIssued', 'consent', 'completion']
          : ['kind', 'mode', 'consent', 'completion'];
      if (!exactProjectionKeys(sequence, expectedKeys)) {
        return fail();
      }
      if (sequence.mode === 'first-party-matching-grant') {
        if (sequence.firstIssued === undefined) {
          return fail();
        }
        validatePrimitiveProjection(sequence.firstIssued);
        if (sequence.firstIssued.status !== 200) {
          return fail();
        }
      } else if (sequence.mode !== 'third-party' || sequence.firstIssued !== undefined) {
        return fail();
      }
      validatePrimitiveProjection(sequence.consent);
      validatePrimitiveProjection(sequence.completion);
      if (
        sequence.consent.kind !== 'consent-read' ||
        sequence.consent.facts.marker !== 'consent-presented' ||
        !sequence.consent.facts.redirectUriAbsent ||
        sequence.completion.kind !== 'resume' ||
        sequence.completion.facts.marker !== 'device-success-redirect'
      ) {
        return fail();
      }
      if (
        sequence.mode === 'first-party-matching-grant' &&
        (sequence.consent.facts.missingOidcScopes.length > 0 ||
          sequence.consent.facts.missingResourceScopeCount !== 0)
      ) {
        return fail();
      }

      break;
    }
    case 'device-concurrency': {
      const sequence = value as DeviceConcurrencyProjection;
      if (
        !exactProjectionKeys(sequence, [
          'kind',
          'target',
          'referenceExpectedMultiWinner',
          'trials',
        ]) ||
        !sequence.referenceExpectedMultiWinner ||
        !Array.isArray(sequence.trials) ||
        sequence.trials.length !== 3
      ) {
        return fail();
      }
      for (const trial of sequence.trials) {
        if (
          !exactProjectionKeys(trial, ['winnerCount', 'responses']) ||
          !Array.isArray(trial.responses) ||
          trial.responses.length !== 2
        ) {
          return fail();
        }
        for (const response of trial.responses) {
          validatePrimitiveProjection(response);
        }
        const winners = trial.responses.filter(isConcurrencyWinner).length;
        const losers = trial.responses.filter(isConcurrencyLoser).length;
        if (
          trial.winnerCount !== winners ||
          (sequence.target === 'oracle' && (winners !== 2 || losers !== 0)) ||
          (sequence.target === 'candidate' && (winners !== 1 || losers !== 1))
        ) {
          return fail();
        }
      }

      break;
    }
    case 'device-token-lifecycle': {
      const sequence = value as DeviceTokenLifecycleProjection;
      const optionalKeys = [
        ...(sequence.action === undefined ? [] : ['action']),
        ...(sequence.siblingBefore === undefined ? [] : ['siblingBefore']),
        ...(sequence.siblingAfter === undefined ? [] : ['siblingAfter']),
        ...(sequence.stateTransition === undefined ? [] : ['stateTransition']),
      ];
      if (!exactProjectionKeys(sequence, ['kind', 'mode', 'before', 'after', ...optionalKeys])) {
        return fail();
      }
      for (const projection of [
        sequence.before,
        sequence.action,
        sequence.after,
        sequence.siblingBefore,
        sequence.siblingAfter,
      ]) {
        if (projection !== undefined) {
          validatePrimitiveProjection(projection);
        }
      }
      if (
        (sequence.mode === 'session-expiry' &&
          (sequence.stateTransition !== 'session-expired' || sequence.action !== undefined)) ||
        (sequence.mode !== 'session-expiry' &&
          (sequence.action?.kind !== 'revocation' || sequence.stateTransition !== undefined))
      ) {
        return fail();
      }
      const introspectionActive = (
        projection: DeviceLifecycleProjection | undefined,
        active: boolean
      ) =>
        projection?.kind === 'introspection' &&
        projection.facts.marker === 'introspection' &&
        projection.facts.active === active;
      if (
        (sequence.mode === 'access-revocation' &&
          (!introspectionActive(sequence.before, true) ||
            !introspectionActive(sequence.siblingBefore, true) ||
            !introspectionActive(sequence.after, false) ||
            sequence.siblingAfter?.kind !== 'refresh' ||
            sequence.siblingAfter.facts.marker !== 'oauth-error' ||
            sequence.siblingAfter.oauthError.category !== 'invalid_grant')) ||
        (sequence.mode === 'refresh-revocation' &&
          (!introspectionActive(sequence.before, true) ||
            !introspectionActive(sequence.siblingBefore, true) ||
            !introspectionActive(sequence.after, false) ||
            !introspectionActive(sequence.siblingAfter, false))) ||
        (sequence.mode === 'session-expiry' &&
          (sequence.before.kind !== 'userinfo' ||
            sequence.before.facts.marker !== 'userinfo' ||
            !introspectionActive(sequence.siblingBefore, true) ||
            sequence.after.kind !== 'userinfo' ||
            sequence.after.facts.marker !== 'oauth-error' ||
            !introspectionActive(sequence.siblingAfter, false)))
      ) {
        return fail();
      }

      break;
    }
    default: {
      validatePrimitiveProjection(
        value as
          | DeviceAuthorizationProjection
          | DeviceLifecycleProjection
          | DeviceCredentialProjection
      );
    }
  }
  assertDeviceAuthorizationEvidenceIsSanitized(value);
  return Object.freeze(value);
};

export const compareDeviceScenarioProjections = (
  oracle: DeviceScenarioProjection,
  candidate: DeviceScenarioProjection,
  scenarioId: DeviceAuthorizationScenarioId
): readonly string[] => {
  publishDeviceScenarioProjection(oracle, scenarioId);
  publishDeviceScenarioProjection(candidate, scenarioId);
  const oracleKind = Object.hasOwn(oracle, 'kind') ? (oracle as { kind: string }).kind : undefined;
  const candidateKind = Object.hasOwn(candidate, 'kind')
    ? (candidate as { kind: string }).kind
    : undefined;
  if (oracleKind === 'device-concurrency' || candidateKind === 'device-concurrency') {
    const oracleConcurrency = oracle as DeviceConcurrencyProjection;
    const candidateConcurrency = candidate as DeviceConcurrencyProjection;
    if (
      scenarioId !== 'device-token.concurrent-reference-multi-winner' ||
      oracleKind !== 'device-concurrency' ||
      candidateKind !== 'device-concurrency' ||
      oracleConcurrency.target !== 'oracle' ||
      candidateConcurrency.target !== 'candidate'
    ) {
      return Object.freeze(['/concurrency']);
    }
    const normalize = (sequence: DeviceConcurrencyProjection) =>
      sequence.trials.map((trial) => {
        const winner = trial.responses.find(isConcurrencyWinner) ?? fail();
        return Object.freeze({
          primary: winner,
          responseCategories: Object.freeze(['winner', 'contended']),
        });
      });
    return JSON.stringify(normalize(oracleConcurrency)) ===
      JSON.stringify(normalize(candidateConcurrency))
      ? Object.freeze([])
      : Object.freeze(['/concurrency']);
  }
  if (
    oracleKind === 'device-verification-follow' ||
    candidateKind === 'device-verification-follow' ||
    oracleKind === 'device-consent-sequence' ||
    candidateKind === 'device-consent-sequence' ||
    oracleKind === 'device-token-lifecycle' ||
    candidateKind === 'device-token-lifecycle'
  ) {
    return JSON.stringify(oracle) === JSON.stringify(candidate)
      ? Object.freeze([])
      : Object.freeze(['/sequence']);
  }
  return compareDeviceAuthorizationProjections(
    oracle as
      | DeviceAuthorizationProjection
      | DeviceLifecycleProjection
      | DeviceCredentialProjection,
    candidate as
      | DeviceAuthorizationProjection
      | DeviceLifecycleProjection
      | DeviceCredentialProjection
  );
};

export const runDeviceAuthorizationNegativeControls = (
  scenarios: readonly DeviceAuthorizationScenarioResult[]
): readonly DeviceAuthorizationControlResult[] => {
  const byId = new Map(scenarios.map((scenario) => [scenario.id, scenario.projection] as const));
  const controls: Array<
    readonly [
      DeviceAuthorizationControlResult['name'],
      DeviceAuthorizationScenarioId,
      string,
      unknown,
    ]
  > = [
    ['status', 'device-authorization.urlencoded-success', '/status', 599],
    ['path', 'device-authorization.urlencoded-success', '/verificationUri/path', '/wrong-device'],
    [
      'cookie-clearing',
      'device-verification.completed-cookie-cleanup',
      '/cookies/0/clearing',
      false,
    ],
    ['oauth', 'device-token.pending-poll', '/oauthError/category', 'phase2_wrong_error'],
    [
      'claimKeys',
      'device-token.id-token-signature-and-claims',
      '/id/claims/claimKeys',
      ['wrong_claim'],
    ],
    ['discovery-fields', 'device-discovery.oidc', '/facts/keys', ['wrong_discovery_field']],
  ];
  const clone = (value: unknown): unknown =>
    Array.isArray(value)
      ? value.map(clone)
      : typeof value === 'object' && value !== null
        ? Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, clone(nested)]))
        : value;
  return Object.freeze(
    controls.map(([name, id, pointer, replacement]) => {
      const original = byId.get(id) ?? fail();
      const mutated = clone(original) as Record<string, unknown>;
      const parts = pointer.slice(1).split('/');
      let cursor: unknown = mutated;
      for (const part of parts.slice(0, -1)) {
        if (typeof cursor !== 'object' || cursor === null) {
          return fail();
        }
        cursor = (cursor as Record<string, unknown>)[part];
      }
      if (typeof cursor !== 'object' || cursor === null) {
        return fail();
      }
      const leaf = parts.at(-1) ?? fail();
      if (!Object.hasOwn(cursor, leaf)) {
        return fail();
      }
      if (name === 'claimKeys') {
        const claims = cursor as Record<string, unknown>;
        const { claimKeys } = claims;
        const { claimTypes } = claims;
        if (!Array.isArray(claimKeys) || typeof claimTypes !== 'object' || claimTypes === null) {
          return fail();
        }
        if (claimKeys.includes('jti')) {
          claims.claimKeys = claimKeys.filter((key) => key !== 'jti');
          delete (claimTypes as Record<string, unknown>).jti;
          delete claims.jwtId;
        } else {
          claims.claimKeys = [...claimKeys, 'jti'].sort();
          (claimTypes as Record<string, unknown>).jti = 'string';
          claims.jwtId = '<opaque-id>';
        }
      } else {
        (cursor as Record<string, unknown>)[leaf] = replacement;
      }
      const differences = compareDeviceAuthorizationProjections(
        original as
          | DeviceAuthorizationProjection
          | DeviceLifecycleProjection
          | DeviceCredentialProjection,
        mutated as
          | DeviceAuthorizationProjection
          | DeviceLifecycleProjection
          | DeviceCredentialProjection
      );
      if (
        !differences.some(
          (difference) => difference === pointer || difference.startsWith(`${pointer}/`)
        )
      ) {
        return fail();
      }
      return Object.freeze({ name, pointer, detected: true as const });
    })
  );
};

/* eslint-enable complexity, max-lines, no-restricted-syntax, no-await-in-loop, unicorn/no-object-as-default-parameter, @silverhand/fp/no-mutating-methods, unicorn/no-array-callback-reference, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-delete, @typescript-eslint/require-array-sort-compare, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unnecessary-condition */
