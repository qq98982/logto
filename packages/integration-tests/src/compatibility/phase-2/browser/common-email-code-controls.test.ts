/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/consistent-function-scoping -- Stateful fake HTTP transport models ownership, consumption, and one outer lease. */
import type { VerificationCodeProjection } from '../clients/verification-code.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import type { VerificationCodeScenarioRuntime } from '../scenarios/verification-code.js';

import {
  captureEmailCodePurposeControl,
  emailCodeExpiryWaitMilliseconds,
  runCommonEmailCodeControlGroups,
  runCommonEmailCodeHttpControls,
  runEmailCodeControls,
  validateCommonEmailCodeControlGroups,
} from './common-email-code-controls.js';
import { createScopedEmailCodeFixture } from './common-email-code-target-driver.js';

const projection = (
  status: number,
  outcome: VerificationCodeProjection['outcome'],
  error?: string
): VerificationCodeProjection =>
  Object.freeze({
    status,
    contentType: 'application/json',
    cacheControl: 'no-store',
    outcome,
    handleField: outcome === 'error' ? null : 'verificationId',
    expiresAt: false,
    ...(error === undefined ? {} : { error }),
  });

const runtime = (id: number, expired: () => boolean): VerificationCodeScenarioRuntime => {
  let consumed = false;
  return {
    request: async ({ identifier }) =>
      Object.freeze({ projection: projection(200, 'created'), delivery: identifier }),
    takeDelivery: async () =>
      Object.freeze({ handle: `handle-${id}`, code: `${id}`.padStart(6, '0') }),
    verify: async ({ identifier }) => {
      if (identifier.startsWith('wrong-')) {
        return projection(400, 'error', 'verification_code.email_mismatch');
      }
      if (expired() || consumed) {
        if (expired()) {
          return projection(400, 'error', 'verification_code.expired');
        }
        return projection(400, 'error', 'verification_code.not_found');
      }
      consumed = true;
      return projection(200, 'verified');
    },
    runRetryCap: async () => [],
    runSendCap: async () => ({ accepted: 0, capped: projection(429, 'error') }),
    runFailedDelivery: async () => ({
      failed: projection(400, 'error'),
      previous: projection(200, 'verified'),
    }),
    runAccountLifecycle: async () => ({
      requested: projection(201, 'created'),
      verified: projection(200, 'verified'),
      replay: projection(400, 'error'),
    }),
  };
};

test('uses fresh interactions for recipient, replay, and real-expiry controls', async () => {
  let instances = 0;
  let expired = false;
  const result = await runEmailCodeControls({
    recipient: 'owner@example.invalid',
    createRuntime: async () => runtime(++instances, () => expired),
    waitForExpiry: async () => {
      expired = true;
    },
  });
  expect(instances).toBe(3);
  expect(result).toEqual({
    recipientMismatchRejected: true,
    ownerAfterRecipientMismatch: 'verified',
    consumedReplayRejected: true,
    expiredChallengeRejected: true,
  });
  expect(JSON.stringify(result)).not.toMatch(/handle|\d{6}/u);
});

test('pins the production expiry wait above the stored 60-second policy', () => {
  expect(emailCodeExpiryWaitMilliseconds).toBe(62_000);
});

test.each([
  ['basic', 'basic'],
  ['purpose', 'foreign-account'],
  ['client', 'secondary-client'],
] as const)(
  'redacts a private %s control failure into its fixed group stage',
  async (failed, stage) => {
    const privateFailure = async () => {
      throw new Error(`private-${failed}-control`);
    };
    const accepted = async () => Object.freeze({ accepted: true });
    await expect(
      runCommonEmailCodeControlGroups({
        basic: failed === 'basic' ? privateFailure : accepted,
        purpose: failed === 'purpose' ? privateFailure : accepted,
        client: failed === 'client' ? privateFailure : accepted,
      })
    ).rejects.toThrow(`Common email code control stage failed: ${stage}`);
  }
);

test('rejects a recipient denial that consumes the owner challenge', async () => {
  const broken = runtime(1, () => false);
  const originalVerify = broken.verify;
  let denied = false;
  await expect(
    runEmailCodeControls({
      recipient: 'owner@example.invalid',
      createRuntime: async () => ({
        ...broken,
        verify: async (input) => {
          if (input.identifier.startsWith('wrong-')) {
            denied = true;
            return projection(400, 'error', 'verification_code.email_mismatch');
          }
          return denied
            ? projection(404, 'error', 'session.verification_session_not_found')
            : originalVerify(input);
        },
      }),
    })
  ).rejects.toThrow('Invalid Common email code control');
});

const validCapturedControls = () => ({
  basic: {
    recipient: {
      status: 400,
      error: 'verification_code.email_mismatch',
      ownerAfterStatus: 200,
    },
    consumedReplay: { status: 400, error: 'verification_code.not_found' },
    expiry: { status: 400, error: 'verification_code.expired' },
  },
  purpose: {
    account: { status: 400, error: 'verification_record.not_found' },
    ownerAfterAccount: { status: 200, outcome: 'verified' as const },
  },
  client: {
    secondary: projection(404, 'error', 'session.verification_session_not_found'),
    owner: projection(200, 'verified'),
  },
});

test.each([
  [
    'basic',
    () => ({
      ...validCapturedControls(),
      basic: { ...validCapturedControls().basic, expiry: { status: 404 } },
    }),
  ],
  [
    'foreign-account',
    () => ({
      ...validCapturedControls(),
      purpose: {
        ...validCapturedControls().purpose,
        account: { status: 404, error: 'verification_record.not_found' },
      },
    }),
  ],
  [
    'secondary-client',
    () => ({
      ...validCapturedControls(),
      client: {
        ...validCapturedControls().client,
        secondary: projection(400, 'error', 'session.verification_session_not_found'),
      },
    }),
  ],
] as const)(
  'labels a wrong %s captured result through production validation',
  async (stage, make) => {
    await expect(validateCommonEmailCodeControlGroups(make())).rejects.toThrow(
      `Common email code control stage failed: ${stage}`
    );
  }
);

test('captures wrong-purpose Reference facts without retaining the challenge secret', async () => {
  const captured = await captureEmailCodePurposeControl({
    recipient: 'owner@example.invalid',
    createRuntime: async () => runtime(7, () => false),
    verifyAccount: async () => projection(400, 'error', 'verification_code.not_found'),
  });
  expect(captured).toEqual({
    account: { status: 400, error: 'verification_code.not_found' },
    ownerAfterAccount: { status: 200, outcome: 'verified' },
  });
  expect(JSON.stringify(captured)).not.toMatch(/handle-7|000007/u);
});

test('runs the complete HTTP control factory with the scoped target redirect and one outer lease', async () => {
  const redirects: string[] = [];
  const challenges = new Map<string, { recipient: string; consumed: boolean; expired: boolean }>();
  const deliveries: string[] = [];
  let sequence = 0;
  let leaseActive = false;
  const target = {
    label: 'oracle' as const,
    coreUrl: 'https://core.example',
    adminUrl: 'https://admin.example',
  };
  const originalFixture = {
    public: { allocationId: 'allocation' },
    status: {
      user: { id: 'baseline-user', username: 'baseline' },
      client: { id: 'browser-app', redirectUri: 'http://localhost:3001/demo-app' },
      confidentialClient: { id: 'confidential', redirectUri: 'https://core.example/secondary' },
      resource: { id: 'resource', indicator: 'https://api.example', scopeName: 'read:profile' },
    },
    withSecretLease: async <Result>(use: (lease: Phase2FixtureSecretLease) => Promise<Result>) => {
      if (leaseActive) {
        throw new Error('outer lease reacquired');
      }
      leaseActive = true;
      try {
        return await use({
          getClientSecret: () => 'unused',
          getStatusClientSecret: () => 'unused',
          getSubjectPassword: () => 'baseline-password',
          takeVerificationCode: async () => deliveries.shift() ?? failTest(),
          toJSON: () => failTest(),
        });
      } finally {
        leaseActive = false;
      }
    },
  } as unknown as ProvisionedPhase2Fixture;
  const json = (value: unknown, status = 200, headers: HeadersInit = {}) =>
    new Response(JSON.stringify(value), {
      status,
      headers: { 'content-type': 'application/json', ...headers },
    });
  const cookies = () => {
    const headers = new Headers();
    headers.append('set-cookie', '_interaction=owned; Path=/; HttpOnly');
    headers.append('set-cookie', '_interaction.sig=signed; Path=/; HttpOnly');
    return headers;
  };
  const requestFetch: typeof fetch = async (request, init) => {
    const url = new URL(
      typeof request === 'string' ? request : request instanceof URL ? request : request.url
    );
    const body =
      typeof init?.body === 'string' && init.body.startsWith('{')
        ? (JSON.parse(init.body) as Record<string, unknown>)
        : {};
    if (url.pathname === '/oidc/auth') {
      const redirect = url.searchParams.get('redirect_uri') ?? '';
      const clientId = url.searchParams.get('client_id');
      if (clientId === 'browser-app') {
        redirects.push(redirect);
      }
      return new Response(null, { status: 303, headers: cookies() });
    }
    if (url.pathname === '/api/experience' && init?.method === 'PUT') {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/api/experience/verification/password') {
      return json({ verificationId: 'baseline-proof' });
    }
    if (url.pathname === '/api/experience/identification') {
      return new Response(null, { status: 204 });
    }
    if (url.pathname === '/api/experience/submit') {
      return json({ redirectTo: '/bridge' });
    }
    if (url.pathname === '/bridge') {
      return new Response(null, { status: 303 });
    }
    if (url.pathname === '/api/interaction/consent' && init?.method === 'GET') {
      return new Response(null, { status: 200 });
    }
    if (url.pathname === '/api/interaction/consent') {
      return json({ redirectTo: '/resume' });
    }
    if (url.pathname === '/resume') {
      return new Response(null, {
        status: 303,
        headers: { location: 'https://core.example/demo-app?code=issued' },
      });
    }
    if (url.pathname === '/oidc/token') {
      return json({
        token_type: 'Bearer',
        access_token: 'opaque-access',
        refresh_token: 'opaque-refresh',
      });
    }
    if (
      url.pathname === '/api/experience/verification/verification-code' &&
      init?.method === 'POST'
    ) {
      sequence += 1;
      const handle = `record-${sequence}`;
      const rawRecipient = Reflect.get(body, 'identifier');
      const recipient =
        typeof rawRecipient === 'object' && rawRecipient !== null
          ? String(Reflect.get(rawRecipient, 'value'))
          : String(rawRecipient);
      challenges.set(handle, { recipient, consumed: false, expired: false });
      deliveries.push(String(sequence).padStart(6, '0'));
      return json({ verificationId: handle });
    }
    if (url.pathname.endsWith('/verification-code/verify')) {
      if (new Headers(init?.headers).has('authorization')) {
        return json({ code: 'verification_record.not_found', message: 'not found' }, 400);
      }
      const identifierValue = Reflect.get(body, 'identifier');
      const identifier =
        typeof identifierValue === 'object' && identifierValue !== null
          ? String(Reflect.get(identifierValue, 'value'))
          : '';
      const handle = String(Reflect.get(body, 'verificationId'));
      const record = challenges.get(handle) ?? failTest();
      const clientId = new Headers(init?.headers).get('aster-app-id');
      if (clientId === 'confidential') {
        return json({ code: 'session.verification_session_not_found', message: 'not found' }, 404);
      }
      if (identifier !== record.recipient) {
        return json({ code: 'verification_code.email_mismatch', message: 'mismatch' }, 400);
      }
      if (record.expired) {
        return json({ code: 'verification_code.expired', message: 'expired' }, 400);
      }
      if (record.consumed) {
        return json({ code: 'verification_code.not_found', message: 'not found' }, 400);
      }
      record.consumed = true;
      return json({ verificationId: handle });
    }
    throw new Error('unexpected HTTP control request');
  };
  const result = await originalFixture.withSecretLease(async (lease) => {
    const scope = createScopedEmailCodeFixture(
      originalFixture,
      lease,
      'https://core.example/demo-app'
    );
    try {
      return await runCommonEmailCodeHttpControls(
        target,
        scope.fixture,
        'Owner@Example.Invalid',
        requestFetch,
        async () => {
          const newest = challenges.get(`record-${sequence}`) ?? failTest();
          newest.expired = true;
        }
      );
    } finally {
      scope.revoke();
    }
  });
  expect(result).toMatchObject({
    recipientMismatch: { status: 400 },
    ownerAfterRecipientMismatch: { status: 200 },
    consumedReplay: { status: 400 },
    expiry: { status: 400 },
    foreignAccountSurface: { status: 400 },
    secondaryVerify: { status: 404 },
    ownerAfterSecondaryVerify: { status: 200 },
  });
  expect(redirects.length).toBeGreaterThan(3);
  expect(new Set(redirects)).toEqual(new Set(['https://core.example/demo-app']));
  expect(leaseActive).toBe(false);
  expect(JSON.stringify(result)).not.toMatch(/record-|\d{6}|opaque-/u);
});

const failTest = (): never => {
  throw new Error('invalid test state');
};
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/consistent-function-scoping */
