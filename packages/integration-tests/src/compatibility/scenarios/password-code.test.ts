/* eslint-disable max-lines, @typescript-eslint/no-explicit-any, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful fakes make the externally observable authorization sequence explicit. */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';

import { compareJson } from '../compare.js';
import { assertEvidenceIsSanitized } from '../evidence.js';
import type { TargetConfig } from '../model.js';
import { runScenarioForTarget } from '../scenario.js';
import { TargetClient } from '../target-client.js';

import {
  createPasswordCodeScenario,
  projectUserForObservation,
  type PasswordCodeScenarioDependencies,
} from './password-code.js';

const timestamp = 1_700_000_000;
const password = ['Aster', 'phase0', 'password', '42'].join('_');
const cookieValue = ['cookie', 'private', 'value'].join('-');
const submitCookieValue = ['submit', 'cookie', 'private'].join('-');
const processCookieValue = ['process', 'cookie', 'private'].join('-');
const upstreamJsonCookieValue = JSON.stringify({
  tenant: ['runtime', 'tenant'].join('-'),
  interaction: ['runtime', 'interaction'].join('-'),
});
const resumeCookieValue = ['resume', 'opaque', 'runtime'].join('-');
const resumeSignatureCookieValue = ['resume', 'signature', 'runtime'].join('-');
const redirectSecret = ['code', 'private'].join('-');
const stateSecret = ['state', 'private'].join('-');
const nonceSecret = ['nonce', 'private'].join('-');
const verificationSecret = ['verification', 'private'].join('-');
const diagnosticSecret = [
  'thrown-secret-marker',
  password,
  cookieValue,
  submitCookieValue,
  processCookieValue,
  upstreamJsonCookieValue,
  resumeCookieValue,
  resumeSignatureCookieValue,
  redirectSecret,
  stateSecret,
  nonceSecret,
  verificationSecret,
].join('|');
const signature = ['signature', 'private'].join('-');

const target = (label: TargetConfig['label']): TargetConfig =>
  Object.freeze({
    label,
    coreUrl: `https://${label}.example.test`,
    adminUrl: `https://${label}-admin.example.test`,
  });

const compactJwt = (header: Record<string, unknown>, claims: Record<string, unknown>) =>
  [header, claims]
    .map((value) => Buffer.from(JSON.stringify(value)).toString('base64url'))
    .concat(Buffer.from(signature).toString('base64url'))
    .join('.');

const captureRejection = async (promise: Promise<unknown>): Promise<unknown> => {
  try {
    await promise;
    return new Error('Expected rejection');
  } catch (error_: unknown) {
    return error_;
  }
};

const assertSanitizedError = (
  error: unknown,
  expectedPrimaryMessage: string,
  additionalSecrets: readonly string[] = []
) => {
  const aggregateErrors: unknown[] = error instanceof AggregateError ? error.errors : [];
  const primaryError = error instanceof AggregateError ? aggregateErrors[0] : error;

  expect(primaryError).toBeInstanceOf(Error);

  if (!(primaryError instanceof Error)) {
    throw new TypeError('Expected Error');
  }

  expect(primaryError.message).toBe(expectedPrimaryMessage);

  const representations = [String(error), inspect(error, { depth: null })];

  for (const representation of representations) {
    for (const secret of [
      diagnosticSecret,
      password,
      cookieValue,
      submitCookieValue,
      processCookieValue,
      upstreamJsonCookieValue,
      resumeCookieValue,
      resumeSignatureCookieValue,
      redirectSecret,
      stateSecret,
      nonceSecret,
      verificationSecret,
      ...additionalSecrets,
    ]) {
      expect(representation).not.toContain(secret);
    }
  }
};

type HarnessOptions = {
  label?: TargetConfig['label'];
  failAt?: string;
  cleanupFails?: boolean;
  accessTokenFormat?: 'jwt' | 'opaque' | 'malformed-jose' | 'malformed-jwe';
  refreshedAccessTokenFormat?: 'opaque' | 'jwt' | 'same' | 'malformed-jose' | 'malformed-jwe';
  idTokenFormat?: 'jwt' | 'absent' | 'malformed';
  userId?: string;
  kid?: string;
  timeOffsetSeconds?: number;
  userInfoValue?: unknown;
  jwtExtraClaims?: Record<string, unknown>;
  idTokenExtraClaims?: Record<string, unknown>;
  createdUserUsername?: string;
  finalUserName?: string;
  echoAccessTokenInUserInfo?: boolean;
  reverseSetClaims?: boolean;
  orderedClaimValues?: string[];
  refreshedJti?: string;
  echoRefreshedTokenInUserInfo?: boolean;
  echoIdTokenInUserInfo?: boolean;
  userInfoCookieEcho?: 'init-json' | 'resume' | 'resume-signature' | 'submit' | 'process';
  initCookieHeaders?: string[];
};

class FakeTargetClient extends TargetClient {
  readonly events: string[];
  readonly failAt: string | undefined;
  readonly cleanupFails: boolean;
  readonly userId: string;
  readonly timeSeconds: number;
  readonly userInfoValue: unknown;
  readonly hasUserInfoValue: boolean;
  readonly createdUserUsername: string;
  readonly finalUserName: string | undefined;
  readonly echoAccessTokenInUserInfo: boolean;
  readonly userInfoCookieEcho: HarnessOptions['userInfoCookieEcho'];
  readonly createdPayloads: unknown[] = [];
  readonly userInfoTokens: string[] = [];

  tracked = false;
  deleteCalls = 0;
  lateSensitiveUserInfoValue: string | undefined;

  constructor(
    runTarget: TargetConfig,
    events: string[],
    options: Pick<
      HarnessOptions,
      | 'failAt'
      | 'cleanupFails'
      | 'userId'
      | 'timeOffsetSeconds'
      | 'userInfoValue'
      | 'createdUserUsername'
      | 'finalUserName'
      | 'echoAccessTokenInUserInfo'
      | 'userInfoCookieEcho'
    >
  ) {
    super(runTarget);
    this.events = events;
    this.failAt = options.failAt;
    this.cleanupFails = options.cleanupFails ?? false;
    this.userId = options.userId ?? `${runTarget.label}-runtime-user`;
    this.timeSeconds = timestamp + (options.timeOffsetSeconds ?? 0);
    this.userInfoValue = options.userInfoValue;
    this.hasUserInfoValue = Object.hasOwn(options, 'userInfoValue');
    this.createdUserUsername = options.createdUserUsername ?? 'aster_phase0_password_user';
    this.finalUserName = options.finalUserName;
    this.echoAccessTokenInUserInfo = options.echoAccessTokenInUserInfo ?? false;
    this.userInfoCookieEcho = options.userInfoCookieEcho;
  }

  check(operation: string) {
    this.events.push(operation);

    if (this.failAt === operation) {
      throw new Error(diagnosticSecret);
    }
  }

  override async setUsernamePasswordExperience(): Promise<any> {
    this.check('set-sign-in-experience');
    return {};
  }

  override async createUser(payload: unknown): Promise<any> {
    this.check('create-user');
    this.createdPayloads.push(payload);
    this.tracked = true;

    return this.userProjection(false);
  }

  override async getUser(userId: string): Promise<any> {
    this.check('read-user');
    expect(userId).toBe(this.userId);
    return { ...this.userProjection(true), updatedAt: (this.timeSeconds + 5) * 1000 };
  }

  override async deleteUser(userId: string): Promise<void> {
    this.deleteCalls += 1;
    this.events.push('delete-user');
    expect(userId).toBe(this.userId);

    if (this.failAt === 'delete-user') {
      throw new Error('Delete user failed');
    }

    this.tracked = false;
  }

  override async getUserInfo(accessToken: string): Promise<any> {
    this.check('call-userinfo');
    this.userInfoTokens.push(accessToken);
    if (this.hasUserInfoValue) {
      return this.userInfoValue;
    }

    if (this.lateSensitiveUserInfoValue !== undefined) {
      return { sub: this.userId, name: `prefix-${this.lateSensitiveUserInfoValue}-suffix` };
    }

    if (this.echoAccessTokenInUserInfo) {
      return { sub: this.userId, custom_data: { rollout: accessToken } };
    }

    if (this.userInfoCookieEcho !== undefined) {
      const echoedCookie =
        this.userInfoCookieEcho === 'init-json'
          ? upstreamJsonCookieValue
          : this.userInfoCookieEcho === 'resume'
            ? resumeCookieValue
            : this.userInfoCookieEcho === 'resume-signature'
              ? resumeSignatureCookieValue
              : this.userInfoCookieEcho === 'submit'
                ? submitCookieValue
                : processCookieValue;

      return {
        sub: this.userId,
        name: echoedCookie,
      };
    }

    return {
      sub: this.userId,
      name: null,
      picture: null,
      preferred_username: 'aster_phase0_password_user',
      username: 'aster_phase0_password_user',
      created_at: this.timeSeconds * 1000 + 987,
      updated_at: (this.timeSeconds + 1) * 1000 + 456,
      unknown_claim: diagnosticSecret,
    };
  }

  override async cleanup(): Promise<void> {
    this.events.push('cleanup');

    if (this.cleanupFails) {
      throw new Error('Cleanup failed');
    }

    if (this.tracked) {
      await this.deleteUser(this.userId);
    }
  }

  setLateSensitiveUserInfoValue(value: string) {
    this.lateSensitiveUserInfoValue = value;
  }

  private userProjection(final: boolean) {
    return {
      id: this.userId,
      username: this.createdUserUsername,
      ...(final && this.finalUserName !== undefined ? { name: this.finalUserName } : {}),
      hasPassword: true,
      passwordAlgorithm: 'Argon2id',
      isSuspended: false,
      profile: {},
      customData: {},
      identities: {},
      createdAt: this.timeSeconds * 1000 + 987,
      updatedAt: (this.timeSeconds + 1) * 1000 + 456,
      lastSignInAt: null,
    };
  }
}

// eslint-disable-next-line complexity -- Token variants are a closed test-fixture matrix.
const createHarness = (options: HarnessOptions = {}) => {
  const runTarget = target(options.label ?? 'oracle');
  const events: string[] = [];
  const client = new FakeTargetClient(runTarget, events, options);
  const kid = options.kid ?? `${runTarget.label}-runtime-kid`;
  const { timeSeconds } = client;
  const setOrder = <Value>(values: readonly Value[]) =>
    options.reverseSetClaims ? values.toReversed() : [...values];
  const idToken = compactJwt(
    { alg: 'ES384', kid },
    {
      iss: `${runTarget.coreUrl}/oidc`,
      sub: client.userId,
      aud: 'demo-app',
      iat: timeSeconds,
      exp: timeSeconds + 3600,
      name: null,
      picture: null,
      preferred_username: 'aster_phase0_password_user',
      username: 'aster_phase0_password_user',
      created_at: timeSeconds * 1000 + 987,
      updated_at: (timeSeconds + 1) * 1000 + 456,
      nonce: nonceSecret,
      code: redirectSecret,
      state: stateSecret,
      verification_id: verificationSecret,
      unknown_claim: diagnosticSecret,
      ...options.idTokenExtraClaims,
    }
  );
  const malformedIdToken = [
    Buffer.from(JSON.stringify({ alg: 'ES384' })).toString('base64url'),
    Buffer.from('{').toString('base64url'),
    Buffer.from(signature).toString('base64url'),
  ].join('.');
  const idTokenResult =
    options.idTokenFormat === 'absent'
      ? null
      : options.idTokenFormat === 'malformed'
        ? malformedIdToken
        : idToken;
  const organizationData = options.reverseSetClaims
    ? [
        { name: 'A', ownerId: client.userId, id: 'org-a' },
        { name: 'B', ownerId: client.userId, id: 'org-b' },
      ]
    : [
        { id: 'org-a', ownerId: client.userId, name: 'A' },
        { id: 'org-b', ownerId: client.userId, name: 'B' },
      ];
  const ssoIdentities = options.reverseSetClaims
    ? [
        { identityId: 'first-id', issuer: 'first' },
        { identityId: 'second-id', issuer: 'second' },
      ]
    : [
        { issuer: 'first', identityId: 'first-id' },
        { issuer: 'second', identityId: 'second-id' },
      ];
  const jwtAccessToken = compactJwt(
    { alg: 'ES384', kid: `${kid}-access` },
    {
      iss: `${runTarget.coreUrl}/oidc`,
      sub: client.userId,
      aud: setOrder(['account', 'api']),
      scope: options.reverseSetClaims ? ' profile   openid ' : 'openid profile',
      amr: setOrder(['mfa', 'pwd']),
      roles: setOrder(['reader', 'writer']),
      organizations: setOrder(['org-a', 'org-b']),
      organization_roles: setOrder(['org-a:admin', 'org-b:reader']),
      permissions: setOrder(['read:data', 'write:data']),
      organization_data: setOrder(organizationData),
      sso_identities: setOrder(ssoIdentities),
      custom_data: {
        rollout: 'aster',
        location: { postal_code: '100-0001' },
        ordered: options.orderedClaimValues ?? ['first', 'second'],
      },
      iat: timeSeconds,
      exp: timeSeconds + 1800,
      created_at: timeSeconds * 1000 + 987,
      updated_at: (timeSeconds + 1) * 1000 + 456,
      nonce: nonceSecret,
      unknown_claim: diagnosticSecret,
      ...options.jwtExtraClaims,
    }
  );
  const refreshedJwtAccessToken = compactJwt(
    { alg: 'ES384', kid: `${kid}-access-refreshed` },
    {
      iss: `${runTarget.coreUrl}/oidc`,
      sub: client.userId,
      aud: ['account'],
      scope: 'openid profile',
      iat: timeSeconds + 1,
      exp: timeSeconds + 1801,
      created_at: timeSeconds * 1000 + 987,
      updated_at: (timeSeconds + 1) * 1000 + 456,
      ...(options.refreshedJti === undefined ? {} : { jti: options.refreshedJti }),
    }
  );
  const opaqueAccessToken = ['opaque', 'runtime', 'private'].join('.');
  const malformedJose = [
    Buffer.from(JSON.stringify({ alg: 'ES384' })).toString('base64url'),
    Buffer.from('{').toString('base64url'),
    Buffer.from(signature).toString('base64url'),
  ].join('.');
  const malformedJwe = [
    Buffer.from(JSON.stringify({ alg: 'dir', enc: 'A256GCM' })).toString('base64url'),
    Buffer.from('encrypted-key').toString('base64url'),
    Buffer.from('iv').toString('base64url'),
    Buffer.from('ciphertext').toString('base64url'),
    Buffer.from('tag').toString('base64url'),
  ].join('.');
  const firstAccessToken =
    options.accessTokenFormat === 'jwt'
      ? jwtAccessToken
      : options.accessTokenFormat === 'malformed-jose'
        ? malformedJose
        : options.accessTokenFormat === 'malformed-jwe'
          ? malformedJwe
          : opaqueAccessToken;
  const secondAccessToken =
    options.refreshedAccessTokenFormat === 'same'
      ? firstAccessToken
      : options.refreshedAccessTokenFormat === 'jwt'
        ? refreshedJwtAccessToken
        : options.refreshedAccessTokenFormat === 'malformed-jose'
          ? malformedJose
          : options.refreshedAccessTokenFormat === 'malformed-jwe'
            ? malformedJwe
            : ['refreshed', 'runtime', 'private'].join('.');

  if (options.echoIdTokenInUserInfo) {
    client.setLateSensitiveUserInfoValue(idToken);
  } else if (options.echoRefreshedTokenInUserInfo) {
    client.setLateSensitiveUserInfoValue(secondAccessToken);
  }
  let accessTokenCalls = 0;
  let authorizationInitialized = false;
  let interactionInitialized = false;
  const accessTokenArgumentTuples: Array<[resource?: string, organizationId?: string]> = [];
  const experience = {
    rawCookies: [] as string[],
    initSession: async (redirectUri: string) => {
      expect(client.target.coreUrl).toBe(`${new URL(client.target.coreUrl).origin}/`);
      expect(redirectUri).toBe(`${new URL(client.target.coreUrl).origin}/demo-app`);
      expect(redirectUri).not.toContain('//demo-app');
      authorizationInitialized = true;
      experience.rawCookies = [];
    },
    initInteraction: async (payload: unknown) => {
      expect(authorizationInitialized).toBe(true);
      expect(payload).toEqual({ interactionEvent: 'SignIn' });
      client.check('start-interaction');
      interactionInitialized = true;
      experience.rawCookies = options.initCookieHeaders ?? [
        `_logto=${upstreamJsonCookieValue}; Path=/; SameSite=Lax`,
        `_interaction_resume=${resumeCookieValue}; Path=/interaction/${resumeCookieValue}; HttpOnly; SameSite=Lax`,
        `_interaction_resume.sig=${resumeSignatureCookieValue}; Path=/interaction/${resumeCookieValue}; HttpOnly; SameSite=Lax`,
        `interaction=${cookieValue}; Path=/api/experience; HttpOnly; Secure; SameSite=Lax`,
      ];
    },
    submitInteraction: async () => {
      client.check('submit-interaction');
      experience.rawCookies = [
        `interaction=${submitCookieValue}; Path=/api/experience; HttpOnly; Secure; SameSite=Lax`,
      ];
      return {
        redirectTo: `${runTarget.coreUrl}/oidc/auth?code=${redirectSecret}&state=${stateSecret}`,
      };
    },
    processSession: async (redirectTo: string) => {
      client.check('process-consent');
      expect(redirectTo).toContain(redirectSecret);
      expect(redirectTo).toContain(stateSecret);
      experience.rawCookies = [
        `interaction=${processCookieValue}; Path=/api/experience; HttpOnly; Secure; SameSite=Lax`,
      ];
    },
    getIdToken: async () => {
      client.check('decode-id-token');
      return idTokenResult;
    },
    getAccessToken: async (...args: [resource?: string, organizationId?: string]) => {
      accessTokenArgumentTuples.push(args);
      expect(args).toEqual([]);
      accessTokenCalls += 1;
      client.check(accessTokenCalls === 1 ? 'obtain-access-token' : 'refresh-access-token');
      return accessTokenCalls === 1 ? firstAccessToken : secondAccessToken;
    },
    clearAccessToken: async () => {
      client.check('clear-access-token');
    },
  };
  const dependencies: PasswordCodeScenarioDependencies = {
    createExperienceClient: (config, api) => {
      expect(config).toEqual({
        endpoint: new URL(client.target.coreUrl).origin,
        appId: 'demo-app',
        persistAccessToken: false,
      });
      expect(api).toBe(client.experience);
      return experience;
    },
    identifyUserWithUsernamePassword: async (_experience, username, suppliedPassword) => {
      expect(username).toBe('aster_phase0_password_user');
      expect(suppliedPassword).toBe(password);
      expect(interactionInitialized).toBe(true);
      client.check('verify-password');
      client.check('identify-user');
      return { verificationId: verificationSecret };
    },
  };

  return {
    runTarget,
    events,
    client,
    idToken,
    firstAccessToken,
    secondAccessToken,
    accessTokenArgumentTuples,
    scenario: createPasswordCodeScenario(dependencies),
    run: async () =>
      runScenarioForTarget(createPasswordCodeScenario(dependencies), runTarget, {
        clientFactory: () => client,
      }),
  };
};

describe('password authorization-code compatibility scenario', () => {
  it('loads in a plain Node process without Jest globals', () => {
    const moduleUrl = new URL('password-code.js', import.meta.url).href;
    const result = spawnSync(process.execPath, [fileURLToPath(moduleUrl)], { encoding: 'utf8' });
    const output = `${result.stdout}${result.stderr}`;

    expect(result.status).toBe(0);
    expect(output).not.toContain(password);
    expect(output).not.toContain(cookieValue);
    expect(output).not.toContain(redirectSecret);
    expect(output).not.toContain(stateSecret);
  });

  it('runs the complete flow in order and emits only semantic sanitized evidence', async () => {
    const harness = createHarness();
    const evidence = await harness.run();

    expect(harness.events).toEqual([
      'set-sign-in-experience',
      'create-user',
      'start-interaction',
      'verify-password',
      'identify-user',
      'submit-interaction',
      'process-consent',
      'decode-id-token',
      'obtain-access-token',
      'call-userinfo',
      'clear-access-token',
      'refresh-access-token',
      'read-user',
      'delete-user',
      'cleanup',
    ]);
    expect(harness.client.deleteCalls).toBe(1);
    expect(harness.client.createdPayloads).toEqual([
      { username: 'aster_phase0_password_user', password },
    ]);
    expect(harness.client.userInfoTokens).toEqual([harness.firstAccessToken]);
    expect(harness.accessTokenArgumentTuples).toEqual([[], []]);
    expect(evidence.observations.map(({ stepId }) => stepId)).toEqual([
      'management.user.created',
      'interaction.cookies',
      'id-token.header',
      'id-token.claims',
      'access-token',
      'userinfo',
      'access-token-refresh',
      'management.user.final',
      'management.user.deleted',
    ]);
    expect(evidence.observations[0]?.value).toMatchObject({
      id: '<user.primary>',
      username: 'aster_phase0_password_user',
      hasPassword: true,
      passwordAlgorithm: 'Argon2id',
      isSuspended: false,
      profileIsEmpty: true,
      customDataIsEmpty: true,
      identityTargets: [],
      createdAt: { $timestamp: timestamp, $toleranceSeconds: 60 },
      lastSignInAt: null,
    });
    expect(evidence.observations[1]?.value).toEqual([
      {
        name: '_logto',
        path: '/',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      },
      {
        name: '_interaction_resume',
        path: '/interaction/aster-redacted',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
      {
        name: '_interaction_resume.sig',
        path: '/interaction/aster-redacted',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
      {
        name: 'interaction',
        path: '/api/experience',
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
      },
    ]);
    expect(evidence.observations[3]?.value).toMatchObject({
      iss: '<target.core-url>/oidc',
      sub: '<user.primary>',
      aud: 'demo-app',
      iat: { $timestamp: timestamp, $toleranceSeconds: 60 },
      exp: { $timestamp: timestamp + 3600, $toleranceSeconds: 60 },
      name: null,
      picture: null,
      preferred_username: 'aster_phase0_password_user',
      username: 'aster_phase0_password_user',
      created_at: { $timestamp: timestamp, $toleranceSeconds: 60 },
      updated_at: { $timestamp: timestamp + 1, $toleranceSeconds: 60 },
      tokenLifetimeSeconds: 3600,
    });
    expect(evidence.observations[2]?.value).toMatchObject({ kid: '<id-token.kid.1>' });
    expect(evidence.observations[4]).toEqual({
      stepId: 'access-token',
      kind: 'semantic-state',
      value: { format: 'opaque', characterCount: harness.firstAccessToken.length },
    });
    expect(evidence.observations[5]?.value).toEqual({
      sub: '<user.primary>',
      name: null,
      picture: null,
      preferred_username: 'aster_phase0_password_user',
      username: 'aster_phase0_password_user',
      created_at: { $timestamp: timestamp, $toleranceSeconds: 60 },
      updated_at: { $timestamp: timestamp + 1, $toleranceSeconds: 60 },
    });
    expect(evidence.observations[6]?.value).toEqual({
      obtainedAfterCacheClear: true,
      format: 'opaque',
    });
    expect(evidence.observations.at(-1)?.value).toEqual({ deleted: true });
    expect(() => {
      assertEvidenceIsSanitized(evidence);
    }).not.toThrow();

    const serialized = JSON.stringify(evidence);
    const inspected = inspect(evidence, { depth: null });
    expect(serialized).not.toContain(password);
    expect(inspected).not.toContain(password);
    expect(serialized).not.toContain(cookieValue);
    expect(inspected).not.toContain(cookieValue);
    expect(serialized).not.toContain(submitCookieValue);
    expect(inspected).not.toContain(submitCookieValue);
    expect(serialized).not.toContain(processCookieValue);
    expect(inspected).not.toContain(processCookieValue);
    expect(serialized).not.toContain(upstreamJsonCookieValue);
    expect(inspected).not.toContain(upstreamJsonCookieValue);
    expect(serialized).not.toContain(resumeCookieValue);
    expect(inspected).not.toContain(resumeCookieValue);
    expect(serialized).not.toContain(resumeSignatureCookieValue);
    expect(inspected).not.toContain(resumeSignatureCookieValue);
    expect(serialized).not.toContain(redirectSecret);
    expect(inspected).not.toContain(redirectSecret);
    expect(serialized).not.toContain(stateSecret);
    expect(inspected).not.toContain(stateSecret);
    expect(serialized).not.toContain(harness.idToken);
    expect(inspected).not.toContain(harness.idToken);
    expect(serialized).not.toContain(harness.firstAccessToken);
    expect(inspected).not.toContain(harness.firstAccessToken);
    expect(serialized).not.toContain(harness.secondAccessToken);
    expect(inspected).not.toContain(harness.secondAccessToken);
    expect(serialized).not.toContain(nonceSecret);
    expect(inspected).not.toContain(nonceSecret);
    expect(serialized).not.toContain(verificationSecret);
    expect(inspected).not.toContain(verificationSecret);
    expect(serialized).not.toContain(diagnosticSecret);
    expect(JSON.stringify(evidence.observations[3]?.value)).not.toMatch(
      /"(?:nonce|code|state|verification_id|unknown_claim)":/u
    );
  });

  it('uses the same deterministic fixture independently for both targets', async () => {
    const oracle = createHarness({ label: 'oracle' });
    const candidate = createHarness({ label: 'candidate' });

    const [oracleEvidence, candidateEvidence] = await Promise.all([oracle.run(), candidate.run()]);

    expect(oracle.client.createdPayloads).toEqual(candidate.client.createdPayloads);
    expect(oracleEvidence.observations).toEqual(candidateEvidence.observations);
  });

  it('compares equal across target-local URLs, IDs, and millisecond user claim timestamps', async () => {
    const oracle = createHarness({ label: 'oracle', timeOffsetSeconds: 0 });
    const candidate = createHarness({ label: 'candidate', timeOffsetSeconds: 30 });
    const [oracleEvidence, candidateEvidence] = await Promise.all([oracle.run(), candidate.run()]);

    expect(
      compareJson(
        { observations: oracleEvidence.observations },
        { observations: candidateEvidence.observations }
      )
    ).toEqual([]);
    expect(oracleEvidence.observations[3]?.value).toMatchObject({
      created_at: { $timestamp: timestamp, $toleranceSeconds: 60 },
      updated_at: { $timestamp: timestamp + 1, $toleranceSeconds: 60 },
    });
    expect(candidateEvidence.observations[5]?.value).toMatchObject({
      created_at: { $timestamp: timestamp + 30, $toleranceSeconds: 60 },
      updated_at: { $timestamp: timestamp + 31, $toleranceSeconds: 60 },
    });
  });

  it('canonicalizes semantic set claims and scope without changing raw ordered arrays', async () => {
    const oracle = createHarness({ label: 'oracle', accessTokenFormat: 'jwt' });
    const candidate = createHarness({
      label: 'candidate',
      accessTokenFormat: 'jwt',
      reverseSetClaims: true,
    });
    const [oracleEvidence, candidateEvidence] = await Promise.all([oracle.run(), candidate.run()]);

    expect(
      compareJson(
        { observations: oracleEvidence.observations },
        { observations: candidateEvidence.observations }
      )
    ).toEqual([]);
    expect(oracleEvidence.observations[5]?.value).toMatchObject({
      aud: ['account', 'api'],
      scope: 'openid profile',
      amr: ['mfa', 'pwd'],
      roles: ['reader', 'writer'],
      organizations: ['org-a', 'org-b'],
      organization_roles: ['org-a:admin', 'org-b:reader'],
      permissions: ['read:data', 'write:data'],
      organization_data: [
        { id: 'org-a', ownerId: '<user.primary>', name: 'A' },
        { id: 'org-b', ownerId: '<user.primary>', name: 'B' },
      ],
      sso_identities: [
        { issuer: 'first', identityId: 'first-id' },
        { issuer: 'second', identityId: 'second-id' },
      ],
      custom_data: {
        rollout: 'aster',
        location: { postal_code: '100-0001' },
        ordered: ['first', 'second'],
      },
    });
  });

  it('keeps genuinely ordered custom arrays order-sensitive', async () => {
    const oracle = createHarness({
      accessTokenFormat: 'jwt',
      orderedClaimValues: ['first', 'second'],
    });
    const candidate = createHarness({
      label: 'candidate',
      accessTokenFormat: 'jwt',
      orderedClaimValues: ['second', 'first'],
    });
    const [oracleEvidence, candidateEvidence] = await Promise.all([oracle.run(), candidate.run()]);
    const differences = compareJson(
      { observations: oracleEvidence.observations },
      { observations: candidateEvidence.observations }
    );

    expect(differences.map(({ path }) => path)).toEqual([
      '/observations/5/value/custom_data/ordered/0',
      '/observations/5/value/custom_data/ordered/1',
    ]);
  });

  it('preserves duplicate members while sorting a semantic set claim', async () => {
    const harness = createHarness({
      accessTokenFormat: 'jwt',
      jwtExtraClaims: { roles: ['writer', 'reader', 'reader'] },
    });
    const evidence = await harness.run();

    expect(evidence.observations[5]?.value).toMatchObject({
      roles: ['reader', 'reader', 'writer'],
    });
  });

  it('uses normalized sort keys without pre-normalizing raw set values', async () => {
    const oracle = createHarness({
      label: 'oracle',
      accessTokenFormat: 'jwt',
      userId: 'oracle-runtime-special',
      jwtExtraClaims: { roles: ['reader', 'oracle-runtime-special'] },
    });
    const candidate = createHarness({
      label: 'candidate',
      accessTokenFormat: 'jwt',
      userId: 'candidate-runtime-special',
      jwtExtraClaims: { roles: ['candidate-runtime-special', 'reader'] },
    });
    const [oracleEvidence, candidateEvidence] = await Promise.all([oracle.run(), candidate.run()]);

    expect(oracleEvidence.observations[5]?.value).toMatchObject({
      roles: ['<user.primary>', 'reader'],
    });
    expect(JSON.stringify(oracleEvidence)).not.toContain('<<user.primary>.primary>');
    expect(oracleEvidence.observations).toEqual(candidateEvidence.observations);
  });

  it.each(['target', '<target', 'user.primary'])(
    'normalizes adversarial user and key identifiers exactly once: %s',
    async (runtimeIdentifier) => {
      const oracle = createHarness({
        label: 'oracle',
        userId: runtimeIdentifier,
        kid: runtimeIdentifier,
      });
      const candidate = createHarness({
        label: 'candidate',
        userId: runtimeIdentifier,
        kid: runtimeIdentifier,
      });
      const [oracleEvidence, candidateEvidence] = await Promise.all([
        oracle.run(),
        candidate.run(),
      ]);

      expect(oracleEvidence.observations).toEqual(candidateEvidence.observations);
      expect(JSON.stringify(oracleEvidence)).toContain('<user.primary>');
      expect(JSON.stringify(oracleEvidence)).not.toContain('<<user.primary>.primary>');
    }
  );

  it('records opaque token shape without bytes and still refreshes only after cache clear', async () => {
    const harness = createHarness({ accessTokenFormat: 'opaque' });
    const evidence = await harness.run();
    const accessObservation = evidence.observations.find(({ stepId }) => stepId === 'access-token');

    expect(accessObservation).toEqual({
      stepId: 'access-token',
      kind: 'semantic-state',
      value: { format: 'opaque', characterCount: harness.firstAccessToken.length },
    });
    expect(evidence.observations).not.toContainEqual(
      expect.objectContaining({ stepId: 'access-token.claims' })
    );
    expect(harness.events.indexOf('clear-access-token')).toBeLessThan(
      harness.events.indexOf('refresh-access-token')
    );
    expect(() => {
      assertEvidenceIsSanitized(evidence);
    }).not.toThrow();
  });

  it('classifies the distinct post-clear token rather than reusing the first token format', async () => {
    const harness = createHarness({
      accessTokenFormat: 'jwt',
      refreshedAccessTokenFormat: 'opaque',
    });
    const evidence = await harness.run();

    expect(evidence.observations[4]?.kind).toBe('jwt-header');
    expect(evidence.observations[4]?.value).toMatchObject({ kid: '<access-token.kid.1>' });
    expect(evidence.observations[5]?.value).toMatchObject({
      sub: '<user.primary>',
      aud: ['account', 'api'],
      scope: 'openid profile',
      roles: ['reader', 'writer'],
      organizations: ['org-a', 'org-b'],
      custom_data: { rollout: 'aster', location: { postal_code: '100-0001' } },
      created_at: { $timestamp: timestamp, $toleranceSeconds: 60 },
      updated_at: { $timestamp: timestamp + 1, $toleranceSeconds: 60 },
    });
    expect(JSON.stringify(evidence.observations[5]?.value)).not.toMatch(
      /"(?:nonce|unknown_claim)":/u
    );
    expect(evidence.observations.find(({ stepId }) => stepId === 'access-token-refresh')).toEqual({
      stepId: 'access-token-refresh',
      kind: 'semantic-state',
      value: { obtainedAfterCacheClear: true, format: 'opaque' },
    });
  });

  it.each([
    { container: 'custom_data', nestedKey: 'verificationId' },
    { container: 'identities', nestedKey: 'nonce' },
    { container: 'organization_data', nestedKey: 'code' },
    { container: 'address', nestedKey: 'state' },
    { container: 'custom_data', nestedKey: 'authorization_code' },
  ])(
    'fails fixed before recording nested ephemeral $container.$nestedKey',
    async ({ container, nestedKey }) => {
      const harness = createHarness({
        accessTokenFormat: 'jwt',
        jwtExtraClaims: {
          [container]: { semantic: 'preserved-when-safe', [nestedKey]: diagnosticSecret },
        },
      });
      const error = await captureRejection(harness.run());

      assertSanitizedError(error, 'Access token normalization failed', [harness.firstAccessToken]);
      expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
    }
  );

  it('classifies a JWT obtained only after cache clear', async () => {
    const harness = createHarness({
      accessTokenFormat: 'opaque',
      refreshedAccessTokenFormat: 'jwt',
    });
    const evidence = await harness.run();

    expect(evidence.observations.find(({ stepId }) => stepId === 'access-token')).toMatchObject({
      value: { format: 'opaque' },
    });
    expect(evidence.observations.find(({ stepId }) => stepId === 'access-token-refresh')).toEqual({
      stepId: 'access-token-refresh',
      kind: 'semantic-state',
      value: { obtainedAfterCacheClear: true, format: 'jwt' },
    });
  });

  it('isolates refreshed JWT identifiers from previously observed semantic values', async () => {
    const oracle = createHarness({
      label: 'oracle',
      accessTokenFormat: 'jwt',
      refreshedAccessTokenFormat: 'jwt',
      refreshedJti: 'reader',
    });
    const candidate = createHarness({
      label: 'candidate',
      accessTokenFormat: 'jwt',
      refreshedAccessTokenFormat: 'jwt',
      refreshedJti: 'reader',
    });
    const [oracleEvidence, candidateEvidence] = await Promise.all([oracle.run(), candidate.run()]);

    expect(oracleEvidence.observations[5]?.value).toMatchObject({
      roles: ['reader', 'writer'],
    });
    expect(JSON.stringify(oracleEvidence)).not.toContain('<access-token.jti.1>');
    expect(oracleEvidence.observations).toEqual(candidateEvidence.observations);
  });

  it('fails fixed when cache clear returns the identical access token', async () => {
    const harness = createHarness({ refreshedAccessTokenFormat: 'same' });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Access token refresh failed', [
      harness.firstAccessToken,
      harness.secondAccessToken,
    ]);
    expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
  });

  it('fails fixed when a JOSE-shaped access token has malformed claims', async () => {
    const harness = createHarness({ accessTokenFormat: 'malformed-jose' });

    await expect(harness.run()).rejects.toThrow('Access token normalization failed');
    expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
  });

  it.each([
    { accessTokenFormat: 'malformed-jwe', refreshedAccessTokenFormat: undefined },
    { accessTokenFormat: 'jwt', refreshedAccessTokenFormat: 'malformed-jwe' },
  ] satisfies ReadonlyArray<{
    accessTokenFormat: NonNullable<HarnessOptions['accessTokenFormat']>;
    refreshedAccessTokenFormat: HarnessOptions['refreshedAccessTokenFormat'];
  }>)(
    'fails closed for JOSE-shaped five-part input',
    async ({ accessTokenFormat, refreshedAccessTokenFormat }) => {
      const harness = createHarness({ accessTokenFormat, refreshedAccessTokenFormat });
      const error = await captureRejection(harness.run());
      const expected =
        refreshedAccessTokenFormat === undefined
          ? 'Access token normalization failed'
          : 'Access token refresh failed';

      assertSanitizedError(error, expected, [harness.firstAccessToken, harness.secondAccessToken]);
    }
  );

  it.each([null, [], 'not-an-object', 42, { sub: 'user', created_at: 'milliseconds' }])(
    'rejects malformed or non-object UserInfo with a fixed sanitized error: %p',
    async (userInfoValue) => {
      const harness = createHarness({ userInfoValue });
      const error = await captureRejection(harness.run());

      assertSanitizedError(error, 'Userinfo read failed', [harness.firstAccessToken]);
      expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
    }
  );

  it('rejects credential-shaped UserInfo without echoing its value', async () => {
    const harness = createHarness({
      userInfoValue: { sub: 'runtime-user', client_secret: diagnosticSecret },
    });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Userinfo read failed', [harness.firstAccessToken]);
  });

  it('rejects nested UserInfo verification identifiers without echoing them', async () => {
    const harness = createHarness({
      userInfoValue: {
        sub: 'oracle-runtime-user',
        custom_data: { semantic: 'safe', verificationId: diagnosticSecret },
      },
    });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Userinfo read failed', [harness.firstAccessToken]);
  });

  it.each([
    { userInfoCookieEcho: 'init-json' as const, cookie: upstreamJsonCookieValue },
    { userInfoCookieEcho: 'resume' as const, cookie: resumeCookieValue },
    {
      userInfoCookieEcho: 'resume-signature' as const,
      cookie: resumeSignatureCookieValue,
    },
    { userInfoCookieEcho: 'submit' as const, cookie: submitCookieValue },
    { userInfoCookieEcho: 'process' as const, cookie: processCookieValue },
  ])(
    'rejects the rotated $userInfoCookieEcho cookie when echoed by an allowed UserInfo field',
    async ({ userInfoCookieEcho, cookie }) => {
      const harness = createHarness({ userInfoCookieEcho });
      const error = await captureRejection(harness.run());

      assertSanitizedError(error, 'Userinfo read failed', [cookie, harness.firstAccessToken]);
      expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
    }
  );

  it('fails closed when a short quoted cookie value appears in attributes', async () => {
    const shortCookieValue = ['x', 'y'].join('');
    const harness = createHarness({
      initCookieHeaders: [
        `quoted="${shortCookieValue}"; Path=/resume/${shortCookieValue}; SameSite=Lax`,
      ],
    });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Cookie normalization failed', [shortCookieValue]);
    expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
  });

  it('does not corrupt attributes when the cookie-pair value is empty', async () => {
    const harness = createHarness({
      initCookieHeaders: ['empty=; Path=/keep-empty-shape; SameSite=Lax'],
    });
    const evidence = await harness.run();

    expect(evidence.observations[1]?.value).toEqual([
      {
        name: 'empty',
        path: '/keep-empty-shape',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      },
    ]);
  });

  it('fails closed when the fixed placeholder contains a tracked long candidate', async () => {
    const harness = createHarness({
      initCookieHeaders: ['overlap=redacted; Path=/safe; SameSite=Lax'],
    });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Cookie normalization failed', ['redacted']);
  });

  it('uses one non-cascading pass for long replacements and ignores unrelated short values', async () => {
    const longValue = ['primary', 'long', 'runtime'].join('-');
    const shortValue = 'aster';
    const harness = createHarness({
      initCookieHeaders: [
        `primary=${longValue}; Path=/resume/${longValue}; SameSite=Lax`,
        `short=${shortValue}; Path=/safe; SameSite=Lax`,
      ],
    });
    const evidence = await harness.run();

    expect(evidence.observations[1]?.value).toEqual([
      {
        name: 'primary',
        path: '/resume/aster-redacted',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      },
      {
        name: 'short',
        path: '/safe',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      },
    ]);
    expect(JSON.stringify(evidence)).not.toContain(longValue);
  });

  it('never replaces a long cookie value inside another header flag name', async () => {
    const flagShapedValue = ['Http', 'Only'].join('');
    const harness = createHarness({
      initCookieHeaders: [
        `source=${flagShapedValue}; Path=/source; SameSite=Lax`,
        'target=runtime-target; Path=/target; HttpOnly; SameSite=Lax',
      ],
    });
    const evidence = await harness.run();

    expect(evidence.observations[1]?.value).toEqual([
      {
        name: 'source',
        path: '/source',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
      },
      {
        name: 'target',
        path: '/target',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
    ]);
    expect(JSON.stringify(evidence)).not.toContain(flagShapedValue);
  });

  it.each([
    {
      label: 'SameSite',
      shortValue: ['L', 'a', 'x'].join(''),
      targetHeader: 'target=runtime-target; SameSite=Lax',
    },
    {
      label: 'Max-Age',
      shortValue: ['6', '0'].join(''),
      targetHeader: 'target=runtime-target; Max-Age=60',
    },
  ])('fails closed for a short value collision in $label attribute data', async (input) => {
    const harness = createHarness({
      initCookieHeaders: [`source=${input.shortValue}; Path=/source`, input.targetHeader],
    });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Cookie normalization failed', [input.shortValue]);
  });

  it.each([
    { caseLabel: 'malformed pair', initCookieHeaders: ['missing-cookie-pair'] },
    {
      caseLabel: 'invalid attribute',
      initCookieHeaders: ['interaction=runtime-value; SameSite=Invalid'],
    },
    {
      caseLabel: 'control character',
      initCookieHeaders: [`interaction=runtime-value;${String.fromCodePoint(10)}Secure`],
    },
    ...[
      { label: 'CR', codePoint: 13 },
      { label: 'LF', codePoint: 10 },
      { label: 'NUL', codePoint: 0 },
      { label: 'DEL', codePoint: 127 },
    ].map(({ label, codePoint }) => ({
      caseLabel: `${label} in the value region`,
      initCookieHeaders: [
        `interaction=runtime${String.fromCodePoint(codePoint)}value; Path=/; Secure`,
      ],
    })),
  ])('rejects a $caseLabel Set-Cookie header with a fixed sanitized error', async (options) => {
    const harness = createHarness(options);
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, 'Cookie normalization failed');
    expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
  });

  it.each([
    {
      label: 'created management username',
      options: { createdUserUsername: `prefix-${password}-suffix` },
      expected: 'Invalid management user projection',
    },
    {
      label: 'ID-token name',
      options: { idTokenExtraClaims: { name: `prefix-${password}-suffix` } },
      expected: 'ID token normalization failed',
    },
    {
      label: 'ID-token extracted nonce echo',
      options: { idTokenExtraClaims: { name: `prefix-${nonceSecret}-suffix` } },
      expected: 'ID token normalization failed',
    },
    {
      label: 'access-token custom data',
      options: {
        accessTokenFormat: 'jwt' as const,
        jwtExtraClaims: { custom_data: { rollout: `prefix-${password}-suffix` } },
      },
      expected: 'Access token normalization failed',
    },
    {
      label: 'UserInfo access-token echo',
      options: { echoAccessTokenInUserInfo: true },
      expected: 'Userinfo read failed',
    },
    {
      label: 'UserInfo ID-token echo',
      options: { echoIdTokenInUserInfo: true },
      expected: 'Userinfo read failed',
    },
    {
      label: 'UserInfo cookie echo',
      options: { userInfoValue: { sub: 'oracle-runtime-user', name: `x-${cookieValue}-x` } },
      expected: 'Userinfo read failed',
    },
    {
      label: 'UserInfo redirect code echo',
      options: { userInfoValue: { sub: 'oracle-runtime-user', name: `x-${redirectSecret}-x` } },
      expected: 'Userinfo read failed',
    },
    {
      label: 'UserInfo redirect state echo',
      options: { userInfoValue: { sub: 'oracle-runtime-user', name: `x-${stateSecret}-x` } },
      expected: 'Userinfo read failed',
    },
    {
      label: 'UserInfo verification ID echo',
      options: { userInfoValue: { sub: 'oracle-runtime-user', name: verificationSecret } },
      expected: 'Userinfo read failed',
    },
    {
      label: 'UserInfo property-name password echo',
      options: {
        userInfoValue: { sub: 'oracle-runtime-user', custom_data: { [password]: 'safe' } },
      },
      expected: 'Userinfo read failed',
    },
    {
      label: 'final management name',
      options: { finalUserName: `prefix-${password}-suffix` },
      expected: 'Invalid management user projection',
    },
    {
      label: 'final management refreshed-token echo',
      options: { finalUserName: 'refreshed.runtime.private' },
      expected: 'Invalid management user projection',
    },
    {
      label: 'earlier UserInfo late refreshed-token echo',
      options: { echoRefreshedTokenInUserInfo: true },
      expected: 'Access token refresh failed',
    },
  ])(
    'rejects a known sensitive value embedded in an allowed $label field',
    async ({ options, expected }) => {
      const harness = createHarness(options);
      const error = await captureRejection(harness.run());

      assertSanitizedError(error, expected, [
        harness.idToken,
        harness.firstAccessToken,
        harness.secondAccessToken,
      ]);
      expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
    }
  );

  it.each([
    { idTokenFormat: 'absent', expected: 'ID token read failed' },
    { idTokenFormat: 'malformed', expected: 'ID token normalization failed' },
  ] satisfies ReadonlyArray<{
    idTokenFormat: NonNullable<HarnessOptions['idTokenFormat']>;
    expected: string;
  }>)('fails fixed for a $idTokenFormat ID token', async ({ idTokenFormat, expected }) => {
    const harness = createHarness({ idTokenFormat });

    await expect(harness.run()).rejects.toThrow(expected);
    expect(harness.events.slice(-2)).toEqual(['cleanup', 'delete-user']);
  });

  it.each([
    { failAt: 'start-interaction', expected: 'Start interaction failed' },
    { failAt: 'verify-password', expected: 'Identify user failed' },
    { failAt: 'identify-user', expected: 'Identify user failed' },
    { failAt: 'submit-interaction', expected: 'Submit interaction failed' },
    { failAt: 'process-consent', expected: 'Process session failed' },
    { failAt: 'decode-id-token', expected: 'ID token read failed' },
    { failAt: 'obtain-access-token', expected: 'Access token read failed' },
    { failAt: 'call-userinfo', expected: 'Userinfo read failed' },
    { failAt: 'clear-access-token', expected: 'Access token cache clear failed' },
    { failAt: 'refresh-access-token', expected: 'Access token refresh failed' },
    { failAt: 'read-user', expected: 'Read user failed' },
    { failAt: 'delete-user', expected: 'Delete user failed' },
  ])('uses runner cleanup after a post-create failure at $failAt', async ({ failAt, expected }) => {
    const harness = createHarness({ failAt });
    const error = await captureRejection(harness.run());

    assertSanitizedError(error, expected, [harness.firstAccessToken, harness.secondAccessToken]);
    expect(harness.events).toContain('cleanup');
    expect(harness.client.deleteCalls).toBe(failAt === 'delete-user' ? 2 : 1);
  });

  it.each([
    { failAt: 'set-sign-in-experience', expected: 'Set sign-in experience failed' },
    { failAt: 'create-user', expected: 'Create user failed' },
  ])(
    'does not delete when failure happens before user creation completes at $failAt',
    async ({ failAt, expected }) => {
      const harness = createHarness({ failAt });
      const error = await captureRejection(harness.run());

      assertSanitizedError(error, expected, [harness.firstAccessToken, harness.secondAccessToken]);
      expect(harness.client.deleteCalls).toBe(0);
    }
  );

  it('preserves runner primary and cleanup errors as an aggregate', async () => {
    const harness = createHarness({ failAt: 'start-interaction', cleanupFails: true });

    const error = await captureRejection(harness.run());
    expect(error).toMatchObject({
      message: 'Scenario execution and target cleanup both failed',
      errors: [expect.any(Error), expect.any(Error)],
    });
    assertSanitizedError(error, 'Start interaction failed', [
      harness.firstAccessToken,
      harness.secondAccessToken,
    ]);
  });
});

describe('management user projection', () => {
  it('projects stable public semantics without carrying schemaless nested payloads', () => {
    const input = {
      id: 'runtime-user',
      createdAt: timestamp * 1000 + 999,
      updatedAt: (timestamp + 1) * 1000,
      lastSignInAt: null,
      profile: { name: 'Aster' },
      customData: { rollout: 'aster' },
      identities: { github: { userId: 'not-evidence' }, google: { userId: 'not-evidence' } },
      unknownMaterial: 'not-evidence',
    };
    const original = structuredClone(input);

    expect(projectUserForObservation(input)).toEqual({
      id: 'runtime-user',
      createdAt: { $timestamp: timestamp, $toleranceSeconds: 60 },
      updatedAt: { $timestamp: timestamp + 1, $toleranceSeconds: 60 },
      lastSignInAt: null,
      profileIsEmpty: false,
      customDataIsEmpty: false,
      identityTargets: ['github', 'google'],
    });
    expect(input).toEqual(original);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, '1700000000', {}, []])(
    'rejects an invalid present timestamp field: %p',
    (createdAt) => {
      expect(() => projectUserForObservation({ id: 'user', createdAt })).toThrow(
        'Invalid management user projection'
      );
    }
  );

  it.each([new Date(), { id: 'user', optional: undefined }, Object.create({ id: 'user' })])(
    'rejects non-faithful JSON input: %p',
    (input) => {
      expect(() => projectUserForObservation(input)).toThrow('Invalid management user projection');
    }
  );

  it.each([
    { id: 'user', password: diagnosticSecret },
    { id: 'user', customData: { api_key: diagnosticSecret } },
  ])('rejects credential-shaped management fields without echoing values', (input) => {
    const error = (() => {
      try {
        projectUserForObservation(input);
        return new Error('Expected rejection');
      } catch (error_: unknown) {
        return error_;
      }
    })();

    assertSanitizedError(error, 'Invalid management user projection');
  });
});
/* eslint-enable max-lines, @typescript-eslint/no-explicit-any, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
