/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment -- The fake Management API and coordinator journal intentionally model mutable partial-apply and rollback state. */
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';

import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import type { TargetConfig } from '../model.js';
import type {
  CommandRunnerRequest,
  CommandRunnerResult,
} from '../phase-1/clients/command-provisioner.js';

import { issueCandidateInvariantUserTokens } from './cli.js';
import { withPhase2AdminManagementBearer } from './clients/admin-management-bearer.js';
import { observeClientCredentialsToken } from './clients/client-credentials.js';
import {
  createCandidatePhase2FixtureProvisioner,
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  createReferencePhase2FixtureProvisioner,
  phase2FixtureContract,
  runWithPhase2Fixture,
  takeOracleVerificationCode,
  type Phase2AdminRequest,
} from './fixtures.js';

const withOracleSmtpControl = async <Result>(
  reply: (requestIndex: number) => string | Readonly<{ value: string; keepOpen: true }> | undefined,
  use: () => Promise<Result>
): Promise<Result> => {
  const directory = await mkdtemp('/var/tmp/henry-build/oracle-smtp-control-test-');
  const socketPath = path.join(directory, 'oracle-smtp.sock');
  let requests = 0;
  const server = createServer((socket) => {
    socket.once('data', () => {
      const value = reply(requests);
      requests += 1;
      if (typeof value === 'string') {
        socket.end(value);
      } else if (value) {
        socket.write(value.value);
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });
  const previous = process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET;
  process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET = socketPath;
  try {
    return await use();
  } finally {
    if (previous === undefined) {
      Reflect.deleteProperty(process.env, 'ASTER_PHASE2_ORACLE_SMTP_SOCKET');
    } else {
      process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET = previous;
    }
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
    await rm(directory, { recursive: true, force: true });
  }
};

const oracle: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://127.0.0.1:4101/',
  adminUrl: 'http://127.0.0.1:4102/',
});

const oracleForeign: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://127.0.0.1:4103/',
  adminUrl: 'http://127.0.0.1:4104/',
});
const candidate: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'http://127.0.0.1:4201/',
  adminUrl: 'http://127.0.0.1:4202/',
});
const candidateForeign: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'http://127.0.0.1:4203/',
  adminUrl: 'http://127.0.0.1:4204/',
});

const primaryCoordinatorEntities = [
  ['tenant', 'default', 'default'],
  ['user', 'phase1-user', 'zdata-user'],
  ['application', 'phase1-app', 'phase1-app'],
  ['application', 'phase1-browser', 'phase1-browser'],
  ['resource', 'phase1-api', 'phase1-api'],
  ['scope', 'phase1-read-profile', 'phase1-read-profile'],
  ['role', 'phase1-reader', 'phase1-reader'],
  ['application', 'phase2-m2m-basic', 'phase2-m2m-basic'],
  ['application', 'phase2-m2m-post', 'phase2-m2m-post'],
  ['application', 'phase2-status', 'phase2-status'],
  ['application', 'phase2-device-first', 'phase2-device-first'],
  ['application', 'phase2-device-third', 'phase2-device-third'],
  ['application', 'phase2-device-nogrant', 'phase2-device-nogrant'],
  ['application', 'phase2-device-web', 'phase2-device-web'],
  ['resource', 'phase2-resource-primary', 'p2-resource-primary'],
  ['scope', 'read-scope', 'read-scope'],
  ['scope', 'write-scope', 'write-scope'],
  ['scope', 'unassigned-scope', 'unassigned-scope'],
  ['resource', 'phase2-resource', 'phase2-resource'],
  ['scope', 'default-scope', 'default-scope'],
  ['organization', 'phase2-org', 'phase2-org'],
].map(([kind, logicalId, runtimeId]) => ({ kind, logicalId, runtimeId }));
const invariantPrimaryCoordinatorEntities = [
  ...primaryCoordinatorEntities,
  { kind: 'user', logicalId: 'phase2-verification-peer', runtimeId: 'vcode-peer' },
];
const foreignCoordinatorEntities = [
  { kind: 'tenant', logicalId: 'default', runtimeId: 'default' },
  {
    kind: 'application',
    logicalId: 'phase2-device-first',
    runtimeId: 'phase2-device-first',
  },
];
const adminCoordinatorEntities = [
  ['tenant', 'admin', 'admin'],
  ['user', 'phase1-admin', 'phase1-admin'],
  ['application', 'admin-console', 'admin-console'],
  ['resource', 'admin.resource.1', 'admin-management'],
  ['resource', 'admin.resource.2', 'admin-account'],
  ['resource', 'admin.resource.3', 'admin-organizations'],
  ['role', 'default:admin', 'default:admin'],
  ['role', 'user', 'user'],
  ['organization', 't-default', 't-default'],
  ['organization-role', 'admin', 'admin'],
].map(([kind, logicalId, runtimeId]) => ({ kind, logicalId, runtimeId }));
const primaryCoordinatorIsolation = {
  persistenceId: 'postgresql:1:aster_phase1_candidate_primary',
  cookieKeyId: '1'.repeat(32),
  signingKeyId: '2'.repeat(32),
};
const foreignCoordinatorIsolation = {
  persistenceId: 'postgresql:2:aster_phase1_candidate_foreign',
  cookieKeyId: '3'.repeat(32),
  signingKeyId: '4'.repeat(32),
};
const adminCoordinatorIsolation = {
  persistenceId: primaryCoordinatorIsolation.persistenceId,
  cookieKeyId: '5'.repeat(32),
  signingKeyId: '6'.repeat(32),
};
const phase2ForeignAllocationId = (allocationId: string) =>
  `phase2-foreign-${createHash('sha256').update(allocationId).digest('hex')}`;
const phase2AdminAllocationId = (allocationId: string) =>
  `phase2-admin-${createHash('sha256').update(allocationId).digest('hex')}`;

const candidateCoordinatorPublic = (
  allocationId: string,
  recipe: 'fullPhase1' | 'phase2CandidateInvariants' = 'fullPhase1'
) => ({
  schemaVersion: 1,
  recipe,
  allocations: [
    {
      allocationId,
      role: 'data',
      target: 'primary',
      isolation: primaryCoordinatorIsolation,
      entities:
        recipe === 'phase2CandidateInvariants'
          ? invariantPrimaryCoordinatorEntities
          : primaryCoordinatorEntities,
    },
    {
      allocationId: phase2AdminAllocationId(allocationId),
      role: 'admin',
      target: 'primary',
      isolation: adminCoordinatorIsolation,
      entities: adminCoordinatorEntities,
    },
    ...(recipe === 'phase2CandidateInvariants'
      ? [
          {
            allocationId: phase2ForeignAllocationId(allocationId),
            role: 'foreign',
            target: 'foreign',
            isolation: foreignCoordinatorIsolation,
            entities: foreignCoordinatorEntities,
          },
        ]
      : []),
  ],
});

const candidateProvisionResult = (
  allocationId: string,
  recipe: 'fullPhase1' | 'phase2CandidateInvariants' = 'fullPhase1'
): CommandRunnerResult =>
  commandResult(
    JSON.stringify({
      schemaVersion: 1,
      operation: 'provision',
      public: candidateCoordinatorPublic(allocationId, recipe),
    })
  );

const commandResult = (stdout: string): CommandRunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout,
  stderr: '',
  timedOut: false,
  killed: false,
  reaped: true,
});

const rejectedCommandResult = (): CommandRunnerResult => ({
  ...commandResult(''),
  exitCode: 1,
  stderr: 'Aster compatibility fixture command failed\n',
});

const candidateAdminLeaseTransport = async (): Promise<typeof fetch> => {
  const { privateKey, publicKey } = await generateKeyPair('ES384');
  const publicJwk = await exportJWK(publicKey);
  const now = Math.floor(Date.now() / 1000);
  const bearer = await new SignJWT({ client_id: 'admin-console', scope: 'all' })
    .setProtectedHeader({ alg: 'ES384', kid: 'email-admin-key' })
    .setIssuer(new URL('/oidc', candidate.adminUrl).href.replace(/\/$/u, ''))
    .setAudience('urn:aster:resource:management')
    .setSubject('phase1-admin')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  const callback = new URL('/console/callback', candidate.adminUrl);
  callback.search = new URLSearchParams({
    code: 'private-code',
    state: 's'.repeat(48),
    iss: new URL('/oidc', candidate.adminUrl).href.replace(/\/$/u, ''),
  }).toString();
  const replies = [
    new Response(null, {
      status: 303,
      headers: { 'set-cookie': 'admin=session; Path=/; HttpOnly' },
    }),
    new Response(null, { status: 204 }),
    new Response(JSON.stringify({ verificationId: 'private-verification' }), { status: 200 }),
    new Response(null, { status: 204 }),
    new Response(JSON.stringify({ redirectTo: '/oidc/auth/login-resume' }), { status: 200 }),
    new Response(null, { status: 303, headers: { location: '/consent?app_id=admin-console' } }),
    new Response(null, { status: 302, headers: { location: '/oidc/auth/consent-resume' } }),
    new Response(null, { status: 303, headers: { location: callback.href } }),
    new Response(
      JSON.stringify({
        access_token: 'initial-access',
        id_token: 'initial-id',
        refresh_token: 'initial-refresh',
        token_type: 'Bearer',
      }),
      { status: 200 }
    ),
    new Response(
      JSON.stringify({
        access_token: bearer,
        id_token: 'rotated-id',
        refresh_token: 'rotated-refresh',
        token_type: 'Bearer',
        scope: 'all',
      }),
      { status: 200 }
    ),
    new Response(
      JSON.stringify({
        keys: [{ ...publicJwk, kid: 'email-admin-key', alg: 'ES384', use: 'sig' }],
      }),
      { status: 200 }
    ),
    new Response(null, { status: 200 }),
  ];
  let index = 0;
  return (async () => replies[index++] ?? new Response(null, { status: 500 })) as typeof fetch;
};

const createReferenceAdmin = () => {
  const calls: Phase2AdminRequest[] = [];
  const ids = new Map<string, number>();
  const entityRows = new Map<string, Array<Record<string, unknown>>>();
  const nextId = (prefix: string) => {
    const next = (ids.get(prefix) ?? 0) + 1;
    ids.set(prefix, next);
    return `${prefix}-${next}`;
  };
  const request = async (input: Phase2AdminRequest): Promise<unknown> => {
    calls.push(input);
    if (
      input.method === 'POST' &&
      /^applications\/(?:application-4|application-6|application-7)\/user-consent-scopes$/u.test(
        input.path
      )
    ) {
      throw new Error('User consent scopes are only configurable for third-party applications');
    }
    if (input.method === 'GET') {
      if (/^applications\/[^/]+\/secrets$/u.test(input.path)) {
        return [{ value: 'ReferenceSecretValue000000000001' }];
      }
      if (input.path === 'sign-in-exp') {
        return {
          signInMode: 'SignInAndRegister',
          signUp: { identifiers: [], password: false, verify: false },
          signIn: { methods: [] },
          mfa: { factors: [], policy: 'PromptAtSignInAndSignUp' },
        };
      }
      if (input.path === 'account-center') {
        return { enabled: false, fields: {} };
      }
      return entityRows.get(input.path) ?? [];
    }
    if (input.method === 'DELETE' || input.method === 'PATCH') {
      if (input.method === 'DELETE') {
        for (const [collection, rows] of entityRows) {
          const prefix = `${collection}/`;
          if (input.path.startsWith(prefix)) {
            const id = decodeURIComponent(input.path.slice(prefix.length).split('/')[0] ?? '');
            entityRows.set(
              collection,
              rows.filter((row) => row.id !== id)
            );
          }
        }
      }
      return input.method === 'DELETE' ? 204 : {};
    }
    if (input.responseKind === 'created') {
      return undefined;
    }
    const prefix = input.path.includes('/scopes')
      ? 'scope'
      : input.path === 'applications'
        ? 'application'
        : input.path === 'users'
          ? 'user'
          : input.path === 'resources'
            ? 'resource'
            : input.path === 'roles'
              ? 'role'
              : input.path === 'organizations'
                ? 'organization'
                : input.path === 'organization-scopes'
                  ? 'organization-scope'
                  : 'organization-role';
    return { id: nextId(prefix) };
  };
  return { calls, entityRows, request };
};

describe('Oracle verification delivery control', () => {
  it('takes one six-digit code and reports the exact not-found response', async () => {
    await withOracleSmtpControl(
      (requestIndex) =>
        requestIndex === 0
          ? JSON.stringify({ code: '123456' })
          : JSON.stringify({ error: 'not_found' }),
      async () => {
        await expect(takeOracleVerificationCode('Owner@Example.Invalid')).resolves.toBe('123456');
        await expect(takeOracleVerificationCode('Owner@Example.Invalid')).rejects.toThrow(
          'Phase 2 verification delivery failed: not-found'
        );
      }
    );
  });

  it('rejects malformed response without retaining its body', async () => {
    await withOracleSmtpControl(
      () => JSON.stringify({ unexpected: 'private' }),
      async () =>
        expect(takeOracleVerificationCode('owner@example.invalid')).rejects.toThrow(
          'Phase 2 verification delivery failed: response'
        )
    );
  });

  it('reports environment, socket-shape, recipient, and connect failures with closed categories', async () => {
    const previous = process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET;
    try {
      Reflect.deleteProperty(process.env, 'ASTER_PHASE2_ORACLE_SMTP_SOCKET');
      await expect(takeOracleVerificationCode('owner@example.invalid')).rejects.toThrow(
        'Phase 2 verification delivery failed: env-missing'
      );
      process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET = '/var/tmp/henry-build/wrong-name.sock';
      await expect(takeOracleVerificationCode('owner@example.invalid')).rejects.toThrow(
        'Phase 2 verification delivery failed: socket-shape'
      );
      process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET =
        '/var/tmp/henry-build/missing-oracle-control/oracle-smtp.sock';
      await expect(takeOracleVerificationCode('not-an-email')).rejects.toThrow(
        'Phase 2 verification delivery failed: recipient'
      );
      await expect(takeOracleVerificationCode('owner@example.invalid')).rejects.toThrow(
        'Phase 2 verification delivery failed: connect'
      );
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(process.env, 'ASTER_PHASE2_ORACLE_SMTP_SOCKET');
      } else {
        process.env.ASTER_PHASE2_ORACLE_SMTP_SOCKET = previous;
      }
    }
  });

  it(
    'reports a silent control connection as a bounded timeout',
    async () =>
      withOracleSmtpControl(
        () => {
          const noReply: string | undefined = undefined;
          return noReply;
        },
        async () =>
          expect(takeOracleVerificationCode('owner@example.invalid')).rejects.toThrow(
            'Phase 2 verification delivery failed: timeout'
          )
      ),
    7000
  );

  it(
    'rejects a valid code when the control peer stays open past the deadline',
    async () =>
      withOracleSmtpControl(
        () => ({ value: JSON.stringify({ code: '654321' }), keepOpen: true }),
        async () =>
          expect(takeOracleVerificationCode('owner@example.invalid')).rejects.toThrow(
            'Phase 2 verification delivery failed: timeout'
          )
      ),
    7000
  );
});

describe('Phase 2 fixture lifecycle', () => {
  it('freezes the exact machine and confidential status client contract', () => {
    expect(phase2FixtureContract).toEqual({
      clients: { basic: 'phase2-m2m-basic', post: 'phase2-m2m-post' },
      deviceClients: {
        firstParty: 'phase2-device-first',
        thirdParty: 'phase2-device-third',
        missingGrant: 'phase2-device-nogrant',
        ineligibleWeb: 'phase2-device-web',
      },
      statusClient: {
        id: 'phase2-status',
        redirectUri: 'http://localhost:3001/demo-app',
      },
      resources: {
        primary: 'https://phase2.example.invalid/api-primary',
        default: 'https://phase2.example.invalid/api-default',
      },
      organization: { id: 'phase2-org', scope: 'organization:read' },
      scopes: ['read', 'write', 'unassigned'],
    });
    expect(Object.isFrozen(phase2FixtureContract)).toBe(true);
  });

  it('provisions the reference in dependency order and cleans up in exact reverse order', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'reference-fixture',
    });
    const fixture = await provisioner.provision();
    expect(fixture.public.boundary).toEqual({ primary: 'provisioned', foreign: 'unchanged' });
    let selectedEmailAfterClosure: (() => string) | undefined;
    let invalidEmailAfterClosure: (() => string) | undefined;
    await fixture.withSecretLease(async (lease) => {
      expect(Object.keys(lease).toSorted()).toEqual([
        'getClientSecret',
        'getInvalidEmailPassword',
        'getSelectedEmailPassword',
        'getSelectedNativePassword',
        'getStatusClientSecret',
        'getSubjectPassword',
        'takeVerificationCode',
        'toJSON',
      ]);
      expect(lease.getClientSecret('basic')).toBe('ReferenceSecretValue000000000001');
      expect(lease.getStatusClientSecret()).toBe('ReferenceSecretValue000000000001');
      expect(lease.getSubjectPassword?.()).toMatch(/A1!$/u);
      expect(lease.getSelectedNativePassword?.()).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
      expect(lease.getSelectedNativePassword?.()).not.toBe(lease.getSubjectPassword?.());
      expect(lease.getSelectedEmailPassword?.()).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
      expect(lease.getInvalidEmailPassword?.()).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
      expect(lease.getSelectedEmailPassword?.()).not.toBe(lease.getSelectedNativePassword?.());
      expect(lease.getInvalidEmailPassword?.()).not.toBe(lease.getSelectedEmailPassword?.());
      selectedEmailAfterClosure = lease.getSelectedEmailPassword;
      invalidEmailAfterClosure = lease.getInvalidEmailPassword;
      expect(JSON.stringify(fixture.public)).not.toContain(lease.getSelectedNativePassword?.());
      expect(JSON.stringify(fixture.public)).not.toContain(lease.getSelectedEmailPassword?.());
      expect(JSON.stringify(fixture.public)).not.toContain(lease.getInvalidEmailPassword?.());
      expect(() => JSON.stringify(lease)).toThrow('Phase 2 fixture operation failed');
    });
    expect(() => selectedEmailAfterClosure?.()).toThrow('Phase 2 fixture operation failed');
    expect(() => invalidEmailAfterClosure?.()).toThrow('Phase 2 fixture operation failed');
    expect(fixture.status).toMatchObject({
      user: { id: 'user-1', username: expect.stringMatching(/^phase1_user_a_[0-9a-f]{16}$/u) },
      client: { id: 'application-8', redirectUri: 'http://localhost:3001/demo-app' },
      confidentialClient: {
        id: 'application-3',
        redirectUri: 'http://localhost:3001/demo-app',
      },
      resource: { indicator: 'https://api.example.com', scopeName: 'read:profile' },
    });
    expect(Object.keys(fixture.public)).not.toContain('status');
    expect(fixture.public.deviceClients).toEqual({
      firstParty: {
        id: 'application-4',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      },
      thirdParty: {
        id: 'application-5',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      },
      missingGrant: {
        id: 'application-6',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
      ineligibleWeb: {
        id: 'application-7',
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
    });
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'applications/application-8/user-consent-scopes',
        body: {
          userScopes: ['profile', 'email', 'address', 'phone', 'urn:logto:scope:sessions'],
          resourceScopes: ['scope-4'],
        },
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'connectors',
        body: expect.objectContaining({
          connectorId: 'simple-mail-transfer-protocol',
          config: expect.objectContaining({ host: '172.30.231.49', port: 2525 }),
        }),
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'organizations/organization-1/users',
        body: { userIds: ['user-1'] },
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'roles',
        body: {
          name: 'phase2-client-credentials-reference-fixture-device-subject-role',
          description:
            'Phase 2 phase2-client-credentials-reference-fixture device subject authority',
          type: 'User',
          isDefault: false,
          scopeIds: ['scope-1'],
        },
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'roles/role-2/users',
        body: { userIds: ['user-1'] },
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'PATCH',
        path: 'account-center',
        body: { enabled: true, fields: { session: 'Edit' } },
      })
    );
    for (const [id, label, isThirdParty, isDeviceFlow] of [
      ['application-4', 'first-party', false, true],
      ['application-5', 'third-party', true, true],
      ['application-6', 'missing-grant', false, undefined],
    ] as const) {
      expect(admin.calls).toContainEqual(
        expect.objectContaining({
          method: 'POST',
          path: 'applications',
          body: expect.objectContaining({
            name: expect.stringContaining(`${label} device client`),
            type: 'Native',
            isThirdParty,
            oidcClientMetadata: { redirectUris: [], postLogoutRedirectUris: [] },
            customClientMetadata: isDeviceFlow ? { isDeviceFlow: true } : {},
          }),
        })
      );
    }
    expect(
      admin.calls
        .filter(
          ({ method, path }) =>
            method === 'POST' &&
            /^applications\/application-[4-7]\/user-consent-scopes$/u.test(path)
        )
        .map(({ path }) => path)
    ).toEqual(['applications/application-5/user-consent-scopes']);
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'applications/application-5/user-consent-scopes',
        body: {
          userScopes: ['profile', 'email', 'address', 'phone', 'urn:logto:scope:organizations'],
          resourceScopes: ['scope-4', 'scope-1', 'scope-2'],
        },
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'POST',
        path: 'applications',
        body: expect.objectContaining({
          name: expect.stringContaining('ineligible-web device client'),
          type: 'SPA',
          isThirdParty: false,
          oidcClientMetadata: {
            redirectUris: ['http://localhost:3001/demo-app'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
        }),
      })
    );
    await provisioner.cleanup(fixture);

    const deletes = admin.calls.filter(({ method }) => method === 'DELETE').map(({ path }) => path);
    expect(deletes.slice(0, 13)).toEqual([
      'connectors/organization-role-10',
      'applications/application-8',
      'applications/application-7',
      'applications/application-6',
      'applications/application-5',
      'applications/application-4',
      'roles/role-3',
      'resources/resource-3/scopes/scope-4',
      'resources/resource-3',
      'roles/role-2/users/user-1',
      'roles/role-2',
      'organizations/organization-1/users/user-1',
      'users/user-1',
    ]);
    expect(deletes.slice(13, 18)).toEqual([
      'organizations/organization-1/applications/application-1/roles/organization-role-3',
      'organizations/organization-1/applications/application-1',
      'organization-roles/organization-role-3',
      'organization-scopes/organization-scope-1',
      'organizations/organization-1',
    ]);
    expect(deletes).toContain('applications/application-1');
    expect(deletes).toContain('applications/application-2');
    expect(deletes).toContain('applications/application-3');
    expect(deletes).toEqual(
      expect.arrayContaining([
        'applications/application-4',
        'applications/application-5',
        'applications/application-6',
      ])
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'PATCH',
        path: 'sign-in-exp',
        body: {
          signInMode: 'SignInAndRegister',
          signUp: { identifiers: [], password: false, verify: false },
          signIn: { methods: [] },
          mfa: { factors: [], policy: 'PromptAtSignInAndSignUp' },
        },
      })
    );
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'PATCH',
        path: 'account-center',
        body: { enabled: false, fields: {} },
      })
    );
    expect(JSON.stringify(fixture.public)).not.toContain('ReferenceSecretValue');
    await expect(
      fixture.withSecretLease(async (lease) => lease.getClientSecret('basic'))
    ).rejects.toThrow('Phase 2 fixture operation failed');
  });

  it('routes every reference Management request through the data-tenant core URL', async () => {
    const originalFetch = globalThis.fetch;
    const requestedUrls: string[] = [];
    globalThis.fetch = (async (input) => {
      requestedUrls.push(String(input));
      throw new Error('stop after observing the Management origin');
    }) as typeof fetch;
    try {
      const provisioner = createReferencePhase2FixtureProvisioner({
        target: oracle,
        foreignTarget: oracleForeign,
        createAllocationId: () => 'management-origin',
      });
      await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(requestedUrls.length).toBeGreaterThan(0);
    expect(requestedUrls.every((url) => url.startsWith(oracle.coreUrl))).toBe(true);
    expect(requestedUrls.some((url) => url.startsWith(oracle.adminUrl))).toBe(false);
  });

  it('builds selected Management list queries structurally and rejects malformed query input', async () => {
    const requested: string[] = [];
    const request = createReferencePhase2AdminRequest(oracle, async (input) => {
      requested.push(String(input));
      return new Response('[]', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    await expect(
      request({
        method: 'GET',
        path: 'resources',
        query: { includeScopes: 'true' },
        expectedStatuses: [200],
        responseKind: 'array',
      })
    ).resolves.toEqual([]);
    expect(requested).toEqual(['http://127.0.0.1:4101/api/resources?includeScopes=true']);
    await expect(
      request({
        method: 'GET',
        path: 'roles',
        query: { 'bad?key': '1' },
        expectedStatuses: [200],
        responseKind: 'array',
      })
    ).rejects.toThrow('Phase 2 fixture operation failed');
    expect(requested).toHaveLength(1);
  });

  it('reuses the selected Management transport with one bounded bearer authority', async () => {
    const requests: Array<Readonly<{ url: string; authorization: string | undefined }>> = [];
    const request = createBearerPhase2AdminRequest(
      candidate,
      'candidate-management-bearer',
      async (input, init) => {
        requests.push(
          Object.freeze({
            url: String(input),
            authorization: new Headers(init?.headers).get('authorization') ?? undefined,
          })
        );
        return new Response('[]', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
    );
    await expect(
      request({
        method: 'GET',
        path: 'resources',
        expectedStatuses: [200],
        responseKind: 'array',
      })
    ).resolves.toEqual([]);
    expect(requests).toEqual([
      {
        url: 'http://127.0.0.1:4201/api/resources',
        authorization: 'Bearer candidate-management-bearer',
      },
    ]);
    expect(() => createBearerPhase2AdminRequest(candidate, 'bad bearer')).toThrow(
      'Phase 2 fixture operation failed'
    );
  });

  it('reconciles owned reference rows after partial provisioning failure', async () => {
    const admin = createReferenceAdmin();
    let posts = 0;
    admin.entityRows.set('applications', [
      { id: 'orphan-app', name: 'Phase 2 phase2-client-credentials-partial basic client' },
      {
        id: 'orphan-device-app',
        name: 'Phase 2 phase2-client-credentials-partial third-party device client',
      },
    ]);
    admin.entityRows.set('resources', [
      { id: 'previous-partial-default', name: 'existing default', isDefault: true },
    ]);
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      createAllocationId: () => 'partial',
      request: async (request) => {
        if (request.method === 'POST') {
          posts += 1;
          if (posts === 2) {
            throw new Error('planted failure');
          }
        }
        return admin.request(request);
      },
    });
    await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(admin.calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ method: 'DELETE', path: 'applications/orphan-app' }),
        expect.objectContaining({ method: 'DELETE', path: 'applications/orphan-device-app' }),
      ])
    );
    expect(admin.calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: 'PATCH',
          path: 'resources/previous-partial-default/is-default',
          body: { isDefault: true },
        }),
      ])
    );
  });

  it('reconciles exact Common email rows left by failed local cleanup and preserves foreign rows', async () => {
    const admin = createReferenceAdmin();
    const failedDeletes = new Set(['users/common-user', 'roles/common-role']);
    const request = async (input: Phase2AdminRequest): Promise<unknown> => {
      if (input.method === 'DELETE' && failedDeletes.delete(input.path)) {
        throw new Error('planted local cleanup failure');
      }
      return admin.request(input);
    };
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      createAllocationId: () => 'common-cleanup',
      request,
    });
    const fixture = await provisioner.provision();
    admin.entityRows.set('users', [
      { id: 'common-user', primaryEmail: 'common-email-common-cleanup@example.invalid' },
      { id: 'foreign-user', primaryEmail: 'common-email-foreign@example.invalid' },
      { id: 'unrelated-user', primaryEmail: 'owner@example.invalid' },
    ]);
    admin.entityRows.set('roles', [
      { id: 'common-role', name: 'common-email-common-cleanup' },
      { id: 'foreign-role', name: 'common-email-foreign' },
      { id: 'unrelated-role', name: 'reader' },
    ]);

    await expect(
      request({
        method: 'DELETE',
        path: 'users/common-user',
        expectedStatuses: [204, 404],
        responseKind: 'status',
      })
    ).rejects.toThrow('planted local cleanup failure');
    await expect(
      request({
        method: 'DELETE',
        path: 'roles/common-role',
        expectedStatuses: [204, 404],
        responseKind: 'status',
      })
    ).rejects.toThrow('planted local cleanup failure');

    await provisioner.cleanup(fixture);

    expect(admin.entityRows.get('users')).toEqual([
      { id: 'foreign-user', primaryEmail: 'common-email-foreign@example.invalid' },
      { id: 'unrelated-user', primaryEmail: 'owner@example.invalid' },
    ]);
    expect(admin.entityRows.get('roles')).toEqual([
      { id: 'foreign-role', name: 'common-email-foreign' },
      { id: 'unrelated-role', name: 'reader' },
    ]);
  });

  it('reconciles exact Common email-code rows after local deletion fails and retains foreign rows', async () => {
    const admin = createReferenceAdmin();
    const failedDeletes = new Set(['users/code-user', 'roles/code-role']);
    const request = async (input: Phase2AdminRequest): Promise<unknown> => {
      if (input.method === 'DELETE' && failedDeletes.delete(input.path)) {
        throw new Error('planted local cleanup failure');
      }
      return admin.request(input);
    };
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      createAllocationId: () => 'code-cleanup',
      request,
    });
    const fixture = await provisioner.provision();
    admin.entityRows.set('users', [
      { id: 'code-user', primaryEmail: 'common-email-code-code-cleanup@example.invalid' },
      { id: 'foreign-user', primaryEmail: 'common-email-code-foreign@example.invalid' },
    ]);
    admin.entityRows.set('roles', [
      { id: 'code-role', name: 'common-email-code-code-cleanup' },
      { id: 'foreign-role', name: 'common-email-code-foreign' },
    ]);

    await expect(
      request({
        method: 'DELETE',
        path: 'users/code-user',
        expectedStatuses: [204, 404],
        responseKind: 'status',
      })
    ).rejects.toThrow('planted local cleanup failure');
    await expect(
      request({
        method: 'DELETE',
        path: 'roles/code-role',
        expectedStatuses: [204, 404],
        responseKind: 'status',
      })
    ).rejects.toThrow('planted local cleanup failure');

    await provisioner.cleanup(fixture);

    expect(admin.entityRows.get('users')).toEqual([
      { id: 'foreign-user', primaryEmail: 'common-email-code-foreign@example.invalid' },
    ]);
    expect(admin.entityRows.get('roles')).toEqual([
      { id: 'foreign-role', name: 'common-email-code-foreign' },
    ]);
  });

  it('restores the exact previous reference default and rejects multiple defaults', async () => {
    const admin = createReferenceAdmin();
    admin.entityRows.set('resources', [
      { id: 'previous-default', name: 'existing', isDefault: true },
    ]);
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'restore-default',
    });
    const fixture = await provisioner.provision();
    await provisioner.cleanup(fixture);
    expect(admin.calls).toContainEqual(
      expect.objectContaining({
        method: 'PATCH',
        path: 'resources/previous-default/is-default',
        body: { isDefault: true },
      })
    );

    const multiple = createReferenceAdmin();
    multiple.entityRows.set('resources', [
      { id: 'one', isDefault: true },
      { id: 'two', isDefault: true },
    ]);
    const rejected = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: multiple.request,
      createAllocationId: () => 'multiple-defaults',
    });
    await expect(rejected.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(multiple.calls.some(({ method }) => method === 'POST')).toBe(false);
  });

  it('uses the Aster fixture coordinator with a secret-safe closed descriptor', async () => {
    const requests: CommandRunnerRequest[] = [];
    let fencedCalls = 0;
    let allocationActive = false;
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin) as Record<string, unknown>;
      const { operation } = descriptor;
      if (operation === 'provision') {
        if (descriptor.recipe !== 'fullPhase1' || allocationActive) {
          return rejectedCommandResult();
        }
        allocationActive = true;
        return candidateProvisionResult('candidate-fixture');
      }
      if (operation === 'projectState') {
        if (!allocationActive) {
          return rejectedCommandResult();
        }
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'projectState',
            projection: { allocations: [] },
          })
        );
      }
      if (!allocationActive) {
        return rejectedCommandResult();
      }
      allocationActive = false;
      return commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }));
    };
    const secrets = [
      'a'.repeat(32),
      'b'.repeat(32),
      'c'.repeat(32),
      'd'.repeat(32),
      'e'.repeat(32),
    ];
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { PATH: '/usr/bin:/bin', ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      runner,
      createAllocationId: () => 'candidate-fixture',
      createSecret: () => secrets.shift() ?? 'unexpected',
      identityFence: {
        assertStable: async () => {
          // The fake identity remains stable during this coordinator contract test.
        },
        run: async <Result>(operation: () => Promise<Result>) => {
          fencedCalls += 1;
          return operation();
        },
      },
    });
    const fixture = await provisioner.provision();
    expect(fixture.public.clients).toEqual({
      basic: { id: 'phase2-m2m-basic', method: 'client_secret_basic' },
      post: { id: 'phase2-m2m-post', method: 'client_secret_post' },
    });
    expect(fixture.public.admin).toEqual({
      allocationId: phase2AdminAllocationId('candidate-fixture'),
    });
    expect(fixture.public.deviceClients).toEqual({
      firstParty: {
        id: 'phase2-device-first',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      },
      thirdParty: {
        id: 'phase2-device-third',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      },
      missingGrant: {
        id: 'phase2-device-nogrant',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
      ineligibleWeb: {
        id: 'phase2-device-web',
        applicationType: 'SPA',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
    });
    const suffix = createHash('sha256').update('candidate-fixture').digest('hex').slice(0, 16);
    expect(fixture.status).toMatchObject({
      user: { id: 'zdata-user', username: expect.stringMatching(/^phase1_user_a_[0-9a-f]{16}$/u) },
      client: { id: 'phase1-browser', redirectUri: 'http://localhost:3001/demo-app' },
      confidentialClient: {
        id: 'phase2-status',
        redirectUri: 'http://localhost:3001/demo-app',
      },
      resource: {
        id: 'phase1-api',
        indicator: `https://api.example.com/?aster_fixture=${suffix}`,
        scopeName: `read:profile_a_${suffix}`,
      },
    });
    await fixture.withSecretLease(async (lease) => {
      expect(Object.keys(lease).toSorted()).toEqual([
        'getAdminPassword',
        'getClientSecret',
        'getInvalidEmailPassword',
        'getSelectedEmailPassword',
        'getSelectedNativePassword',
        'getStatusClientSecret',
        'getSubjectPassword',
        'takeVerificationCode',
        'toJSON',
      ]);
      expect(lease.getStatusClientSecret()).toBe('c'.repeat(32));
      expect(lease.getSubjectPassword?.()).toBe('d'.repeat(32));
      expect(lease.getAdminPassword?.()).toBe('e'.repeat(32));
      expect(lease.getSelectedNativePassword?.()).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
      expect(lease.getSelectedNativePassword?.()).not.toContain('e'.repeat(32));
      expect(lease.getSelectedEmailPassword?.()).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
      expect(lease.getInvalidEmailPassword?.()).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
      expect(lease.getSelectedEmailPassword?.()).not.toBe(lease.getSelectedNativePassword?.());
      expect(lease.getInvalidEmailPassword?.()).not.toBe(lease.getSelectedEmailPassword?.());
      expect(JSON.stringify(fixture.public)).not.toContain(lease.getSelectedNativePassword?.());
      expect(JSON.stringify(fixture.public)).not.toContain(lease.getSelectedEmailPassword?.());
      expect(JSON.stringify(fixture.public)).not.toContain(lease.getInvalidEmailPassword?.());
    });
    const adminFetch = await candidateAdminLeaseTransport();
    let selectedAfterAdmin: (() => string) | undefined;
    let invalidAfterAdmin: (() => string) | undefined;
    await withPhase2AdminManagementBearer(
      candidate,
      fixture,
      async (_bearer, lease) => {
        const selected = lease.getSelectedEmailPassword?.() ?? '';
        const invalid = lease.getInvalidEmailPassword?.() ?? '';
        expect(selected).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
        expect(invalid).toMatch(/^[A-Za-z0-9_-]{27}A1!$/u);
        expect(invalid).not.toBe(selected);
        expect(JSON.stringify(fixture.public)).not.toContain(selected);
        expect(JSON.stringify(fixture.public)).not.toContain(invalid);
        selectedAfterAdmin = lease.getSelectedEmailPassword;
        invalidAfterAdmin = lease.getInvalidEmailPassword;
      },
      {
        fetch: adminFetch,
        codeVerifier: () => 'v'.repeat(48),
        state: () => 's'.repeat(48),
      }
    );
    expect(() => selectedAfterAdmin?.()).toThrow('Phase 2 fixture operation failed');
    expect(() => invalidAfterAdmin?.()).toThrow('Phase 2 fixture operation failed');
    expect(JSON.stringify(fixture.public)).not.toContain('c'.repeat(32));
    expect(await provisioner.projectState(fixture)).toEqual({ allocations: [] });
    await provisioner.cleanup(fixture);

    const provision = JSON.parse(requests[0]?.stdin ?? '{}');
    expect(provision).toMatchObject({
      schemaVersion: 1,
      operation: 'provision',
      recipe: 'fullPhase1',
      allocationId: 'candidate-fixture',
      seeds: {
        passwords: [
          { logicalId: 'phase1-user', value: 'd'.repeat(32) },
          { logicalId: 'phase1-admin', value: 'e'.repeat(32) },
        ],
      },
      profile: {
        fixtures: {
          phase2: {
            subjectPrimaryEmail: null,
            subjectResourceScopeIds: ['read-scope'],
            machineClients: [
              {
                clientId: 'phase2-m2m-basic',
                grantTypes: ['client_credentials'],
                resourceScopeIds: ['read-scope', 'write-scope'],
              },
              {
                clientId: 'phase2-m2m-post',
                grantTypes: ['client_credentials'],
                resourceScopeIds: ['read-scope', 'write-scope'],
                organizations: [],
              },
            ],
            statusClient: {
              clientId: 'phase2-status',
              redirectUri: 'http://localhost:3001/demo-app',
              authenticationMethod: 'client_secret_basic',
              userConsentScopes: [
                'profile',
                'email',
                'address',
                'phone',
                'urn:aster:scope:sessions',
              ],
              resourceScopeIds: ['phase1-read-profile'],
            },
            deviceClients: [
              {
                clientId: 'phase2-device-first',
                applicationType: 'Native',
                authenticationMethod: 'none',
                isThirdParty: false,
                grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
                userConsentScopes: [
                  'profile',
                  'email',
                  'address',
                  'phone',
                  'urn:aster:scope:organizations',
                ],
                resourceScopeIds: ['phase1-read-profile', 'read-scope', 'write-scope'],
              },
              {
                clientId: 'phase2-device-third',
                applicationType: 'Native',
                authenticationMethod: 'none',
                isThirdParty: true,
                grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
                userConsentScopes: [
                  'profile',
                  'email',
                  'address',
                  'phone',
                  'urn:aster:scope:organizations',
                ],
                resourceScopeIds: ['phase1-read-profile', 'read-scope', 'write-scope'],
              },
              {
                clientId: 'phase2-device-nogrant',
                applicationType: 'Native',
                authenticationMethod: 'none',
                isThirdParty: false,
                grantTypes: [],
                userConsentScopes: [
                  'profile',
                  'email',
                  'address',
                  'phone',
                  'urn:aster:scope:organizations',
                ],
                resourceScopeIds: ['phase1-read-profile', 'read-scope', 'write-scope'],
              },
              {
                clientId: 'phase2-device-web',
                applicationType: 'SPA',
                authenticationMethod: 'none',
                isThirdParty: false,
                grantTypes: [],
                userConsentScopes: [
                  'profile',
                  'email',
                  'address',
                  'phone',
                  'urn:aster:scope:organizations',
                ],
                resourceScopeIds: ['phase1-read-profile', 'read-scope', 'write-scope'],
              },
            ],
            defaultResourceId: 'phase2-resource',
          },
        },
      },
    });
    expect(
      requests.every(({ env }) =>
        Object.keys(env).every((key) =>
          [
            'ASTER_FIXTURE_SOCKET',
            'ASTER_TARGET_LABEL',
            'ASTER_CORE_URL',
            'ASTER_ADMIN_URL',
            'ASTER_FOREIGN_CORE_URL',
            'ASTER_FOREIGN_ADMIN_URL',
            'LC_ALL',
          ].includes(key)
        )
      )
    ).toBe(true);
    expect(
      requests.every(
        ({ command, args }) =>
          command === '/usr/bin/true' &&
          JSON.stringify(args) === JSON.stringify(['fixture', 'apply'])
      )
    ).toBe(true);
    expect(requests).toHaveLength(4);
    expect(fencedCalls).toBe(4);
    expect(allocationActive).toBe(false);
    const projectDescriptor = JSON.parse(requests[1]?.stdin ?? '{}') as {
      public?: { recipe?: string; allocations?: Array<{ allocationId?: string }> };
    };
    const cleanupDescriptors = [requests[2], requests[3]].map((request) =>
      JSON.parse(request?.stdin ?? '{}')
    ) as Array<{
      public?: { recipe?: string; allocations?: Array<{ allocationId?: string }> };
    }>;
    for (const descriptor of [projectDescriptor, ...cleanupDescriptors]) {
      expect(descriptor.public).toEqual(candidateCoordinatorPublic('candidate-fixture'));
      expect(descriptor.public).not.toHaveProperty('clients');
    }
  });

  it('uses one phase2CandidateInvariants composite allocation for provision, projection, and cleanup', async () => {
    const requests: CommandRunnerRequest[] = [];
    let allocationActive = false;
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin) as Record<string, unknown>;
      if (descriptor.operation === 'provision') {
        if (descriptor.recipe !== 'phase2CandidateInvariants' || allocationActive) {
          return rejectedCommandResult();
        }
        allocationActive = true;
        return candidateProvisionResult(
          'candidate-invariants-fixture',
          'phase2CandidateInvariants'
        );
      }
      if (descriptor.operation === 'projectState') {
        if (!allocationActive) {
          return rejectedCommandResult();
        }
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'projectState',
            projection: { allocations: [] },
          })
        );
      }
      if (!allocationActive) {
        return rejectedCommandResult();
      }
      allocationActive = false;
      return commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }));
    };
    const sensitiveValues = [
      'e'.repeat(32),
      'f'.repeat(32),
      'g'.repeat(32),
      'h'.repeat(32),
      'i'.repeat(32),
    ];
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      runner,
      recipe: 'phase2CandidateInvariants',
      createAllocationId: () => 'candidate-invariants-fixture',
      createSecret: () => sensitiveValues.shift() ?? 'unexpected',
    });

    const fixture = await provisioner.provision();
    expect(fixture.verificationPeer).toEqual({
      id: 'vcode-peer',
      username: 'phase2-verification-peer',
    });
    await fixture.withSecretLease(async (lease) => {
      expect(lease.getVerificationPeerPassword?.()).toMatch(/^[a-z0-9]{32}$/u);
    });
    await provisioner.projectState(fixture);
    await provisioner.cleanup(fixture);
    expect(allocationActive).toBe(false);

    const descriptors = requests.map(({ stdin }) => JSON.parse(stdin) as Record<string, unknown>);
    expect(descriptors.map(({ recipe }) => recipe)).toEqual([
      'phase2CandidateInvariants',
      'phase2CandidateInvariants',
      'phase2CandidateInvariants',
      'phase2CandidateInvariants',
    ]);
    expect(descriptors[0]).toMatchObject({
      profile: {
        fixtures: {
          phase2: {
            verificationCode: {
              smtpPort: 2525,
              peerAccount: {
                userId: 'vcode-peer',
                username: 'phase2-verification-peer',
              },
            },
          },
        },
      },
      seeds: {
        passwords: expect.arrayContaining([
          expect.objectContaining({ logicalId: 'phase2-verification-peer' }),
        ]),
      },
    });
    for (const descriptor of descriptors.filter(
      ({ recipe }, index) => recipe === 'phase2CandidateInvariants' && index > 0
    )) {
      expect(descriptor.public).toEqual(
        candidateCoordinatorPublic('candidate-invariants-fixture', 'phase2CandidateInvariants')
      );
      expect(JSON.stringify(descriptor)).not.toMatch(/e{32}|f{32}|g{32}|h{32}/u);
    }
  });

  it.each([
    [
      'an extra allocation field',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: primaryCoordinatorEntities,
        privateValue: 'not-public',
      },
    ],
    [
      'missing entities',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
      },
    ],
    [
      'the wrong entities',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: [],
      },
    ],
    [
      'a malformed entity',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: [
          { ...primaryCoordinatorEntities[0], privateValue: 'not-public' },
          ...primaryCoordinatorEntities.slice(1),
        ],
      },
    ],
    [
      'a secret-bearing entity',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: [
          { ...primaryCoordinatorEntities[0], runtimeId: 'a'.repeat(32) },
          ...primaryCoordinatorEntities.slice(1),
        ],
      },
    ],
    [
      'wrong isolation',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: {
          persistenceId: 'postgresql:1:aster_phase1_candidate_primary',
          cookieKeyId: '1'.repeat(32),
          signingKeyId: '1'.repeat(32),
        },
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'an uppercase primary key ID',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: { ...primaryCoordinatorIsolation, cookieKeyId: 'A'.repeat(32) },
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'a short primary key ID',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: { ...primaryCoordinatorIsolation, signingKeyId: 'a'.repeat(31) },
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'a wrong primary persistence prefix',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: {
          ...primaryCoordinatorIsolation,
          persistenceId: 'mysql:1:aster_phase1_candidate_primary',
        },
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'a foreign suffix on primary persistence',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: {
          ...primaryCoordinatorIsolation,
          persistenceId: 'postgresql:1:aster_phase1_candidate_foreign',
        },
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'an overflowing primary persistence ID',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: {
          ...primaryCoordinatorIsolation,
          persistenceId: 'postgresql:18446744073709551616:aster_phase1_candidate_primary',
        },
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'a primary suffix on foreign persistence',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'an uppercase foreign key ID',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'a short foreign key ID',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'a wrong foreign persistence prefix',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: primaryCoordinatorEntities,
      },
    ],
    [
      'wrong foreign allocation ID',
      {
        allocationId: 'invalid-public-fixture',
        role: 'data',
        target: 'primary',
        isolation: primaryCoordinatorIsolation,
        entities: primaryCoordinatorEntities,
      },
    ],
  ])('rejects coordinator public output with %s', async (_label, primaryAllocation) => {
    let cleanupCalls = 0;
    let provisionCalls = 0;
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      recipe: 'phase2CandidateInvariants',
      createAllocationId: () => 'invalid-public-fixture',
      createSecret: (() => {
        const secrets = [
          'a'.repeat(32),
          'b'.repeat(32),
          'c'.repeat(32),
          'd'.repeat(32),
          'e'.repeat(32),
        ];
        return () => secrets.shift() ?? 'unexpected';
      })(),
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as Record<string, unknown>;
        if (descriptor.operation === 'provision') {
          provisionCalls += 1;
          const foreignIsolation =
            _label === 'a primary suffix on foreign persistence'
              ? {
                  ...foreignCoordinatorIsolation,
                  persistenceId: 'postgresql:2:aster_phase1_candidate_primary',
                }
              : _label === 'an uppercase foreign key ID'
                ? { ...foreignCoordinatorIsolation, signingKeyId: 'F'.repeat(32) }
                : _label === 'a short foreign key ID'
                  ? { ...foreignCoordinatorIsolation, cookieKeyId: 'f'.repeat(31) }
                  : _label === 'a wrong foreign persistence prefix'
                    ? {
                        ...foreignCoordinatorIsolation,
                        persistenceId: 'mysql:2:aster_phase1_candidate_foreign',
                      }
                    : foreignCoordinatorIsolation;
          return commandResult(
            JSON.stringify({
              schemaVersion: 1,
              operation: 'provision',
              public: {
                schemaVersion: 1,
                recipe: 'phase2CandidateInvariants',
                allocations: [
                  primaryAllocation,
                  {
                    allocationId: phase2AdminAllocationId('invalid-public-fixture'),
                    role: 'admin',
                    target: 'primary',
                    isolation: adminCoordinatorIsolation,
                    entities: adminCoordinatorEntities,
                  },
                  {
                    allocationId:
                      _label === 'wrong foreign allocation ID'
                        ? 'phase2-foreign-wrong'
                        : phase2ForeignAllocationId('invalid-public-fixture'),
                    role: 'foreign',
                    target: 'foreign',
                    isolation: foreignIsolation,
                    entities: foreignCoordinatorEntities,
                  },
                ],
              },
            })
          );
        }
        cleanupCalls += 1;
        return cleanupCalls === 1
          ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
          : rejectedCommandResult();
      },
    });

    await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(provisionCalls).toBeGreaterThan(0);
  });

  it.each([
    [
      'a different primary database',
      {
        ...adminCoordinatorIsolation,
        persistenceId: 'postgresql:2:aster_phase1_candidate_primary',
      },
    ],
    [
      'a reused data cookie key',
      { ...adminCoordinatorIsolation, cookieKeyId: primaryCoordinatorIsolation.cookieKeyId },
    ],
    [
      'a signing key reused as a cookie key',
      { ...adminCoordinatorIsolation, cookieKeyId: primaryCoordinatorIsolation.signingKeyId },
    ],
    [
      'the same admin signing and cookie key',
      { ...adminCoordinatorIsolation, signingKeyId: adminCoordinatorIsolation.cookieKeyId },
    ],
    ['the wrong child allocation ID', adminCoordinatorIsolation],
  ])('rejects composite admin authority with %s', async (label, isolation) => {
    let provisionCalls = 0;
    let cleanupCalls = 0;
    const secrets = ['a', 'b', 'c', 'd', 'e'].map((value) => value.repeat(32));
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'invalid-admin-fixture',
      createSecret: () => secrets.shift() ?? 'unexpected',
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as { operation?: string };
        if (descriptor.operation === 'provision') {
          provisionCalls += 1;
          const publicMap = candidateCoordinatorPublic('invalid-admin-fixture');
          const admin = publicMap.allocations[1];
          if (!admin) {
            throw new Error('fake coordinator admin allocation missing');
          }
          admin.isolation = isolation;
          if (label === 'the wrong child allocation ID') {
            admin.allocationId = 'phase2-admin-wrong';
          }
          return commandResult(
            JSON.stringify({ schemaVersion: 1, operation: 'provision', public: publicMap })
          );
        }
        cleanupCalls += 1;
        return cleanupCalls === 1
          ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
          : rejectedCommandResult();
      },
    });
    await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(provisionCalls).toBeGreaterThan(0);
  });

  it('reconciles one failed candidate provision and retries the exact descriptor once', async () => {
    const requests: CommandRunnerRequest[] = [];
    let provisionAttempts = 0;
    let cleanupCalls = 0;
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      requests.push(request);
      const descriptor = JSON.parse(request.stdin) as { operation?: string; recipe?: string };
      if (descriptor.operation === 'provision') {
        if (descriptor.recipe !== 'fullPhase1') {
          return rejectedCommandResult();
        }
        provisionAttempts += 1;
        if (provisionAttempts === 1) {
          return {
            ...commandResult(''),
            exitCode: 1,
            stderr: 'Aster compatibility fixture command failed\n',
          };
        }
        return candidateProvisionResult('candidate-retry');
      }
      if (descriptor.operation === 'cleanup') {
        cleanupCalls += 1;
        return cleanupCalls % 2 === 1
          ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
          : rejectedCommandResult();
      }
      return commandResult(
        JSON.stringify({
          schemaVersion: 1,
          operation: 'projectState',
          projection: { allocations: [] },
        })
      );
    };
    const secrets = [
      'a'.repeat(32),
      'b'.repeat(32),
      'c'.repeat(32),
      'd'.repeat(32),
      'e'.repeat(32),
    ];
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'candidate-retry',
      createSecret: () => secrets.shift() ?? 'unexpected',
      runner,
    });

    const fixtureValue = await provisioner.provision();
    await provisioner.cleanup(fixtureValue);

    expect(requests.map(({ stdin }) => JSON.parse(stdin).operation)).toEqual([
      'provision',
      'cleanup',
      'cleanup',
      'provision',
      'cleanup',
      'cleanup',
    ]);
    const provisions = requests.filter(({ stdin }) => JSON.parse(stdin).operation === 'provision');
    expect(provisions).toHaveLength(2);
    expect(provisions[0]?.stdin).toBe(provisions[1]?.stdin);
    expect(JSON.parse(provisions[0]?.stdin ?? '{}')).toHaveProperty(
      'profile.fixtures.phase2.subjectPrimaryEmail',
      null
    );
    expect(JSON.parse(requests[1]?.stdin ?? '{}')).not.toHaveProperty('public');
    expect(JSON.parse(requests[2]?.stdin ?? '{}')).not.toHaveProperty('public');
    expect(JSON.parse(requests[4]?.stdin ?? '{}')).toHaveProperty('public');
    expect(JSON.parse(requests[5]?.stdin ?? '{}')).toHaveProperty('public');
  });

  it('rejects coordinator output that leaks the private subject password', async () => {
    const planted = [
      'a'.repeat(32),
      'b'.repeat(32),
      'c'.repeat(32),
      'd'.repeat(32),
      'e'.repeat(32),
    ];
    let cleanupCalls = 0;
    let provisionCalls = 0;
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { PATH: '/usr/bin:/bin', ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'candidate-leak',
      createSecret: () => planted.shift() ?? 'unexpected',
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as { operation?: string };
        if (descriptor.operation === 'cleanup') {
          cleanupCalls += 1;
          return cleanupCalls % 2 === 1
            ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
            : rejectedCommandResult();
        }
        provisionCalls += 1;
        const publicMap = candidateCoordinatorPublic('candidate-leak');
        const [data] = publicMap.allocations;
        if (!data) {
          throw new Error('fake coordinator data allocation missing');
        }
        data.isolation = { ...primaryCoordinatorIsolation, cookieKeyId: 'd'.repeat(32) };
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'provision',
            public: publicMap,
          })
        );
      },
    });
    await expect(provisioner.provision()).rejects.toThrow('Phase 2 fixture operation failed');
    expect(provisionCalls).toBeGreaterThan(0);
  });

  it('generates production candidate secrets as exact 32 lowercase alphanumeric characters', async () => {
    const provisionDescriptors: any[] = [];
    let cleanupCalls = 0;
    const provisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'production-secrets',
      runner: async (request) => {
        const input = JSON.parse(request.stdin);
        if (input.operation === 'provision') {
          provisionDescriptors.push(input);
          return candidateProvisionResult('production-secrets');
        }
        if (input.operation === 'projectState') {
          return commandResult(
            JSON.stringify({
              schemaVersion: 1,
              operation: 'projectState',
              projection: { allocations: [] },
            })
          );
        }
        cleanupCalls += 1;
        return cleanupCalls % 2 === 1
          ? commandResult(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }))
          : rejectedCommandResult();
      },
    });
    const fixtureValue = await provisioner.provision();
    const serialized = JSON.stringify(provisionDescriptors);
    const seeds = provisionDescriptors.flatMap(({ seeds }) => [
      ...seeds.passwords,
      ...seeds.clientSecrets,
    ]);
    for (const seed of seeds) {
      expect(seed.value).toMatch(/^[a-z0-9]{32}$/u);
    }
    expect(new Set(seeds.map((seed: any) => seed.value)).size).toBe(5);
    expect(JSON.stringify(fixtureValue.public)).not.toContain(
      provisionDescriptors[0].seeds.clientSecrets[0].value
    );
    expect(serialized).toContain('clientSecrets');
    await provisioner.cleanup(fixtureValue);
  });

  it('rejects reference and candidate cleanup acknowledgements that leave fixture state behind', async () => {
    const admin = createReferenceAdmin();
    const reference = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      createAllocationId: () => 'noop-reference',
      request: async (request) => (request.method === 'DELETE' ? 204 : admin.request(request)),
    });
    const referenceFixture = await reference.provision();
    admin.entityRows.set('applications', [
      {
        id: 'left-behind',
        name: 'Phase 2 phase2-client-credentials-noop-reference basic client',
      },
    ]);
    await expect(reference.cleanup(referenceFixture)).rejects.toThrow(
      'Phase 2 fixture cleanup failed'
    );

    const candidateCleanupRecipes: string[] = [];
    const candidateProvisioner = createCandidatePhase2FixtureProvisioner({
      executablePath: '/usr/bin/true',
      target: candidate,
      foreignTarget: candidateForeign,
      environment: { ASTER_FIXTURE_SOCKET: '/tmp/phase2-fixture.sock' },
      createAllocationId: () => 'noop-candidate',
      createSecret: (() => {
        const values = [
          'a'.repeat(32),
          'b'.repeat(32),
          'c'.repeat(32),
          'd'.repeat(32),
          'e'.repeat(32),
        ];
        return () => values.shift() ?? 'unexpected';
      })(),
      runner: async (request) => {
        const descriptor = JSON.parse(request.stdin) as { operation?: string; recipe?: string };
        if (descriptor.operation === 'provision') {
          return candidateProvisionResult('noop-candidate');
        }
        if (descriptor.operation === 'cleanup') {
          candidateCleanupRecipes.push(descriptor.recipe ?? 'missing');
          return commandResult(
            JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true })
          );
        }
        return commandResult(
          JSON.stringify({
            schemaVersion: 1,
            operation: 'projectState',
            projection: { allocations: [{ allocationId: 'noop-candidate' }] },
          })
        );
      },
    });
    const candidateFixture = await candidateProvisioner.provision();
    await expect(candidateProvisioner.cleanup(candidateFixture)).rejects.toThrow(
      'Phase 2 fixture cleanup replay failed'
    );
    expect(candidateCleanupRecipes).toEqual(['fullPhase1', 'fullPhase1']);
  });

  it('runs cleanup when fixture use fails and does not publish leased secrets', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'use-failure',
    });
    await expect(
      runWithPhase2Fixture(provisioner, async (fixture) =>
        fixture.withSecretLease(async () => {
          throw new Error('scenario failed');
        })
      )
    ).rejects.toThrow('scenario failed');
    expect(admin.calls.some(({ method }) => method === 'DELETE')).toBe(true);
  });

  it('runs fixture cleanup after a hanging token transport reaches its deadline', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'hanging-request',
    });
    await expect(
      runWithPhase2Fixture(provisioner, async (fixtureValue) =>
        fixtureValue.withSecretLease(async (lease) =>
          observeClientCredentialsToken(
            new URL('/oidc/token', oracle.coreUrl),
            { keys: [{ kty: 'EC', kid: 'hanging-key' }] },
            {
              method: 'client_secret_basic',
              clientId: fixtureValue.public.clients.basic.id,
              clientSecret: lease.getClientSecret('basic'),
              resource: fixtureValue.public.resources.primary.indicator,
            },
            {
              fetch: (async () =>
                new Promise<Response>(() => {
                  // Intentionally unresolved to prove fixture cleanup after the deadline.
                })) as typeof fetch,
              timeoutMs: 20,
            }
          )
        )
      )
    ).rejects.toThrow('Client credentials request failed');
    expect(admin.calls.some(({ method }) => method === 'DELETE')).toBe(true);
  });

  it('sequences candidate invariant token setup within one fixture lease authority', async () => {
    const admin = createReferenceAdmin();
    const provisioner = createReferencePhase2FixtureProvisioner({
      target: oracle,
      foreignTarget: oracleForeign,
      request: admin.request,
      createAllocationId: () => 'candidate-token-sequence',
    });
    const fixture = await provisioner.provision();
    const events: string[] = [];
    try {
      const issued = await issueCandidateInvariantUserTokens(
        async () =>
          fixture.withSecretLease(async (lease) => {
            events.push('public-start');
            expect(lease.getSubjectPassword?.()).toBeDefined();
            await new Promise<void>((resolve) => {
              setImmediate(resolve);
            });
            events.push('public-end');
            return 'owner-token';
          }),
        async () =>
          fixture.withSecretLease(async (lease) => {
            events.push('confidential-start');
            expect(lease.getStatusClientSecret()).toBeDefined();
            events.push('confidential-end');
            return 'cross-client-token';
          })
      );
      expect(issued).toEqual({
        verificationOwner: 'owner-token',
        verificationCrossClient: 'cross-client-token',
      });
      expect(events).toEqual([
        'public-start',
        'public-end',
        'confidential-start',
        'confidential-end',
      ]);

      let confidentialCalls = 0;
      await expect(
        issueCandidateInvariantUserTokens(
          async () =>
            fixture.withSecretLease(async () => {
              throw new Error('public setup failed');
            }),
          async () => {
            confidentialCalls += 1;
            return 'must-not-run';
          }
        )
      ).rejects.toThrow('public setup failed');
      expect(confidentialCalls).toBe(0);
      await expect(
        fixture.withSecretLease(async (lease) => lease.getClientSecret('basic'))
      ).resolves.toBeDefined();
    } finally {
      await provisioner.cleanup(fixture);
    }
  });

  it('rejects aliased primary and foreign boundaries', () => {
    expect(() =>
      createReferencePhase2FixtureProvisioner({
        target: oracle,
        foreignTarget: oracle,
      })
    ).toThrow('Phase 2 fixture operation failed');
    expect(() =>
      createCandidatePhase2FixtureProvisioner({
        executablePath: '/usr/bin/true',
        target: candidate,
        foreignTarget: candidate,
        environment: { ASTER_FIXTURE_SOCKET: '/tmp/socket' },
      })
    ).toThrow('Phase 2 fixture operation failed');
  });
});

/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment */
