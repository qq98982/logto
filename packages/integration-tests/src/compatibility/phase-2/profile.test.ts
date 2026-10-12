/* eslint-disable @silverhand/fp/no-mutation -- Tests create isolated private file fixtures and mutate copied bytes. */
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { loadPhase2Profile, Phase2ProfileValidationError } from './profile.js';

const buildRoot = '/var/tmp/henry-build';
const fixtureDirectory = path.resolve(process.cwd(), 'src/compatibility/phase-2/testing');
const canonicalProfilePath = path.join(fixtureDirectory, 'phase-2-profile.json');
const canonicalSchemaPath = path.join(fixtureDirectory, 'phase-2-profile.schema.json');
const createdRoots = new Set<string>();

const createPrivateRoot = async () => {
  await mkdir(buildRoot, { recursive: true });
  const root = await mkdtemp(path.join(buildRoot, 'aster-phase2-h-profile-'));
  await chmod(root, 0o700);
  createdRoots.add(root);
  return root;
};

const copyCanonicalFiles = async () => {
  const root = await createPrivateRoot();
  const profilePath = path.join(root, 'profile.json');
  const schemaPath = path.join(root, 'schema.json');
  await Promise.all([
    writeFile(profilePath, await readFile(canonicalProfilePath), { mode: 0o600 }),
    writeFile(schemaPath, await readFile(canonicalSchemaPath), { mode: 0o600 }),
  ]);
  return { root, profilePath, schemaPath };
};

afterAll(async () => {
  await Promise.all(
    [...createdRoots].map(async (root) => rm(root, { force: true, recursive: true }))
  );
});

describe('Phase 2 profile loader', () => {
  it('loads exact Aster bytes and returns only deeply frozen typed registries', async () => {
    const registries = await loadPhase2Profile({
      profilePath: canonicalProfilePath,
      schemaPath: canonicalSchemaPath,
    });

    expect(registries.deviceOperations).toEqual([
      'device.authorize',
      'device.open-shortcut',
      'device.open-verification',
      'device.submit-verification',
      'device.submit-password',
      'device.read-consent',
      'device.submit-consent',
      'device.resume-consent',
      'device.open-success',
      'device.poll-token',
      'device.rotate-refresh',
      'device.introspect-token',
      'device.revoke-token',
      'device.request-userinfo',
      'device.open-logout',
      'device.confirm-logout',
      'device.discover-oidc',
      'device.discover-oauth',
    ]);
    expect(registries.differentialScenarios).toHaveLength(206);
    expect(registries.differentialScenarios[20]).toBe('token-status.public-access-active');
    expect(registries.differentialScenarios[46]).toBe(
      'token-status.confidential-owner-after-cross-client-active'
    );
    expect(registries.differentialScenarios[56]).toBe('account-sessions.wrong-password');
    expect(registries.differentialScenarios[57]).toBe('logout.authenticated-get');
    expect(registries.differentialScenarios[69]).toBe('account-sessions.list-zero-current');
    expect(registries.differentialScenarios[70]).toBe('device-authorization.urlencoded-success');
    expect(registries.differentialScenarios[109]).toBe(
      'device-verification.confirmed-sign-in-redirect'
    );
    expect(registries.differentialScenarios[132]).toBe(
      'device-token.concurrent-reference-multi-winner'
    );
    expect(registries.differentialScenarios[138]).toBe('device-discovery.oauth');
    expect(registries.differentialScenarios[179]).toBe('common.email.code-registration');
    expect(registries.differentialScenarios.slice(139)).toEqual([
      'custom-jwt.management-missing-get',
      'custom-jwt.management-missing-delete',
      'custom-jwt.management-put',
      'custom-jwt.management-get',
      'custom-jwt.management-list',
      'custom-jwt.management-patch',
      'custom-jwt.management-patch-missing-script',
      'custom-jwt.management-patch-nonstring-script',
      'custom-jwt.management-test',
      'custom-jwt.management-unknown-token-type',
      'custom-jwt.management-delete',
      'custom-jwt.m2m-success',
      'custom-jwt.m2m-deny',
      'custom-jwt.m2m-throw-block',
      'custom-jwt.m2m-throw-open',
      'custom-jwt.m2m-protected-claims',
      'custom-jwt.user-initial-resource',
      'custom-jwt.user-refresh-context',
      'custom-jwt.user-old-refresh-after-rotation',
      'custom-jwt.user-refresh-deny',
      'custom-jwt.user-refresh-throw-block',
      'custom-jwt.user-refresh-throw-open-retry',
      'custom-jwt.device-resource-refresh-context',
      'custom-jwt.fetch-get-text',
      'custom-jwt.fetch-get-json',
      'custom-jwt.fetch-post',
      'custom-jwt.fetch-not-found',
      'custom-jwt.fetch-redirect',
      'custom-jwt.fetch-reset-connection',
      'verification-code.experience-request-verify',
      'verification-code.experience-recipient-mismatch',
      'verification-code.experience-replaced-current',
      'verification-code.experience-retry-cap',
      'verification-code.recipient-send-cap',
      'verification-code.failed-delivery-preserves-current',
      'verification-code.experience-consumed-replay',
      'verification-code.account-request-verify-replay',
      'common.native.code-pkce',
      'common.email.password-sign-in',
      'common.email.code-sign-in',
      'common.email.code-registration',
      'common.email.password-registration',
      'common.password.recovery',
      'common.google.existing-owner',
      'common.google.registration',
      'common.wechat.web',
      'common.account.password-update',
      'common.account.email-change',
      'common.phone.code-registration',
      'common.phone.code-sign-in',
      'common.account.phone-change',
      'common.management.user-create',
      'common.management.user-contact-update',
      'common.password.policy',
      'common.google.configured-collision',
      'common.account.google-link',
      'common.wechat.h5',
      'common.wechat.mini',
      'common.wechat.mini-phone-registration',
      'common.wechat.native',
      'common.account.wechat-link',
      'common.management.applications-secrets',
      'common.management.native-resource-role',
      'common.management.connectors-experience',
      'common.management.user-suspend-delete',
      'common.management.provisioning-convergence',
      'common.session.logout-preservation',
    ]);
    expect(registries.differentialScenarios[12]).toBe('client-credentials.mixed-authentication');
    expect(registries.candidateInvariantScenarios).toEqual([
      'client-credentials.cross-tenant-authority-rejected',
      'client-credentials.request-role-write-rejected',
      'client-credentials.signing-failure-rolls-back',
      'client-credentials.user-authority-unchanged',
      'logout-session.verification-storage-closed',
      'verification-code.cross-tenant-owner-rejected',
      'verification-code.cross-account-owner-rejected',
      'verification-code.cross-client-owner-rejected',
      'verification-code.wrong-audience-rejected',
      'verification-code.retry-budget-committed',
      'verification-code.concurrent-single-consumer',
      'verification-code.failed-delivery-state-preserved',
      'verification-code.envelope-secret-absent',
      'device-authorization.forced-rls-isolation',
      'device-authorization.credentials-digest-only',
      'device-authorization.cross-tenant-lookup-rejected',
      'device-authorization.transition-failure-rolls-back',
      'device-token.concurrent-poll-one-winner',
      'device-token.consumed-replay-revokes-grant',
      'device-authorization.expired-cleanup-bounded',
      'device-evidence.secret-material-absent',
      'custom-jwt.storage-confidential-forced-rls',
      'custom-jwt.blocking-refresh-rolls-back',
      'custom-jwt.fetch-policy-boundary',
    ]);
    expect(registries.candidateInvariantScenarios).toHaveLength(24);
    expect(registries.discovery).toEqual({
      grantTypesSupportedAppend: [
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
      endpointFieldsAppend: [
        'introspection_endpoint',
        'revocation_endpoint',
        'end_session_endpoint',
        'device_authorization_endpoint',
      ],
      scopesSupportedAppend: ['urn:aster:scope:sessions'],
      stillAbsent: ['registration_endpoint'],
    });
    expect(Object.keys(registries).toSorted()).toEqual([
      'baseAcceptance',
      'candidateInvariantScenarios',
      'deviceOperations',
      'differentialScenarios',
      'discovery',
      'profileSha256',
      'schemaSha256',
    ]);
    expect(registries.profileSha256).toBe(
      '3fe3407f415e01dfa8271ac82d5f586dec452dd0326968ff493304fbbf8be631'
    );
    expect(registries.schemaSha256).toBe(
      '242b8c9edb56140651bf16f74ed619d165342306293008a196422ca64e2566a6'
    );
    expect(registries.baseAcceptance.harnessCommit).toBe(
      '83d08f0821345d1bdc01491152949cc6f044ecfb'
    );
    expect(Object.isFrozen(registries)).toBe(true);
    expect(Object.isFrozen(registries.deviceOperations)).toBe(true);
    expect(Object.isFrozen(registries.differentialScenarios)).toBe(true);
    expect(Object.isFrozen(registries.candidateInvariantScenarios)).toBe(true);
    expect(Object.isFrozen(registries.discovery)).toBe(true);
    expect(Object.isFrozen(registries.discovery.grantTypesSupportedAppend)).toBe(true);
    expect(Object.isFrozen(registries.discovery.endpointFieldsAppend)).toBe(true);
    expect(Object.isFrozen(registries.discovery.scopesSupportedAppend)).toBe(true);
    expect(Object.isFrozen(registries.discovery.stillAbsent)).toBe(true);
  });

  it('accepts byte-identical private copies without trusting a repository path alias', async () => {
    const paths = await copyCanonicalFiles();
    await expect(loadPhase2Profile(paths)).resolves.toEqual(
      await loadPhase2Profile({
        profilePath: canonicalProfilePath,
        schemaPath: canonicalSchemaPath,
      })
    );
  });

  it('rejects missing, reordered, duplicate, and extra device operation IDs', async () => {
    const mutations: ReadonlyArray<(operations: readonly string[]) => string[]> = [
      (operations) => operations.slice(0, -1),
      (operations) => operations.toReversed(),
      (operations) =>
        operations.map((value, index) => (index === 1 ? (operations[0] ?? '') : value)),
      (operations) => [...operations, 'device.unregistered'],
    ];

    await Promise.all(
      mutations.map(async (mutate) => {
        const paths = await copyCanonicalFiles();
        const document = JSON.parse(await readFile(paths.profilePath, 'utf8')) as {
          deviceOperations: string[];
        };
        document.deviceOperations = mutate(document.deviceOperations);
        await writeFile(paths.profilePath, JSON.stringify(document), { mode: 0o600 });
        await expect(loadPhase2Profile(paths)).rejects.toThrow('Invalid Phase 2 profile');
      })
    );
  });

  it('rejects profile and schema byte mutations with one fixed public error', async () => {
    await Promise.all(
      (['profile', 'schema'] as const).map(async (kind) => {
        const paths = await copyCanonicalFiles();
        const targetPath = kind === 'profile' ? paths.profilePath : paths.schemaPath;
        const bytes = await readFile(targetPath);
        const mutationIndex = bytes.length - 2;
        const original = bytes[mutationIndex];
        if (original === undefined) {
          throw new TypeError('fixture bytes missing');
        }
        bytes[mutationIndex] = original === 0x20 ? 0x21 : 0x20;
        await writeFile(targetPath, bytes, { mode: 0o600 });
        const error = await loadPhase2Profile(paths).catch((error_: unknown) => error_);
        expect(error).toBeInstanceOf(Phase2ProfileValidationError);
        expect(String(error)).toBe('Phase2ProfileValidationError: Invalid Phase 2 profile');
      })
    );
  });

  it('rejects relative, duplicate, symlinked, oversized, and replaced inputs before parsing', async () => {
    await expect(
      loadPhase2Profile({ profilePath: 'relative.json', schemaPath: canonicalSchemaPath })
    ).rejects.toThrow('Invalid Phase 2 profile');
    await expect(
      loadPhase2Profile({ profilePath: canonicalProfilePath, schemaPath: canonicalProfilePath })
    ).rejects.toThrow('Invalid Phase 2 profile');

    const root = await createPrivateRoot();
    const profileLink = path.join(root, 'profile-link.json');
    await symlink(canonicalProfilePath, profileLink);
    await expect(
      loadPhase2Profile({ profilePath: profileLink, schemaPath: canonicalSchemaPath })
    ).rejects.toThrow('Invalid Phase 2 profile');

    const oversizedPath = path.join(root, 'oversized.json');
    await writeFile(oversizedPath, Buffer.alloc(1024 * 1024 + 1, 0x20), { mode: 0o600 });
    await expect(
      loadPhase2Profile({ profilePath: oversizedPath, schemaPath: canonicalSchemaPath })
    ).rejects.toThrow('Invalid Phase 2 profile');

    const marker = randomBytes(24).toString('hex');
    const markerPath = path.join(root, 'marker.json');
    await writeFile(markerPath, marker, { mode: 0o600 });
    const error = await loadPhase2Profile({
      profilePath: markerPath,
      schemaPath: canonicalSchemaPath,
    }).catch((error_: unknown) => error_);
    expect(String(error)).not.toContain(marker);
  });
});
/* eslint-enable @silverhand/fp/no-mutation */
