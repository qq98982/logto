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

    expect(registries.differentialScenarios).toHaveLength(20);
    expect(registries.differentialScenarios[12]).toBe('client-credentials.mixed-authentication');
    expect(registries.candidateInvariantScenarios).toEqual([
      'client-credentials.cross-tenant-authority-rejected',
      'client-credentials.request-role-write-rejected',
      'client-credentials.signing-failure-rolls-back',
      'client-credentials.user-authority-unchanged',
    ]);
    expect(registries.discovery).toEqual({
      grantTypesSupportedAppend: ['client_credentials'],
      stillAbsent: [
        'introspection_endpoint',
        'revocation_endpoint',
        'device_authorization_endpoint',
        'registration_endpoint',
      ],
    });
    expect(Object.keys(registries).toSorted()).toEqual([
      'candidateInvariantScenarios',
      'differentialScenarios',
      'discovery',
    ]);
    expect(Object.isFrozen(registries)).toBe(true);
    expect(Object.isFrozen(registries.differentialScenarios)).toBe(true);
    expect(Object.isFrozen(registries.candidateInvariantScenarios)).toBe(true);
    expect(Object.isFrozen(registries.discovery)).toBe(true);
    expect(Object.isFrozen(registries.discovery.grantTypesSupportedAppend)).toBe(true);
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
