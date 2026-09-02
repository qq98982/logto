import { chmod, mkdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  asterPhase1BuildRootEnvironmentVariable,
  defaultAsterPhase1BuildRoot,
  requireAsterPhase1BuildPath,
  resolveAsterPhase1BuildRoot,
  withTrustedAsterPhase1BuildDirectory,
  withTrustedAsterPhase1BuildDirectoryForTesting,
} from './build-root.js';

const roots = new Set<string>();
const createRoot = async () => {
  const root = path.join(
    '/var/tmp',
    `aster-phase1-build-root-${process.pid}-${Date.now()}-${roots.size}`
  );
  const consumer = path.join(root, 'private');
  await mkdir(consumer, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  await chmod(consumer, 0o700);
  roots.add(root);

  return { root, consumer };
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

describe('Aster Phase 1 build-root contract', () => {
  it('defaults to the workstation build root and accepts a normalized custom root', () => {
    expect(resolveAsterPhase1BuildRoot({})).toBe('/var/tmp/henry-build');
    expect(defaultAsterPhase1BuildRoot).toBe('/var/tmp/henry-build');
    expect(asterPhase1BuildRootEnvironmentVariable).toBe('ASTER_PHASE1_BUILD_ROOT');
    expect(
      resolveAsterPhase1BuildRoot({
        ASTER_PHASE1_BUILD_ROOT: '/var/tmp/aster-portable-build',
      })
    ).toBe('/var/tmp/aster-portable-build');
    expect(
      requireAsterPhase1BuildPath('/var/tmp/aster-portable-build/private/run', {
        ASTER_PHASE1_BUILD_ROOT: '/var/tmp/aster-portable-build',
      })
    ).toBe('/var/tmp/aster-portable-build/private/run');
  });

  it.each([
    '',
    'relative/build',
    '/',
    '/tmp',
    '/var/tmp',
    '/dev/shm/aster-build',
    '/proc/aster-build',
    '/var/tmp/aster-build/../escape',
  ])('rejects unsafe or non-absolute build root %j', (buildRoot) => {
    expect(() => resolveAsterPhase1BuildRoot({ ASTER_PHASE1_BUILD_ROOT: buildRoot })).toThrow(
      /^Invalid Aster Phase 1 build root$/u
    );
  });

  it.each([
    '/var/tmp/aster-portable-build',
    '/var/tmp/aster-portable-build/../escape',
    '/var/tmp/other-build/private',
    'relative/private',
  ])('rejects non-descendant build path %j', (candidate) => {
    expect(() =>
      requireAsterPhase1BuildPath(candidate, {
        ASTER_PHASE1_BUILD_ROOT: '/var/tmp/aster-portable-build',
      })
    ).toThrow(/^Invalid Aster Phase 1 build root$/u);
  });

  it('pins a trusted owner-only build directory for the complete operation', async () => {
    const { root, consumer } = await createRoot();
    const marker = await withTrustedAsterPhase1BuildDirectory(
      consumer,
      { ASTER_PHASE1_BUILD_ROOT: root },
      async (descriptorPath) => {
        expect(descriptorPath).toMatch(/^\/proc\/self\/fd\/\d+$/u);
        const output = path.join(descriptorPath, 'marker');
        await writeFile(output, 'trusted', { mode: 0o600 });
        return output;
      }
    );

    expect(await readFile(path.join(consumer, path.basename(marker)), 'utf8')).toBe('trusted');
  });

  it.each(['build-root', 'consumer'] as const)(
    'rejects a group-readable %s directory',
    async (target) => {
      const { root, consumer } = await createRoot();
      const operation = import.meta.jest.fn(async () => false);
      await chmod(target === 'build-root' ? root : consumer, 0o750);

      await expect(
        withTrustedAsterPhase1BuildDirectory(consumer, { ASTER_PHASE1_BUILD_ROOT: root }, operation)
      ).rejects.toThrow(/^Invalid Aster Phase 1 build root$/u);
      expect(operation).not.toHaveBeenCalled();
    }
  );

  it('rejects a symlinked configured build root', async () => {
    const { root, consumer } = await createRoot();
    const alias = `${root}-alias`;
    const operation = import.meta.jest.fn(async () => false);
    await symlink(root, alias, 'dir');
    roots.add(alias);

    await expect(
      withTrustedAsterPhase1BuildDirectory(
        path.join(alias, path.basename(consumer)),
        { ASTER_PHASE1_BUILD_ROOT: alias },
        operation
      )
    ).rejects.toThrow(/^Invalid Aster Phase 1 build root$/u);
    expect(operation).not.toHaveBeenCalled();
  });

  it('rejects a symlinked consumer directory before the operation', async () => {
    const { root, consumer } = await createRoot();
    const realConsumer = path.join(root, 'private-real');
    const operation = import.meta.jest.fn(async () => false);
    await rename(consumer, realConsumer);
    await symlink(realConsumer, consumer, 'dir');

    await expect(
      withTrustedAsterPhase1BuildDirectory(consumer, { ASTER_PHASE1_BUILD_ROOT: root }, operation)
    ).rejects.toThrow(/^Invalid Aster Phase 1 build root$/u);
    expect(operation).not.toHaveBeenCalled();
  });

  it('rejects a directory owned by another user before the operation', async () => {
    const { root, consumer } = await createRoot();
    const uid = process.getuid?.();
    const operation = import.meta.jest.fn(async () => false);

    if (uid === undefined) {
      throw new Error('test requires a current uid');
    }
    await expect(
      withTrustedAsterPhase1BuildDirectoryForTesting(
        consumer,
        { ASTER_PHASE1_BUILD_ROOT: root },
        operation,
        { getCurrentUserId: () => uid + 1 }
      )
    ).rejects.toThrow(/^Invalid Aster Phase 1 build root$/u);
    expect(operation).not.toHaveBeenCalled();
  });

  it('uses the pinned descriptor but rejects path replacement before returning', async () => {
    const { root, consumer } = await createRoot();
    const moved = path.join(root, 'private-original');

    await expect(
      withTrustedAsterPhase1BuildDirectory(
        consumer,
        { ASTER_PHASE1_BUILD_ROOT: root },
        async (descriptorPath) => {
          await rename(consumer, moved);
          await mkdir(consumer, { mode: 0o700 });
          await writeFile(path.join(descriptorPath, 'marker'), 'original', { mode: 0o600 });
        }
      )
    ).rejects.toThrow(/^Invalid Aster Phase 1 build root$/u);
    await expect(readFile(path.join(moved, 'marker'), 'utf8')).resolves.toBe('original');
    await expect(readFile(path.join(consumer, 'marker'), 'utf8')).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });
});
