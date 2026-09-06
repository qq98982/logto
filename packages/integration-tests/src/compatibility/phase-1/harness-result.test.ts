/* eslint-disable max-lines, no-await-in-loop, @silverhand/fp/no-mutation, no-use-extend-native/no-use-extend-native -- Hostile closed-result and sequential CLI controls stay together with their bounded fixture. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import {
  phase1EvidenceFileNames,
  type Phase1ArtifactMode,
  type Phase1EvidenceFileName,
} from './artifact-contract.js';
import { phase1BrowserFlowIds } from './browser/contracts.js';
import { writePhase1EvidenceManifest } from './evidence-manifest.js';
import {
  assertPhase1HarnessResultUploadable,
  parsePhase1HarnessResultBytes,
  resolvePhase1HarnessLogtoRootForTesting,
  runPhase1HarnessResultCli,
  serializePhase1HarnessResultForTesting,
  verifyPhase1HarnessResultBytes,
  writePhase1HarnessResult,
} from './harness-result.js';
import {
  candidateInvariantScenarioIds,
  differentialScenarioIds,
  phase1ObservationKinds,
} from './model.js';
import type { Phase1Profile } from './profile-types.js';
import { createPhase1ProfileBundleFromBytes, type Phase1ProfileBundle } from './profile.js';

const roots = new Set<string>();
const executeFile = promisify(execFile);
const harnessCommit = 'a'.repeat(40);
const imageDigest = `sha256:${'b'.repeat(64)}`;
const adapterIds = ['oidf-basic-1', 'oidf-basic-2', 'oidf-post-1'] as const;
const planIds = [
  'oidcc-basic-certification-test-plan',
  'oidcc-config-certification-test-plan',
] as const;

const createRoot = async () => {
  const root = path.join('/var/tmp/henry-build', `phase1-result-${process.pid}-${Date.now()}`);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

const createProfileBundle = async (): Promise<Phase1ProfileBundle> => {
  const schema = {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object',
    required: [
      'profileSchema',
      'phase1Harness',
      'differentialScenarios',
      'browserFlows',
      'candidateInvariantScenarios',
      'conformance',
    ],
    properties: {
      profileSchema: {},
      phase1Harness: {},
      differentialScenarios: {},
      browserFlows: {},
      candidateInvariantScenarios: {},
      conformance: {},
    },
  };
  const schemaBytes = Buffer.from(`${JSON.stringify(schema)}\n`);
  const schemaSha256 = hash(schemaBytes);
  const profile = {
    profileSchema: {
      repository: 'aster',
      path: 'compatibility/phase-1-profile.schema.json',
      sourceCommit: 'c'.repeat(40),
      sha256: schemaSha256,
      lockState: 'locked',
    },
    phase1Harness: { repository: 'logto', baseCommit: 'd'.repeat(40), commit: harnessCommit },
    differentialScenarios: differentialScenarioIds,
    browserFlows: phase1BrowserFlowIds.map((id) => ({ id })),
    candidateInvariantScenarios: candidateInvariantScenarioIds,
    conformance: {
      staticClients: adapterIds.map((id) => ({ id })),
      plans: planIds.map((testPlanName) => ({ testPlanName })),
    },
  } as unknown as Phase1Profile;
  const profileBytes = Buffer.from(`${JSON.stringify(profile)}\n`);

  return createPhase1ProfileBundleFromBytes(profileBytes, schemaBytes, {
    sourceCommit: 'c'.repeat(40),
    sha256: schemaSha256,
  });
};

const projection = (label: string, id: string) => ({
  label,
  projectionSha256: 'e'.repeat(64),
  value: { id, accepted: true },
});

const writeHarnessEvidence = async (
  root: string,
  bundle: Phase1ProfileBundle,
  mode: Phase1ArtifactMode,
  options: Readonly<{ planNameResults?: boolean }> = {}
) => {
  const provenance = {
    harnessCommit,
    profileSha256: bundle.profileSha256,
    schemaSha256: bundle.schemaSha256,
    imageDigest,
  };
  const officialResultIds =
    mode === 'runtime-candidate'
      ? options.planNameResults
        ? [...planIds]
        : ['official-result-alpha', 'official-result-beta']
      : [];
  const values: Record<Phase1EvidenceFileName, unknown> = {
    'phase-1-browser.json': {
      schemaVersion: 1,
      mode,
      provenance,
      sanitizerSuccess: true,
      flows: [...phase1BrowserFlowIds].toSorted().map((id) => ({
        id,
        oracle: projection('oracle-browser', id),
        candidate: projection('candidate-browser', id),
        differences: [],
      })),
    },
    'phase-1-candidate-invariants.json': {
      schemaVersion: 1,
      mode,
      provenance,
      sanitizerSuccess: true,
      outcomes: [...candidateInvariantScenarioIds].toSorted().map((id) => ({
        id,
        detected: true,
        candidate: projection('candidate', id),
        positiveControl: { detected: true, result: projection('positive', id) },
        negativeControl: {
          detected: true,
          pointer: '/safe/control',
          result: projection('negative', id),
        },
      })),
      observationNegativeControls: phase1ObservationKinds.map((kind) => ({
        kind,
        pointer: `/value/${kind}`,
        detected: true,
        observation: projection('observation-control', kind),
      })),
      discoveryExtraControl: {
        pointer: '/value/__unexpected',
        detected: true,
        observation: projection('discovery-control', 'extra'),
      },
    },
    'phase-1-conformance.json': {
      schemaVersion: 1,
      mode,
      provenance,
      sanitizerSuccess: true,
      adapterControls: adapterIds.map((id) => ({
        id,
        detected: true,
        result: projection('adapter-control', id),
      })),
      officialResultIds,
      planResults:
        mode === 'runtime-candidate'
          ? planIds.map((planId, index) => ({
              planId,
              resultId: officialResultIds[index],
              resultSha256: 'e'.repeat(64),
              result: projection('official-plan-result', officialResultIds[index]!),
            }))
          : [],
    },
    'phase-1-differential.json': {
      schemaVersion: 1,
      mode,
      provenance,
      sanitizerSuccess: true,
      scenarios: [...differentialScenarioIds].toSorted().map((id) => ({
        id,
        oracle: projection('oracle', id),
        candidate: projection('candidate', id),
        differences: [],
      })),
    },
  };

  await Promise.all(
    phase1EvidenceFileNames.map(async (name) =>
      writeFile(path.join(root, name), `${JSON.stringify(values[name])}\n`, { mode: 0o600 })
    )
  );
};

const createFixture = async (
  mode: Phase1ArtifactMode,
  options: Readonly<{ planNameResults?: boolean }> = {}
) => {
  const root = await createRoot();
  const evidenceDirectory = path.join(root, 'evidence');
  await mkdir(evidenceDirectory, { mode: 0o700 });
  const bundle = await createProfileBundle();
  const profilePath = path.join(root, 'phase-1-profile.json');
  const schemaPath = path.join(root, 'phase-1-profile.schema.json');
  await Promise.all([
    writeFile(profilePath, bundle.readProfileBytes(), { mode: 0o600 }),
    writeFile(schemaPath, bundle.readSchemaBytes(), { mode: 0o600 }),
  ]);
  await writeHarnessEvidence(evidenceDirectory, bundle, mode, options);
  const manifest = await writePhase1EvidenceManifest(evidenceDirectory, mode);
  return { root, evidenceDirectory, profilePath, schemaPath, bundle, manifest };
};

describe('Phase 1 harness result', () => {
  it('resolves a repository root with the canonical integration package markers', async () => {
    const root = resolvePhase1HarnessLogtoRootForTesting();
    const packageDocument = JSON.parse(
      await readFile(path.join(root, 'packages/integration-tests/package.json'), 'utf8')
    ) as unknown;

    expect(packageDocument).toMatchObject({ name: '@logto/integration-tests' });
    await expect(
      readFile(path.join(root, 'compatibility/phases/phase-1-capabilities.json'))
    ).resolves.toBeInstanceOf(Buffer);
  });

  it('derives the exact closed mirror result from profile schema manifest and evidence bytes', async () => {
    const fixture = await createFixture('mirror-control');
    const artifact = await writePhase1HarnessResult({
      profileBundle: fixture.bundle,
      evidenceManifest: fixture.manifest,
    });
    const parsed = parsePhase1HarnessResultBytes(await readFile(artifact.outputPath));

    expect(Object.keys(parsed)).toEqual([
      'schemaVersion',
      'mode',
      'harnessCommit',
      'profileSha256',
      'schemaSha256',
      'imageDigest',
      'evidenceManifestSha256',
      'differential',
      'browser',
      'controls',
      'conformance',
    ]);
    expect(parsed.differential).toEqual({ scenarioCount: 22, differenceCount: 0 });
    expect(parsed.browser).toEqual({ flowCount: 4, differenceCount: 0 });
    expect(parsed.controls).toEqual({
      observationKindCount: 6,
      discoveryExtraDetected: true,
      candidateInvariantCount: 18,
      allDetected: true,
    });
    expect(parsed.conformance).toEqual({ adapterControlIds: adapterIds, officialResultIds: [] });
    expect(artifact.uploadable).toBe(true);
    expect(() => {
      assertPhase1HarnessResultUploadable(artifact);
    }).not.toThrow();
  });

  it('keeps review-candidate result nonuploadable', async () => {
    const fixture = await createFixture('review-candidate');
    const artifact = await writePhase1HarnessResult({
      profileBundle: fixture.bundle,
      evidenceManifest: fixture.manifest,
    });

    expect(artifact.uploadable).toBe(false);
    expect(() => {
      assertPhase1HarnessResultUploadable(artifact);
    }).toThrow(/^Invalid phase 1 harness result$/u);
  });

  it('removes the exact result publication when post-publication work fails', async () => {
    const fixture = await createFixture('mirror-control');
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');

    await expect(
      writePhase1HarnessResult({
        profileBundle: fixture.bundle,
        evidenceManifest: fixture.manifest,
        hooks: {
          afterPublication: async () => {
            throw new Error('simulated post-publication failure');
          },
        },
      })
    ).rejects.toThrow(/^Invalid phase 1 harness result$/u);
    await expect(readFile(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not delete a pre-existing result that this invocation did not publish', async () => {
    const fixture = await createFixture('mirror-control');
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');
    const stale = '{"stale":true}\n';
    await writeFile(output, stale, { mode: 0o600 });

    await expect(
      writePhase1HarnessResult({
        profileBundle: fixture.bundle,
        evidenceManifest: fixture.manifest,
      })
    ).rejects.toThrow(/^Invalid phase 1 harness result$/u);
    await expect(readFile(output, 'utf8')).resolves.toBe(stale);
  });

  it('refuses to delete a replacement result and surfaces rollback identity failure', async () => {
    const fixture = await createFixture('mirror-control');
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');
    const displaced = path.join(fixture.evidenceDirectory, 'displaced-harness-result.json');
    const replacement = '{"replacement":true}\n';

    await expect(
      writePhase1HarnessResult({
        profileBundle: fixture.bundle,
        evidenceManifest: fixture.manifest,
        hooks: {
          afterPublication: async () => {
            await rename(output, displaced);
            await writeFile(output, replacement, { mode: 0o600 });
            throw new Error('simulated result replacement');
          },
        },
      })
    ).rejects.toThrow(/^Phase 1 harness result cleanup failed$/u);
    await expect(readFile(output, 'utf8')).resolves.toBe(replacement);
    expect(parsePhase1HarnessResultBytes(await readFile(displaced)).mode).toBe('mirror-control');
  });

  it('surfaces unlink failure instead of silently retaining a stale result', async () => {
    const fixture = await createFixture('mirror-control');
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');

    try {
      await expect(
        writePhase1HarnessResult({
          profileBundle: fixture.bundle,
          evidenceManifest: fixture.manifest,
          hooks: {
            afterPublication: async () => {
              await chmod(fixture.evidenceDirectory, 0o500);
              throw new Error('simulated post-publication failure');
            },
          },
        })
      ).rejects.toThrow(/^Phase 1 harness result cleanup failed$/u);
      expect(parsePhase1HarnessResultBytes(await readFile(output)).mode).toBe('mirror-control');
    } finally {
      await chmod(fixture.evidenceDirectory, 0o700);
    }
  });

  it('derives runtime opaque results and rejects plan-name substitutions', async () => {
    const valid = await createFixture('runtime-candidate');
    const artifact = await writePhase1HarnessResult({
      profileBundle: valid.bundle,
      evidenceManifest: valid.manifest,
    });
    expect(artifact.result.conformance.officialResultIds).toEqual([
      'official-result-alpha',
      'official-result-beta',
    ]);

    const invalid = await createFixture('runtime-candidate', { planNameResults: true });
    await expect(
      writePhase1HarnessResult({
        profileBundle: invalid.bundle,
        evidenceManifest: invalid.manifest,
      })
    ).rejects.toThrow(/^Invalid phase 1 harness result$/u);
  });

  it('rejects contradictory counts and private reviewer credential fields', async () => {
    const fixture = await createFixture('mirror-control');
    const artifact = await writePhase1HarnessResult({
      profileBundle: fixture.bundle,
      evidenceManifest: fixture.manifest,
    });
    const contradictory = JSON.parse(JSON.stringify(artifact.result)) as {
      differential: { scenarioCount: number };
    };
    contradictory.differential.scenarioCount = 21;
    await expect(
      verifyPhase1HarnessResultBytes(serializePhase1HarnessResultForTesting(contradictory), {
        profileBundle: fixture.bundle,
        evidenceManifest: fixture.manifest,
      })
    ).rejects.toThrow(/^Invalid phase 1 harness result$/u);

    for (const field of ['approvingReviewer', 'pullRequest', 'ruleset', 'clientSecret']) {
      const hostile = { ...artifact.result, [field]: 'private-material' };
      expect(() =>
        parsePhase1HarnessResultBytes(serializePhase1HarnessResultForTesting(hostile))
      ).toThrow(/^Invalid phase 1 harness result$/u);
    }
  });

  it('enforces exact harness CLI arguments paths authorities and image binding', async () => {
    const fixture = await createFixture('mirror-control');
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');
    const valid = [
      '--mode',
      'mirror-control',
      '--profile',
      fixture.profilePath,
      '--schema',
      fixture.schemaPath,
      '--image-digest',
      imageDigest,
      '--manifest',
      fixture.manifest.outputPath,
      '--output',
      output,
    ];
    const dependencies = { loadProfileBundle: async () => fixture.bundle };

    for (const invalid of [
      valid.slice(0, -2),
      [...valid, '--extra', 'value'],
      [...valid, '--mode', 'mirror-control'],
      [...valid.slice(0, -1), path.join(fixture.root, 'cross-directory-harness-result.json')],
    ]) {
      await expect(runPhase1HarnessResultCli(invalid, dependencies)).resolves.toBe(1);
    }
    await expect(
      runPhase1HarnessResultCli(
        valid.map((value) => (value === imageDigest ? `sha256:${'f'.repeat(64)}` : value)),
        dependencies
      )
    ).resolves.toBe(1);
    await expect(
      runPhase1HarnessResultCli(valid, {
        loadProfileBundle: async () => ({ ...fixture.bundle }),
      })
    ).resolves.toBe(1);
  });

  it('rejects forged on-disk evidence before cross-process result publication', async () => {
    const fixture = await createFixture('runtime-candidate');
    await writeFile(path.join(fixture.evidenceDirectory, phase1EvidenceFileNames[0]), '{}\n', {
      mode: 0o600,
    });
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');

    await expect(
      runPhase1HarnessResultCli(
        [
          '--mode',
          'runtime-candidate',
          '--profile',
          fixture.profilePath,
          '--schema',
          fixture.schemaPath,
          '--image-digest',
          imageDigest,
          '--manifest',
          fixture.manifest.outputPath,
          '--output',
          output,
        ],
        { loadProfileBundle: async () => fixture.bundle }
      )
    ).resolves.toBe(1);
  });

  it('runs the harness CLI in a separate process without a prior-process manifest capability', async () => {
    const fixture = await createFixture('mirror-control');
    const output = path.join(fixture.evidenceDirectory, 'harness-result.json');
    const moduleUrl = pathToFileURL(
      path.resolve(process.cwd(), 'lib/compatibility/phase-1/harness-result.js')
    ).href;
    const profileModuleUrl = pathToFileURL(
      path.resolve(process.cwd(), 'lib/compatibility/phase-1/profile.js')
    ).href;
    const sourceCommit = 'c'.repeat(40);
    const script = `
      import { readFile } from 'node:fs/promises';
      import { createHash } from 'node:crypto';
      import { runPhase1HarnessResultCli } from ${JSON.stringify(moduleUrl)};
      import { createPhase1ProfileBundleFromBytes } from ${JSON.stringify(profileModuleUrl)};
      const args = ${JSON.stringify([
        '--mode',
        'mirror-control',
        '--profile',
        fixture.profilePath,
        '--schema',
        fixture.schemaPath,
        '--image-digest',
        imageDigest,
        '--manifest',
        fixture.manifest.outputPath,
        '--output',
        output,
      ])};
      const profileBytes = await readFile(${JSON.stringify(fixture.profilePath)});
      const schemaBytes = await readFile(${JSON.stringify(fixture.schemaPath)});
      const sha256 = createHash('sha256').update(schemaBytes).digest('hex');
      const bundle = await createPhase1ProfileBundleFromBytes(profileBytes, schemaBytes, {
        sourceCommit: ${JSON.stringify(sourceCommit)}, sha256
      });
      process.exitCode = await runPhase1HarnessResultCli(args, {
        loadProfileBundle: async () => bundle
      });
    `;

    await expect(
      executeFile(process.execPath, ['--input-type=module', '--eval', script], {
        env: { NODE_ENV: 'test', PATH: '/usr/bin:/bin' },
      })
    ).resolves.toMatchObject({ stdout: '', stderr: '' });
    expect(parsePhase1HarnessResultBytes(await readFile(output)).mode).toBe('mirror-control');
  });
});

/* eslint-enable max-lines, no-await-in-loop, @silverhand/fp/no-mutation, no-use-extend-native/no-use-extend-native */
