/* eslint-disable max-lines, complexity, max-params, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The public result derives several closed aggregate contracts and owns a bounded CLI parser. */
import { existsSync, realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

import { capabilityManifestGuard, type CapabilityManifest } from '../model.js';
import type { JsonValue } from '../normalize.js';

import {
  assertPhase1PublicArtifactValue,
  bytewiseCompare,
  canonicalPhase1ArtifactBytes,
  exactArtifactKeys,
  hashPhase1ArtifactBytes,
  isArtifactRecord,
  parseStrictPhase1ArtifactJson,
  phase1ArtifactModes,
  phase1HarnessResultName,
  type Phase1ArtifactMode,
  type Phase1EvidenceFileName,
} from './artifact-contract.js';
import { candidateInvariantRegistryIds } from './candidate-invariants/index.js';
import { parsePhase1CapabilityDocument } from './capabilities.js';
import {
  loadPhase1EvidenceManifestFromDisk,
  readPhase1EvidenceManifestArtifactForHarnessResult,
  type Phase1EvidenceManifestArtifact,
} from './evidence-manifest.js';
import { cloneAndDeepFreeze, differentialScenarioIds } from './model.js';
import { phase1ProfileSchemaLock } from './profile-lock.js';
import { assertPhase1ProfileSemantics } from './profile-semantics.js';
import {
  assertValidatedPhase1ProfileBundle,
  createPhase1ProfileBundleLoader,
  type Phase1ProfileBundle,
} from './profile.js';
import {
  rollbackSecureJsonArtifact,
  setSecureJsonArtifactMode,
  writeSecureJsonArtifact,
  type SecureJsonPublication,
} from './secure-evidence-sink.js';

export type Phase1HarnessResult = Readonly<{
  schemaVersion: 1;
  mode: Phase1ArtifactMode;
  harnessCommit: string;
  profileSha256: string;
  schemaSha256: string;
  imageDigest: string;
  evidenceManifestSha256: string;
  differential: Readonly<{ scenarioCount: number; differenceCount: number }>;
  browser: Readonly<{ flowCount: number; differenceCount: number }>;
  controls: Readonly<{
    observationKindCount: number;
    discoveryExtraDetected: boolean;
    candidateInvariantCount: number;
    allDetected: boolean;
  }>;
  conformance: Readonly<{
    adapterControlIds: readonly string[];
    officialResultIds: readonly string[];
  }>;
}>;

export type Phase1HarnessResultArtifact = Readonly<{
  outputPath: string;
  sha256: string;
  mode: Phase1ArtifactMode;
  uploadable: boolean;
  result: Phase1HarnessResult;
}>;

export type WritePhase1HarnessResultInput = Readonly<{
  profileBundle: Phase1ProfileBundle;
  evidenceManifest: Phase1EvidenceManifestArtifact;
  expectedMode?: Phase1ArtifactMode;
  expectedImageDigest?: string;
  hooks?: Readonly<{ afterPublication?: () => Promise<void> }>;
}>;

type EvidenceSummary = Readonly<{
  imageDigest: string;
  differential: Phase1HarnessResult['differential'];
  browser: Phase1HarnessResult['browser'];
  controls: Phase1HarnessResult['controls'];
  conformance: Phase1HarnessResult['conformance'];
}>;

const diagnostic = 'Invalid phase 1 harness result';
const cleanupDiagnostic = 'Phase 1 harness result cleanup failed';
const commitPattern = /^[0-9a-f]{40}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;
const resultIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const exactAdapterIds = Object.freeze(['oidf-basic-1', 'oidf-basic-2', 'oidf-post-1'] as const);
const resultAuthorities = new WeakSet<Phase1HarnessResultArtifact>();

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const failCleanup = (): never => {
  throw new TypeError(cleanupDiagnostic);
};

const sortedUniqueStrings = (value: unknown): value is readonly string[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every(
    (item, index) =>
      typeof item === 'string' &&
      item.length > 0 &&
      (index === 0 || bytewiseCompare(value[index - 1] as string, item) < 0)
  );

const requireCommonEvidence = (
  value: unknown,
  mode: Phase1ArtifactMode,
  harnessCommit: string,
  profileSha256: string,
  schemaSha256: string,
  detailKeys: readonly string[]
): Readonly<Record<string, unknown>> => {
  if (
    !isArtifactRecord(value) ||
    !exactArtifactKeys(value, [
      'schemaVersion',
      'mode',
      'provenance',
      'sanitizerSuccess',
      ...detailKeys,
    ]) ||
    value.schemaVersion !== 1 ||
    value.mode !== mode ||
    value.sanitizerSuccess !== true ||
    !isArtifactRecord(value.provenance) ||
    !exactArtifactKeys(value.provenance, [
      'harnessCommit',
      'profileSha256',
      'schemaSha256',
      'imageDigest',
    ]) ||
    value.provenance.harnessCommit !== harnessCommit ||
    value.provenance.profileSha256 !== profileSha256 ||
    value.provenance.schemaSha256 !== schemaSha256 ||
    typeof value.provenance.imageDigest !== 'string' ||
    !imageDigestPattern.test(value.provenance.imageDigest)
  ) {
    return fail();
  }

  return value;
};

const parseEvidence = (
  bytes: Uint8Array,
  mode: Phase1ArtifactMode,
  harnessCommit: string,
  profileSha256: string,
  schemaSha256: string,
  detailKeys: readonly string[]
) => {
  const value = parseStrictPhase1ArtifactJson(bytes);
  assertPhase1PublicArtifactValue(value);
  return requireCommonEvidence(value, mode, harnessCommit, profileSha256, schemaSha256, detailKeys);
};

const differenceCount = (items: readonly unknown[], labelKeys: readonly string[]): number =>
  items.reduce<number>((total, item) => {
    if (
      !isArtifactRecord(item) ||
      !exactArtifactKeys(item, labelKeys) ||
      typeof item.id !== 'string' ||
      !Array.isArray(item.differences)
    ) {
      return fail();
    }
    return total + item.differences.length;
  }, 0);

const deriveEvidenceSummary = (
  evidenceBytes: Readonly<Record<Phase1EvidenceFileName, Uint8Array>>,
  mode: Phase1ArtifactMode,
  profile: Phase1ProfileBundle['profile'],
  profileSha256: string,
  schemaSha256: string
): EvidenceSummary => {
  const harnessCommit = profile.phase1Harness.commit;

  if (typeof harnessCommit !== 'string' || !commitPattern.test(harnessCommit)) {
    return fail();
  }
  const differential = parseEvidence(
    evidenceBytes['phase-1-differential.json'],
    mode,
    harnessCommit,
    profileSha256,
    schemaSha256,
    ['scenarios']
  );
  const browser = parseEvidence(
    evidenceBytes['phase-1-browser.json'],
    mode,
    harnessCommit,
    profileSha256,
    schemaSha256,
    ['flows']
  );
  const controls = parseEvidence(
    evidenceBytes['phase-1-candidate-invariants.json'],
    mode,
    harnessCommit,
    profileSha256,
    schemaSha256,
    ['outcomes', 'observationNegativeControls', 'discoveryExtraControl']
  );
  const conformance = parseEvidence(
    evidenceBytes['phase-1-conformance.json'],
    mode,
    harnessCommit,
    profileSha256,
    schemaSha256,
    ['adapterControls', 'officialResultIds', 'planResults']
  );
  const imageDigests = [differential, browser, controls, conformance].map(
    (value) => (value.provenance as Readonly<Record<string, unknown>>).imageDigest
  );

  if (new Set(imageDigests).size !== 1 || typeof imageDigests[0] !== 'string') {
    return fail();
  }
  if (!Array.isArray(differential.scenarios) || !Array.isArray(browser.flows)) {
    return fail();
  }
  const scenarioIds = differential.scenarios.map((item) =>
    isArtifactRecord(item) && typeof item.id === 'string' ? item.id : fail()
  );
  const flowIds = browser.flows.map((item) =>
    isArtifactRecord(item) && typeof item.id === 'string' ? item.id : fail()
  );
  const expectedScenarioIds = [...profile.differentialScenarios].toSorted(bytewiseCompare);
  const expectedFlowIds = profile.browserFlows.map(({ id }) => id).toSorted(bytewiseCompare);

  if (
    !isDeepStrictEqual(scenarioIds, expectedScenarioIds) ||
    !isDeepStrictEqual(flowIds, expectedFlowIds)
  ) {
    return fail();
  }
  if (
    !Array.isArray(controls.outcomes) ||
    !Array.isArray(controls.observationNegativeControls) ||
    !isArtifactRecord(controls.discoveryExtraControl)
  ) {
    return fail();
  }
  const outcomeIds = controls.outcomes.map((outcome) => {
    if (
      !isArtifactRecord(outcome) ||
      !exactArtifactKeys(outcome, [
        'id',
        'detected',
        'candidate',
        'positiveControl',
        'negativeControl',
      ]) ||
      typeof outcome.id !== 'string' ||
      outcome.detected !== true ||
      !isArtifactRecord(outcome.positiveControl) ||
      outcome.positiveControl.detected !== true ||
      !isArtifactRecord(outcome.negativeControl) ||
      outcome.negativeControl.detected !== true
    ) {
      return fail();
    }
    return outcome.id;
  });
  const expectedOutcomeIds = [...profile.candidateInvariantScenarios].toSorted(bytewiseCompare);
  const observationKinds = controls.observationNegativeControls.map((control) => {
    if (
      !isArtifactRecord(control) ||
      typeof control.kind !== 'string' ||
      control.detected !== true
    ) {
      return fail();
    }
    return control.kind;
  });

  if (
    !isDeepStrictEqual(outcomeIds, expectedOutcomeIds) ||
    new Set(observationKinds).size !== observationKinds.length ||
    controls.discoveryExtraControl.detected !== true
  ) {
    return fail();
  }
  if (
    !Array.isArray(conformance.adapterControls) ||
    !Array.isArray(conformance.officialResultIds) ||
    !Array.isArray(conformance.planResults)
  ) {
    return fail();
  }
  const adapterControlIds = conformance.adapterControls.map((control) => {
    if (
      !isArtifactRecord(control) ||
      !exactArtifactKeys(control, ['id', 'detected', 'result']) ||
      typeof control.id !== 'string' ||
      control.detected !== true
    ) {
      return fail();
    }
    return control.id;
  });
  const { officialResultIds } = conformance;
  const expectedAdapters = profile.conformance.staticClients
    .map(({ id }) => id)
    .toSorted(bytewiseCompare);
  const planNames = profile.conformance.plans
    .map(({ testPlanName }) => testPlanName)
    .toSorted(bytewiseCompare);
  const planNameSet = new Set<string>(planNames);

  if (
    !isDeepStrictEqual(adapterControlIds, expectedAdapters) ||
    !isDeepStrictEqual(adapterControlIds, exactAdapterIds) ||
    (officialResultIds.length > 0 && !sortedUniqueStrings(officialResultIds)) ||
    officialResultIds.some(
      (resultId) =>
        typeof resultId !== 'string' || !resultIdPattern.test(resultId) || planNameSet.has(resultId)
    )
  ) {
    return fail();
  }
  const planResults = conformance.planResults.map((result) => {
    if (
      !isArtifactRecord(result) ||
      !exactArtifactKeys(result, ['planId', 'resultId', 'resultSha256', 'result']) ||
      typeof result.planId !== 'string' ||
      typeof result.resultId !== 'string' ||
      typeof result.resultSha256 !== 'string' ||
      !sha256Pattern.test(result.resultSha256)
    ) {
      return fail();
    }
    return Object.freeze({ planId: result.planId, resultId: result.resultId });
  });

  if (
    mode === 'runtime-candidate'
      ? !isDeepStrictEqual(
          planResults.map(({ planId }) => planId),
          planNames
        ) ||
        !isDeepStrictEqual(
          planResults.map(({ resultId }) => resultId).toSorted(bytewiseCompare),
          officialResultIds
        ) ||
        officialResultIds.length !== planNames.length
      : officialResultIds.length > 0 || planResults.length > 0
  ) {
    return fail();
  }

  return cloneAndDeepFreeze({
    imageDigest: imageDigests[0],
    differential: {
      scenarioCount: differential.scenarios.length,
      differenceCount: differenceCount(differential.scenarios, [
        'id',
        'oracle',
        'candidate',
        'differences',
      ]),
    },
    browser: {
      flowCount: browser.flows.length,
      differenceCount: differenceCount(browser.flows, ['id', 'oracle', 'candidate', 'differences']),
    },
    controls: {
      observationKindCount: observationKinds.length,
      discoveryExtraDetected: true,
      candidateInvariantCount: outcomeIds.length,
      allDetected: true,
    },
    conformance: { adapterControlIds, officialResultIds },
  });
};

export const parsePhase1HarnessResultBytes = (bytes: Uint8Array): Phase1HarnessResult => {
  try {
    const value = parseStrictPhase1ArtifactJson(bytes);
    assertPhase1PublicArtifactValue(value);

    if (
      !isArtifactRecord(value) ||
      !exactArtifactKeys(value, [
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
      ]) ||
      value.schemaVersion !== 1 ||
      !phase1ArtifactModes.includes(value.mode as Phase1ArtifactMode) ||
      typeof value.harnessCommit !== 'string' ||
      !commitPattern.test(value.harnessCommit) ||
      typeof value.profileSha256 !== 'string' ||
      !sha256Pattern.test(value.profileSha256) ||
      typeof value.schemaSha256 !== 'string' ||
      !sha256Pattern.test(value.schemaSha256) ||
      typeof value.imageDigest !== 'string' ||
      !imageDigestPattern.test(value.imageDigest) ||
      typeof value.evidenceManifestSha256 !== 'string' ||
      !sha256Pattern.test(value.evidenceManifestSha256) ||
      !isArtifactRecord(value.differential) ||
      !exactArtifactKeys(value.differential, ['scenarioCount', 'differenceCount']) ||
      !isArtifactRecord(value.browser) ||
      !exactArtifactKeys(value.browser, ['flowCount', 'differenceCount']) ||
      !isArtifactRecord(value.controls) ||
      !exactArtifactKeys(value.controls, [
        'observationKindCount',
        'discoveryExtraDetected',
        'candidateInvariantCount',
        'allDetected',
      ]) ||
      !isArtifactRecord(value.conformance) ||
      !exactArtifactKeys(value.conformance, ['adapterControlIds', 'officialResultIds'])
    ) {
      return fail();
    }
    const counts = [
      value.differential.scenarioCount,
      value.differential.differenceCount,
      value.browser.flowCount,
      value.browser.differenceCount,
      value.controls.observationKindCount,
      value.controls.candidateInvariantCount,
    ];

    if (
      counts.some((count) => !Number.isSafeInteger(count) || Number(count) < 0) ||
      typeof value.controls.discoveryExtraDetected !== 'boolean' ||
      typeof value.controls.allDetected !== 'boolean' ||
      !sortedUniqueStrings(value.conformance.adapterControlIds) ||
      !Array.isArray(value.conformance.officialResultIds) ||
      (value.conformance.officialResultIds.length > 0 &&
        !sortedUniqueStrings(value.conformance.officialResultIds))
    ) {
      return fail();
    }

    return cloneAndDeepFreeze(value as Phase1HarnessResult);
  } catch {
    return fail();
  }
};

const deriveResult = async (
  profileBundle: Phase1ProfileBundle,
  evidenceManifest: Phase1EvidenceManifestArtifact,
  expected: Readonly<{
    mode?: Phase1ArtifactMode;
    imageDigest?: string;
    includeHarnessResult?: boolean;
  }> = {}
): Promise<Phase1HarnessResult> => {
  assertValidatedPhase1ProfileBundle(profileBundle);
  const profileBytes = profileBundle.readProfileBytes();
  const schemaBytes = profileBundle.readSchemaBytes();
  parseStrictPhase1ArtifactJson(schemaBytes);
  const profileSha256 = hashPhase1ArtifactBytes(profileBytes);
  const schemaSha256 = hashPhase1ArtifactBytes(schemaBytes);

  if (
    profileSha256 !== profileBundle.profileSha256 ||
    schemaSha256 !== profileBundle.schemaSha256
  ) {
    return fail();
  }
  const artifacts = await readPhase1EvidenceManifestArtifactForHarnessResult(
    evidenceManifest,
    expected.includeHarnessResult === true
  );
  const summary = deriveEvidenceSummary(
    artifacts.evidenceBytes,
    artifacts.manifest.mode,
    profileBundle.profile,
    profileSha256,
    schemaSha256
  );
  const harnessCommit = profileBundle.profile.phase1Harness.commit;

  if (typeof harnessCommit !== 'string') {
    return fail();
  }
  if (
    (expected.mode !== undefined && artifacts.manifest.mode !== expected.mode) ||
    (expected.imageDigest !== undefined && summary.imageDigest !== expected.imageDigest)
  ) {
    return fail();
  }
  const result = cloneAndDeepFreeze({
    schemaVersion: 1 as const,
    mode: artifacts.manifest.mode,
    harnessCommit,
    profileSha256,
    schemaSha256,
    imageDigest: summary.imageDigest,
    evidenceManifestSha256: hashPhase1ArtifactBytes(artifacts.manifestBytes),
    differential: summary.differential,
    browser: summary.browser,
    controls: summary.controls,
    conformance: summary.conformance,
  });

  if (
    result.differential.scenarioCount !== 22 ||
    result.differential.differenceCount !== 0 ||
    result.browser.flowCount !== 4 ||
    result.browser.differenceCount !== 0 ||
    result.controls.observationKindCount !== 6 ||
    result.controls.candidateInvariantCount !== 18 ||
    !result.controls.discoveryExtraDetected ||
    !result.controls.allDetected ||
    !isDeepStrictEqual(result.conformance.adapterControlIds, exactAdapterIds) ||
    (result.mode === 'mirror-control' && result.conformance.officialResultIds.length > 0)
  ) {
    return fail();
  }

  return result;
};

export const verifyPhase1HarnessResultBytes = async (
  bytes: Uint8Array,
  input: Omit<WritePhase1HarnessResultInput, 'hooks'>,
  includePublishedResult = false
): Promise<Phase1HarnessResult> => {
  try {
    const parsed = parsePhase1HarnessResultBytes(bytes);
    const derived = await deriveResult(input.profileBundle, input.evidenceManifest, {
      mode: input.expectedMode,
      imageDigest: input.expectedImageDigest,
      includeHarnessResult: includePublishedResult,
    });

    if (!isDeepStrictEqual(parsed, derived)) {
      return fail();
    }

    return parsed;
  } catch {
    return fail();
  }
};

export const writePhase1HarnessResult = async (
  input: WritePhase1HarnessResultInput
): Promise<Phase1HarnessResultArtifact> => {
  let publication: SecureJsonPublication | undefined;

  try {
    const result = await deriveResult(input.profileBundle, input.evidenceManifest, {
      mode: input.expectedMode,
      imageDigest: input.expectedImageDigest,
    });
    const outputPath = path.join(
      path.dirname(input.evidenceManifest.outputPath),
      phase1HarnessResultName
    );
    const expectedBytes = canonicalPhase1ArtifactBytes(result);
    publication = await writeSecureJsonArtifact(outputPath, result as unknown as JsonValue);
    await input.hooks?.afterPublication?.();
    await setSecureJsonArtifactMode(publication, 0o600);
    const publishedBytes = await readFile(publication.path);
    await setSecureJsonArtifactMode(publication, 0o600);

    if (!Buffer.from(publishedBytes).equals(Buffer.from(expectedBytes))) {
      return fail();
    }
    const verified = await verifyPhase1HarnessResultBytes(publishedBytes, input, true);
    const artifact = Object.freeze({
      outputPath: publication.path,
      sha256: hashPhase1ArtifactBytes(publishedBytes),
      mode: result.mode,
      uploadable: result.mode !== 'review-candidate',
      result: verified,
    });

    resultAuthorities.add(artifact);

    return artifact;
  } catch {
    if (publication !== undefined) {
      try {
        await rollbackSecureJsonArtifact(publication);
      } catch {
        return failCleanup();
      }
    }
    return fail();
  }
};

export const assertPhase1HarnessResultUploadable = (
  artifact: Phase1HarnessResultArtifact
): void => {
  if (!resultAuthorities.has(artifact) || !artifact.uploadable) {
    return fail();
  }
};

type HarnessResultCliCommand = Readonly<{
  mode: Phase1ArtifactMode;
  profilePath: string;
  schemaPath: string;
  imageDigest: string;
  manifestPath: string;
  outputPath: string;
}>;

const findIntegrationTestsPackageRoot = (): string => {
  let current = path.dirname(realpathSync(fileURLToPath(import.meta.url)));

  for (let remaining = 8; remaining > 0; remaining -= 1) {
    if (
      path.basename(current) === 'integration-tests' &&
      path.basename(path.dirname(current)) === 'packages' &&
      existsSync(path.join(current, 'package.json'))
    ) {
      return current;
    }

    current = path.dirname(current);
  }

  return fail();
};

const packageRoot = findIntegrationTestsPackageRoot();
const logtoRoot = path.resolve(packageRoot, '../..');

export const resolvePhase1HarnessLogtoRootForTesting = (): string => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return logtoRoot;
};

const parseHarnessResultCliArguments = (arguments_: readonly string[]): HarnessResultCliCommand => {
  const values = new Map<string, string>();
  const flags = new Set([
    '--mode',
    '--profile',
    '--schema',
    '--image-digest',
    '--manifest',
    '--output',
  ]);

  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];

    if (
      !flag ||
      !flags.has(flag) ||
      flag.includes('=') ||
      !value ||
      value.startsWith('--') ||
      values.has(flag)
    ) {
      return fail();
    }
    values.set(flag, value);
  }
  const mode = values.get('--mode');
  const profilePath = values.get('--profile');
  const schemaPath = values.get('--schema');
  const imageDigest = values.get('--image-digest');
  const manifestPath = values.get('--manifest');
  const outputPath = values.get('--output');
  const evidenceDirectory = manifestPath === undefined ? undefined : path.dirname(manifestPath);

  if (
    values.size !== flags.size ||
    !phase1ArtifactModes.includes(mode as Phase1ArtifactMode) ||
    !profilePath ||
    !schemaPath ||
    !imageDigest ||
    !imageDigestPattern.test(imageDigest) ||
    !manifestPath ||
    !outputPath ||
    !evidenceDirectory ||
    manifestPath !== path.join(evidenceDirectory, 'evidence-manifest.json') ||
    outputPath !== path.join(evidenceDirectory, 'harness-result.json')
  ) {
    return fail();
  }

  return Object.freeze({
    mode: mode as Phase1ArtifactMode,
    profilePath,
    schemaPath,
    imageDigest,
    manifestPath,
    outputPath,
  });
};

const loadCanonicalProfileBundle = async (
  profilePath: string,
  schemaPath: string
): Promise<Phase1ProfileBundle> => {
  const bundle = await createPhase1ProfileBundleLoader(phase1ProfileSchemaLock)({
    profilePath,
    schemaPath,
  });
  const [capabilityBytes, manifestBytes] = await Promise.all([
    readFile(path.join(logtoRoot, 'compatibility/phases/phase-1-capabilities.json')),
    readFile(path.join(logtoRoot, 'compatibility/baseline-manifest.json')),
  ]);
  const capability = parseStrictPhase1ArtifactJson(capabilityBytes);
  const manifestValue = parseStrictPhase1ArtifactJson(manifestBytes);
  const parsedManifest = capabilityManifestGuard.safeParse(manifestValue);

  if (!parsedManifest.success) {
    return fail();
  }
  const manifest: CapabilityManifest = parsedManifest.data;
  const document = parsePhase1CapabilityDocument(capability, bundle.profile, manifest);
  const baselineCapabilityIds = new Set(document.baselineCapabilityIds);

  assertPhase1ProfileSemantics(bundle.profile, {
    baselineCapabilityIds,
    differentialRegistryIds: differentialScenarioIds,
    candidateInvariantRegistryIds,
  });

  return bundle;
};

export const runPhase1HarnessResultCli = async (
  arguments_: readonly string[] = process.argv.slice(2),
  injectedDependencies:
    | Readonly<{
        loadProfileBundle: (
          profilePath: string,
          schemaPath: string
        ) => Promise<Phase1ProfileBundle>;
      }>
    | undefined = undefined
): Promise<number> => {
  try {
    if (injectedDependencies !== undefined && process.env.NODE_ENV !== 'test') {
      return fail();
    }
    const command = parseHarnessResultCliArguments(arguments_);
    const profileBundle = await (
      injectedDependencies?.loadProfileBundle ?? loadCanonicalProfileBundle
    )(command.profilePath, command.schemaPath);
    const evidenceManifest = await loadPhase1EvidenceManifestFromDisk({
      mode: command.mode,
      directory: path.dirname(command.manifestPath),
      manifestPath: command.manifestPath,
    });
    const artifact = await writePhase1HarnessResult({
      profileBundle,
      evidenceManifest,
      expectedMode: command.mode,
      expectedImageDigest: command.imageDigest,
    });

    if (
      artifact.outputPath !== command.outputPath ||
      artifact.result.imageDigest !== command.imageDigest
    ) {
      return fail();
    }
    await verifyPhase1HarnessResultBytes(
      await readFile(command.outputPath),
      {
        profileBundle,
        evidenceManifest,
        expectedMode: command.mode,
        expectedImageDigest: command.imageDigest,
      },
      true
    );

    return 0;
  } catch {
    return 1;
  }
};

const isMainModule =
  process.argv[1]?.replaceAll('\\', '/').endsWith('/compatibility/phase-1/harness-result.js') ===
  true;

if (isMainModule) {
  const exitCode = await runPhase1HarnessResultCli();

  if (exitCode !== 0) {
    console.error(diagnostic);
    process.exitCode = exitCode;
  }
}

export const serializePhase1HarnessResultForTesting = (value: unknown): Uint8Array => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return canonicalPhase1ArtifactBytes(value);
};

/* eslint-enable max-lines, complexity, max-params, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
