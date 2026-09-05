/* eslint-disable complexity -- Strict JSON parsing and recursive public-artifact screening are one closed boundary. */
import { createHash } from 'node:crypto';

import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import { assertEvidenceIsSanitized } from '../evidence.js';
import { jsonValueGuard } from '../model.js';

import { snapshotClosedDataGraph } from './model.js';
import { phase1ScenarioContracts, phase1ScenarioStepIds } from './scenario-contracts.js';

export const phase1ArtifactMaximumBytes = 1024 * 1024;
export const phase1EvidenceFileNames = Object.freeze([
  'phase-1-browser.json',
  'phase-1-candidate-invariants.json',
  'phase-1-conformance.json',
  'phase-1-differential.json',
] as const);
export const phase1EvidenceManifestName = 'evidence-manifest.json';
export const phase1HarnessResultName = 'harness-result.json';
export const phase1ArtifactModes = Object.freeze([
  'review-candidate',
  'mirror-control',
  'runtime-candidate',
] as const);

export type Phase1ArtifactMode = (typeof phase1ArtifactModes)[number];
export type Phase1EvidenceFileName = (typeof phase1EvidenceFileNames)[number];

const forbiddenPropertyFragments = Object.freeze([
  'apikey',
  'approvingreviewer',
  'credential',
  'githubtoken',
  'privatekey',
  'privateprovenance',
  'pullrequest',
  'reviewer',
  'ruleset',
] as const);
const permittedSensitiveMetadataKeys = new Set(['haspassword', 'passwordalgorithm']);
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const logicalResumeCredentialPattern = /^<redirect\.resume-credential\.[1-9]\d*>$/u;
const denseArrayIndexPattern = /^(?:0|[1-9]\d*)$/u;
const resumeCredentialStepIdsByScenario = new Map<string, ReadonlySet<string>>(
  phase1ScenarioContracts
    .map(
      ({ id, normalizablePointers }) =>
        [
          id,
          new Set(
            normalizablePointers.flatMap((pointer) => {
              const match = /^\/steps\/([^/]+)\/value\/redirect\/resumeCredential$/u.exec(pointer);

              return match?.[1] ? [match[1]] : [];
            })
          ),
        ] as const
    )
    .filter(([, stepIds]) => stepIds.size > 0)
);

export const bytewiseCompare = (left: string, right: string): number =>
  Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));

export const hashPhase1ArtifactBytes = (bytes: Uint8Array): string =>
  createHash('sha256').update(bytes).digest('hex');

export const exactArtifactKeys = (
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[]
): boolean => {
  const keys = Reflect.ownKeys(value);

  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === 'string' && expected.includes(key))
  );
};

export const isArtifactRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const inspectJsonNode = (node: JsonNode | undefined): void => {
  if (!node) {
    throw new TypeError('invalid JSON node');
  }
  if (node.type === 'object') {
    const keys = new Set<string>();

    for (const property of node.children ?? []) {
      const [keyNode, valueNode] = property.children ?? [];
      const key: unknown = keyNode?.value;

      if (typeof key !== 'string' || keys.has(key)) {
        throw new TypeError('invalid JSON property');
      }
      keys.add(key);
      inspectJsonNode(valueNode);
    }
  } else if (node.type === 'array') {
    for (const child of node.children ?? []) {
      inspectJsonNode(child);
    }
  }
};

export const parseStrictPhase1ArtifactJson = (bytes: Uint8Array): unknown => {
  if (bytes.byteLength < 1 || bytes.byteLength > phase1ArtifactMaximumBytes) {
    throw new TypeError('invalid artifact bytes');
  }
  const source = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  const errors: ParseError[] = [];
  const root = parseTree(source, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });

  if (!root || errors.length > 0) {
    throw new TypeError('invalid artifact JSON');
  }
  inspectJsonNode(root);
  const value: unknown = JSON.parse(source);
  const snapshot = snapshotClosedDataGraph<unknown>(value);

  if (snapshot === undefined || !jsonValueGuard.safeParse(snapshot).success) {
    throw new TypeError('invalid artifact graph');
  }

  return snapshot;
};

const normalizedKey = (key: string): string => key.replaceAll(/[_\s-]/gu, '').toLowerCase();

const containsPrivateJwk = (value: Readonly<Record<string, unknown>>): boolean =>
  typeof value.kty === 'string' &&
  Object.keys(value).some((member) => privateJwkMembers.has(member));

export const assertPhase1PublicArtifactValue = (value: unknown): void => {
  const visit = (candidate: unknown, path: readonly string[] = [], scenarioId?: string): void => {
    if (typeof candidate === 'string') {
      assertEvidenceIsSanitized({ value: candidate });
      return;
    }
    if (Array.isArray(candidate)) {
      for (const [index, item] of candidate.entries()) {
        visit(item, [...path, String(index)], scenarioId);
      }
      return;
    }
    if (!isArtifactRecord(candidate)) {
      return;
    }
    if (containsPrivateJwk(candidate)) {
      throw new TypeError('private JWK');
    }
    const ownedScenarioId =
      path.length === 2 &&
      path[0] === 'scenarios' &&
      typeof path[1] === 'string' &&
      denseArrayIndexPattern.test(path[1]) &&
      typeof candidate.id === 'string' &&
      resumeCredentialStepIdsByScenario.has(candidate.id)
        ? candidate.id
        : scenarioId;

    for (const [key, nested] of Object.entries(candidate)) {
      const normalized = normalizedKey(key);
      const parentKey = path.at(-1);
      const registeredScenarioStep =
        parentKey === 'steps' &&
        phase1ScenarioStepIds.includes(key) &&
        isArtifactRecord(nested) &&
        exactArtifactKeys(nested, ['value']);
      const resumeStepId = path[5];
      const isCanonicalRedirectCredential = path.length === 8 && parentKey === 'redirect';
      const isBodyRedirectMirrorCredential =
        path.length === 9 && path[7] === 'body' && parentKey === 'redirectTo';
      const allowedResumeCredential =
        key === 'resumeCredential' &&
        (isCanonicalRedirectCredential || isBodyRedirectMirrorCredential) &&
        path[0] === 'scenarios' &&
        typeof path[1] === 'string' &&
        denseArrayIndexPattern.test(path[1]) &&
        (path[2] === 'oracle' || path[2] === 'candidate') &&
        path[3] === 'value' &&
        path[4] === 'steps' &&
        typeof resumeStepId === 'string' &&
        path[6] === 'value' &&
        typeof ownedScenarioId === 'string' &&
        resumeCredentialStepIdsByScenario.get(ownedScenarioId)?.has(resumeStepId) === true &&
        typeof nested === 'string' &&
        logicalResumeCredentialPattern.test(nested);

      if (
        !allowedResumeCredential &&
        ((!registeredScenarioStep &&
          !permittedSensitiveMetadataKeys.has(normalized) &&
          (normalized.includes('secret') || normalized.includes('password'))) ||
          forbiddenPropertyFragments.some((fragment) => normalized.includes(fragment)) ||
          normalized === 'pr' ||
          normalized.includes('branchprotection'))
      ) {
        throw new TypeError('private artifact property');
      }
      assertEvidenceIsSanitized({ value: allowedResumeCredential ? 'metadata' : key });
      visit(nested, [...path, key], ownedScenarioId);
    }
  };

  if (!jsonValueGuard.safeParse(value).success) {
    throw new TypeError('invalid public artifact');
  }
  visit(value);
};

export const canonicalPhase1ArtifactBytes = (value: unknown): Uint8Array => {
  const snapshot = snapshotClosedDataGraph<unknown>(value);

  if (snapshot === undefined || !jsonValueGuard.safeParse(snapshot).success) {
    throw new TypeError('invalid artifact value');
  }

  const serialize = (candidate: unknown): string => {
    if (Array.isArray(candidate)) {
      return `[${candidate.map((item) => serialize(item)).join(',')}]`;
    }
    if (typeof candidate === 'object' && candidate !== null) {
      return `{${Object.keys(candidate)
        .map((key) => {
          const descriptor = Object.getOwnPropertyDescriptor(candidate, key);

          if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
            throw new TypeError('invalid artifact value');
          }

          return `${serialize(key)}:${serialize(descriptor.value)}`;
        })
        .join(',')}}`;
    }
    const serialized = JSON.stringify(candidate);

    if (typeof serialized !== 'string') {
      throw new TypeError('invalid artifact value');
    }

    return serialized;
  };

  return Buffer.from(`${serialize(snapshot)}\n`, 'utf8');
};

/* eslint-enable complexity */
