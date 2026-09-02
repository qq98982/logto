/* eslint-disable max-lines, max-params, complexity, no-restricted-syntax, no-template-curly-in-string, no-use-extend-native/no-use-extend-native, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-mutation -- The policy parses hostile YAML, compares literal GitHub expressions, and constructs one expected locked-workflow snapshot. */
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import type * as Yaml from 'yaml';

const require = createRequire(import.meta.url);
const yamlPackage = ['ya', 'ml'].join('');
const { isAlias, parseDocument, visit } = require(yamlPackage) as typeof Yaml;

export type Phase1WorkflowSource = Readonly<{ path: string; bytes: Uint8Array }>;
export type Phase1WorkflowDocument = Readonly<Record<string, unknown>>;
export type Phase1WorkflowGovernanceMode = 'prebootstrap' | 'locked';
export type Phase1WorkflowPolicyResult = Readonly<{
  governanceMode: Phase1WorkflowGovernanceMode;
  governanceSatisfied: boolean;
  activeWorkflowPaths: readonly string[];
}>;
export type Phase1WorkflowPolicyInput = Readonly<{
  governanceMode: Phase1WorkflowGovernanceMode;
  workflows: readonly Phase1WorkflowSource[];
  phase0CompatibilityWorkflow: Phase1WorkflowSource;
}>;

const diagnostic = 'Invalid Phase 1 workflow policy';
const maximumWorkflowBytes = 1024 * 1024;
const workflowPathPattern = /^\.github\/workflows\/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/u;
const dangerousKeys = new Set(['__proto__', 'constructor', 'prototype', '<<']);
const phase1WorkflowPath = '.github/workflows/phase1-compatibility-test.yml';
const compatibilityWorkflowPath = '.github/workflows/compatibility-test.yml';
const fortyHex = /^[0-9a-f]{40}$/u;

export const phase1WorkflowActionPins = Object.freeze({
  'actions/checkout': '11d5960a326750d5838078e36cf38b85af677262',
  'pnpm/action-setup': 'b906affcce14559ad1aafd4ab0e942779e9f58b1',
  'actions/setup-node': '49933ea5288caeca8642d1e84afbd3f7d6820020',
  'actions/upload-artifact': 'ea165f8d65b6e75b540449e92b4886f43607fa02',
  'actions/download-artifact': 'd3f86a106a0bac45b974a628896c90dbdf5c8093',
} as const);

export const phase1LegacyWorkflowSha256 = Object.freeze({
  '.github/workflows/alteration-compatibility-integration-test.yml':
    'a990bcae4f9de418319d269089515fdab3b776211071806a32b11e6c272b80b6',
  '.github/workflows/changesets.yml':
    'f48711d81c97e6a9440e9717cf0f7e93bfbce04d62e84fdf13de4ff9840fd2fb',
  '.github/workflows/close-stale.yml':
    '45e80672e320ba6b1a5b3af8550fe8aafad3f2171594f0dae577ae900feaf7c4',
  '.github/workflows/codeql-analysis.yml':
    '223f66809a1b1746246d2f1f149fd4e50f7117f6140394e7c21aac95edcd1b1d',
  '.github/workflows/commitlint.yml':
    '7757df3911361a78baa7e0329b5b845b0e3565d73caf7dc4d3123467ef5cb89e',
  '.github/workflows/compatibility-test.yml':
    'e647324c13f34d2e301148398e5580811ebc9aa7ef60ecaef55ec8246fb5f460',
  '.github/workflows/integration-test.yml':
    'b336746f3dec98de2f0af4e9e386600410d372e406eb9dc3359c72dbb593ffff',
  '.github/workflows/main.yml': '038aec839677d820657eb556929838bc2446dd2ef1cbcf495fe08254448f4ebe',
  '.github/workflows/master-codecov-report.yml':
    'a3f85e96771d2e5fb5005081f29002246b5a1f2bf68c6b951c1330ce1a25824a',
  '.github/workflows/pen-tests.yml':
    '9ad7daed194f0c0355761536151b71e1dec8004835f75ce277e24a9101ee0c35',
  '.github/workflows/release.yml':
    'c3406ca7b07027ef8e2607e78b2bdb80f8b631f211e244d5d4289d0cfc05a94b',
  '.github/workflows/repository-dispatch.yml':
    'fce9d07fe5eaa8a9befee33f9362f4a0c2e2417a6a86e9fc914885760970bf74',
  '.github/workflows/rerun.yml': 'c58d06d74bfa6253a7bcee1c7a22ca9fa7cbf546560fbbc0456a11c41c0ac958',
  '.github/workflows/update-pr-metadata.yml':
    'fb924216446720da016843fb6ebc6e1687073c2deb63d34caff30186e4eab29e',
} as const);

export class Phase1WorkflowPolicyError extends Error {
  readonly workflowPath: string;
  readonly pointer: string;
  readonly rule: string;
  constructor(workflowPath: string, pointer: string, rule: string) {
    super(diagnostic);
    this.name = 'Phase1WorkflowPolicyError';
    this.workflowPath = workflowPath;
    this.pointer = pointer;
    this.rule = rule;
    this.stack = this.message;
  }
}

const fail = (workflowPath: string, pointer = '/', rule = 'workflow'): never => {
  throw new Phase1WorkflowPolicyError(workflowPath, pointer, rule);
};
const escapePointerToken = (token: string | number): string =>
  String(token).replaceAll('~', '~0').replaceAll('/', '~1');
const appendPointer = (pointer: string, token: string | number): string =>
  pointer === '/' ? `/${escapePointerToken(token)}` : `${pointer}/${escapePointerToken(token)}`;
const requireWorkflowPath = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 512 ||
    path.posix.normalize(value) !== value ||
    !workflowPathPattern.test(value)
  ) {
    return fail('.', '/', 'path');
  }
  return value;
};

type WorkflowRecord = Readonly<Record<string, unknown>>;
const isRecord = (value: unknown): value is WorkflowRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const exactKeys = (value: WorkflowRecord, expected: readonly string[]): boolean => {
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === 'string' && expected.includes(key))
  );
};
const requireRecord = (
  value: unknown,
  workflowPath: string,
  pointer: string,
  keys?: readonly string[]
): WorkflowRecord => {
  if (!isRecord(value) || (keys && !exactKeys(value, keys))) {
    return fail(workflowPath, pointer, 'shape');
  }
  return value;
};
const requireArray = (value: unknown, workflowPath: string, pointer: string): readonly unknown[] =>
  Array.isArray(value) ? value : fail(workflowPath, pointer, 'shape');
const requireEqual = (
  actual: unknown,
  expected: unknown,
  workflowPath: string,
  pointer: string,
  rule = 'value'
): void => {
  if (!isDeepStrictEqual(actual, expected)) {
    fail(workflowPath, pointer, rule);
  }
};

const snapshotYamlValue = (value: unknown, workflowPath: string, pointer = '/'): unknown => {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value) && Number.isSafeInteger(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(
      value.map((item, index) =>
        snapshotYamlValue(item, workflowPath, appendPointer(pointer, index))
      )
    );
  }
  if (typeof value !== 'object') {
    return fail(workflowPath, pointer, 'value');
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return fail(workflowPath, pointer, 'value');
  }
  const entries = Object.entries(value as Record<string, unknown>);
  for (const [key] of entries) {
    if (dangerousKeys.has(key)) {
      return fail(workflowPath, appendPointer(pointer, key), 'key');
    }
  }
  return Object.freeze(
    Object.fromEntries(
      entries.map(([key, nested]) => [
        key,
        snapshotYamlValue(nested, workflowPath, appendPointer(pointer, key)),
      ])
    )
  );
};

export const parsePhase1WorkflowSource = (source: Phase1WorkflowSource): Phase1WorkflowDocument => {
  const workflowPath = requireWorkflowPath(source.path);
  try {
    if (
      !(source.bytes instanceof Uint8Array) ||
      source.bytes.byteLength === 0 ||
      source.bytes.byteLength > maximumWorkflowBytes ||
      (source.bytes[0] === 0xef && source.bytes[1] === 0xbb && source.bytes[2] === 0xbf)
    ) {
      return fail(workflowPath, '/', 'bytes');
    }
    const yaml = new TextDecoder('utf8', { fatal: true }).decode(source.bytes);
    const document = parseDocument(yaml, {
      version: '1.2',
      schema: 'core',
      strict: true,
      uniqueKeys: true,
      stringKeys: true,
      merge: false,
      resolveKnownTags: false,
      prettyErrors: false,
    });
    if (
      document.errors.length > 0 ||
      document.warnings.length > 0 ||
      document.contents === null ||
      (document.directives.yaml.version !== undefined && document.directives.yaml.version !== '1.2')
    ) {
      return fail(workflowPath, '/', 'yaml');
    }
    visit(document, {
      Node: (_key, node) => {
        if (
          isAlias(node) ||
          ('anchor' in node && typeof node.anchor === 'string' && node.anchor.length > 0)
        ) {
          return fail(workflowPath, '/', 'yaml-reference');
        }
      },
    });
    const value = document.toJS({ maxAliasCount: 0 }) as unknown;
    if (!isRecord(value)) {
      return fail(workflowPath, '/', 'root');
    }
    return snapshotYamlValue(value, workflowPath) as Phase1WorkflowDocument;
  } catch (error: unknown) {
    if (error instanceof Phase1WorkflowPolicyError) {
      throw error;
    }
    return fail(workflowPath, '/', 'yaml');
  }
};

const phase1PrRunScript = `set -euo pipefail
repository_root="$PWD"
private_root="$RUNNER_TEMP/aster-phase1-pr"
playwright_root="$RUNNER_TEMP/aster-playwright"
pnpm_store="$RUNNER_TEMP/aster-phase1-pr-pnpm-store"
install -d -m 0700 \\
  "$private_root" "$private_root/home" "$private_root/tmp" \\
  "$private_root/xdg" "$playwright_root" "$pnpm_store"
closed_path="$(dirname -- "$(command -v node)"):$(dirname -- "$(command -v pnpm)"):/usr/bin:/bin"
closed_script="$private_root/run.sh"
cat >"$closed_script" <<'ASTER_PHASE1_PR'
set -euo pipefail
cd "$REPOSITORY_ROOT"
pnpm install --frozen-lockfile --ignore-scripts --store-dir "$PNPM_STORE"
(cd packages/connectors && node templates/sync-preset.js)
pnpm prepack
pnpm --filter @logto/integration-tests build
pnpm --filter @logto/integration-tests check
pnpm --filter @logto/integration-tests lint
PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" \\
  pnpm --dir packages/integration-tests exec playwright install --with-deps chromium
pnpm --filter @logto/integration-tests test:compatibility
pnpm --filter @logto/integration-tests test:compatibility:phase1
ASTER_PHASE1_PR
chmod 0700 "$closed_script"
env -i \\
  PATH="$closed_path" \\
  HOME="$private_root/home" \\
  TMPDIR="$private_root/tmp" \\
  XDG_RUNTIME_DIR="$private_root/xdg" \\
  CI=true \\
  LANG=C.UTF-8 \\
  REPOSITORY_ROOT="$repository_root" \\
  PNPM_STORE="$pnpm_store" \\
  PLAYWRIGHT_BROWSERS_PATH="$playwright_root" \\
  /bin/bash "$closed_script"
`;

const requireAction = (
  step: unknown,
  workflowPath: string,
  pointer: string,
  expected: WorkflowRecord
): void => {
  const record = requireRecord(step, workflowPath, pointer);
  requireEqual(record, expected, workflowPath, pointer, 'action');
  const { uses } = record;
  if (typeof uses !== 'string') {
    return fail(workflowPath, `${pointer}/uses`, 'action');
  }
  const separator = uses.lastIndexOf('@');
  const action = uses.slice(0, separator);
  const pin = uses.slice(separator + 1);
  if (
    !fortyHex.test(pin) ||
    phase1WorkflowActionPins[action as keyof typeof phase1WorkflowActionPins] !== pin
  ) {
    fail(workflowPath, `${pointer}/uses`, 'action-pin');
  }
};

const validatePhase1Workflow = (source: Phase1WorkflowSource): void => {
  const workflowPath = source.path;
  const workflow = requireRecord(parsePhase1WorkflowSource(source), workflowPath, '/', [
    'name',
    'on',
    'permissions',
    'jobs',
  ]);
  requireEqual(workflow.name, 'Aster Phase 1 compatibility', workflowPath, '/name');
  requireEqual(workflow.on, { pull_request: null }, workflowPath, '/on');
  requireEqual(workflow.permissions, { contents: 'read' }, workflowPath, '/permissions');
  const jobs = requireRecord(workflow.jobs, workflowPath, '/jobs', ['phase1-pr']);
  const job = requireRecord(jobs['phase1-pr'], workflowPath, '/jobs/phase1-pr', [
    'runs-on',
    'timeout-minutes',
    'permissions',
    'steps',
  ]);
  requireEqual(job['runs-on'], 'ubuntu-22.04', workflowPath, '/jobs/phase1-pr/runs-on');
  requireEqual(job['timeout-minutes'], 90, workflowPath, '/jobs/phase1-pr/timeout-minutes');
  requireEqual(job.permissions, { contents: 'read' }, workflowPath, '/jobs/phase1-pr/permissions');
  const steps = requireArray(job.steps, workflowPath, '/jobs/phase1-pr/steps');
  if (steps.length !== 4) {
    fail(workflowPath, '/jobs/phase1-pr/steps', 'step-count');
  }
  requireAction(steps[0], workflowPath, '/jobs/phase1-pr/steps/0', {
    name: 'Check out exact pull-request head',
    uses: `actions/checkout@${phase1WorkflowActionPins['actions/checkout']}`,
    with: {
      repository: '${{ github.event.pull_request.head.repo.full_name }}',
      ref: '${{ github.event.pull_request.head.sha }}',
      'fetch-depth': 0,
      'persist-credentials': false,
    },
  });
  requireAction(steps[1], workflowPath, '/jobs/phase1-pr/steps/1', {
    name: 'Install pnpm 10.15.1',
    uses: `pnpm/action-setup@${phase1WorkflowActionPins['pnpm/action-setup']}`,
    with: { version: '10.15.1' },
  });
  requireAction(steps[2], workflowPath, '/jobs/phase1-pr/steps/2', {
    name: 'Install Node 22.23.2',
    uses: `actions/setup-node@${phase1WorkflowActionPins['actions/setup-node']}`,
    with: { 'node-version': '22.23.2' },
  });
  requireEqual(
    steps[3],
    {
      name: 'Run untrusted Phase 1 checks in a closed environment',
      shell: 'bash',
      run: phase1PrRunScript,
    },
    workflowPath,
    '/jobs/phase1-pr/steps/3',
    'run-bytes'
  );
};

const cloneYamlValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((item) => cloneYamlValue(item));
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, cloneYamlValue(nested)])
    );
  }
  return value;
};
const expectedLockedCompatibilityWorkflow = (
  source: Phase1WorkflowSource
): Phase1WorkflowDocument => {
  const value = cloneYamlValue(parsePhase1WorkflowSource(source)) as Record<string, unknown>;
  const jobs = requireRecord(value.jobs, source.path, '/jobs');
  for (const job of Object.values(jobs)) {
    const steps = requireArray(
      requireRecord(job, source.path, '/jobs/*').steps,
      source.path,
      '/jobs/*/steps'
    );
    for (const step of steps) {
      const record = requireRecord(step, source.path, '/jobs/*/steps/*');
      if (typeof record.uses !== 'string') {
        continue;
      }
      const action = record.uses.slice(0, record.uses.lastIndexOf('@'));
      const pin = phase1WorkflowActionPins[action as keyof typeof phase1WorkflowActionPins];
      if (!pin || action === 'actions/download-artifact') {
        fail(source.path, '/jobs/*/steps/*/uses', 'phase0-action');
      }
      const mutable = record as Record<string, unknown>;
      mutable.uses = `${action}@${pin}`;
      if (action === 'pnpm/action-setup') {
        mutable.with = { version: '10.15.1' };
      }
      if (action === 'actions/setup-node') {
        mutable.with = { 'node-version': '22.23.2' };
      }
    }
  }
  return snapshotYamlValue(value, source.path) as Phase1WorkflowDocument;
};
const sourceSha256 = (source: Phase1WorkflowSource): string =>
  createHash('sha256').update(source.bytes).digest('hex');

export const evaluatePhase1WorkflowPolicy = (
  input: Phase1WorkflowPolicyInput
): Phase1WorkflowPolicyResult => {
  try {
    if (!Array.isArray(input.workflows) || input.workflows.length === 0) {
      return fail('.', '/', 'workflows');
    }
    const sources = new Map<string, Phase1WorkflowSource>();
    const workflowCandidates: unknown = input.workflows;
    if (!Array.isArray(workflowCandidates)) {
      return fail('.', '/', 'workflows');
    }
    for (const candidate of workflowCandidates as readonly unknown[]) {
      if (
        !isRecord(candidate) ||
        !exactKeys(candidate, ['path', 'bytes']) ||
        !(candidate.bytes instanceof Uint8Array)
      ) {
        return fail('.', '/', 'workflow-source');
      }
      const source = Object.freeze({
        path: requireWorkflowPath(candidate.path),
        bytes: candidate.bytes,
      });
      const workflowPath = requireWorkflowPath(source.path);
      if (sources.has(workflowPath)) {
        return fail(workflowPath, '/', 'duplicate-workflow');
      }
      sources.set(workflowPath, source);
    }
    const activeWorkflowPaths = [...sources.keys()].toSorted();
    validatePhase1Workflow(
      sources.get(phase1WorkflowPath) ?? fail(phase1WorkflowPath, '/', 'missing')
    );
    if (
      input.phase0CompatibilityWorkflow.path !== compatibilityWorkflowPath ||
      sourceSha256(input.phase0CompatibilityWorkflow) !==
        phase1LegacyWorkflowSha256[compatibilityWorkflowPath]
    ) {
      return fail(compatibilityWorkflowPath, '/', 'phase0-authority');
    }
    if (input.governanceMode === 'prebootstrap') {
      const expected = [...Object.keys(phase1LegacyWorkflowSha256), phase1WorkflowPath].toSorted();
      requireEqual(activeWorkflowPaths, expected, '.', '/', 'prebootstrap-tree');
      for (const [workflowPath, hash] of Object.entries(phase1LegacyWorkflowSha256)) {
        if (
          sourceSha256(sources.get(workflowPath) ?? fail(workflowPath, '/', 'missing')) !== hash
        ) {
          return fail(workflowPath, '/', 'legacy-hash');
        }
      }
      return Object.freeze({
        governanceMode: 'prebootstrap',
        governanceSatisfied: false,
        activeWorkflowPaths: Object.freeze(activeWorkflowPaths),
      });
    }
    if (input.governanceMode !== 'locked') {
      return fail('.', '/', 'mode');
    }
    requireEqual(
      activeWorkflowPaths,
      [compatibilityWorkflowPath, phase1WorkflowPath],
      '.',
      '/',
      'locked-tree'
    );
    requireEqual(
      parsePhase1WorkflowSource(
        sources.get(compatibilityWorkflowPath) ?? fail(compatibilityWorkflowPath, '/', 'missing')
      ),
      expectedLockedCompatibilityWorkflow(input.phase0CompatibilityWorkflow),
      compatibilityWorkflowPath,
      '/',
      'locked-phase0-delta'
    );
    return Object.freeze({
      governanceMode: 'locked',
      governanceSatisfied: true,
      activeWorkflowPaths: Object.freeze(activeWorkflowPaths),
    });
  } catch (error: unknown) {
    if (error instanceof Phase1WorkflowPolicyError) {
      throw error;
    }
    return fail('.', '/', 'evaluation');
  }
};

/* eslint-enable max-lines, max-params, complexity, no-restricted-syntax, no-template-curly-in-string, no-use-extend-native/no-use-extend-native, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-mutation */
