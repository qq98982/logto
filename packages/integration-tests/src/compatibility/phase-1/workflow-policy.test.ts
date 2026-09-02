/* eslint-disable no-template-curly-in-string, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-delete, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Each hostile fixture mutates one isolated workflow copy and records literal GitHub expressions. */
import { readFile, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';

import type * as Yaml from 'yaml';

import {
  evaluatePhase1WorkflowPolicy,
  phase1LegacyWorkflowSha256,
  Phase1WorkflowPolicyError,
  parsePhase1WorkflowSource,
  type Phase1WorkflowSource,
} from './workflow-policy.js';

const require = createRequire(import.meta.url);
const yamlPackage = ['ya', 'ml'].join('');
const { parse: parseYaml, stringify: stringifyYaml } = require(yamlPackage) as typeof Yaml;
const encoder = new TextEncoder();
const repositoryRoot = path.resolve(process.cwd(), '../..');
const workflowDirectory = path.join(repositoryRoot, '.github/workflows');
const phase1WorkflowPath = '.github/workflows/phase1-compatibility-test.yml';
const compatibilityWorkflowPath = '.github/workflows/compatibility-test.yml';
const source = (yaml: string, workflowPath = phase1WorkflowPath): Phase1WorkflowSource =>
  Object.freeze({ path: workflowPath, bytes: encoder.encode(yaml) });

type MutableStep = {
  name?: string;
  uses?: string;
  run?: string;
  env?: Record<string, unknown>;
  with?: Record<string, unknown>;
};
type MutableJob = {
  'runs-on'?: unknown;
  'timeout-minutes'?: number;
  permissions?: unknown;
  steps: MutableStep[];
};
type MutableWorkflow = {
  name: string;
  on: Record<string, unknown>;
  permissions: unknown;
  jobs: Record<string, MutableJob>;
};

const readWorkflowSources = async (): Promise<Phase1WorkflowSource[]> => {
  const directoryEntries = await readdir(workflowDirectory);
  const names = directoryEntries.filter((name) => /\.ya?ml$/u.test(name)).toSorted();

  return Promise.all(
    names.map(async (name) =>
      Object.freeze({
        path: `.github/workflows/${name}`,
        bytes: await readFile(path.join(workflowDirectory, name)),
      })
    )
  );
};

const parsedPhase1Workflow = async (): Promise<MutableWorkflow> =>
  parseYaml(
    await readFile(path.join(repositoryRoot, phase1WorkflowPath), 'utf8')
  ) as MutableWorkflow;

const mutatedPhase1Source = async (
  mutate: (workflow: MutableWorkflow) => void
): Promise<Phase1WorkflowSource> => {
  const workflow = await parsedPhase1Workflow();
  mutate(workflow);
  return source(stringifyYaml(workflow));
};

const evaluateMutation = async (mutate: (workflow: MutableWorkflow) => void) => {
  const workflows = await readWorkflowSources();
  const mutated = await mutatedPhase1Source(mutate);
  const values = workflows.map((workflow) =>
    workflow.path === phase1WorkflowPath ? mutated : workflow
  );
  const phase0 = values.find(
    ({ path: workflowPath }) => workflowPath === compatibilityWorkflowPath
  );

  if (!phase0) {
    throw new Error('missing compatibility workflow fixture');
  }
  return evaluatePhase1WorkflowPolicy({
    governanceMode: 'prebootstrap',
    workflows: values,
    phase0CompatibilityWorkflow: phase0,
  });
};

const hardenCompatibilityWorkflow = (yaml: string): string => {
  const workflow = parseYaml(yaml) as MutableWorkflow;
  const pins = new Map([
    ['actions/checkout', '11d5960a326750d5838078e36cf38b85af677262'],
    ['pnpm/action-setup', 'b906affcce14559ad1aafd4ab0e942779e9f58b1'],
    ['actions/setup-node', '49933ea5288caeca8642d1e84afbd3f7d6820020'],
    ['actions/upload-artifact', 'ea165f8d65b6e75b540449e92b4886f43607fa02'],
  ]);

  for (const job of Object.values(workflow.jobs)) {
    for (const step of job.steps) {
      if (step.uses) {
        const [action] = step.uses.split('@');
        const pin = pins.get(action ?? '');
        if (pin) {
          step.uses = `${action}@${pin}`;
        }
      }
      if (step.uses?.startsWith('pnpm/action-setup@')) {
        step.with = { version: '10.15.1' };
      }
      if (step.uses?.startsWith('actions/setup-node@')) {
        step.with = { 'node-version': '22.23.2' };
      }
    }
  }

  return stringifyYaml(workflow);
};

describe('Phase 1 workflow policy', () => {
  it('parses only closed YAML 1.2 workflow documents', () => {
    const parsed = parsePhase1WorkflowSource(
      source('name: safe\non:\n  pull_request: null\npermissions: {}\njobs: {}\n')
    );
    expect(parsed).toMatchObject({ name: 'safe', on: { pull_request: null } });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(
      parsePhase1WorkflowSource(
        source(
          'name: safe\non:\n  pull_request: null\npermissions: {}\njobs: {}\n',
          '.github/workflows/safe.yaml'
        )
      )
    ).toMatchObject({ name: 'safe' });
    expect(() =>
      parsePhase1WorkflowSource(
        source(
          '%YAML 1.1\n---\nname: safe\n"on": { pull_request: null }\npermissions: {}\njobs: {}\n'
        )
      )
    ).toThrow(/^Invalid Phase 1 workflow policy$/u);
  });

  it.each([
    ['byte-order mark', '\uFEFFname: unsafe\n'],
    ['duplicate key', 'name: first\nname: second\n'],
    ['multiple documents', '---\nname: first\n---\nname: second\n'],
    ['alias', 'shared: &shared { contents: read }\npermissions: *shared\n'],
    ['unused anchor', 'permissions: &permissions { contents: read }\n'],
    ['merge key', 'base: &base { contents: read }\npermissions:\n  <<: *base\n'],
    ['custom tag', 'name: !unsafe value\n'],
    ['dangerous key', '__proto__:\n  polluted: true\n'],
    ['non-object root', '- name: unsafe\n'],
  ] as const)('rejects %s without echoing source data', (_name, yaml) => {
    const privateValue = 'private-workflow-value';
    expect(() => parsePhase1WorkflowSource(source(`${yaml}# ${privateValue}\n`))).toThrow(
      Phase1WorkflowPolicyError
    );
    try {
      parsePhase1WorkflowSource(source(`${yaml}# ${privateValue}\n`));
    } catch (error: unknown) {
      expect(error).toMatchObject({ message: 'Invalid Phase 1 workflow policy' });
      expect(String(error)).not.toContain(privateValue);
    }
  });

  it('rejects invalid bytes and unsafe workflow paths', () => {
    const invalidUtf8 = Object.freeze({ path: phase1WorkflowPath, bytes: Uint8Array.from([0xff]) });
    const oversized = source(`name: ${'x'.repeat(1024 * 1024)}\n`);
    for (const input of [
      invalidUtf8,
      oversized,
      source('name: unsafe\n', '.github/workflows/../unsafe.yml'),
      source('name: unsafe\n', '.github/workflows/not-yaml.txt'),
    ]) {
      expect(() => parsePhase1WorkflowSource(input)).toThrow(/^Invalid Phase 1 workflow policy$/u);
    }
  });

  it('records only the exact current tree as prebootstrap without granting governance', async () => {
    const workflows = await readWorkflowSources();
    const phase0 = workflows.find(
      ({ path: workflowPath }) => workflowPath === compatibilityWorkflowPath
    );
    if (!phase0) {
      throw new Error('missing compatibility workflow');
    }
    expect(
      evaluatePhase1WorkflowPolicy({
        governanceMode: 'prebootstrap',
        workflows,
        phase0CompatibilityWorkflow: phase0,
      })
    ).toEqual({
      governanceMode: 'prebootstrap',
      governanceSatisfied: false,
      activeWorkflowPaths: [
        ...Object.keys(phase1LegacyWorkflowSha256),
        phase1WorkflowPath,
      ].toSorted(),
    });
    const mutated = workflows.map((workflow) =>
      workflow.path === '.github/workflows/main.yml'
        ? Object.freeze({ ...workflow, bytes: encoder.encode('name: changed\n') })
        : workflow
    );
    expect(() =>
      evaluatePhase1WorkflowPolicy({
        governanceMode: 'prebootstrap',
        workflows: mutated,
        phase0CompatibilityWorkflow: phase0,
      })
    ).toThrow(/^Invalid Phase 1 workflow policy$/u);
  });

  it('accepts only the normalized seven-change Phase 0 workflow when locked', async () => {
    const workflows = await readWorkflowSources();
    const phase0 = workflows.find(
      ({ path: workflowPath }) => workflowPath === compatibilityWorkflowPath
    );
    const phase1 = workflows.find(({ path: workflowPath }) => workflowPath === phase1WorkflowPath);
    if (!phase0 || !phase1) {
      throw new Error('missing workflow fixture');
    }
    const hardened = source(
      hardenCompatibilityWorkflow(new TextDecoder().decode(phase0.bytes)),
      compatibilityWorkflowPath
    );
    expect(
      evaluatePhase1WorkflowPolicy({
        governanceMode: 'locked',
        workflows: [hardened, phase1],
        phase0CompatibilityWorkflow: phase0,
      })
    ).toEqual({
      governanceMode: 'locked',
      governanceSatisfied: true,
      activeWorkflowPaths: [compatibilityWorkflowPath, phase1WorkflowPath],
    });
    expect(() =>
      evaluatePhase1WorkflowPolicy({
        governanceMode: 'locked',
        workflows: [
          hardened,
          phase1,
          source('name: extra\non: {}\npermissions: {}\njobs: {}\n', '.github/workflows/extra.yml'),
        ],
        phase0CompatibilityWorkflow: phase0,
      })
    ).toThrow(/^Invalid Phase 1 workflow policy$/u);
    const changed = parseYaml(
      hardenCompatibilityWorkflow(new TextDecoder().decode(phase0.bytes))
    ) as MutableWorkflow;
    changed.name = 'Changed compatibility';
    expect(() =>
      evaluatePhase1WorkflowPolicy({
        governanceMode: 'locked',
        workflows: [source(stringifyYaml(changed), compatibilityWorkflowPath), phase1],
        phase0CompatibilityWorkflow: phase0,
      })
    ).toThrow(/^Invalid Phase 1 workflow policy$/u);
    expect(() =>
      evaluatePhase1WorkflowPolicy({
        governanceMode: 'locked',
        workflows: [hardened, phase1],
        phase0CompatibilityWorkflow: Object.freeze({
          ...phase0,
          bytes: encoder.encode('name: forged\n'),
        }),
      })
    ).toThrow(/^Invalid Phase 1 workflow policy$/u);
  });

  it.each([
    [
      'pull_request_target trigger',
      (workflow: MutableWorkflow) => {
        workflow.on.pull_request_target = null;
      },
    ],
    [
      'push trigger',
      (workflow: MutableWorkflow) => {
        workflow.on.push = null;
      },
    ],
    [
      'missing permissions',
      (workflow: MutableWorkflow) => {
        delete workflow.jobs['phase1-pr']!.permissions;
      },
    ],
    [
      'write permission',
      (workflow: MutableWorkflow) => {
        workflow.permissions = { contents: 'write' };
      },
    ],
    [
      'self-hosted runner',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!['runs-on'] = ['self-hosted'];
      },
    ],
    [
      'mutable action',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[0]!.uses = 'actions/checkout@v4';
      },
    ],
    [
      'unknown pinned action',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[0]!.uses = `actions/cache@${'a'.repeat(40)}`;
      },
    ],
    [
      'setup-node cache',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[2]!.with = { 'node-version': '22.23.2', cache: 'pnpm' };
      },
    ],
    [
      'checkout credentials',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[0]!.with!['persist-credentials'] = true;
      },
    ],
    [
      'secret environment',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[3]!.env = { TOKEN: '${{secrets.PRIVATE_TOKEN}}' };
      },
    ],
    [
      'artifact upload',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps.push({
          uses: `actions/upload-artifact@${'a'.repeat(40)}`,
        });
      },
    ],
    [
      'early success',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[3]!.run =
          `exit 0\n${workflow.jobs['phase1-pr']!.steps[3]!.run}`;
      },
    ],
    [
      'ambient command',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[3]!.run +=
          '\npnpm --filter @logto/integration-tests build\n';
      },
    ],
    [
      'missing env-i',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[3]!.run = workflow.jobs[
          'phase1-pr'
        ]!.steps[3]!.run!.replace('env -i \\\n', 'env \\\n');
      },
    ],
    [
      'Playwright path drift',
      (workflow: MutableWorkflow) => {
        workflow.jobs['phase1-pr']!.steps[3]!.run = workflow.jobs[
          'phase1-pr'
        ]!.steps[3]!.run!.replaceAll(
          '$RUNNER_TEMP/aster-playwright',
          '$RUNNER_TEMP/other-playwright'
        );
      },
    ],
  ] as const)('rejects %s', async (_name, mutate) => {
    await expect(evaluateMutation(mutate)).rejects.toThrow(/^Invalid Phase 1 workflow policy$/u);
  });
});

/* eslint-enable no-template-curly-in-string, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-delete, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
