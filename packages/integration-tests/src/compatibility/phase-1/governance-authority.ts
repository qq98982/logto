/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Exact ordered line validation carries one reviewer identity across the canonical block. */
const diagnostic = 'Invalid Phase 1 governance authority';
const maximumCodeownersBytes = 1024 * 1024;
const githubLoginPattern = /^(?=.{1,39}$)[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/u;

export const phase1CodeownersCoveragePaths = Object.freeze([
  '/packages/integration-tests/src/compatibility/phase-1/',
  '/packages/integration-tests/src/compatibility/normalize.ts',
  '/packages/integration-tests/src/compatibility/compare.ts',
  '/packages/integration-tests/src/compatibility/evidence.ts',
  '/packages/integration-tests/src/compatibility/model.ts',
  '/packages/integration-tests/src/compatibility/scenario.ts',
  '/packages/integration-tests/src/compatibility/config.ts',
  '/packages/integration-tests/src/compatibility/target-client.ts',
  '/packages/integration-tests/src/compatibility/cli.ts',
  '/packages/integration-tests/src/compatibility/scenarios/index.ts',
  '/packages/integration-tests/package.json',
  '/pnpm-lock.yaml',
  '/.scripts/compatibility/',
  '/compatibility/baseline-manifest.json',
  '/compatibility/phase-1-schema-lock.json',
  '/compatibility/phases/phase-1-capabilities.json',
  '/compatibility/phase-1-acceptance/',
  '/docker-compose.compatibility.yml',
  '/docker-compose.phase1-compatibility.yml',
  '/.github/CODEOWNERS',
  '/.github/workflows/',
] as const);

export class Phase1GovernanceAuthorityError extends Error {
  readonly pointer: string;
  readonly rule: string;

  constructor(pointer: string, rule: string) {
    super(diagnostic);
    this.name = 'Phase1GovernanceAuthorityError';
    this.pointer = pointer;
    this.rule = rule;
    this.stack = this.message;
  }
}

const fail = (pointer: string, rule: string): never => {
  throw new Phase1GovernanceAuthorityError(pointer, rule);
};

const requireBytes = (value: unknown, pointer: string): Uint8Array => {
  if (
    !(value instanceof Uint8Array) ||
    value.byteLength === 0 ||
    value.byteLength > maximumCodeownersBytes ||
    (value[0] === 0xef && value[1] === 0xbb && value[2] === 0xbf)
  ) {
    return fail(pointer, 'bytes');
  }

  try {
    new TextDecoder('utf8', { fatal: true }).decode(value);
  } catch {
    return fail(pointer, 'bytes');
  }

  return value;
};

export const assertPhase1CodeownersGovernanceAuthority = (
  phase0Bytes: Uint8Array,
  governanceBytes: Uint8Array,
  expectedReviewer?: string
): string => {
  const base = requireBytes(phase0Bytes, '/phase0');
  const governance = requireBytes(governanceBytes, '/codeowners');

  if (base.at(-1) !== 0x0a) {
    return fail('/phase0', 'final-newline');
  }
  const baseBuffer = Buffer.from(base);
  const governanceBuffer = Buffer.from(governance);

  if (
    governanceBuffer.byteLength <= baseBuffer.byteLength ||
    !governanceBuffer.subarray(0, baseBuffer.byteLength).equals(baseBuffer)
  ) {
    return fail('/codeowners', 'canonical-block');
  }
  const suffix = new TextDecoder('utf8', { fatal: true }).decode(
    governanceBuffer.subarray(baseBuffer.byteLength)
  );
  const lines = suffix.split('\n');

  if (
    lines.length !== phase1CodeownersCoveragePaths.length + 3 ||
    lines[0] !== '' ||
    lines[1] !== '# Aster Phase 1 acceptance authority' ||
    lines.at(-1) !== ''
  ) {
    return fail('/codeowners', 'canonical-block');
  }
  let reviewer = '';
  for (const [index, path] of phase1CodeownersCoveragePaths.entries()) {
    const prefix = `${path} @qq98982 @`;
    const line = lines[index + 2] ?? '';

    if (!line.startsWith(prefix)) {
      return fail('/codeowners', 'canonical-block');
    }
    const candidate = line.slice(prefix.length);

    if (candidate.length === 0 || candidate.includes(' ') || (reviewer && candidate !== reviewer)) {
      return fail('/codeowners', 'canonical-block');
    }
    reviewer = candidate;
  }
  if (
    !githubLoginPattern.test(reviewer) ||
    reviewer.includes('--') ||
    reviewer.toLowerCase() === 'qq98982' ||
    (expectedReviewer !== undefined && expectedReviewer !== reviewer)
  ) {
    return fail('/reviewer', 'github-login');
  }

  return reviewer;
};

/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
