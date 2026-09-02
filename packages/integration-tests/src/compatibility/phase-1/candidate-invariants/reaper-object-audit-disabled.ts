import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  settings: {
    logStatement: 'none',
    minimumErrorStatement: 'panic',
    logDuration: false,
    minimumDuration: 'disabled',
    minimumSampleDuration: 'disabled',
    statementSampleRate: 0,
    parameterLogging: false,
    parameterMaximumLength: 0,
    errorParameterMaximumLength: 0,
    autoExplain: { minimumDuration: 'disabled', parameterMaximumLength: 0 },
    pgauditLog: 'none',
    pgauditStatement: false,
    pgauditParameter: false,
    pgauditRole: 'empty',
    objectAudit: { membershipClosure: 'clear', reachableAsterRelations: 0 },
    managedAuditPolicy: {
      requestWorkerRolesExcluded: true,
      statementCapture: false,
      parameterCapture: false,
    },
  },
  artifacts: [
    {
      sink: 'postgres',
      sha256: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      matches: [],
    },
    {
      sink: 'managed-export',
      sha256: 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      matches: [],
    },
    {
      sink: 'application',
      sha256: 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      matches: [],
    },
  ],
  allClear: true,
};
const negativeProjection = {
  ...positiveProjection,
  artifacts: [
    { ...positiveProjection.artifacts[0], matches: ['sentinel-detected'] },
    ...positiveProjection.artifacts.slice(1),
  ],
};

export const reaperObjectAuditDisabled = defineCandidateInvariant({
  id: 'reaper.object-audit-disabled',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'designed-request-worker-log-and-audit-settings-active' },
  perturbation: { kind: 'execute-and-terminate-sentinel-transactions-across-all-sinks' },
  expectedPublicOutcome: { allClear: true, artifactCount: 3 },
  expectedPersistedOutcome: positiveProjection.settings,
  forbiddenOutcome: { sentinelMatch: true, rawStatementPresent: true, rawParameterPresent: true },
  cleanup: { kind: 'destroy-per-run-log-volume' },
  sanitizedProjection: {
    fields: ['settings', 'artifacts.sink', 'artifacts.sha256', 'artifacts.matches', 'allClear'],
    matchedTextAbsent: true,
    safeSettingCategoriesOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'no sentinel appears in any complete log artifact',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'a log sink reports a sentinel match',
    input: {
      variant: 'negative',
      fault: { operation: 'add', path: '/artifacts/0/matches/0', value: 'sentinel-detected' },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/artifacts/0/matches/0',
  },
} satisfies CandidateInvariantContract);

export default reaperObjectAuditDisabled;
