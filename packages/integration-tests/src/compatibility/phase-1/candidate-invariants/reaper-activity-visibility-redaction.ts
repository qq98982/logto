import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  observations: [
    {
      roleClass: 'request',
      backendClass: 'client',
      stateClass: 'in-transaction',
      timingClass: 'overdue',
      terminated: true,
    },
    {
      roleClass: 'worker',
      backendClass: 'client',
      stateClass: 'in-transaction',
      timingClass: 'overdue',
      terminated: true,
    },
  ],
  summary: { eligible: 2, terminated: 2, missed: 0 },
  sentinelMatches: 0,
};
const negativeProjection = {
  ...positiveProjection,
  observations: [
    { ...positiveProjection.observations[0], queryText: 'disallowed-field-present' },
    ...positiveProjection.observations.slice(1),
  ],
};

export const reaperActivityVisibilityRedaction = defineCandidateInvariant({
  id: 'reaper.activity-visibility-redaction',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'overdue-request-and-worker-transactions-with-distinct-sentinels' },
  perturbation: { kind: 'maintainer-invokes-fixed-reaper-wrapper' },
  expectedPublicOutcome: { boundedObservationCount: 2, terminatedCount: 2, sentinelMatches: 0 },
  expectedPersistedOutcome: { overdueBackendsRemaining: 0 },
  forbiddenOutcome: {
    queryTextPresent: true,
    parameterPresent: true,
    tenantDataPresent: true,
    missedTermination: true,
  },
  cleanup: { kind: 'terminate-fixtures-and-destroy-ephemeral-logs' },
  sanitizedProjection: {
    fields: [
      'observations.roleClass',
      'observations.backendClass',
      'observations.stateClass',
      'observations.timingClass',
      'observations.terminated',
      'summary',
      'sentinelMatches',
    ],
    rawPidAbsent: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'reaper output is bounded and redacted',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'query text appears in a reaper observation',
    input: {
      variant: 'negative',
      fault: {
        operation: 'add',
        path: '/observations/0/queryText',
        value: 'disallowed-field-present',
      },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/observations/0/queryText',
  },
} satisfies CandidateInvariantContract);

export default reaperActivityVisibilityRedaction;
