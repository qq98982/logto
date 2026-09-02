import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  protocol: {
    pkce: { available: true, startStatus: 'continued', exchangeStatus: 'succeeded' },
  },
  hosts: [
    { kind: 'connector', availability: 'unavailable', errorClass: 'host-unavailable' },
    { kind: 'saml', availability: 'rejected', errorClass: 'peer-identity-invalid' },
    { kind: 'script', availability: 'rejected', errorClass: 'protocol-version-invalid' },
  ],
  authority: { identityAcceptedFromHost: false, databaseAccess: false, sensitiveAccess: false },
};
const negativeProjection = {
  ...positiveProjection,
  protocol: { pkce: { ...positiveProjection.protocol.pkce, available: false } },
};

export const hostsUnavailablePkceIndependent = defineCandidateInvariant({
  id: 'hosts.unavailable-pkce-independent',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'healthy-password-pkce-core-and-three-compatibility-hosts' },
  perturbation: { kind: 'stop-hosts-then-present-invalid-peer-identity-and-version-responses' },
  expectedPublicOutcome: { pkceAvailable: true, hostFailuresIndependent: true },
  expectedPersistedOutcome: {
    identityAuthorityGrantedToHosts: false,
    hostDatabaseAuthority: false,
  },
  forbiddenOutcome: {
    corePkceOutage: true,
    hostIdentityAuthorityAccepted: true,
    hostSensitiveOrDataAccess: true,
  },
  cleanup: { kind: 'restart-or-destroy-host-fixtures' },
  sanitizedProjection: {
    fields: [
      'protocol.pkce.available',
      'protocol.pkce.startStatus',
      'protocol.pkce.exchangeStatus',
      'hosts.*.kind',
      'hosts.*.availability',
      'hosts.*.errorClass',
      'authority',
    ],
    fixedErrorClassesOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'password PKCE remains available while hosts fail independently',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'host outage takes down password PKCE',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/protocol/pkce/available', value: false },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/protocol/pkce/available',
  },
} satisfies CandidateInvariantContract);

export default hostsUnavailablePkceIndependent;
