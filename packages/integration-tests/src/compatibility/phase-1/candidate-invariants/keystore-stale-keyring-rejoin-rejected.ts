import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  replica: {
    loadedGeneration: 1,
    minimumGeneration: 2,
    loadedSetFingerprint: 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    allowedSetFingerprint:
      'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    requiredSetFingerprint:
      'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    preReload: {
      heartbeat: 'rejected',
      readiness: 'not-ready',
      reasonClass: 'stale-generation',
    },
    postReload: {
      loadedGeneration: 2,
      heartbeat: 'accepted',
      readiness: 'ready',
      reasonClass: 'current-generation',
    },
    heartbeat: 'rejected',
    readiness: 'not-ready',
    reasonClass: 'stale-generation',
    fullReloadRequired: true,
    writerResumed: false,
    tombstonedIdAccepted: false,
    nonLiveIdAccepted: false,
  },
};
const negativeProjection = {
  replica: { ...positiveProjection.replica, readiness: 'ready' },
};

export const keystoreStaleKeyringRejoinRejected = defineCandidateInvariant({
  id: 'keystore.stale-keyring-rejoin-rejected',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'partitioned-replica-with-old-generation-and-key-set' },
  perturbation: { kind: 'restore-replica-after-promotion-removal-and-tombstone' },
  expectedPublicOutcome: { heartbeat: 'rejected', readiness: 'not-ready', writerResumed: false },
  expectedPersistedOutcome: { minimumGeneration: 2, staleLeaseRenewed: false },
  forbiddenOutcome: {
    staleReady: true,
    oldGenerationHeartbeatAccepted: true,
    tombstonedOrNonLiveIdAccepted: true,
  },
  cleanup: { kind: 'reload-replica-or-remove-lease' },
  sanitizedProjection: {
    fields: [
      'replica.loadedGeneration',
      'replica.minimumGeneration',
      'replica.loadedSetFingerprint',
      'replica.allowedSetFingerprint',
      'replica.requiredSetFingerprint',
      'replica.preReload',
      'replica.postReload',
      'replica.heartbeat',
      'replica.readiness',
      'replica.reasonClass',
      'replica.fullReloadRequired',
      'replica.writerResumed',
      'replica.tombstonedIdAccepted',
      'replica.nonLiveIdAccepted',
    ],
    setValuesFingerprintOnly: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'stale keyring replica remains unready',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'stale replica reports ready',
    input: {
      variant: 'negative',
      fault: { operation: 'replace', path: '/replica/readiness', value: 'ready' },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/replica/readiness',
  },
} satisfies CandidateInvariantContract);

export default keystoreStaleKeyringRejoinRejected;
