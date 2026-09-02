/* eslint-disable no-await-in-loop, no-use-extend-native/no-use-extend-native, @typescript-eslint/consistent-type-assertions -- Closed hostile fixtures intentionally cast partial profiles and await each rejected runtime case. */
import type { Phase1RunAuthorization, Phase1RunMode } from '../cli.js';
import { hashCanonicalPhase1Json } from '../evidence-envelope.js';
import { candidateInvariantScenarioIds, phase1ObservationKinds } from '../model.js';
import type { Phase1Profile } from '../profile-types.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import { candidateInvariantContracts } from './index.js';
import {
  runPhase1CandidateControlRuntime,
  type Phase1CandidateControlsEvidence,
} from './runtime.js';

const harnessCommit = '1'.repeat(40);
const oracleImageDigest = `sha256:${'2'.repeat(64)}`;

const authorization = (mode: Phase1RunMode): Phase1RunAuthorization => {
  const provenance = Object.freeze(
    mode === 'review-candidate'
      ? { kind: 'review-candidate' as const, harnessCommit, publishable: false as const }
      : {
          kind: 'accepted-harness' as const,
          harnessCommit,
          protectedBranch: 'phase1-acceptance-lock',
          pullRequestNumber: 17,
          publishable: true as const,
        }
  );

  return Object.freeze({
    mode,
    profile: Object.freeze({
      phase1Harness: Object.freeze({ commit: harnessCommit }),
      candidateInvariantScenarios: candidateInvariantScenarioIds,
    }) as unknown as Phase1Profile,
    profileSha256: '3'.repeat(64),
    schemaSha256: '4'.repeat(64),
    provenance,
    protectedExecution:
      mode === 'review-candidate' ? undefined : Object.freeze({ mode, provenance }),
    controls: Object.freeze({
      recordOracle: false,
      observationControls: true,
      discoveryExtraControl: true,
      candidateInvariantControls: true,
    }),
  }) as unknown as Phase1RunAuthorization;
};

const context = (mode: Phase1RunMode = 'mirror-control'): Phase1EvidenceRuntimeContext =>
  ({
    authorization: authorization(mode),
    oracleImageDigest,
    candidateImageDigest:
      mode === 'mirror-control' ? oracleImageDigest : `sha256:${'5'.repeat(64)}`,
    evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
    oracleSnapshotPath: '/var/tmp/henry-build/phase1/oracle-snapshots.json',
    repositoryRoot: '/home/henry/repo/logto',
    conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
    targets: {},
    isolationAttestations: {},
  }) as Phase1EvidenceRuntimeContext;

const expectedObservationPointers = [
  '/value/status',
  '/value/path',
  '/value/sameSite',
  '/value/alg',
  '/value/aud',
  '/value/grants/0/scopes/0',
] as const;

describe('Phase 1 candidate control production runtime', () => {
  it.each(['review-candidate', 'mirror-control'] as const)(
    'emits the exact complete sanitized %s control artifact',
    async (mode) => {
      const result: Phase1CandidateControlsEvidence = await runPhase1CandidateControlRuntime(
        context(mode)
      );

      expect(Object.keys(result)).toEqual([
        'schemaVersion',
        'mode',
        'provenance',
        'sanitizerSuccess',
        'outcomes',
        'observationNegativeControls',
        'discoveryExtraControl',
      ]);
      expect(result).toMatchObject({
        schemaVersion: 1,
        mode,
        provenance: {
          harnessCommit,
          profileSha256: '3'.repeat(64),
          schemaSha256: '4'.repeat(64),
          imageDigest: oracleImageDigest,
        },
        sanitizerSuccess: true,
      });
      expect(result.outcomes.map(({ id }) => id)).toEqual(
        [...candidateInvariantScenarioIds].toSorted()
      );
      expect(result.observationNegativeControls.map(({ kind }) => kind)).toEqual(
        phase1ObservationKinds
      );
      expect(result.observationNegativeControls.map(({ pointer }) => pointer)).toEqual(
        expectedObservationPointers
      );
      expect(result.discoveryExtraControl).toMatchObject({
        pointer: '/value/__unexpected',
        detected: true,
      });
      expect(Object.isFrozen(result)).toBe(true);
    }
  );

  it('retains the verified positive and faulted projections in candidate-only envelopes', async () => {
    const result = await runPhase1CandidateControlRuntime(context());

    for (const outcome of result.outcomes) {
      const contract = candidateInvariantContracts.find(({ id }) => id === outcome.id);

      if (!contract) {
        throw new Error('missing candidate invariant contract');
      }
      expect(outcome.detected).toBe(true);
      expect(outcome.candidate).toMatchObject({ label: 'candidate-only' });
      expect(outcome.candidate.value).toEqual(contract.positiveControl.expectedProjection);
      expect(outcome.positiveControl).toMatchObject({ detected: true });
      expect(outcome.positiveControl.result.value).toEqual(
        contract.positiveControl.expectedProjection
      );
      expect(outcome.negativeControl).toMatchObject({
        detected: true,
        pointer: contract.negativeControl.expectedDifferencePointer,
      });
      expect(outcome.negativeControl.result.value).toEqual(
        contract.negativeControl.expectedProjection
      );
      for (const envelope of [
        outcome.candidate,
        outcome.positiveControl.result,
        outcome.negativeControl.result,
      ]) {
        expect(envelope.projectionSha256).toBe(hashCanonicalPhase1Json(envelope.value));
        expect(JSON.stringify(envelope.value)).not.toMatch(
          /"(?:candidate|oracle|differences|compare|oracleComparison)"\s*:/u
        );
      }
    }
  });

  it('emits hashed detailed observation controls without serializing comparison vocabulary', async () => {
    const result = await runPhase1CandidateControlRuntime(context());
    const envelopes = [
      ...result.observationNegativeControls.map(({ observation }) => observation),
      result.discoveryExtraControl.observation,
    ];

    for (const envelope of envelopes) {
      expect(envelope.projectionSha256).toBe(hashCanonicalPhase1Json(envelope.value));
      expect(Object.hasOwn(envelope.value, 'baseline')).toBe(true);
      expect(Object.hasOwn(envelope.value, 'injected')).toBe(true);
      expect(envelope.value.baseline).not.toBeUndefined();
      expect(envelope.value.injected).not.toBeUndefined();
      expect(JSON.stringify(envelope.value)).not.toMatch(/"(?:candidate|oracle|differences)"\s*:/u);
    }
  });

  it('fails closed for runtime-candidate before fake controls can become runtime evidence', async () => {
    await expect(runPhase1CandidateControlRuntime(context('runtime-candidate'))).rejects.toThrow(
      /^Phase 1 candidate invariant runtime is unavailable$/u
    );
  });

  it('rejects disabled controls and profile registry drift with one fixed diagnostic', async () => {
    const disabled = context();
    const disabledAuthorization = {
      ...disabled.authorization,
      controls: { ...disabled.authorization.controls, discoveryExtraControl: false },
    };
    const drifted = context();
    const driftedAuthorization = {
      ...drifted.authorization,
      profile: {
        ...drifted.authorization.profile,
        candidateInvariantScenarios: candidateInvariantScenarioIds.slice(1),
      } as Phase1Profile,
    };

    for (const invalid of [
      { ...disabled, authorization: disabledAuthorization },
      { ...drifted, authorization: driftedAuthorization },
    ]) {
      await expect(
        runPhase1CandidateControlRuntime(invalid as Phase1EvidenceRuntimeContext)
      ).rejects.toThrow(/^Invalid phase 1 candidate control runtime$/u);
    }
  });
});

/* eslint-enable no-await-in-loop, no-use-extend-native/no-use-extend-native, @typescript-eslint/consistent-type-assertions */
