import { assertBrowserSemantics } from './profile-semantics/browser.js';
import { assertConformanceSemantics } from './profile-semantics/conformance.js';
import { assertFixtureSemantics } from './profile-semantics/fixtures.js';
import { assertKeyedArraySemantics } from './profile-semantics/keyed-arrays.js';
import { assertNativeSurfaceSemantics } from './profile-semantics/native-surface.js';
import { assertOperationSemantics } from './profile-semantics/operations.js';
import {
  verifyPhase1ProfileProvenance as verifyDefaultPhase1ProfileProvenance,
  type Phase1ProvenanceContext,
  type Phase1ProvenanceResult,
} from './profile-semantics/provenance.js';
import type { Phase1Profile, Phase1ProfileSemanticContext } from './profile-types.js';

export {
  authorizePhase1ProtectedExecution,
  requireAcceptedPhase1Provenance,
} from './profile-semantics/provenance.js';
export { assertConformanceExecution } from './profile-semantics/conformance.js';
export type { Phase1ConformanceExecution } from './profile-semantics/conformance.js';
export type {
  Phase0EvidenceFileName,
  Phase0EvidenceReproducer,
  Phase0EvidenceReproduction,
  Phase0EvidenceReproductionRequest,
  Phase1AcceptedHarnessProvenance,
  Phase1ProvenanceContext,
  Phase1ProvenanceResult,
  Phase1ProtectedExecutionAuthorization,
  Phase1ProtectedExecutionMode,
  Phase1ReviewCandidateProvenance,
  Phase1SourceEvidenceRef,
} from './profile-semantics/provenance.js';

export type Phase1ProfileValidationDependencies = {
  assertKeyedArrays: (profile: Phase1Profile, context: Phase1ProfileSemanticContext) => void;
  assertNativeSurface: (profile: Phase1Profile) => void;
  assertFixtures: (profile: Phase1Profile) => void;
  assertOperations: (profile: Phase1Profile) => void;
  assertBrowser: (profile: Phase1Profile) => void;
  assertConformance: (profile: Phase1Profile) => void;
  verifyProvenance: (
    profile: Phase1Profile,
    context: Phase1ProvenanceContext
  ) => Promise<Phase1ProvenanceResult>;
};

export type Phase1ProfileValidationCoordinator = Readonly<{
  assertSemantics: (profile: Phase1Profile, context: Phase1ProfileSemanticContext) => void;
  verifyProvenance: (
    profile: Phase1Profile,
    context: Phase1ProvenanceContext
  ) => Promise<Phase1ProvenanceResult>;
}>;

export const createPhase1ProfileValidationCoordinator = (
  dependencies: Phase1ProfileValidationDependencies
): Phase1ProfileValidationCoordinator => {
  const {
    assertKeyedArrays,
    assertNativeSurface,
    assertFixtures,
    assertOperations,
    assertBrowser,
    assertConformance,
    verifyProvenance,
  } = dependencies;
  const assertSemantics = (profile: Phase1Profile, context: Phase1ProfileSemanticContext): void => {
    assertKeyedArrays(profile, context);
    assertNativeSurface(profile);
    assertFixtures(profile);
    assertOperations(profile);
    assertBrowser(profile);
    assertConformance(profile);
  };

  return Object.freeze({
    assertSemantics,
    verifyProvenance,
  });
};

const phase1ProfileValidationCoordinator = createPhase1ProfileValidationCoordinator({
  assertNativeSurface: assertNativeSurfaceSemantics,
  assertKeyedArrays: assertKeyedArraySemantics,
  assertFixtures: assertFixtureSemantics,
  assertOperations: assertOperationSemantics,
  assertBrowser: assertBrowserSemantics,
  assertConformance: assertConformanceSemantics,
  verifyProvenance: verifyDefaultPhase1ProfileProvenance,
});

export const assertPhase1ProfileSemantics = phase1ProfileValidationCoordinator.assertSemantics;
export const verifyPhase1ProfileProvenance = phase1ProfileValidationCoordinator.verifyProvenance;
export const assertPhase1ProfileProvenance = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): Promise<void> => {
  await phase1ProfileValidationCoordinator.verifyProvenance(profile, context);
};
