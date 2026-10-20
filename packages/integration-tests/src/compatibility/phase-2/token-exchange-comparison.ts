/* eslint-disable complexity, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition -- The publication validator rejects hostile deserialized evidence before restoring its closed type. */
import { isDeepStrictEqual } from 'node:util';

import type { ProvisionedPhase2Fixture } from './fixtures.js';
import {
  assertPreparedPhase2TargetCapability,
  type Phase2TargetDescriptor,
  type PreparedPhase2Target,
} from './runtime.js';
import {
  runTokenExchangeUserJwtForTarget,
  tokenExchangeUserJwtScenarioId,
  type TokenExchangeUserJwtProjection,
} from './scenarios/token-exchange-target-driver.js';

export type TokenExchangeComparisonTarget = Readonly<{
  descriptor: Phase2TargetDescriptor;
  fixture: ProvisionedPhase2Fixture;
}>;
const capabilities = new WeakSet<Record<string, unknown>>();
const fail = (): never => {
  throw new TypeError('Invalid token-exchange supplemental comparison');
};

export const createTokenExchangeComparisonTarget = (
  preparedInput: PreparedPhase2Target,
  fixture: ProvisionedPhase2Fixture
): TokenExchangeComparisonTarget => {
  const prepared = assertPreparedPhase2TargetCapability(preparedInput);
  const target = Object.freeze({ descriptor: prepared.descriptor, fixture });
  capabilities.add(target);
  return target;
};

type Executor = typeof runTokenExchangeUserJwtForTarget;
export const runBoundTokenExchangeComparisonTargets = async (
  input: Readonly<{
    oracle: TokenExchangeComparisonTarget;
    candidate: TokenExchangeComparisonTarget;
    signal: AbortSignal;
  }>,
  execute: Executor
) => {
  const { oracle, candidate, signal } = input;
  if (
    signal.aborted ||
    !capabilities.has(oracle) ||
    !capabilities.has(candidate) ||
    oracle.descriptor.kind !== 'oracle' ||
    candidate.descriptor.kind !== 'candidate'
  ) {
    return fail();
  }
  const [oracleResult, candidateResult] = await Promise.allSettled([
    execute({ target: oracle.descriptor.target, fixture: oracle.fixture, signal }),
    execute({ target: candidate.descriptor.target, fixture: candidate.fixture, signal }),
  ]);
  if (oracleResult.status === 'rejected' && candidateResult.status === 'rejected') {
    throw new AggregateError(
      [oracleResult.reason, candidateResult.reason],
      'Token-exchange comparison targets failed'
    );
  }
  if (oracleResult.status === 'rejected') {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Preserve the executor's original rejection reason.
    throw oracleResult.reason;
  }
  if (candidateResult.status === 'rejected') {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Preserve the executor's original rejection reason.
    throw candidateResult.reason;
  }
  const oracleProjection = oracleResult.value;
  const candidateProjection = candidateResult.value;
  return Object.freeze([
    Object.freeze({ target: oracle, projection: oracleProjection }),
    Object.freeze({ target: candidate, projection: candidateProjection }),
  ] as const);
};

export type TokenExchangeComparisonEvidence = Readonly<{
  schemaVersion: 1;
  kind: 'aster-token-exchange-supplemental-comparison';
  scenarioId: typeof tokenExchangeUserJwtScenarioId;
  oracle: Readonly<{
    binding: Readonly<{ sourceCommit: string; imageDigest: string; stateDriverSha256: string }>;
    projection: TokenExchangeUserJwtProjection;
  }>;
  candidate: Readonly<{
    binding: Readonly<{ sourceCommit: string; imageDigest: string; stateDriverSha256: string }>;
    projection: TokenExchangeUserJwtProjection;
  }>;
  differences: readonly never[];
}>;
export const assertTokenExchangeComparisonEvidence = (
  value: unknown
): TokenExchangeComparisonEvidence => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    !Object.hasOwn(value, 'schemaVersion') ||
    !Object.hasOwn(value, 'kind') ||
    !Object.hasOwn(value, 'scenarioId') ||
    !Object.hasOwn(value, 'oracle') ||
    !Object.hasOwn(value, 'candidate') ||
    !Object.hasOwn(value, 'differences') ||
    Object.keys(value).length !== 6
  ) {
    return fail();
  }
  const evidence = value as TokenExchangeComparisonEvidence;
  if (
    evidence.schemaVersion !== 1 ||
    evidence.kind !== 'aster-token-exchange-supplemental-comparison' ||
    evidence.scenarioId !== tokenExchangeUserJwtScenarioId ||
    evidence.differences.length > 0 ||
    !isDeepStrictEqual(evidence.oracle.projection, evidence.candidate.projection)
  ) {
    return fail();
  }
  for (const target of [evidence.oracle, evidence.candidate]) {
    if (
      Object.keys(target).length !== 2 ||
      Object.keys(target.binding).length !== 3 ||
      !/^[0-9a-f]{40}$/u.test(target.binding.sourceCommit) ||
      !/^sha256:[0-9a-f]{64}$/u.test(target.binding.imageDigest) ||
      !/^[0-9a-f]{64}$/u.test(target.binding.stateDriverSha256) ||
      !target.projection.scopeMatchesFixtureAuthority ||
      target.projection.managedSubject.expiresIn !== 600 ||
      target.projection.managedSubject.badTarget.error !== 'invalid_target' ||
      target.projection.managedSubject.replay.error !== 'invalid_grant' ||
      target.projection.managedSubject.badActor.error !== 'invalid_grant' ||
      !target.projection.personalAccessToken.expiresAtNull ||
      !target.projection.personalAccessToken.repeatedResourceExchange ||
      target.projection.personalAccessToken.deleteStatus !== 204 ||
      target.projection.personalAccessToken.rejectedAfterDelete.error !== 'invalid_grant' ||
      target.projection.opaque.lifetimeSeconds !== 3600 ||
      target.projection.opaque.compact !== 'opaque' ||
      target.projection.opaque.scope !== 'openid profile' ||
      !target.projection.opaque.userinfoSubject ||
      !target.projection.opaque.introspectionActive ||
      !target.projection.opaque.subjectToResourceJwt ||
      !target.projection.opaque.openidActorClaim ||
      target.projection.opaque.profileActorRejected.error !== 'invalid_grant' ||
      !target.projection.opaque.profileActorRejected.sourcePreserved ||
      !target.projection.opaque.profileSubjectAccepted ||
      target.projection.opaque.revokedSubjectRejected.error !== 'invalid_grant' ||
      target.projection.opaque.revokedActorRejected.error !== 'invalid_grant' ||
      !target.projection.opaque.revokedActorRejected.sourcePreserved ||
      !target.projection.opaque.priorOpaqueOutputRemainsActive ||
      target.projection.admissionGrammar.disabled.error !== 'invalid_request' ||
      target.projection.admissionGrammar.disabled.errorDescription !==
        'requested grant type is not allowed for this client' ||
      target.projection.admissionGrammar.unknownClientMasksMissingSubject.error !==
        'invalid_client' ||
      target.projection.admissionGrammar.unknownClientMasksMissingSubject.errorDescription !==
        'invalid client unknown-client' ||
      target.projection.admissionGrammar.publicMissingSubject.error !== 'invalid_request' ||
      target.projection.admissionGrammar.publicMissingSubject.errorDescription !==
        "missing required parameter 'subject_token'" ||
      target.projection.admissionGrammar.publicMissingSubjectType.error !== 'invalid_request' ||
      target.projection.admissionGrammar.publicMissingSubjectType.errorDescription !==
        "missing required parameter 'subject_token_type'" ||
      target.projection.admissionGrammar.confidentialMissingProof.error !== 'invalid_request' ||
      target.projection.admissionGrammar.confidentialMissingProof.errorDescription !==
        'no client authentication mechanism provided' ||
      target.projection.admissionGrammar.confidentialWrongProof.status !== 401 ||
      target.projection.admissionGrammar.confidentialWrongProof.error !== 'invalid_client' ||
      target.projection.admissionGrammar.confidentialWrongProof.errorDescription !==
        'client authentication failed' ||
      target.projection.admissionGrammar.confidentialCorrectProofMasksMissingSubject.error !==
        'invalid_request' ||
      target.projection.admissionGrammar.confidentialCorrectProofMasksMissingSubject
        .errorDescription !==
        "missing required parameters 'subject_token' and 'subject_token_type'" ||
      target.projection.admissionGrammar.duplicateSubject.error !== 'invalid_request' ||
      target.projection.admissionGrammar.duplicateSubject.errorDescription !==
        "'subject_token' parameter must not be provided twice" ||
      target.projection.admissionGrammar.duplicateSubjectType.error !== 'invalid_request' ||
      target.projection.admissionGrammar.duplicateSubjectType.errorDescription !==
        "'subject_token_type' parameter must not be provided twice" ||
      target.projection.admissionGrammar.duplicateActor.error !== 'invalid_request' ||
      target.projection.admissionGrammar.duplicateActor.errorDescription !==
        "'actor_token' parameter must not be provided twice" ||
      target.projection.admissionGrammar.duplicateActorType.error !== 'invalid_request' ||
      target.projection.admissionGrammar.duplicateActorType.errorDescription !==
        "'actor_token_type' parameter must not be provided twice" ||
      !target.projection.admissionGrammar.repeatedResourceSelectsOpaque ||
      !target.projection.admissionGrammar.requestedTokenTypeIgnored ||
      !target.projection.admissionGrammar.metadataRestored ||
      target.projection.organization.organizationOnly.lifetimeSeconds !== 3600 ||
      target.projection.organization.organizationOnly.scope !== '' ||
      !target.projection.organization.organizationOnly.audienceMapped ||
      !target.projection.organization.organizationOnly.organizationIdClaimAbsent ||
      target.projection.organization.resourceAndOrganization.lifetimeSeconds !==
        target.projection.lifetimeSeconds ||
      !target.projection.organization.resourceAndOrganization.scopePreserved ||
      !target.projection.organization.resourceAndOrganization.audienceIsResource ||
      !target.projection.organization.resourceAndOrganization.organizationIdClaim ||
      !target.projection.customizer.managedTokenShape ||
      !target.projection.customizer.managedUserContext ||
      !target.projection.customizer.managedApplicationContext ||
      !target.projection.customizer.managedOrganizationContext ||
      !target.projection.customizer.managedSubjectTokenContext ||
      !target.projection.customizer.managedActorOverridden ||
      !target.projection.customizer.throwingFailOpenConsumedSource ||
      !target.projection.customizer.ordinaryJwtSubjectTokenContextAbsent ||
      !target.projection.customizer.personalAccessTokenSubjectTokenContextAbsent ||
      target.projection.customizer.deny.error !== 'access_denied' ||
      !target.projection.customizer.deny.sourcePreserved ||
      !target.projection.customizer.configurationRestored ||
      !target.projection.scopeCanonicalization.opaque.duplicateNamesCollapsed ||
      !target.projection.scopeCanonicalization.opaque.unknownNamesFiltered ||
      target.projection.scopeCanonicalization.opaque.scope !== 'openid profile' ||
      !target.projection.scopeCanonicalization.resource.duplicateNamesCollapsed ||
      !target.projection.scopeCanonicalization.resource.unknownNamesFiltered ||
      !target.projection.scopeCanonicalization.resource.scopeMatchesFixtureAuthority ||
      !target.projection.scopeCanonicalization.organization.duplicateNamesCollapsed ||
      !target.projection.scopeCanonicalization.organization.unauthorizedNamesFiltered ||
      target.projection.scopeCanonicalization.organization.scope !== '' ||
      target.projection.scopeCanonicalization.organization.lifetimeSeconds !== 3600
    ) {
      return fail();
    }
  }
  return Object.freeze(evidence);
};
const binding = (descriptor: Phase2TargetDescriptor) =>
  Object.freeze({
    sourceCommit: descriptor.sourceCommit,
    imageDigest: descriptor.imageDigest,
    stateDriverSha256: descriptor.stateDriver.sha256,
  });

export const runTokenExchangeComparison = async (
  input: Readonly<{
    oracle: TokenExchangeComparisonTarget;
    candidate: TokenExchangeComparisonTarget;
    signal: AbortSignal;
  }>
): Promise<TokenExchangeComparisonEvidence> => {
  if (
    Object.keys(input).length !== 3 ||
    !Object.hasOwn(input, 'oracle') ||
    !Object.hasOwn(input, 'candidate') ||
    !Object.hasOwn(input, 'signal')
  ) {
    return fail();
  }
  const { oracle, candidate, signal } = input;
  const [oracleExecution, candidateExecution] = await runBoundTokenExchangeComparisonTargets(
    { oracle, candidate, signal },
    runTokenExchangeUserJwtForTarget
  );
  if (!isDeepStrictEqual(oracleExecution.projection, candidateExecution.projection)) {
    return fail();
  }
  return assertTokenExchangeComparisonEvidence(
    Object.freeze({
      schemaVersion: 1,
      kind: 'aster-token-exchange-supplemental-comparison',
      scenarioId: tokenExchangeUserJwtScenarioId,
      oracle: Object.freeze({
        binding: binding(oracleExecution.target.descriptor),
        projection: oracleExecution.projection,
      }),
      candidate: Object.freeze({
        binding: binding(candidateExecution.target.descriptor),
        projection: candidateExecution.projection,
      }),
      differences: Object.freeze([] as const),
    })
  );
};
/* eslint-enable complexity, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition */
