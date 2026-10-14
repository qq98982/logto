/* eslint-disable complexity, max-lines, no-restricted-syntax, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The closed Phase 2 CLI owns exact grammar, canonical paths, private session lifetime, real mode orchestration, and success-only atomic publication. */
import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, mkdtemp, open, realpath, rm } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { Browser, BrowserType } from '@playwright/test';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import type { JsonValue } from '../normalize.js';
import { createPlaywrightBrowserGroupObserver } from '../phase-1/browser/playwright-session.js';
import { runPhase1FixtureCommand } from '../phase-1/clients/command-provisioner.js';
import { writeSecureJsonArtifact } from '../phase-1/secure-evidence-sink.js';

import {
  getCommonCompletionBoundaryFailure,
  runBoundCommonCompletionScenarios,
} from './browser/common-completion-target-driver.js';
import { readCommonGoogleExistingOwnerFixtureRuntime } from './browser/common-google-existing-owner-fixture-runtime.js';
import { readCommonGoogleRegistrationFixtureRuntime } from './browser/common-google-registration-fixture-runtime.js';
import { readCommonWechatWebFixtureRuntime } from './browser/common-wechat-web-fixture-runtime.js';
import { withSmsProviderLease } from './browser/sms-provider-lease.js';
import {
  runClientCredentialsCandidateInvariants,
  type CandidateInvariantControlEvidence,
} from './candidate-invariants/client-credentials.js';
import {
  runCustomJwtFetchPolicyCandidateInvariant,
  type CustomJwtFetchPolicyControlEvidence,
} from './candidate-invariants/custom-jwt-fetch-policy.js';
import {
  createCustomJwtCandidateInvariantExecutor,
  customJwtCandidateInvariantIds,
  runCustomJwtCandidateInvariantControls,
  type CustomJwtCandidateInvariantControlEvidence,
} from './candidate-invariants/custom-jwt.js';
import {
  createLiveDeviceCandidateInvariantExecutor,
  runDeviceCandidateInvariants,
  type DeviceCandidateInvariantControlEvidence,
} from './candidate-invariants/device-authorization.js';
import {
  createCommandVerificationCodePersistenceProbe,
  createLiveVerificationCodeCandidateInvariantExecutor,
} from './candidate-invariants/verification-code-live.js';
import {
  runVerificationCodeCandidateInvariants,
  type VerificationCodeCandidateInvariantControlEvidence,
} from './candidate-invariants/verification-code.js';
import { withPhase2AdminManagementBearer } from './clients/admin-management-bearer.js';
import { createCustomJwtHttpPort } from './clients/custom-jwt.js';
import {
  createDeviceAuthorizationTransportLease,
  type DeviceCredentialLease,
  type DeviceLifecycleRequest,
} from './clients/device-authorization.js';
import {
  issueConfidentialUserTokens,
  issuePublicUserResourceTokensWithPassword,
  issuePublicUserTokens,
} from './clients/user-token-issuance.js';
import { phase2InvariantRequestKind } from './driver-protocol.js';
import {
  assertPhase2TargetEvidenceIsSanitized,
  createPhase2EvidenceEnvelope,
  Phase2SanitizerFailure,
  validatePhase2OracleArtifact,
  type Phase2EvidenceEnvelope,
  type Phase2TargetProvenance,
} from './envelope.js';
import {
  createBearerPhase2AdminRequest,
  createCandidatePhase2FixtureProvisioner,
  createReferencePhase2AdminRequest,
  createReferencePhase2FixtureProvisioner,
  runWithPhase2Fixture,
  type Phase2AdminRequestFunction,
  type Phase2CandidateFixtureRecipe,
  type Phase2FixtureSecretLease,
  type Phase2FixtureProvisioner,
  type ProvisionedPhase2Fixture,
} from './fixtures.js';
import {
  loadPhase2Profile,
  type Phase2ProfilePaths,
  type Phase2ProfileRegistries,
} from './profile.js';
import { createClientCredentialsJwtAudit } from './projections/client-credentials.js';
import { compareLogoutSessionProjections } from './projections/logout-session.js';
import { compareTokenStatus } from './projections/token-status.js';
import { compareVerificationCodeProjections } from './projections/verification-code.js';
import {
  inspectLaunchedPhase2HarnessSource,
  recheckCleanPhase2HarnessSource,
  type Phase2SourceIdentity,
} from './provenance.js';
import {
  createCommandPhase2ScenarioStateDriver,
  fetchPhase2Discovery,
  fetchPhase2PublicJwks,
  preparePhase2TargetForExecution,
  readAndResetPhase2FetchReceipts,
  requestPhase2Json,
  validatePhase2TargetDescriptor,
  verifyPhase2Target,
  type Phase2TargetDescriptor,
  type PreparedPhase2Target,
  type VerifiedPhase2Target,
} from './runtime.js';
import {
  assertDiscoveryAbsentFieldsContract,
  assertDiscoveryAppendContract,
  assertDiscoveryEndpointFieldsContract,
  assertDiscoveryGrantContract,
  assertDiscoveryScopeAppendContract,
  clientCredentialsScenarioIds,
  compareClientCredentialsProjections,
  createClientCredentialsScenarioRegistry,
  runClientCredentialsNegativeControls,
  waitForClientCredentialsFixtureReady,
  type ClientCredentialsControlResult,
  type ClientCredentialsScenarioResult,
} from './scenarios/client-credentials.js';
import {
  commonAccountEmailChangeScenarioIds,
  compareCommonAccountEmailChangeProjections,
  runCommonAccountEmailChangeScenarioRow,
  type CommonAccountEmailChangeScenarioResult,
} from './scenarios/common-account-email-change.js';
import {
  commonAccountPasswordUpdateScenarioIds,
  compareCommonAccountPasswordUpdateProjections,
  runCommonAccountPasswordUpdateScenarioRow,
  type CommonAccountPasswordUpdateScenarioResult,
} from './scenarios/common-account-password-update.js';
import {
  commonAccountPhoneChangeScenarioIds,
  compareCommonAccountPhoneChangeProjections,
  runCommonAccountPhoneChangeScenarioRow,
  type CommonAccountPhoneChangeScenarioResult,
} from './scenarios/common-account-phone-change.js';
import {
  commonCompletionScenarioIds,
  compareCommonCompletionProjections,
  type CommonCompletionScenarioId,
  type CommonCompletionScenarioResult,
} from './scenarios/common-completion.js';
import {
  commonEmailCodeRegistrationScenarioIds,
  compareCommonEmailCodeRegistrationProjections,
  runCommonEmailCodeRegistrationScenarioRow,
  type CommonEmailCodeRegistrationScenarioResult,
} from './scenarios/common-email-code-registration.js';
import {
  compareCommonEmailCodeProjections,
  commonEmailCodeScenarioIds,
  runCommonEmailCodeScenarioRow,
  type CommonEmailCodeScenarioResult,
} from './scenarios/common-email-code.js';
import {
  commonEmailPasswordRegistrationScenarioIds,
  compareCommonEmailPasswordRegistrationProjections,
  runCommonEmailPasswordRegistrationScenarioRow,
  type CommonEmailPasswordRegistrationScenarioResult,
} from './scenarios/common-email-password-registration.js';
import {
  compareCommonEmailPasswordProjections,
  commonEmailPasswordScenarioIds,
  runCommonEmailPasswordScenarioRow,
  type CommonEmailPasswordScenarioResult,
} from './scenarios/common-email-password.js';
import {
  commonGoogleExistingOwnerScenarioIds,
  compareCommonGoogleExistingOwnerProjections,
  describeCommonGoogleExistingOwnerProjectionDifference,
  runCommonGoogleExistingOwnerScenarioRow,
  type CommonGoogleExistingOwnerScenarioResult,
} from './scenarios/common-google-existing-owner.js';
import {
  commonGoogleRegistrationScenarioIds,
  compareCommonGoogleRegistrationProjections,
  describeCommonGoogleRegistrationProjectionDifference,
  describeCommonGoogleRegistrationFailure,
  runCommonGoogleRegistrationScenarioRow,
  type CommonGoogleRegistrationScenarioResult,
} from './scenarios/common-google-registration.js';
import {
  commonManagementUserScenarioIds,
  compareCommonManagementUserProjections,
  runCommonManagementUserScenarioRow,
  type CommonManagementUserScenarioResult,
} from './scenarios/common-management-users.js';
import {
  commonNativeScenarioIds,
  compareCommonNativeCodePkceProjections,
  createCommonNativeScenarioRegistry,
  type CommonNativeScenarioResult,
} from './scenarios/common-native.js';
import {
  commonPasswordRecoveryScenarioIds,
  compareCommonPasswordRecoveryProjections,
  runCommonPasswordRecoveryScenarioRow,
  type CommonPasswordRecoveryScenarioResult,
} from './scenarios/common-password-recovery.js';
import {
  commonPhoneCodeScenarioIds,
  compareCommonPhoneCodeProjections,
  runCommonPhoneCodeScenarioRow,
  type CommonPhoneCodeScenarioResult,
} from './scenarios/common-phone-code.js';
import {
  commonWechatWebScenarioIds,
  compareCommonWechatWebProjections,
  describeCommonWechatWebProjectionDifference,
  describeCommonWechatWebFailure,
  runCommonWechatWebScenarioRow,
  type CommonWechatWebScenarioResult,
} from './scenarios/common-wechat-web.js';
import {
  compareCustomJwtProjections,
  customJwtFetchScenarioIds,
  customJwtScenarioIds,
  runCustomJwtFetchScenarios,
  runCustomJwtScenarios,
  type CustomJwtFetchScenarioEvidence,
  type CustomJwtScenarioEvidence,
} from './scenarios/custom-jwt.js';
import {
  createDeviceAuthorizationScenarioRegistry,
  compareDeviceScenarioProjections,
  deviceAuthorizationScenarioIds,
  approveDeviceAuthorization,
  runDeviceAuthorizationNegativeControls,
  type DeviceAuthorizationControlResult,
  type DeviceAuthorizationScenarioId,
  type DeviceAuthorizationScenarioResult,
} from './scenarios/device-authorization.js';
import {
  logoutSessionScenarioIds,
  runLogoutSessionScenarios,
  type LogoutSessionScenarioResult,
} from './scenarios/logout-session.js';
import {
  runTokenStatusScenarios,
  tokenStatusScenarioIds,
  type TokenStatusScenarioResult,
} from './scenarios/token-status.js';
import {
  createVerificationCodeScenarioRuntime,
  runVerificationCodeScenarios,
  VerificationCodeScenarioFailure,
  verificationCodeScenarioIds,
  type VerificationCodeScenarioResult,
} from './scenarios/verification-code.js';

const loadChromium = (): BrowserType<Browser> =>
  (
    createRequire(import.meta.url)('@playwright/test') as {
      chromium: BrowserType<Browser>;
    }
  ).chromium;

export type Phase2CliCommand =
  | Readonly<{
      mode: 'oracle';
      profilePath: string;
      schemaPath: string;
      targetPath: string;
      outputPath: string;
      tempRoot: string;
    }>
  | Readonly<{
      mode: 'differential';
      profilePath: string;
      schemaPath: string;
      oracleEvidencePath: string;
      candidateTargetPath: string;
      outputPath: string;
      tempRoot: string;
    }>
  | Readonly<{
      mode: 'candidate-invariants';
      profilePath: string;
      schemaPath: string;
      targetPath: string;
      outputPath: string;
      tempRoot: string;
    }>;

export type Phase2CliDependencies = Readonly<{
  loadProfile(paths: Phase2ProfilePaths): Promise<Phase2ProfileRegistries>;
  readTarget(path: string): Promise<Phase2TargetDescriptor>;
  readOracleArtifact(
    path: string,
    profile: Phase2ProfileRegistries,
    harness: Phase2SourceIdentity
  ): Promise<Phase2EvidenceEnvelope>;
  executeOracle(
    input: Readonly<{
      profile: Phase2ProfileRegistries;
      target: PreparedPhase2Target;
      sessionRoot: string;
    }>
  ): Promise<unknown>;
  executeDifferential(
    input: Readonly<{
      profile: Phase2ProfileRegistries;
      oracle: TargetScenarioEvidence;
      candidate: PreparedPhase2Target;
      sessionRoot: string;
    }>
  ): Promise<unknown>;
  executeCandidateInvariants(
    input: Readonly<{
      profile: Phase2ProfileRegistries;
      target: PreparedPhase2Target;
      sessionRoot: string;
    }>
  ): Promise<unknown>;
  publish(outputPath: string, value: JsonValue): Promise<void>;
  removeSessionRoot(sessionRoot: string): Promise<void>;
  stdout(message: string): void | Promise<void>;
  stderr(message: string): void | Promise<void>;
  inspectHarness(runtimeCapability?: string): Promise<Phase2SourceIdentity>;
  recheckHarness(capability: Phase2SourceIdentity): Promise<void>;
  verifyTarget(target: Phase2TargetDescriptor): Promise<VerifiedPhase2Target>;
  prepareTarget(
    target: VerifiedPhase2Target,
    sessionRoot: string,
    namespace: 'oracle' | 'candidate'
  ): Promise<PreparedPhase2Target>;
}>;

type TargetScenarioEvidence = Readonly<{
  target: 'oracle' | 'candidate';
  scenarios: ReadonlyArray<
    | ClientCredentialsScenarioResult
    | TokenStatusScenarioResult
    | LogoutSessionScenarioResult
    | DeviceAuthorizationScenarioResult
    | VerificationCodeScenarioResult
    | CommonNativeScenarioResult
    | CommonEmailCodeScenarioResult
    | CommonEmailPasswordRegistrationScenarioResult
    | CommonGoogleExistingOwnerScenarioResult
    | CommonWechatWebScenarioResult
    | CommonGoogleRegistrationScenarioResult
    | CommonPasswordRecoveryScenarioResult
    | CommonEmailCodeRegistrationScenarioResult
    | CommonEmailPasswordScenarioResult
    | CommonAccountPasswordUpdateScenarioResult
    | CommonAccountEmailChangeScenarioResult
    | CommonAccountPhoneChangeScenarioResult
    | CommonManagementUserScenarioResult
    | CommonCompletionScenarioResult
    | CommonPhoneCodeScenarioResult
    | CustomJwtScenarioEvidence
    | CustomJwtFetchScenarioEvidence
  >;
  discovery: Readonly<{
    grantTypesSupported: readonly string[];
    endpointFieldsAppend: Phase2ProfileRegistries['discovery']['endpointFieldsAppend'];
    scopesSupportedAppend: readonly ['urn:aster:scope:sessions'];
    stillAbsent: readonly string[];
  }>;
  controls: ReadonlyArray<ClientCredentialsControlResult | DeviceAuthorizationControlResult>;
}>;

const invalidArguments = 'Invalid Phase 2 arguments.\n';
const runFailure = 'Phase 2 client credentials command failed.\n';
const deviceProjectionDifferenceFields = Object.freeze([
  'status',
  'contentType',
  'headers',
  'keys',
  'cookies',
  'challenge',
  'location',
  'oauthError',
  'userCodeShape',
  'deviceCodeShape',
  'expiresIn',
  'interval',
  'tokenType',
  'verificationUri',
  'verificationUriComplete',
  'experience',
  'kind',
  'facts',
  'access',
  'id',
  'refresh',
  'redirect',
  'terminal',
  'other',
] as const);
type DeviceProjectionDifferenceField = (typeof deviceProjectionDifferenceFields)[number];
const deviceProjectionDifferenceFieldSet = new Set<string>(deviceProjectionDifferenceFields);
const deviceConsentSequenceChildren = Object.freeze([
  'firstIssued',
  'consent',
  'completion',
] as const);
type DeviceConsentSequenceChild = (typeof deviceConsentSequenceChildren)[number];
const deviceConsentSequenceChildSet = new Set<string>(deviceConsentSequenceChildren);
type DeviceConsentSequenceDifferenceField =
  `${DeviceConsentSequenceChild}-${DeviceProjectionDifferenceField}`;
const deviceTokenLifecycleChildren = Object.freeze([
  'before',
  'action',
  'after',
  'siblingBefore',
  'siblingAfter',
] as const);
type DeviceTokenLifecycleChild = (typeof deviceTokenLifecycleChildren)[number];
const deviceTokenLifecycleChildSet = new Set<string>(deviceTokenLifecycleChildren);
type DeviceTokenLifecycleDifferenceField =
  `sequence-${DeviceTokenLifecycleChild}-${DeviceProjectionDifferenceField}`;
const deviceIdClaimTypes = Object.freeze([
  'aud',
  'created_at',
  'email',
  'email_verified',
  'exp',
  'iat',
  'iss',
  'name',
  'picture',
  'preferred_username',
  'sub',
  'updated_at',
  'username',
  'auth_time',
  'acr',
  'amr',
  'sid',
] as const);
type DeviceIdClaimType = (typeof deviceIdClaimTypes)[number];
const deviceIdClaimTypeSet = new Set<string>(deviceIdClaimTypes);
const deviceIdClaimKeyPattern =
  /^(?:iss|aud|sub|iat|exp|nbf|auth_time|sid|jti|client_id|acr|amr|name|picture|username|email|email_verified|phone_number|phone_number_verified|family_name|given_name|middle_name|nickname|preferred_username|profile|website|gender|birthdate|zoneinfo|locale|address|created_at|updated_at|roles|organizations|organization_roles|organization_id|permissions)$/u;
const deviceIdDifferenceFields = Object.freeze([
  'issuer',
  'audience',
  'subject',
  'issuedAt',
  'lifetimeSeconds',
] as const);
type DeviceIdDifferenceField = (typeof deviceIdDifferenceFields)[number];
const deviceIdDifferenceFieldSet = new Set<string>(deviceIdDifferenceFields);
type DeviceIdProjectionDifferenceField =
  | 'id-claimKeys'
  | `id-claimTypes-${DeviceIdClaimType}`
  | `id-${DeviceIdDifferenceField}`
  | 'id-header'
  | 'id-signature'
  | 'id-format'
  | 'id-other';
export const deviceProjectionDifferenceField = (
  pointer: unknown
):
  | DeviceProjectionDifferenceField
  | DeviceConsentSequenceDifferenceField
  | DeviceTokenLifecycleDifferenceField
  | DeviceIdProjectionDifferenceField => {
  const parts = typeof pointer === 'string' ? pointer.split('/').slice(1) : [];
  const [root, child, childField] = parts;
  if (
    root === 'sequence' &&
    child &&
    deviceConsentSequenceChildSet.has(child) &&
    childField &&
    deviceProjectionDifferenceFieldSet.has(childField)
  ) {
    return `${child as DeviceConsentSequenceChild}-${childField as DeviceProjectionDifferenceField}`;
  }
  if (
    root === 'sequence' &&
    child &&
    deviceTokenLifecycleChildSet.has(child) &&
    childField &&
    deviceProjectionDifferenceFieldSet.has(childField)
  ) {
    return `sequence-${child as DeviceTokenLifecycleChild}-${childField as DeviceProjectionDifferenceField}`;
  }
  if (root === 'id') {
    if (child === 'claims' && childField === 'claimKeys') {
      return 'id-claimKeys';
    }
    const claimType = parts[3];
    if (
      child === 'claims' &&
      childField === 'claimTypes' &&
      claimType &&
      deviceIdClaimTypeSet.has(claimType)
    ) {
      return `id-claimTypes-${claimType as DeviceIdClaimType}`;
    }
    if (child === 'claims' && childField && deviceIdDifferenceFieldSet.has(childField)) {
      return `id-${childField as DeviceIdDifferenceField}`;
    }
    if (child === 'header' || child === 'signature' || child === 'format') {
      return `id-${child}`;
    }
    return 'id-other';
  }
  return root && deviceProjectionDifferenceFieldSet.has(root)
    ? (root as DeviceProjectionDifferenceField)
    : 'other';
};
const claimKeysFromDeviceProjection = (projection: unknown): readonly string[] | undefined => {
  if (typeof projection !== 'object' || projection === null) {
    return undefined;
  }
  const id = Object.getOwnPropertyDescriptor(projection, 'id')?.value as unknown;
  if (typeof id !== 'object' || id === null) {
    return undefined;
  }
  const claims = Object.getOwnPropertyDescriptor(id, 'claims')?.value as unknown;
  if (typeof claims !== 'object' || claims === null) {
    return undefined;
  }
  const claimKeys = Object.getOwnPropertyDescriptor(claims, 'claimKeys')?.value as unknown;
  if (
    !Array.isArray(claimKeys) ||
    claimKeys.some((name) => typeof name !== 'string' || !deviceIdClaimKeyPattern.test(name)) ||
    new Set(claimKeys).size !== claimKeys.length
  ) {
    return undefined;
  }
  return claimKeys as readonly string[];
};
export const deviceIdClaimKeysDifferenceDiagnostic = (
  oracleProjection: unknown,
  candidateProjection: unknown
): string | undefined => {
  const oracle = claimKeysFromDeviceProjection(oracleProjection);
  const candidate = claimKeysFromDeviceProjection(candidateProjection);
  if (!oracle || !candidate) {
    return undefined;
  }
  const oracleSet = new Set(oracle);
  const candidateSet = new Set(candidate);
  const onlyOracle = oracle.filter((name) => !candidateSet.has(name)).sort();
  const onlyCandidate = candidate.filter((name) => !oracleSet.has(name)).sort();
  return `Phase 2 device ID claimKeys differ (only on oracle: ${onlyOracle.join(',') || 'none'}; only on candidate: ${onlyCandidate.join(',') || 'none'}).`;
};

class DeviceScenarioProjectionFailure extends Error {
  public constructor(
    message: string,
    public readonly structuralDiagnostic?: string
  ) {
    super(message);
  }
}

export const deviceScenarioProjectionFailure = (
  scenarioId: DeviceAuthorizationScenarioId,
  pointer: unknown,
  oracleProjection: unknown,
  candidateProjection: unknown
): Error => {
  const field = deviceProjectionDifferenceField(pointer);
  const structuralDiagnostic =
    field === 'id-claimKeys'
      ? deviceIdClaimKeysDifferenceDiagnostic(oracleProjection, candidateProjection)
      : undefined;
  return new DeviceScenarioProjectionFailure(
    `Phase 2 scenario failed: candidate/${scenarioId}:projection-${field}`,
    structuralDiagnostic
  );
};
const scenarioFailurePattern =
  /^(?!.*common\.(?:email\.(?:code-sign-in|code-registration|password-registration)|password\.recovery|google\.existing-owner):)Phase 2 scenario failed: (oracle|candidate)\/(client-credentials\.[a-z-]+|token-status\.[a-z-]+|logout\.[a-z-]+|account-sessions\.[a-z-]+|verification-code\.[a-z-]+|common\.native\.code-pkce|common\.email\.(?:password-sign-in|code-sign-in|code-registration|password-registration)|common\.password\.recovery|common\.google\.existing-owner|common\.(?:password\.policy|google\.configured-collision|account\.(?:google-link|wechat-link)|wechat\.(?:h5|mini|mini-phone-registration|native)|management\.(?:applications-secrets|native-resource-role|connectors-experience|user-suspend-delete|provisioning-convergence)|session\.logout-preservation)|device-(?:authorization|verification|consent|token|token-status|discovery)\.[a-z-]+)(?::(lifecycle-request|lifecycle-response|token-response|credential-lease|projection|scenario|approval(?:-(?:authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final))?|transition|verification-get|verification-post|projection-(?:(?:firstIssued|consent|completion)-(?:status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)|sequence-(?:before|action|after|siblingBefore|siblingAfter)-(?:status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)|id-(?:claimKeys|claimTypes-(?:aud|created_at|email|email_verified|exp|iat|iss|name|picture|preferred_username|sub|updated_at|username|auth_time|acr|amr|sid)|header|signature|format|issuer|audience|subject|issuedAt|lifetimeSeconds|other)|status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)))?$/u;
const deviceFailureStagePattern =
  /^Invalid Phase 2 device authorization transport \((lifecycle-request|lifecycle-response|token-response|credential-lease)\)$/u;
const usedCodeFailureStagePattern =
  /^Invalid Phase 2 device already-used-code step \((approval(?:-(?:authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final))?|transition|verification-get|verification-post)\)$/u;
type DeviceFailureStage =
  | 'lifecycle-request'
  | 'lifecycle-response'
  | 'token-response'
  | 'credential-lease'
  | 'projection'
  | 'scenario'
  | 'approval'
  | 'approval-authorize'
  | 'approval-capture'
  | 'approval-verify'
  | 'approval-experience-open'
  | 'approval-password'
  | 'approval-identification'
  | 'approval-experience-submit'
  | 'approval-resume-initial'
  | 'approval-consent-read'
  | 'approval-consent-write'
  | 'approval-resume-final'
  | 'transition'
  | 'verification-get'
  | 'verification-post';
type DeviceResourceRefreshFailureStage =
  | 'authorize'
  | Extract<DeviceFailureStage, `approval-${string}`>
  | 'token-poll'
  | 'initial-lease'
  | 'refresh-request'
  | 'refresh-http'
  | 'jwt-verify'
  | 'projection';
const stageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(fixture(?:-(?:provision|readiness|public-jwks|cleanup(?:-(?:first(?:-(?:command(?:-(?:transport|timeout|signal|nonzero|malformed|response|unknown))?|ack))?|replay))?|body-cleanup))?|completion-(?:fixture|machine-authority|runtime-read|required-controls|scenarios|owned-app-cleanup|machine-cleanup-result|(?:owned-app-cleanup|machine-cleanup-result)\/(?:common\.(?:password\.policy|google\.configured-collision|account\.(?:google-link|wechat-link)|wechat\.(?:h5|mini|mini-phone-registration|native)|management\.(?:applications-secrets|native-resource-role|connectors-experience|user-suspend-delete|provisioning-convergence)|session\.logout-preservation)))|discovery|controls|sanitizer(?:-(?:target|discovery|controls|ids|(?:client|device)-(?:[0-9]|[1-9][0-9]|1[0-6][0-9]|17[0-5])|native-176|email-177|code-178|registration-179|password-registration-180|recovery-181|google-182|google-registration-183|wechat-web-184|common-completion-(?:19[2-9]|20[0-5])))?|comparison|logout-session|verification-code|custom-jwt|status-(?:admission|authorization|bootstrap|verification|identification|submit|bridge-(?:url|send|http-(?:[1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(?:http|body|type|access|refresh)|introspection)|status-comparison-(?:kind|status|headers|body(?:-(?:sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-case-(?:[0-9]|1[0-9]|2[0-6])-(?:kind|status|headers|body(?:-(?:sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-scope-(?:[0-9]|1[0-9]|2[0-6])-(?:short|full|resource|offline|other)-(?:short|full|resource|offline|other))(?::.*)?$/u;
const candidateAdminBearerStageFailurePattern =
  /^Phase 2 stage failed: (candidate)-(admin-bearer-(?:admission|authorization|bootstrap|password|identification|submit|bridge|consent|resume|code-token|management-refresh|jwks))$/u;
export const commonEmailPasswordScenarioFailure = (
  kind: 'oracle' | 'candidate',
  error: unknown
): never => {
  if (
    kind === 'candidate' &&
    error instanceof Error &&
    candidateAdminBearerStageFailurePattern.test(error.message)
  ) {
    throw error;
  }
  const adminStage =
    kind === 'candidate' && error instanceof Error
      ? candidateAdminBearerFailurePattern.exec(error.message)?.[1]
      : undefined;
  if (adminStage) {
    throw new Error(`Phase 2 stage failed: candidate-admin-bearer-${adminStage}`);
  }
  throw new Error(`Phase 2 scenario failed: ${kind}/${commonEmailPasswordScenarioIds[0]}`);
};
export const commonCompletionFailure = (kind: 'oracle' | 'candidate', error: unknown): never => {
  const boundary = getCommonCompletionBoundaryFailure(error);
  if (boundary?.scenarioId && boundary.phase === 'scenarios') {
    throw new TypeError(`Phase 2 scenario failed: ${kind}/${boundary.scenarioId}`);
  }
  if (boundary) {
    throw new Error(
      `Phase 2 stage failed: ${kind}-completion-${boundary.phase}${
        boundary.scenarioId ? `/${boundary.scenarioId}` : ''
      }`
    );
  }
  throw new Error(`Phase 2 stage failed: ${kind}-completion-fixture`);
};
export const commonEmailCodeScenarioFailure = (
  kind: 'oracle' | 'candidate',
  _error: unknown
): never => {
  throw new Error(`Phase 2 scenario failed: ${kind}/${commonEmailCodeScenarioIds[0]}`);
};
export const commonEmailCodeRegistrationScenarioFailure = (
  kind: 'oracle' | 'candidate',
  _error: unknown
): never => {
  throw new Error(`Phase 2 scenario failed: ${kind}/${commonEmailCodeRegistrationScenarioIds[0]}`);
};
const commonReadyStageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(common-ready-(?:password-registration|recovery|google|google-registration|wechat-web)-(?:admission|capability|discovery|subject|lease|cleanup|fixture|browser|admin|context|consent-field-invalid-(?:route|operation|status|binding|code|authorization|state|tuple)|context-adapter|context-flow|context-after-flow|context-control-(?:open|route|count|reset|click|response|owner)|context-positive-(?:admission|initialization|provider-count|provider-click|consent-route|consent-click|callback|profile|refresh|provider)|context-positive-consent-(?:response|authorization|state|route|complete)|credentials|management|other|wrong-state-owner-before|wrong-state-browser|wrong-state-owner-after|wrong-state-provider|flow-admission|flow-initialization|flow-identifier|flow-delivery|flow-verification|flow-credential-fulfillment|flow-persisted-user|flow-callback|flow-registration-profile-refresh|flow-fresh-sign-in|flow-fresh-profile-refresh|flow-initial-password|flow-forgot-password|flow-passcode-retrieval|flow-passcode-format|flow-passcode-fill|flow-new-password-reset|flow-prior-access|flow-prior-refresh|flow-new-password-sign-in|flow-old-password-rejection|flow-profile|flow-refresh|flow-provider|flow-provider-count|flow-provider-click|flow-consent|flow-provider-case|flow-authorization|controls-admission|controls-incomplete-before|controls-incomplete-proof|controls-incomplete-identification|controls-incomplete-after|controls-duplicate-before|controls-duplicate-proof|controls-duplicate-identification|controls-duplicate-after|controls-policy-before|controls-policy-proof|controls-policy-profile|controls-policy-after|controls-replay|controls-wrong-purpose|flow-callback-callback-route|flow-callback-cardinality|flow-callback-signin-authority|flow-callback-signin-response|flow-callback-signin-client|flow-callback-signin-redirect|flow-callback-signin-mode|flow-callback-signin-scope|flow-callback-signin-resource|flow-callback-signin-pkce|flow-callback-callback-authority|flow-callback-callback-response|flow-callback-callback-state|flow-callback-callback-issuer|flow-callback-callback-code|flow-callback-exchange-authority|flow-callback-exchange-response|flow-callback-exchange-correlation|flow-callback-exchange-client|flow-callback-exchange-refresh|flow-callback-exchange-target|flow-callback-exchange-scope|flow-callback-exchange-access|fixture-read-sie|fixture-get-app|fixture-patch-app|fixture-read-app|fixture-read-resource|fixture-create-role|fixture-create-connector|fixture-prepare-connector|fixture-prepare-connector-docker-environment|fixture-prepare-connector-admission|fixture-prepare-connector-configuration-file|fixture-prepare-connector-receipt-file|fixture-prepare-connector-container-admission|fixture-prepare-connector-configuration-write|fixture-prepare-connector-start|fixture-prepare-connector-health|fixture-prepare-connector-compensation|fixture-prepare-connector-unknown|fixture-patch-sie|fixture-read-sie-updated|fixture-existing-owner-create-user|fixture-existing-owner-associate|fixture-existing-owner-read-before|fixture-existing-owner-use|fixture-existing-owner-read-after|fixture-existing-owner-cleanup-user|fixture-stop-provider(?:-(?:state|config-identity|receipt-identity))?|fixture-restore-app|fixture-delete-role|fixture-restore-sie|fixture-delete-connector|fixture-input|scenario-fixture|scenario-projection|wrong-state-authorization|wrong-state-authorization-request-count|wrong-state-authorization-query-shape|wrong-state-authorization-client|wrong-state-authorization-callback|wrong-state-authorization-response-type|wrong-state-authorization-scope|wrong-state-authorization-state-format|wrong-state-authorization-state-round-trip|wrong-state-authorization-fulfilled|flow-callback-callback-facts-s0-c0-i0|flow-callback-callback-facts-s0-c0-i1|flow-callback-callback-facts-s0-c0-imany|flow-callback-callback-facts-s0-c1-i0|flow-callback-callback-facts-s0-c1-i1|flow-callback-callback-facts-s0-c1-imany|flow-callback-callback-facts-s0-cmany-i0|flow-callback-callback-facts-s0-cmany-i1|flow-callback-callback-facts-s0-cmany-imany|flow-callback-callback-facts-s1-c0-i0|flow-callback-callback-facts-s1-c0-i1|flow-callback-callback-facts-s1-c0-imany|flow-callback-callback-facts-s1-c1-i0|flow-callback-callback-facts-s1-c1-i1|flow-callback-callback-facts-s1-c1-imany|flow-callback-callback-facts-s1-cmany-i0|flow-callback-callback-facts-s1-cmany-i1|flow-callback-callback-facts-s1-cmany-imany|flow-callback-callback-facts-smany-c0-i0|flow-callback-callback-facts-smany-c0-i1|flow-callback-callback-facts-smany-c0-imany|flow-callback-callback-facts-smany-c1-i0|flow-callback-callback-facts-smany-c1-i1|flow-callback-callback-facts-smany-c1-imany|flow-callback-callback-facts-smany-cmany-i0|flow-callback-callback-facts-smany-cmany-i1|flow-callback-callback-facts-smany-cmany-imany|wrong-state-open|wrong-state-sign-in|wrong-state-provider-count|wrong-state-provider-click|wrong-state-callback-outcome|wrong-state-callback-signal|wrong-state-callback-guard|wrong-state-callback-observation-other|wrong-state-callback-external-callback-method|wrong-state-callback-external-callback-query|wrong-state-callback-external-callback-fragment|wrong-state-callback-cardinality|authorization|callback|initialization|missing-owner|owner-lookup|profile|provider-count|provider-click|refresh|registration-route|registration-transition|consent-click|consent-route|consent-route-(?:sign-in|register|continue|demo|error|callback|other)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:complete|missing-resume-(?:not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(?:user-identity_not_exist|user-missing_profile|session-verification_session_not_found|session-interaction_not_found|session-invalid_credentials|user-suspended|user-sign_in_method_not_enabled|session-identity_conflict|user-email_already_in_use|verification_record-permission_denied|guard-invalid_input|connector-general|connector-wechat_unionid_required|connector-social_auth_code_invalid|connector-invalid_response|unknown|none)-auth-[01]{9}-state-(?:stored|cleared|unavailable)|fixture-registration-owner-before|fixture-registration-owner-use|fixture-registration-owner-after|fixture-registration-owner-cleanup|fixture-registration-owner-discovery|controls-no-union-id|controls-invalid-code|controls-replay|controls-malformed-provider|controls-cross-interaction(?:-(?:execution(?:-(?:target|result|not-observed|after-control|browser|context|init-request|init-status|replay-request|replay-body|cleanup|first-response|owner-before|request|owner-after|fulfill))?|status|error|accepted))?|controls-missing-state|controls-wrong-state|controls-wrong-callback|unverified-email-control-(?:invalid-status|disallowed-error)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:connector.general|guard.invalid_input|user.identity_not_exist|user.missing_profile|verification_record.permission_denied|session.identity_conflict|user.email_already_in_use|none)|occupied-email-control-(?:invalid-status|disallowed-error)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:connector.general|guard.invalid_input|user.identity_not_exist|user.missing_profile|verification_record.permission_denied|session.identity_conflict|user.email_already_in_use|none)|unverified-email-control-rejected-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:user.identity_not_exist|session.verification_session_not_found|session.interaction_not_found|session.invalid_credentials|user.suspended|user.sign_in_method_not_enabled|connector.wechat_unionid_required|connector.social_auth_code_invalid|connector.invalid_response)|unverified-email-control-unknown-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)|unverified-email-control-observed-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:known|unknown)-(?:incomplete|other)|unverified-email-control(?:-(?:response|consent|profile-route|profile-input|outcome|outcome-code|outcome-status|outcome-error|outcome-accepted|link-count|link-click|link-complete))?|unverified-email-owner|occupied-email-control(?:-(?:response|consent|profile-route|profile-input|outcome|outcome-code|outcome-status|outcome-error|outcome-accepted|link-count|link-click|link-complete))?|occupied-email-owner|control-publication))$/u;
const accountReadyStageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(common-ready-account-(?:(?:password|email)-other|phone-(?:admission|discovery|account-transport|fixture|token-issuance|browser-login|provider-lease|flow)))$/u;
const commonManagementReadyStageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(common-ready-management-(?:user-create|user-contact-update)-(?:admission|client|redirect|password|default-role|default-role-membership|resource-token|refreshed-resource-token|duplicate-s(?:200|201|400|401|409|422)-(?:none|guard-invalid_input|user-email_already_in_use|user-phone_already_in_use|auth-unauthorized|unknown)|create-account-reads|create-predicates|retained-resource-token|collision-s(?:200|201|400|401|409|422)-(?:none|guard-invalid_input|user-email_already_in_use|user-phone_already_in_use|auth-unauthorized|unknown)|malformed-s(?:200|201|400|401|409|422)-(?:none|guard-invalid_input|user-email_already_in_use|user-phone_already_in_use|auth-unauthorized|unknown)|auth-first-s(?:200|201|400|401|409|422)-(?:none|guard-invalid_input|user-email_already_in_use|user-phone_already_in_use|auth-unauthorized|unknown)|contact-account-reads|contact-predicates|contract|user-create-flow|user-contact-update-flow))$/u;
const commonManagementTargetStagePattern =
  /^Invalid Common Management user target \(([a-z0-9_-]+)\)$/u;
export const closedCommonManagementTargetStage = (error: unknown): string | undefined =>
  error instanceof Error ? commonManagementTargetStagePattern.exec(error.message)?.[1] : undefined;
export const commonManagementScenarioFailure = (
  kind: 'oracle' | 'candidate',
  id: CommonManagementUserScenarioResult['id'],
  error: unknown
): never => {
  const stage = closedCommonManagementTargetStage(error);
  const scenario = id.endsWith('user-create') ? 'user-create' : 'user-contact-update';
  const message = `Phase 2 stage failed: ${kind}-common-ready-management-${scenario}-${stage ?? 'contract'}`;
  if (!commonManagementReadyStageFailurePattern.test(message)) {
    throw new Error(`Phase 2 stage failed: ${kind}-common-ready-management-${scenario}-contract`);
  }
  throw new Error(message);
};
const commonPhoneStageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(phone-(?:registration|sign-in)-(?:admission|capability|discovery|subject|sms-lease|controls|fixture|fixture-cleanup|other|(?:registration|sign-in)-(?:input|initialization|identifier|delivery|code-format|code-fill|consent|callback|profile|refresh|subject)))$/u;
const commonPhoneTargetFailurePattern =
  /^Common phone code target failed: (admission|capability|discovery|subject)$/u;
const commonPhoneFlowFailurePattern =
  /^Common phone code stage failed: ((?:registration|sign-in)-(?:input|initialization|identifier|delivery|code-format|code-fill|consent|callback|profile|refresh|subject))$/u;
const commonPhoneFixtureFailurePattern =
  /^Selected phone code fixture failed: (?:read-sie|get-app|patch-app|read-resource|create-role|create-connector|patch-sie|create-owner|create-control-owner|create-collision-owner|create-suspended|assign-role|registration-owner-before|use)$/u;
const commonPhoneFixtureCleanupFailurePattern =
  /^Selected phone code fixture failed: cleanup-(?:discover-registered-ambiguous|discover-registered|registered-owner-remains|read-registered-owner-after|delete-role|delete-connector|restore-sie|restore-app)(?:\+(?:discover-registered-ambiguous|discover-registered|registered-owner-remains|read-registered-owner-after|delete-role|delete-connector|restore-sie|restore-app))*$/u;

const ownErrorMessage = (error: unknown): string | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
    ? descriptor.value
    : undefined;
};

const commonPhoneFailureStage = (error: unknown): string | undefined => {
  const message = ownErrorMessage(error);
  if (message === undefined) {
    return undefined;
  }
  if (message === 'Invalid SMS provider lease') {
    return 'sms-lease';
  }
  if (message === 'Invalid Common phone code controls') {
    return 'controls';
  }
  if (
    message === 'Invalid Common phone code scenario fixture' ||
    message === 'Missing Common phone provider fixture'
  ) {
    return 'fixture';
  }
  return (
    commonPhoneTargetFailurePattern.exec(message)?.[1] ??
    commonPhoneFlowFailurePattern.exec(message)?.[1] ??
    (commonPhoneFixtureFailurePattern.test(message) ? 'fixture' : undefined) ??
    (commonPhoneFixtureCleanupFailurePattern.test(message) ? 'fixture-cleanup' : undefined)
  );
};

const closedCommonPhoneFailure = (error: unknown): Error | undefined => {
  const message = ownErrorMessage(error);
  if (message !== undefined && commonPhoneStageFailurePattern.test(message)) {
    return error as Error;
  }
  if (!(error instanceof AggregateError)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'errors');
  const errors: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  if (
    !Array.isArray(errors) ||
    Object.getPrototypeOf(errors) !== Array.prototype ||
    errors.length !== 2
  ) {
    return undefined;
  }
  const primary = commonPhoneStageFailurePattern.exec(ownErrorMessage(errors[0]) ?? '');
  if (!primary?.[1] || !primary[2]) {
    return undefined;
  }
  const role = primary[2].startsWith('phone-registration-') ? 'registration' : 'sign-in';
  return new Error(`Phase 2 stage failed: ${primary[1]}-phone-${role}-fixture-cleanup`);
};

export const commonPhoneScenarioFailure = (
  kind: 'oracle' | 'candidate',
  id: (typeof commonPhoneCodeScenarioIds)[number],
  error: unknown
): never => {
  const role = id === commonPhoneCodeScenarioIds[0] ? 'registration' : 'sign-in';
  const stage = commonPhoneFailureStage(error) ?? 'other';
  const aggregate = closedCommonPhoneFailure(error);
  if (aggregate) {
    throw aggregate;
  }
  throw new Error(`Phase 2 stage failed: ${kind}-phone-${role}-${stage}`);
};
const commonReadyStages = new Set([
  'unverified-email-control',
  'unverified-email-control-response',
  'unverified-email-control-consent',
  'unverified-email-control-profile-route',
  'unverified-email-control-profile-input',
  'unverified-email-control-outcome',
  'unverified-email-control-outcome-code',
  'unverified-email-control-outcome-status',
  'unverified-email-control-outcome-error|outcome-accepted',
  'unverified-email-control-outcome-accepted',
  'unverified-email-owner',
  'occupied-email-control',
  'occupied-email-control-response',
  'occupied-email-control-consent',
  'occupied-email-control-profile-route',
  'occupied-email-control-profile-input',
  'occupied-email-control-outcome',
  'occupied-email-control-outcome-code',
  'occupied-email-control-outcome-status',
  'occupied-email-control-outcome-error|outcome-accepted',
  'occupied-email-control-outcome-accepted',
  'occupied-email-control-link-count',
  'occupied-email-control-link-click',
  'occupied-email-control-link-complete',
  'occupied-email-owner',
  'control-publication',

  'authorization',
  'callback',
  'initialization',
  'missing-owner',
  'owner-lookup',
  'profile',
  'provider-count',
  'provider-click',
  'refresh',
  'registration-route',
  'registration-transition',
  'consent-click',
  'consent-route',
  'fixture-registration-owner-before',
  'fixture-registration-owner-use',
  'fixture-registration-owner-after',
  'fixture-registration-owner-cleanup',
  'fixture-registration-owner-discovery',
  'controls-no-union-id',
  'controls-invalid-code',
  'controls-replay',
  'controls-malformed-provider',
  'controls-cross-interaction',
  'controls-cross-interaction-execution',
  'controls-cross-interaction-execution-target',
  'controls-cross-interaction-execution-result',
  'controls-cross-interaction-execution-not-observed',
  'controls-cross-interaction-execution-after-control',
  'controls-cross-interaction-execution-browser',
  'controls-cross-interaction-execution-context',
  'controls-cross-interaction-execution-init-request',
  'controls-cross-interaction-execution-init-status',
  'controls-cross-interaction-execution-replay-request',
  'controls-cross-interaction-execution-replay-body',
  'controls-cross-interaction-execution-cleanup',
  'controls-cross-interaction-execution-first-response',
  'controls-cross-interaction-execution-owner-before',
  'controls-cross-interaction-execution-request',
  'controls-cross-interaction-execution-owner-after',
  'controls-cross-interaction-execution-fulfill',
  'controls-cross-interaction-status',
  'controls-cross-interaction-error',
  'controls-cross-interaction-accepted',
  'controls-missing-state',
  'controls-wrong-state',
  'controls-wrong-callback',

  'admission',
  'capability',
  'discovery',
  'subject',
  'lease',
  'cleanup',
  'fixture',
  'browser',
  'admin',
  'context',
  'credentials',
  'management',
  'other',
  'wrong-state-owner-before',
  'wrong-state-browser',
  'wrong-state-owner-after',
  'wrong-state-provider',
  'flow-admission',
  'flow-initialization',
  'flow-identifier',
  'flow-delivery',
  'flow-verification',
  'flow-credential-fulfillment',
  'flow-persisted-user',
  'flow-callback',
  'flow-registration-profile-refresh',
  'flow-fresh-sign-in',
  'flow-fresh-profile-refresh',
  'flow-initial-password',
  'flow-forgot-password',
  'flow-passcode-retrieval',
  'flow-passcode-format',
  'flow-passcode-fill',
  'flow-new-password-reset',
  'flow-prior-access',
  'flow-prior-refresh',
  'flow-new-password-sign-in',
  'flow-old-password-rejection',
  'flow-profile',
  'flow-refresh',
  'flow-provider',
  'flow-provider-count',
  'flow-provider-click',
  'flow-consent',
  'flow-provider-case',
  'flow-authorization',
  'controls-admission',
  'controls-incomplete-before',
  'controls-incomplete-proof',
  'controls-incomplete-identification',
  'controls-incomplete-after',
  'controls-duplicate-before',
  'controls-duplicate-proof',
  'controls-duplicate-identification',
  'controls-duplicate-after',
  'controls-policy-before',
  'controls-policy-proof',
  'controls-policy-profile',
  'controls-policy-after',
  'controls-replay',
  'controls-wrong-purpose',
  'flow-callback-callback-route',
  'flow-callback-cardinality',
  'flow-callback-signin-authority',
  'flow-callback-signin-response',
  'flow-callback-signin-client',
  'flow-callback-signin-redirect',
  'flow-callback-signin-mode',
  'flow-callback-signin-scope',
  'flow-callback-signin-resource',
  'flow-callback-signin-pkce',
  'flow-callback-callback-authority',
  'flow-callback-callback-response',
  'flow-callback-callback-state',
  'flow-callback-callback-issuer',
  'flow-callback-callback-code',
  'flow-callback-exchange-authority',
  'flow-callback-exchange-response',
  'flow-callback-exchange-correlation',
  'flow-callback-exchange-client',
  'flow-callback-exchange-refresh',
  'flow-callback-exchange-target',
  'flow-callback-exchange-scope',
  'flow-callback-exchange-access',
  'fixture-read-sie',
  'fixture-get-app',
  'fixture-patch-app',
  'fixture-read-app',
  'fixture-read-resource',
  'fixture-create-role',
  'fixture-create-connector',
  'fixture-prepare-connector',
  'fixture-prepare-connector-docker-environment',
  'fixture-prepare-connector-admission',
  'fixture-prepare-connector-configuration-file',
  'fixture-prepare-connector-receipt-file',
  'fixture-prepare-connector-container-admission',
  'fixture-prepare-connector-configuration-write',
  'fixture-prepare-connector-start',
  'fixture-prepare-connector-health',
  'fixture-prepare-connector-compensation',
  'fixture-prepare-connector-unknown',
  'fixture-patch-sie',
  'fixture-read-sie-updated',
  'fixture-existing-owner-create-user',
  'fixture-existing-owner-associate',
  'fixture-existing-owner-read-before',
  'fixture-existing-owner-use',
  'fixture-existing-owner-read-after',
  'fixture-existing-owner-cleanup-user',
  'fixture-stop-provider',
  'fixture-stop-provider-state',
  'fixture-stop-provider-config-identity',
  'fixture-stop-provider-receipt-identity',
  'fixture-restore-app',
  'fixture-delete-role',
  'fixture-restore-sie',
  'fixture-delete-connector',
  'fixture-input',
  'scenario-fixture',
  'scenario-projection',
  'wrong-state-authorization',
  'wrong-state-authorization-request-count',
  'wrong-state-authorization-query-shape',
  'wrong-state-authorization-client',
  'wrong-state-authorization-callback',
  'wrong-state-authorization-response-type',
  'wrong-state-authorization-scope',
  'wrong-state-authorization-state-format',
  'wrong-state-authorization-state-round-trip',
  'wrong-state-authorization-fulfilled',
  'flow-callback-callback-facts-s0-c0-i0',
  'flow-callback-callback-facts-s0-c0-i1',
  'flow-callback-callback-facts-s0-c0-imany',
  'flow-callback-callback-facts-s0-c1-i0',
  'flow-callback-callback-facts-s0-c1-i1',
  'flow-callback-callback-facts-s0-c1-imany',
  'flow-callback-callback-facts-s0-cmany-i0',
  'flow-callback-callback-facts-s0-cmany-i1',
  'flow-callback-callback-facts-s0-cmany-imany',
  'flow-callback-callback-facts-s1-c0-i0',
  'flow-callback-callback-facts-s1-c0-i1',
  'flow-callback-callback-facts-s1-c0-imany',
  'flow-callback-callback-facts-s1-c1-i0',
  'flow-callback-callback-facts-s1-c1-i1',
  'flow-callback-callback-facts-s1-c1-imany',
  'flow-callback-callback-facts-s1-cmany-i0',
  'flow-callback-callback-facts-s1-cmany-i1',
  'flow-callback-callback-facts-s1-cmany-imany',
  'flow-callback-callback-facts-smany-c0-i0',
  'flow-callback-callback-facts-smany-c0-i1',
  'flow-callback-callback-facts-smany-c0-imany',
  'flow-callback-callback-facts-smany-c1-i0',
  'flow-callback-callback-facts-smany-c1-i1',
  'flow-callback-callback-facts-smany-c1-imany',
  'flow-callback-callback-facts-smany-cmany-i0',
  'flow-callback-callback-facts-smany-cmany-i1',
  'flow-callback-callback-facts-smany-cmany-imany',
  'wrong-state-open',
  'wrong-state-sign-in',
  'wrong-state-provider-count',
  'wrong-state-provider-click',
  'wrong-state-callback-outcome',
  'wrong-state-callback-signal',
  'wrong-state-callback-guard',
  'wrong-state-callback-observation-other',
  'wrong-state-callback-external-callback-method',
  'wrong-state-callback-external-callback-query',
  'wrong-state-callback-external-callback-fragment',
  'wrong-state-callback-cardinality',
  'context-adapter',
  'context-flow',
  'context-after-flow',
  'context-control-open',
  'context-control-route',
  'context-control-count',
  'context-control-reset',
  'context-control-click',
  'context-control-response',
  'context-control-owner',
  'context-positive-admission',
  'context-positive-initialization',
  'context-positive-provider-count',
  'context-positive-provider-click',
  'context-positive-consent-route',
  'context-positive-consent-click',
  'context-positive-callback',
  'context-positive-profile',
  'context-positive-refresh',
  'context-positive-provider',
  'context-positive-consent-response',
  'context-positive-consent-authorization',
  'context-positive-consent-state',
  'context-positive-consent-route',
  'context-positive-consent-complete',
  'consent-field-invalid-route',
  'consent-field-invalid-operation',
  'consent-field-invalid-status',
  'consent-field-invalid-binding',
  'consent-field-invalid-code',
  'consent-field-invalid-authorization',
  'consent-field-invalid-state',
  'consent-field-invalid-tuple',
]);

export const commonReadyScenarioFailure = (
  kind: 'oracle' | 'candidate',
  id:
    | 'common.email.password-registration'
    | 'common.password.recovery'
    | 'common.google.existing-owner'
    | 'common.google.registration'
    | 'common.wechat.web'
    | 'common.account.password-update'
    | 'common.account.email-change'
    | 'common.account.phone-change',
  error: unknown
): never => {
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'message') : undefined;
  const message: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
  const label =
    id === 'common.account.password-update'
      ? 'account-password'
      : id === 'common.account.email-change'
        ? 'account-email'
        : id === 'common.account.phone-change'
          ? 'account-phone'
          : id === 'common.email.password-registration'
            ? 'password-registration'
            : id === 'common.password.recovery'
              ? 'recovery'
              : id === 'common.google.registration'
                ? 'google-registration'
                : id === 'common.wechat.web'
                  ? 'wechat-web'
                  : 'google';
  const prefix =
    id === 'common.account.password-update' ||
    id === 'common.account.email-change' ||
    id === 'common.account.phone-change'
      ? 'Invalid Common Account '
      : id === 'common.email.password-registration'
        ? 'Common email password registration target failed: '
        : id === 'common.password.recovery'
          ? 'Common email recovery target failed: '
          : id === 'common.google.registration'
            ? 'Common Google registration target failed: '
            : id === 'common.wechat.web'
              ? 'Common Wechat existing-owner target failed: '
              : 'Common Google existing-owner target failed: ';
  const detail =
    typeof message === 'string' && message.startsWith(prefix)
      ? message.slice(prefix.length)
      : id === 'common.google.existing-owner' &&
          typeof message === 'string' &&
          message.startsWith('Common Google existing-owner failed: ')
        ? `flow-${message.slice('Common Google existing-owner failed: '.length)}`
        : id === 'common.google.existing-owner' &&
            message === 'Invalid Common Google existing-owner fixture runtime'
          ? 'fixture-input'
          : id === 'common.google.existing-owner' &&
              message === 'Invalid Common Google existing-owner scenario fixture'
            ? 'scenario-fixture'
            : id === 'common.wechat.web' &&
                message === 'Invalid Common WeChat Web scenario projection'
              ? 'scenario-projection'
              : id === 'common.google.existing-owner' &&
                  message === 'Invalid Common Google existing-owner scenario projection'
                ? 'scenario-projection'
                : 'other';
  const ownedDetail =
    id === 'common.google.registration'
      ? describeCommonGoogleRegistrationFailure(error)
      : id === 'common.wechat.web'
        ? describeCommonWechatWebFailure(error)
        : undefined;
  const selectedDetail = ownedDetail ?? detail;
  const stage =
    commonReadyStages.has(selectedDetail) ||
    /^consent-route-(?:sign-in|register|continue|demo|error|callback|other)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:complete|missing-resume-(?:not-issued|path-mismatch|expired|secure-mismatch|other)|missing-mapping|missing-shared|missing-session|not-applicable)-(?:user-identity_not_exist|user-missing_profile|session-verification_session_not_found|session-interaction_not_found|session-invalid_credentials|user-suspended|user-sign_in_method_not_enabled|session-identity_conflict|user-email_already_in_use|verification_record-permission_denied|guard-invalid_input|connector-general|connector-wechat_unionid_required|connector-social_auth_code_invalid|connector-invalid_response|unknown|none)-auth-[01]{9}-state-(?:stored|cleared|unavailable)$/u.test(
      selectedDetail
    ) ||
    /^(?:unverified-email|occupied-email)-control-observed-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:known|unknown)-(?:incomplete|other)$/u.test(
      selectedDetail
    ) ||
    /^(?:unverified-email|occupied-email)-control-unknown-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)$/u.test(
      selectedDetail
    ) ||
    /^(?:unverified-email|occupied-email)-control-rejected-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:user\.identity_not_exist|session\.verification_session_not_found|session\.interaction_not_found|session\.invalid_credentials|user\.suspended|user\.sign_in_method_not_enabled|connector\.wechat_unionid_required|connector\.social_auth_code_invalid|connector\.invalid_response)$/u.test(
      selectedDetail
    ) ||
    /^(?:unverified-email|occupied-email)-control-(?:invalid-status|disallowed-error)-(?:social-verify|identification|submit|resume|none)-(?:200|201|204|302|303|400|401|403|404|409|422|500|503|0)-(?:connector\.general|guard\.invalid_input|user\.identity_not_exist|user\.missing_profile|verification_record\.permission_denied|session\.identity_conflict|user\.email_already_in_use|none)$/u.test(
      selectedDetail
    )
      ? selectedDetail
      : 'other';
  throw new Error(`Phase 2 stage failed: ${kind}-common-ready-${label}-${stage}`);
};

export const commonAccountPhoneChangeScenarioFailure = (
  kind: 'oracle' | 'candidate',
  error: unknown
): never => {
  const descriptor =
    error instanceof Error ? Object.getOwnPropertyDescriptor(error, 'message') : undefined;
  const message: unknown = descriptor?.value;
  const stage =
    typeof message === 'string'
      ? /^Invalid Common Account phone change target \((admission|discovery|account-transport|fixture|token-issuance|browser-login|provider-lease|flow)\)$/u.exec(
          message
        )?.[1]
      : undefined;
  throw new Error(`Phase 2 stage failed: ${kind}-common-ready-account-phone-${stage ?? 'flow'}`);
};

const googleProjectionStageFailurePattern =
  /^Phase 2 stage failed: (candidate)-(google-projection-(?:(?:wrong-state-status|replay-second-status)-o[1-5][0-9]{2}-c[1-5][0-9]{2}|wrong-state-error-o(?:none|session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general|unknown)-c(?:none|session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general|unknown)|replay-second-error-o(?:session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general)-c(?:session\.verification_session_not_found|entity\.not_found|guard\.invalid_input|connector\.general)|contract-o(?:true|false)-c(?:true|false)|other))$/u;
export const commonGoogleProjectionScenarioFailure = (
  oracle: unknown,
  candidate: unknown
): never => {
  const difference = describeCommonGoogleExistingOwnerProjectionDifference(oracle, candidate);
  if (!difference) {
    throw new Error('Phase 2 stage failed: candidate-google-projection-other');
  }
  const detail =
    difference.field === 'contract'
      ? `contract-o${difference.oracleMatches}-c${difference.candidateMatches}`
      : `${difference.field}-o${difference.oracle}-c${difference.candidate}`;
  throw new Error(`Phase 2 stage failed: candidate-google-projection-${detail}`);
};

const commonAdditionProjectionStageFailurePattern =
  /^Phase 2 stage failed: (candidate)-((?:google-registration|wechat-web)-projection-(?:contract-o(?:true|false)-c(?:true|false)|(?:unverified-email|occupied-email|no-union-id|invalid-code|replay|malformed-provider|cross-interaction|missing-state|wrong-state|wrong-callback)-(?:status-o[1-5][0-9]{2}-c[1-5][0-9]{2}|error-o(?:connector\.(?:general|wechat_unionid_required|social_auth_code_invalid|invalid_response)|guard\.invalid_input|verification_record\.permission_denied|session\.(?:identity_conflict|verification_session_not_found)|user\.email_already_in_use|user\.missing_profile|unknown|none)-c(?:connector\.(?:general|wechat_unionid_required|social_auth_code_invalid|invalid_response)|guard\.invalid_input|verification_record\.permission_denied|session\.(?:identity_conflict|verification_session_not_found)|user\.email_already_in_use|user\.missing_profile|unknown|none))|other))$/u;
export const commonAdditionProjectionScenarioFailure = (
  kind: 'google-registration' | 'wechat-web',
  oracle: unknown,
  candidate: unknown
): never => {
  const difference =
    kind === 'google-registration'
      ? describeCommonGoogleRegistrationProjectionDifference(oracle, candidate)
      : describeCommonWechatWebProjectionDifference(oracle, candidate);
  const detail = difference
    ? difference.field === 'contract'
      ? `contract-o${difference.oracleMatches}-c${difference.candidateMatches}`
      : `${difference.field}-o${difference.oracle}-c${difference.candidate}`
    : 'other';
  const message = `Phase 2 stage failed: candidate-${kind}-projection-${detail}`;
  throw new Error(
    commonAdditionProjectionStageFailurePattern.test(message)
      ? message
      : `Phase 2 stage failed: candidate-${kind}-projection-other`
  );
};

const candidateAdminConsumerStageFailurePattern =
  /^Phase 2 stage failed: (candidate)-(admin-consumer-unknown)$/u;
const customJwtStageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(custom-jwt-(?:[0-9]|1[0-9]|2[0-3])(?::(?:http-[1-5][0-9]{2}|issuance-(?:admission|authorization|bootstrap|verification|identification|submit|bridge-(?:url|send|http-(?:[1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(?:http|body|type|access|refresh))))?|custom-jwt-fetch-[0-5]|custom-jwt-22:(?:authorize|approval-(?:authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final)|token-poll|initial-lease|refresh-request|refresh-http|jwt-verify|projection))$/u;
const customJwtFailurePattern =
  /^Phase 2 custom JWT scenario failed \(primary:([0-9]|1[0-9]|2[0-3])(?::(http-[1-5][0-9]{2}|issuance-(?:admission|authorization|bootstrap|verification|identification|submit|bridge-(?:url|send|http-(?:[1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(?:http|body|type|access|refresh))))?\)$/u;
const customJwtFetchFailurePattern =
  /^Phase 2 custom JWT fetch scenario failed \(primary:([0-5])\)$/u;
const candidateInvariantStageFailurePattern =
  /^Phase 2 stage failed: (candidate)-(invariant-legacy-[0-4]|invariant-device-(?:[0-7]|1-(?:private-code-extraction|row-sql|row-missing|row-facts|schema-query|schema-clear-columns)|2-(?:arm|abort|foreign-poll-(?:error|invalid-client|authorization-pending|status)|response|finish)|7-(?:prepare|approval|issuance|evidence-(?:open|values|validation|lease)|driver-unclassified|private-extraction|row-sql|row-facts|schema-query|schema-clear-columns|scan-(?:input|query|match)|normalized-(?:input|query|match))))$/u;
const commandFailurePattern =
  /^Phase 2 command stage failed: (oracle|candidate|differential)-(target-path|target-read|target-pair|target-verify|target-prepare|execution|harness|evidence|publish|cleanup)$/u;
const profileScenarioIdIsClosed = (value: string): boolean =>
  (clientCredentialsScenarioIds as readonly string[]).includes(value) ||
  (tokenStatusScenarioIds as readonly string[]).includes(value) ||
  (logoutSessionScenarioIds as readonly string[]).includes(value) ||
  (verificationCodeScenarioIds as readonly string[]).includes(value) ||
  (commonNativeScenarioIds as readonly string[]).includes(value) ||
  (commonEmailPasswordScenarioIds as readonly string[]).includes(value) ||
  (commonEmailCodeScenarioIds as readonly string[]).includes(value) ||
  (commonEmailCodeRegistrationScenarioIds as readonly string[]).includes(value) ||
  (commonEmailPasswordRegistrationScenarioIds as readonly string[]).includes(value) ||
  (commonPasswordRecoveryScenarioIds as readonly string[]).includes(value) ||
  (commonGoogleExistingOwnerScenarioIds as readonly string[]).includes(value) ||
  (commonWechatWebScenarioIds as readonly string[]).includes(value) ||
  (commonGoogleRegistrationScenarioIds as readonly string[]).includes(value) ||
  (commonAccountPasswordUpdateScenarioIds as readonly string[]).includes(value) ||
  (commonAccountEmailChangeScenarioIds as readonly string[]).includes(value) ||
  (commonAccountPhoneChangeScenarioIds as readonly string[]).includes(value) ||
  (commonManagementUserScenarioIds as readonly string[]).includes(value) ||
  (commonCompletionScenarioIds as readonly string[]).includes(value) ||
  (commonPhoneCodeScenarioIds as readonly string[]).includes(value) ||
  (deviceAuthorizationScenarioIds as readonly string[]).includes(value);
const candidateAdminBearerFailurePattern =
  /^Invalid Phase 2 Admin Management bearer flow \((admission|authorization|bootstrap|password|identification|submit|bridge|consent|resume|code-token|management-refresh|jwks)\)$/u;
export const withCandidateAdminBearerDiagnostic = async <Result>(
  authenticate: (
    use: (bearer: string, lease: Phase2FixtureSecretLease) => Promise<Result>
  ) => Promise<Result>,
  use: (bearer: string, lease: Phase2FixtureSecretLease) => Promise<Result>,
  deviceStage?: () => DeviceResourceRefreshFailureStage | undefined
): Promise<Result> => {
  let consumerError: unknown;
  try {
    return await authenticate(async (bearer, lease) => {
      try {
        return await use(bearer, lease);
      } catch (error: unknown) {
        consumerError = error;
        throw error;
      }
    });
  } catch (error: unknown) {
    if (
      error instanceof Error &&
      error.message === 'Invalid Phase 2 Admin Management bearer flow (consumer)'
    ) {
      const failure =
        consumerError instanceof Error
          ? customJwtFailurePattern.exec(consumerError.message)
          : undefined;
      const failureIndex = failure?.[1];
      if (failureIndex !== undefined) {
        const stage = deviceStage?.();
        throw new Error(
          failureIndex === '22' && stage !== undefined
            ? `Phase 2 stage failed: candidate-custom-jwt-22:${stage}`
            : `Phase 2 stage failed: candidate-custom-jwt-${failureIndex}${failure?.[2] ? `:${failure[2]}` : ''}`
        );
      }
      const fetchFailureIndex =
        consumerError instanceof Error
          ? customJwtFetchFailurePattern.exec(consumerError.message)?.[1]
          : undefined;
      if (fetchFailureIndex !== undefined) {
        throw new Error(`Phase 2 stage failed: candidate-custom-jwt-fetch-${fetchFailureIndex}`);
      }
      throw new Error(
        consumerError instanceof Error && consumerError.message.startsWith('Phase 2 custom JWT')
          ? 'Phase 2 stage failed: candidate-fixture'
          : 'Phase 2 stage failed: candidate-admin-consumer-unknown'
      );
    }
    const adminStage =
      error instanceof Error
        ? candidateAdminBearerFailurePattern.exec(error.message)?.[1]
        : undefined;
    throw new Error(
      adminStage
        ? `Phase 2 stage failed: candidate-admin-bearer-${adminStage}`
        : 'Phase 2 stage failed: candidate-fixture'
    );
  }
};

type CandidateFixturePhase =
  | 'provision'
  | 'readiness'
  | 'public-jwks'
  | 'cleanup-first'
  | 'cleanup-first-command'
  | 'cleanup-first-command-transport'
  | 'cleanup-first-command-timeout'
  | 'cleanup-first-command-signal'
  | 'cleanup-first-command-nonzero'
  | 'cleanup-first-command-malformed'
  | 'cleanup-first-command-response'
  | 'cleanup-first-command-unknown'
  | 'cleanup-first-ack'
  | 'cleanup-replay'
  | 'body-cleanup';
const candidateFixturePhase = (name: CandidateFixturePhase) =>
  new Error(`Phase 2 stage failed: candidate-fixture-${name}`);

type Phase2TargetFixtureOptions<Jwks, Result> = Readonly<{
  kind: 'oracle' | 'candidate';
  provisioner: Phase2FixtureProvisioner;
  waitUntilReady: (fixture: ProvisionedPhase2Fixture) => Promise<void>;
  readPublicJwks: (fixture: ProvisionedPhase2Fixture) => Promise<Jwks>;
  use: (jwks: Jwks, fixture: ProvisionedPhase2Fixture) => Promise<Result>;
}>;

export const runPhase2TargetFixture = async <Jwks, Result>({
  kind,
  provisioner,
  waitUntilReady,
  readPublicJwks,
  use,
}: Phase2TargetFixtureOptions<Jwks, Result>): Promise<Result> => {
  const cleanupState = { failed: false };
  const classifiedProvisioner =
    kind === 'candidate'
      ? {
          ...provisioner,
          provision: async () => {
            try {
              return await provisioner.provision();
            } catch {
              throw candidateFixturePhase('provision');
            }
          },
          cleanup: async (fixture: ProvisionedPhase2Fixture) => {
            try {
              await provisioner.cleanup(fixture);
            } catch (error: unknown) {
              cleanupState.failed = true;
              throw candidateFixturePhase(
                error instanceof Error && error.message.includes('replay')
                  ? 'cleanup-replay'
                  : error instanceof Error && error.message.includes('first command')
                    ? (`cleanup-first-command-${/^Phase 2 fixture cleanup first command-(transport|timeout|signal|nonzero|malformed|response|unknown) failed$/u.exec(error.message)?.[1] ?? 'unknown'}` as CandidateFixturePhase)
                    : error instanceof Error && error.message.includes('first ack')
                      ? 'cleanup-first-ack'
                      : 'cleanup-first'
              );
            }
          },
        }
      : provisioner;
  try {
    return await runWithPhase2Fixture(classifiedProvisioner, async (fixture) => {
      await waitUntilReady(fixture).catch(() => {
        throw kind === 'candidate'
          ? candidateFixturePhase('readiness')
          : new Error('Phase 2 stage failed: oracle-fixture');
      });
      const jwks = await readPublicJwks(fixture).catch(() => {
        throw kind === 'candidate'
          ? candidateFixturePhase('public-jwks')
          : new Error('Phase 2 stage failed: oracle-fixture');
      });
      return use(jwks, fixture);
    });
  } catch (error: unknown) {
    if (kind === 'candidate' && cleanupState.failed && error instanceof AggregateError) {
      throw candidateFixturePhase('body-cleanup');
    }
    throw error;
  }
};
export const closedDeviceFailureStage = (error: unknown): DeviceFailureStage | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const transport = deviceFailureStagePattern.exec(error.message)?.[1];
  if (transport) {
    return transport as DeviceFailureStage;
  }
  const usedCode = usedCodeFailureStagePattern.exec(error.message)?.[1];
  if (usedCode) {
    return usedCode as DeviceFailureStage;
  }
  if (error.message === 'Invalid Phase 2 device authorization projection') {
    return 'projection';
  }
  if (error.message === 'Invalid Phase 2 device authorization scenario') {
    return 'scenario';
  }
  return undefined;
};
const successMessages = Object.freeze({
  oracle: 'Phase 2 client credentials oracle complete.\n',
  differential: 'Phase 2 client credentials differential complete.\n',
  'candidate-invariants': 'Phase 2 client credentials candidate invariants complete.\n',
});
const maximumInputBytes = 1024 * 1024;
const fixedOutputNames = Object.freeze({
  oracle: 'phase-2-client-credentials-oracle.json',
  differential: 'phase-2-client-credentials-differential.json',
  'candidate-invariants': 'phase-2-client-credentials-candidate-invariants.json',
});

const findRepositoryRoot = (): string => {
  let current = path.dirname(fileURLToPath(import.meta.url));
  for (let remaining = 8; remaining > 0; remaining -= 1) {
    if (
      path.basename(current) === 'integration-tests' &&
      path.basename(path.dirname(current)) === 'packages'
    ) {
      return path.resolve(current, '../..');
    }
    current = path.dirname(current);
  }
  return fail();
};
const repositoryRoot = findRepositoryRoot();
const runtimeEntryPath = path.resolve(
  repositoryRoot,
  'packages/integration-tests/lib/compatibility/phase-2/cli.js'
);

const fail = (): never => {
  throw new TypeError(invalidArguments.trim());
};

export const projectDeviceResourceRefreshClaims = (
  claims: Readonly<Record<string, unknown>>,
  expected: Readonly<{ issuer: string; audience: string; subject: string; clientId: string }>
) =>
  Object.freeze({
    invoked: claims.probe_invoked === true,
    userContextPresent: claims.probe_user_context_present === true,
    applicationContextPresent: claims.probe_application_context_present === true,
    userMatchesToken:
      claims.probe_user_matches_token === true &&
      claims.probe_user_id === expected.subject &&
      claims.probe_token_account_id === expected.subject,
    applicationMatchesToken:
      claims.probe_application_matches_token === true &&
      claims.probe_application_id === expected.clientId &&
      claims.probe_token_client_id === expected.clientId,
    protectedClaimsMatch:
      claims.iss === expected.issuer &&
      claims.aud === expected.audience &&
      claims.sub === expected.subject &&
      claims.client_id === expected.clientId,
    tokenKind: claims.probe_token_kind === 'AccessToken' ? 'access_token' : null,
    grantType:
      claims.probe_grant_type === 'device_code refresh_token' ? 'device_code refresh_token' : null,
  });

const invalidDeviceResourceRefreshContext =
  'Invalid Phase 2 custom JWT device resource refresh context';

export const observeDeviceResourceRefreshContext = async (
  input: Readonly<{
    refreshRequest: DeviceLifecycleRequest & Readonly<{ kind: 'refresh' }>;
    expected: Readonly<{ issuer: string; audience: string; subject: string; clientId: string }>;
    transport: Readonly<{
      withCredentialLease<Result>(
        use: (lease: DeviceCredentialLease) => Result | Promise<Result>
      ): Promise<Result>;
      requestLifecycle(
        request: DeviceLifecycleRequest & Readonly<{ kind: 'refresh' }>
      ): Promise<Readonly<{ status: number }>>;
      clear(): void;
    }>;
    approveAuthorization(): Promise<void>;
    pollToken(): Promise<void>;
    verifyAccessToken(token: string): Promise<Readonly<Record<string, unknown>>>;
    recordStage(stage: DeviceResourceRefreshFailureStage): void;
  }>
) => {
  try {
    try {
      input.recordStage('authorize');
      try {
        await input.approveAuthorization();
      } catch (error: unknown) {
        const approvalStage = closedDeviceFailureStage(error);
        if (approvalStage?.startsWith('approval-') === true) {
          input.recordStage(approvalStage as Extract<DeviceFailureStage, `approval-${string}`>);
        }
        throw new TypeError(invalidDeviceResourceRefreshContext);
      }
      input.recordStage('token-poll');
      await input.pollToken();
      input.recordStage('initial-lease');
      const initialAccessOpaque = await input.transport.withCredentialLease(async (lease) => {
        const access = lease.getAccessToken();
        const refresh = lease.getRefreshToken();
        return (
          typeof access === 'string' &&
          access.split('.').length !== 3 &&
          typeof refresh === 'string' &&
          refresh.length > 0
        );
      });
      input.recordStage('refresh-request');
      const refreshed = await input.transport.requestLifecycle(input.refreshRequest);
      input.recordStage('refresh-http');
      if (refreshed.status !== 200) {
        throw new TypeError(invalidDeviceResourceRefreshContext);
      }
      input.recordStage('jwt-verify');
      const claims = await input.transport.withCredentialLease(async (lease) => {
        const access = lease.getAccessToken() ?? fail();
        return input.verifyAccessToken(access);
      });
      input.recordStage('projection');
      const projected = projectDeviceResourceRefreshClaims(claims, input.expected);
      return Object.freeze({
        status: refreshed.status,
        initialAccessOpaque,
        ...projected,
      });
    } finally {
      input.transport.clear();
    }
  } catch {
    throw new TypeError(invalidDeviceResourceRefreshContext);
  }
};

const parseFlagMap = (
  values: readonly string[],
  allowed: ReadonlySet<string>
): ReadonlyMap<string, string> => {
  if (values.length !== allowed.size * 2) {
    return fail();
  }
  const result = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (
      !name ||
      !value ||
      name.includes('=') ||
      !allowed.has(name) ||
      result.has(name) ||
      value.startsWith('--') ||
      /\p{Cc}/u.test(value) ||
      Buffer.byteLength(value) > 4096
    ) {
      return fail();
    }
    result.set(name, value);
  }
  return result;
};

const required = (values: ReadonlyMap<string, string>, name: string): string =>
  values.get(name) ?? fail();

export const parsePhase2Arguments = (arguments_: readonly string[]): Phase2CliCommand => {
  const [mode, ...rest] = arguments_;
  if (mode === 'oracle' || mode === 'candidate-invariants') {
    const values = parseFlagMap(
      rest,
      new Set(['--profile', '--schema', '--target', '--output', '--temp-root'])
    );
    return Object.freeze({
      mode,
      profilePath: required(values, '--profile'),
      schemaPath: required(values, '--schema'),
      targetPath: required(values, '--target'),
      outputPath: required(values, '--output'),
      tempRoot: required(values, '--temp-root'),
    });
  }
  if (mode === 'differential') {
    const values = parseFlagMap(
      rest,
      new Set([
        '--profile',
        '--schema',
        '--oracle-evidence',
        '--candidate-target',
        '--output',
        '--temp-root',
      ])
    );
    return Object.freeze({
      mode,
      profilePath: required(values, '--profile'),
      schemaPath: required(values, '--schema'),
      oracleEvidencePath: required(values, '--oracle-evidence'),
      candidateTargetPath: required(values, '--candidate-target'),
      outputPath: required(values, '--output'),
      tempRoot: required(values, '--temp-root'),
    });
  }
  return fail();
};

const currentUid = (): number => {
  const uid = process.getuid?.();
  return typeof uid === 'number' ? uid : fail();
};

const validatePrivateRoot = async (value: string): Promise<string> => {
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.uid !== currentUid() ||
    (state.mode & 0o777) !== 0o700 ||
    resolved !== value
  ) {
    return fail();
  }
  return value;
};

const validateInputFile = async (value: string): Promise<string> => {
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.size > maximumInputBytes ||
    resolved !== value
  ) {
    return fail();
  }
  return value;
};

const validateOutputPath = async (
  mode: Phase2CliCommand['mode'],
  outputPath: string,
  temporaryRoot: string
): Promise<string> => {
  if (
    !path.isAbsolute(outputPath) ||
    path.normalize(outputPath) !== outputPath ||
    path.dirname(outputPath) !== temporaryRoot ||
    path.basename(outputPath) !== fixedOutputNames[mode]
  ) {
    return fail();
  }
  try {
    await lstat(outputPath);
    return fail();
  } catch (error: unknown) {
    if (
      typeof error !== 'object' ||
      error === null ||
      Object.getOwnPropertyDescriptor(error, 'code')?.value !== 'ENOENT'
    ) {
      return fail();
    }
  }
  return outputPath;
};

const inspectJsonNode = (node: JsonNode | undefined): void => {
  if (!node) {
    return fail();
  }
  if (node.type === 'object') {
    const names = new Set<string>();
    for (const property of node.children ?? []) {
      const [nameNode, valueNode] = property.children ?? [];
      const name: unknown = nameNode?.value;
      if (typeof name !== 'string' || names.has(name)) {
        return fail();
      }
      names.add(name);
      inspectJsonNode(valueNode);
    }
  } else if (node.type === 'array') {
    for (const child of node.children ?? []) {
      inspectJsonNode(child);
    }
  }
};

const parseStrictJsonBytes = (bytes: Uint8Array): unknown => {
  const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  const errors: ParseError[] = [];
  const tree = parseTree(text, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });
  if (!tree || errors.length > 0) {
    return fail();
  }
  inspectJsonNode(tree);
  return JSON.parse(text) as unknown;
};

const readStrictJson = async (filePath: string): Promise<unknown> => {
  const [before, resolved] = await Promise.all([lstat(filePath), realpath(filePath)]).catch(fail);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.size > maximumInputBytes ||
    resolved !== filePath
  ) {
    return fail();
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const state = await handle.stat();
    if (
      !state.isFile() ||
      state.size > maximumInputBytes ||
      state.dev !== before.dev ||
      state.ino !== before.ino
    ) {
      return fail();
    }
    const bytes = new Uint8Array(state.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead <= 0) {
        return fail();
      }
      offset += bytesRead;
    }
    const [openedAfter, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]);
    if (
      openedAfter.dev !== state.dev ||
      openedAfter.ino !== state.ino ||
      openedAfter.size !== state.size ||
      openedAfter.mtimeMs !== state.mtimeMs ||
      pathAfter.isSymbolicLink() ||
      pathAfter.dev !== state.dev ||
      pathAfter.ino !== state.ino ||
      pathAfter.size !== state.size ||
      pathAfter.mtimeMs !== state.mtimeMs
    ) {
      return fail();
    }
    return parseStrictJsonBytes(bytes);
  } finally {
    await handle.close();
  }
};

export const readPhase2TargetDescriptor = async (
  filePath: string
): Promise<Phase2TargetDescriptor> =>
  validatePhase2TargetDescriptor(await readStrictJson(await validateInputFile(filePath)));

const readPrivateOracleArtifact = async (filePath: string): Promise<unknown> => {
  if (!path.isAbsolute(filePath) || path.normalize(filePath) !== filePath) {
    return fail();
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.uid !== currentUid() ||
      (before.mode & 0o777) !== 0o600 ||
      before.nlink !== 1 ||
      before.size <= 0 ||
      before.size > maximumInputBytes
    ) {
      return fail();
    }
    const bytes = new Uint8Array(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead <= 0) {
        return fail();
      }
      offset += bytesRead;
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]).catch(fail);
    if (
      !after.isFile() ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.uid !== before.uid ||
      after.mode !== before.mode ||
      after.nlink !== before.nlink ||
      after.size !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ctimeMs !== before.ctimeMs ||
      pathAfter.isSymbolicLink() ||
      pathAfter.dev !== before.dev ||
      pathAfter.ino !== before.ino ||
      pathAfter.uid !== before.uid ||
      pathAfter.mode !== before.mode ||
      pathAfter.nlink !== before.nlink ||
      pathAfter.size !== before.size ||
      pathAfter.mtimeMs !== before.mtimeMs ||
      pathAfter.ctimeMs !== before.ctimeMs
    ) {
      return fail();
    }
    return parseStrictJsonBytes(bytes);
  } finally {
    await handle.close();
  }
};

export const readPhase2OracleArtifact = async (
  filePath: string,
  profile: Phase2ProfileRegistries,
  harness: Phase2SourceIdentity
): Promise<Phase2EvidenceEnvelope> =>
  validatePhase2OracleArtifact(await readPrivateOracleArtifact(filePath), profile, harness);

const projectDiscovery = async (
  descriptor: Phase2TargetDescriptor,
  profile: Phase2ProfileRegistries
): Promise<TargetScenarioEvidence['discovery']> => {
  assertDiscoveryAppendContract(profile.discovery);
  const discovery = await fetchPhase2Discovery(descriptor.target);
  const grantTypes = assertDiscoveryGrantContract(
    discovery.grant_types_supported,
    profile.discovery.grantTypesSupportedAppend,
    descriptor.kind
  );
  return Object.freeze({
    grantTypesSupported: grantTypes,
    endpointFieldsAppend: assertDiscoveryEndpointFieldsContract(
      discovery,
      profile.discovery.endpointFieldsAppend,
      new URL('oidc', descriptor.target.coreUrl).toString()
    ),
    scopesSupportedAppend: assertDiscoveryScopeAppendContract(
      discovery.scopes_supported,
      profile.discovery.scopesSupportedAppend,
      descriptor.kind
    ),
    stillAbsent: assertDiscoveryAbsentFieldsContract(
      discovery,
      profile.discovery.stillAbsent,
      descriptor.kind
    ),
  });
};

export const phase2FixtureRecipeForMode = (
  mode: Phase2CliCommand['mode']
): Phase2CandidateFixtureRecipe =>
  mode === 'candidate-invariants' ? 'phase2CandidateInvariants' : 'fullPhase1';

const provisionerFor = (
  prepared: PreparedPhase2Target,
  recipe: Phase2CandidateFixtureRecipe
): Phase2FixtureProvisioner => {
  const { descriptor } = prepared;
  return descriptor.kind === 'oracle'
    ? createReferencePhase2FixtureProvisioner({
        target: descriptor.target,
        foreignTarget: descriptor.foreignTarget,
      })
    : createCandidatePhase2FixtureProvisioner({
        executablePath: descriptor.fixtureExecutable?.path ?? fail(),
        target: descriptor.target,
        foreignTarget: descriptor.foreignTarget,
        environment: {
          ASTER_FIXTURE_SOCKET: descriptor.fixtureSocket,
        },
        identityFence: prepared.fence,
        recipe,
      });
};

const publicTargetProvenance = (verified: VerifiedPhase2Target): Phase2TargetProvenance =>
  Object.freeze({
    sourceCommit: verified.descriptor.sourceCommit,
    imageDigest: verified.descriptor.imageDigest,
    topology: Object.freeze({
      primaryRole: verified.topology.primary.service,
      foreignRole: verified.topology.foreign.service,
    }),
    drivers: Object.freeze({
      state: Object.freeze({ role: 'state-driver', sha256: verified.stateDriver.sha256 }),
      ...(verified.fixtureExecutable && {
        fixture: Object.freeze({
          role: 'fixture-executable' as const,
          sha256: verified.fixtureExecutable.sha256,
        }),
      }),
      ...(verified.invariantDriver && {
        invariant: Object.freeze({
          role: 'invariant-driver' as const,
          sha256: verified.invariantDriver.sha256,
        }),
      }),
    }),
  });

const runTargetScenarios = async (
  profile: Phase2ProfileRegistries,
  prepared: PreparedPhase2Target
): Promise<TargetScenarioEvidence> => {
  const { descriptor } = prepared;
  const state = await createCommandPhase2ScenarioStateDriver({
    descriptor,
    identityFence: prepared.fence,
  });
  const jwtAudit = createClientCredentialsJwtAudit();
  const provisioner = provisionerFor(prepared, phase2FixtureRecipeForMode('differential'));
  const collectScenarios = async (
    jwks: Awaited<ReturnType<typeof fetchPhase2PublicJwks>>,
    fixture: ProvisionedPhase2Fixture
  ) => {
    const results: ClientCredentialsScenarioResult[] = [];
    for (const scenario of createClientCredentialsScenarioRegistry(profile)) {
      try {
        results.push(
          await scenario.run({
            target: descriptor.target,
            fixture,
            jwks,
            state,
            jwtAudit,
          })
        );
      } catch {
        throw new Error(`Phase 2 scenario failed: ${descriptor.kind}/${scenario.id}`);
      }
    }
    let statusScenarios: readonly TokenStatusScenarioResult[];
    try {
      statusScenarios = await runTokenStatusScenarios(profile, descriptor.target, fixture);
    } catch (error: unknown) {
      if (error instanceof Error && scenarioFailurePattern.test(error.message)) {
        throw error;
      }
      const step =
        error instanceof Error
          ? /^Invalid Phase 2 public user token issuance \((admission|authorization|bootstrap|verification|identification|submit|bridge-(?:url|send|http-(?:[1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(?:http|body|type|access|refresh))\)$/u.exec(
              error.message
            )?.[1]
          : undefined;
      throw new Error(
        'Phase 2 stage failed: ' + descriptor.kind + '-status-' + (step ?? 'introspection')
      );
    }
    let logoutSessionScenarios: readonly LogoutSessionScenarioResult[];
    try {
      logoutSessionScenarios = await runLogoutSessionScenarios(profile, descriptor.target, fixture);
    } catch (error: unknown) {
      if (error instanceof Error && scenarioFailurePattern.test(error.message)) {
        throw error;
      }
      throw new Error(`Phase 2 stage failed: ${descriptor.kind}-logout-session`);
    }
    let verificationCodeScenarios: readonly VerificationCodeScenarioResult[];
    try {
      verificationCodeScenarios = await runVerificationCodeScenarios(
        profile,
        await createVerificationCodeScenarioRuntime(descriptor.target, fixture)
      );
    } catch (error: unknown) {
      if (error instanceof VerificationCodeScenarioFailure) {
        throw new TypeError(`Phase 2 scenario failed: ${descriptor.kind}/${error.scenarioId}`);
      }
      if (error instanceof Error && scenarioFailurePattern.test(error.message)) {
        throw error;
      }
      throw new Error(`Phase 2 stage failed: ${descriptor.kind}-verification-code`);
    }
    let commonNativeScenarios: readonly CommonNativeScenarioResult[];
    try {
      const scenario = createCommonNativeScenarioRegistry(profile)[0];
      const run = async (
        managementRequest: Phase2AdminRequestFunction,
        getSelectedNativePassword?: () => string
      ) =>
        scenario.run({
          target: descriptor.target,
          fixture,
          managementRequest,
          jwks,
          ...(getSelectedNativePassword && { getSelectedNativePassword }),
        });
      const result =
        descriptor.kind === 'candidate'
          ? await withCandidateAdminBearerDiagnostic<CommonNativeScenarioResult>(
              async (use) => withPhase2AdminManagementBearer(descriptor.target, fixture, use),
              async (bearer, lease) =>
                run(
                  createBearerPhase2AdminRequest(descriptor.target, bearer),
                  lease.getSelectedNativePassword ?? fail()
                )
            )
          : await run(createReferencePhase2AdminRequest(descriptor.target));
      commonNativeScenarios = Object.freeze([result]);
    } catch (error: unknown) {
      if (
        descriptor.kind === 'candidate' &&
        error instanceof Error &&
        candidateAdminBearerStageFailurePattern.test(error.message)
      ) {
        throw error;
      }
      throw new Error(`Phase 2 scenario failed: ${descriptor.kind}/${commonNativeScenarioIds[0]}`);
    }
    const commonEmailPasswordScenario = await runCommonEmailPasswordScenarioRow({
      target: descriptor.target,
      fixture,
      observer: createPlaywrightBrowserGroupObserver(loadChromium()),
      signal: AbortSignal.timeout(300_000),
    }).catch((error: unknown) => commonEmailPasswordScenarioFailure(descriptor.kind, error));
    const commonEmailCodeScenario = await runCommonEmailCodeScenarioRow({
      target: descriptor.target,
      fixture,
      observer: createPlaywrightBrowserGroupObserver(loadChromium()),
      signal: AbortSignal.timeout(420_000),
    }).catch((error: unknown) => commonEmailCodeScenarioFailure(descriptor.kind, error));
    const commonEmailCodeRegistrationScenario = await runCommonEmailCodeRegistrationScenarioRow({
      target: descriptor.target,
      fixture,
      observer: createPlaywrightBrowserGroupObserver(loadChromium()),
      signal: AbortSignal.timeout(600_000),
    }).catch((error: unknown) =>
      commonEmailCodeRegistrationScenarioFailure(descriptor.kind, error)
    );
    const commonEmailPasswordRegistrationScenario =
      await runCommonEmailPasswordRegistrationScenarioRow({
        target: descriptor.target,
        fixture,
        observer: createPlaywrightBrowserGroupObserver(loadChromium()),
        signal: AbortSignal.timeout(600_000),
      }).catch((error: unknown) =>
        commonReadyScenarioFailure(
          descriptor.kind,
          commonEmailPasswordRegistrationScenarioIds[0],
          error
        )
      );
    const commonPasswordRecoveryScenario = await runCommonPasswordRecoveryScenarioRow({
      target: descriptor.target,
      fixture,
      observer: createPlaywrightBrowserGroupObserver(loadChromium()),
      signal: AbortSignal.timeout(600_000),
    }).catch((error: unknown) =>
      commonReadyScenarioFailure(descriptor.kind, commonPasswordRecoveryScenarioIds[0], error)
    );
    const commonGoogleExistingOwnerScenario = await (async () => {
      const providerPath =
        descriptor.kind === 'oracle'
          ? process.env.ASTER_PHASE2_ORACLE_GOOGLE_PROVIDER_INPUT
          : process.env.ASTER_PHASE2_CANDIDATE_GOOGLE_PROVIDER_INPUT;
      if (!providerPath) {
        throw new Error('Missing Common Google provider fixture');
      }
      const runtime = await readCommonGoogleExistingOwnerFixtureRuntime(
        providerPath,
        descriptor.stateDriver.controlSocket
      );
      const googleFixture = Object.freeze({
        public: fixture.public,
        ...(fixture.status && { status: fixture.status }),
        ...(fixture.verificationPeer && { verificationPeer: fixture.verificationPeer }),
        withSecretLease: async <Result>(
          use: (lease: Phase2FixtureSecretLease) => Promise<Result>
        ) => fixture.withSecretLease(use),
        commonGoogleExistingOwner: runtime,
      });
      return runCommonGoogleExistingOwnerScenarioRow({
        target: descriptor.target,
        fixture: googleFixture,
        observer: createPlaywrightBrowserGroupObserver(loadChromium()),
        signal: AbortSignal.timeout(900_000),
      });
    })().catch((error: unknown) =>
      commonReadyScenarioFailure(descriptor.kind, commonGoogleExistingOwnerScenarioIds[0], error)
    );
    const commonGoogleRegistrationScenario = await (async () => {
      const providerPath =
        descriptor.kind === 'oracle'
          ? process.env.ASTER_PHASE2_ORACLE_GOOGLE_PROVIDER_INPUT
          : process.env.ASTER_PHASE2_CANDIDATE_GOOGLE_PROVIDER_INPUT;
      if (!providerPath) {
        throw new Error('Missing Common GoogleRegistration provider fixture');
      }
      const runtime = await readCommonGoogleRegistrationFixtureRuntime(
        providerPath,
        descriptor.stateDriver.controlSocket
      );
      const providerFixture = Object.freeze({
        public: fixture.public,
        ...(fixture.status && { status: fixture.status }),
        ...(fixture.verificationPeer && { verificationPeer: fixture.verificationPeer }),
        withSecretLease: async <Result>(
          use: (lease: Phase2FixtureSecretLease) => Promise<Result>
        ) => fixture.withSecretLease(use),
        commonGoogleRegistration: runtime,
      });
      return runCommonGoogleRegistrationScenarioRow({
        target: descriptor.target,
        fixture: providerFixture,
        observer: createPlaywrightBrowserGroupObserver(loadChromium()),
        signal: AbortSignal.timeout(1_200_000),
      });
    })().catch((error: unknown) =>
      commonReadyScenarioFailure(descriptor.kind, commonGoogleRegistrationScenarioIds[0], error)
    );
    const commonWechatWebScenario = await (async () => {
      const providerPath =
        descriptor.kind === 'oracle'
          ? process.env.ASTER_PHASE2_ORACLE_WECHAT_PROVIDER_INPUT
          : process.env.ASTER_PHASE2_CANDIDATE_WECHAT_PROVIDER_INPUT;
      if (!providerPath) {
        throw new Error('Missing Common WechatWeb provider fixture');
      }
      const runtime = await readCommonWechatWebFixtureRuntime(
        providerPath,
        descriptor.stateDriver.controlSocket
      );
      const providerFixture = Object.freeze({
        public: fixture.public,
        ...(fixture.status && { status: fixture.status }),
        ...(fixture.verificationPeer && { verificationPeer: fixture.verificationPeer }),
        withSecretLease: async <Result>(
          use: (lease: Phase2FixtureSecretLease) => Promise<Result>
        ) => fixture.withSecretLease(use),
        commonWechatWeb: runtime,
      });
      return runCommonWechatWebScenarioRow({
        target: descriptor.target,
        fixture: providerFixture,
        observer: createPlaywrightBrowserGroupObserver(loadChromium()),
        signal: AbortSignal.timeout(1_200_000),
      });
    })().catch((error: unknown) =>
      commonReadyScenarioFailure(descriptor.kind, commonWechatWebScenarioIds[0], error)
    );
    const commonAccountPasswordUpdateScenario = await runCommonAccountPasswordUpdateScenarioRow({
      target: descriptor.target,
      fixture,
      signal: AbortSignal.timeout(1_200_000),
    }).catch((error: unknown) =>
      commonReadyScenarioFailure(descriptor.kind, commonAccountPasswordUpdateScenarioIds[0], error)
    );
    const commonAccountEmailChangeScenario = await runCommonAccountEmailChangeScenarioRow({
      target: descriptor.target,
      fixture,
      signal: AbortSignal.timeout(1_200_000),
    }).catch((error: unknown) =>
      commonReadyScenarioFailure(descriptor.kind, commonAccountEmailChangeScenarioIds[0], error)
    );
    const commonPhoneCodeScenarios: CommonPhoneCodeScenarioResult[] = [];
    for (const scenario of ['registration', 'sign-in'] as const) {
      const id = commonPhoneCodeScenarioIds[scenario === 'registration' ? 0 : 1];
      try {
        const inputFile =
          descriptor.kind === 'oracle'
            ? process.env.ASTER_PHASE2_ORACLE_SMS_PROVIDER_INPUT
            : process.env.ASTER_PHASE2_CANDIDATE_SMS_PROVIDER_INPUT;
        if (!inputFile) {
          throw new TypeError('Missing Common phone provider fixture');
        }
        commonPhoneCodeScenarios.push(
          await runCommonPhoneCodeScenarioRow({
            scenario,
            target: descriptor.target,
            fixture,
            observer: createPlaywrightBrowserGroupObserver(loadChromium()),
            signal: AbortSignal.timeout(600_000),
            withProviderLease: async (use) => withSmsProviderLease(inputFile, use),
          })
        );
      } catch (error: unknown) {
        commonPhoneScenarioFailure(descriptor.kind, id, error);
      }
    }
    const commonAccountPhoneChangeScenario = await (async () => {
      const inputFile =
        descriptor.kind === 'oracle'
          ? process.env.ASTER_PHASE2_ORACLE_SMS_PROVIDER_INPUT
          : process.env.ASTER_PHASE2_CANDIDATE_SMS_PROVIDER_INPUT;
      if (!inputFile) {
        throw new TypeError('Missing Common phone provider fixture');
      }
      return runCommonAccountPhoneChangeScenarioRow({
        target: descriptor.target,
        fixture,
        observer: createPlaywrightBrowserGroupObserver(loadChromium()),
        signal: AbortSignal.timeout(1_200_000),
        withProviderLease: async (use) => withSmsProviderLease(inputFile, use),
      });
    })().catch((error: unknown) => commonAccountPhoneChangeScenarioFailure(descriptor.kind, error));
    const commonManagementUserScenarios: CommonManagementUserScenarioResult[] = [];
    for (const id of commonManagementUserScenarioIds) {
      try {
        commonManagementUserScenarios.push(
          await runCommonManagementUserScenarioRow({
            id,
            target: descriptor.target,
            fixture,
            jwks,
            signal: AbortSignal.timeout(1_200_000),
          })
        );
      } catch (error: unknown) {
        commonManagementScenarioFailure(descriptor.kind, id, error);
      }
    }
    const deviceScenarios: DeviceAuthorizationScenarioResult[] = [];
    for (const scenario of createDeviceAuthorizationScenarioRegistry(profile)) {
      try {
        deviceScenarios.push(
          await scenario.run({
            target: descriptor.target,
            fixture,
            jwks,
            state,
          })
        );
      } catch (error: unknown) {
        const stage = closedDeviceFailureStage(error);
        throw new Error(
          `Phase 2 scenario failed: ${descriptor.kind}/${scenario.id}${stage ? `:${stage}` : ''}`
        );
      }
    }
    let customJwtScenarios: readonly CustomJwtScenarioEvidence[];
    let customJwtFetchScenarios: readonly CustomJwtFetchScenarioEvidence[];
    let deviceFailureStage: DeviceResourceRefreshFailureStage | undefined;
    try {
      const collect = async (
        authorizationHeaders: Readonly<Record<string, string>>,
        clientSecret: string,
        subjectPassword: string
      ) => {
        const port = createCustomJwtHttpPort({
          assertInvocationFence: async () => prepared.fence.assertStable(),
          managementRequest: async ({ method, path: requestPath, body, signal }) => {
            if (
              ![
                'configs/jwt-customizer',
                'configs/jwt-customizer/client-credentials',
                'configs/jwt-customizer/access-token',
                'configs/jwt-customizer/test',
                'configs/jwt-customizer/unknown-token-type',
              ].includes(requestPath)
            ) {
              return fail();
            }
            return requestPhase2Json({
              url: new URL(`/api/${requestPath}`, descriptor.target.coreUrl),
              method,
              headers: {
                ...authorizationHeaders,
                ...(body === undefined ? {} : { 'content-type': 'application/json' }),
              },
              ...(body === undefined ? {} : { body: JSON.stringify(body) }),
              signal,
            });
          },
          withM2MSecret: async (use) => use(clientSecret),
          issueClientCredentials: async ({ clientSecret, signal }) => {
            const body = new URLSearchParams({
              grant_type: 'client_credentials',
              resource: fixture.public.resources.primary.indicator,
              scope: 'read write',
            });
            return requestPhase2Json({
              url: new URL('oidc/token', descriptor.target.coreUrl),
              method: 'POST',
              headers: {
                authorization: `Basic ${Buffer.from(
                  `${fixture.public.clients.basic.id}:${clientSecret}`
                ).toString('base64')}`,
                'content-type': 'application/x-www-form-urlencoded',
              },
              body,
              signal,
            });
          },
          verifyAccessToken: async (token) => {
            const verified = await jwtVerify(token, createLocalJWKSet(jwks));
            return Object.freeze({ ...verified.payload });
          },
          issueUserTokens: async ({ signal }) => {
            const issued = await issuePublicUserResourceTokensWithPassword(
              descriptor.target,
              fixture,
              subjectPassword,
              signal
            );
            return Object.freeze({ access: issued.access, refresh: issued.refresh });
          },
          exchangeUserRefresh: async ({ refreshToken, signal }) => {
            const status = fixture.status ?? fail();
            return requestPhase2Json({
              url: new URL('/oidc/token', descriptor.target.coreUrl),
              method: 'POST',
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: status.client.id,
                resource: status.resource.indicator,
              }),
              signal,
            });
          },
          observeDeviceResourceRefresh: async () => {
            const transport = createDeviceAuthorizationTransportLease({
              target: descriptor.target,
            });
            const resource = fixture.public.resources.primary.indicator;
            return observeDeviceResourceRefreshContext({
              transport,
              approveAuthorization: async () => {
                await approveDeviceAuthorization(
                  transport,
                  { target: descriptor.target, fixture, jwks, state },
                  {
                    client: 'firstParty',
                    scope: 'openid offline_access read',
                    resource,
                    traceUsedCodeApproval: true,
                    withSubjectPassword: async (use) => use(subjectPassword),
                  }
                );
              },
              pollToken: async () => {
                await transport.pollToken({
                  proof: {
                    method: 'public',
                    clientId: fixture.public.deviceClients.firstParty.id,
                  },
                });
              },
              verifyAccessToken: async (access) => {
                const verified = await jwtVerify(access, createLocalJWKSet(jwks));
                return verified.payload;
              },
              refreshRequest: {
                kind: 'refresh',
                method: 'POST',
                proof: {
                  method: 'public',
                  clientId: fixture.public.deviceClients.firstParty.id,
                },
                resource,
                scope: 'read',
              },
              expected: {
                issuer: new URL('oidc', descriptor.target.coreUrl).toString(),
                audience: resource,
                subject: fixture.status?.user.id ?? fail(),
                clientId: fixture.public.deviceClients.firstParty.id,
              },
              recordStage: (stage) => {
                deviceFailureStage = stage;
              },
            });
          },
          readAndResetFetchReceipts: async ({ accept }) =>
            readAndResetPhase2FetchReceipts(prepared, accept),
        });
        const standard = await runCustomJwtScenarios(port, {
          expected: {
            issuer: new URL('oidc', descriptor.target.coreUrl).toString(),
            subject: fixture.public.clients.basic.id,
            audience: fixture.public.resources.primary.indicator,
            clientId: fixture.public.clients.basic.id,
            scope: 'read write',
            userSubject: fixture.status?.user.id ?? fail(),
            userClientId: fixture.status?.client.id ?? fail(),
            userApplicationName: fixture.status?.client.name ?? fail(),
            userAudience: fixture.status?.resource.indicator ?? fail(),
            userScope: fixture.status?.resource.scopeName ?? fail(),
          },
        });
        const fetch = await runCustomJwtFetchScenarios(port);
        return Object.freeze({ standard, fetch });
      };
      const collected =
        descriptor.kind === 'candidate'
          ? await withCandidateAdminBearerDiagnostic<Awaited<ReturnType<typeof collect>>>(
              async (use) => withPhase2AdminManagementBearer(descriptor.target, fixture, use),
              async (bearer, lease) =>
                collect(
                  { authorization: `Bearer ${bearer}` },
                  lease.getClientSecret('basic'),
                  lease.getSubjectPassword?.() ?? fail()
                ),
              () => deviceFailureStage
            )
          : await fixture.withSecretLease(async (lease) =>
              collect(
                { 'development-user-id': 'integration-test-admin-user' },
                lease.getClientSecret('basic'),
                lease.getSubjectPassword?.() ?? fail()
              )
            );
      customJwtScenarios = collected.standard;
      customJwtFetchScenarios = collected.fetch;
    } catch (error: unknown) {
      if (descriptor.kind === 'candidate') {
        if (
          error instanceof Error &&
          (customJwtStageFailurePattern.test(error.message) ||
            candidateAdminBearerStageFailurePattern.test(error.message) ||
            error.message === 'Phase 2 stage failed: candidate-admin-consumer-unknown' ||
            error.message === 'Phase 2 stage failed: candidate-fixture')
        ) {
          throw error;
        }
        throw new Error('Phase 2 stage failed: candidate-fixture');
      }
      const failure =
        error instanceof Error ? customJwtFailurePattern.exec(error.message) : undefined;
      const failureIndex = failure?.[1];
      if (failureIndex !== undefined) {
        if (failureIndex === '22' && deviceFailureStage !== undefined) {
          throw new Error(
            `Phase 2 stage failed: ${descriptor.kind}-custom-jwt-22:${deviceFailureStage}`
          );
        }
        throw new Error(
          `Phase 2 stage failed: ${descriptor.kind}-custom-jwt-${failureIndex}${failure?.[2] ? `:${failure[2]}` : ''}`
        );
      }
      const fetchFailureIndex =
        error instanceof Error ? customJwtFetchFailurePattern.exec(error.message)?.[1] : undefined;
      if (fetchFailureIndex !== undefined) {
        throw new Error(
          `Phase 2 stage failed: ${descriptor.kind}-custom-jwt-fetch-${fetchFailureIndex}`
        );
      }
      throw new Error(`Phase 2 stage failed: ${descriptor.kind}-custom-jwt`);
    }
    const commonCompletionScenarios = await (async () => {
      const runtimeFile =
        descriptor.kind === 'oracle'
          ? process.env.ASTER_PHASE2_ORACLE_COMPLETION_INPUT
          : process.env.ASTER_PHASE2_CANDIDATE_COMPLETION_INPUT;
      if (!runtimeFile) {
        throw new TypeError('Missing Common completion fixture');
      }
      return runBoundCommonCompletionScenarios({
        target: descriptor.target,
        fixture,
        jwks,
        browserType: loadChromium(),
        runtimeFile,
        controlSocket: descriptor.stateDriver.controlSocket,
        signal: AbortSignal.timeout(1_620_000),
      });
    })().catch((error: unknown) => {
      return commonCompletionFailure(descriptor.kind, error);
    });
    return Object.freeze([
      ...results,
      ...statusScenarios,
      ...logoutSessionScenarios,
      ...deviceScenarios,
      ...customJwtScenarios,
      ...customJwtFetchScenarios,
      ...verificationCodeScenarios,
      ...commonNativeScenarios,
      commonEmailPasswordScenario,
      commonEmailCodeScenario,
      commonEmailCodeRegistrationScenario,
      commonEmailPasswordRegistrationScenario,
      commonPasswordRecoveryScenario,
      commonGoogleExistingOwnerScenario,
      commonGoogleRegistrationScenario,
      commonWechatWebScenario,
      commonAccountPasswordUpdateScenario,
      commonAccountEmailChangeScenario,
      ...commonPhoneCodeScenarios,
      commonAccountPhoneChangeScenario,
      ...commonManagementUserScenarios,
      ...commonCompletionScenarios,
    ]);
  };
  const scenarios = await runPhase2TargetFixture({
    kind: descriptor.kind,
    provisioner,
    waitUntilReady: async (fixture) =>
      waitForClientCredentialsFixtureReady(descriptor.target, fixture.public),
    readPublicJwks: async () => fetchPhase2PublicJwks(descriptor.target),
    use: collectScenarios,
  }).catch((error: unknown) => {
    const phoneFailure = closedCommonPhoneFailure(error);
    if (phoneFailure) {
      throw phoneFailure;
    }
    if (
      error instanceof Error &&
      (scenarioFailurePattern.test(error.message) ||
        customJwtStageFailurePattern.test(error.message) ||
        candidateAdminBearerStageFailurePattern.test(error.message) ||
        candidateAdminConsumerStageFailurePattern.test(error.message) ||
        commonReadyStageFailurePattern.test(error.message) ||
        accountReadyStageFailurePattern.test(error.message) ||
        commonManagementReadyStageFailurePattern.test(error.message) ||
        googleProjectionStageFailurePattern.test(error.message) ||
        commonAdditionProjectionStageFailurePattern.test(error.message) ||
        commonPhoneStageFailurePattern.test(error.message) ||
        stageFailurePattern.test(error.message))
    ) {
      throw error;
    }
    throw descriptor.kind === 'candidate'
      ? new Error('Phase 2 stage failed: candidate-fixture')
      : new Error('Phase 2 stage failed: oracle-fixture');
  });
  const success = scenarios.find(
    ({ id }) => id === 'client-credentials.organization-resource-scope'
  )?.projection;
  const authenticationError = scenarios.find(
    ({ id }) => id === 'client-credentials.wrong-secret-basic'
  )?.projection;
  if (
    !success ||
    !authenticationError ||
    typeof success !== 'object' ||
    typeof authenticationError !== 'object' ||
    'kind' in success ||
    'kind' in authenticationError
  ) {
    return fail();
  }
  const discovery = await projectDiscovery(descriptor, profile).catch(() => {
    throw new Error(`Phase 2 stage failed: ${descriptor.kind}-discovery`);
  });
  let controls: ReadonlyArray<ClientCredentialsControlResult | DeviceAuthorizationControlResult>;
  try {
    controls = Object.freeze([
      ...runClientCredentialsNegativeControls({
        success: success as ClientCredentialsScenarioResult['projection'],
        authenticationError: authenticationError as ClientCredentialsScenarioResult['projection'],
        discoveryGrantTypes: discovery.grantTypesSupported,
      }),
      ...runDeviceAuthorizationNegativeControls(
        scenarios.filter(({ id }) =>
          (deviceAuthorizationScenarioIds as readonly string[]).includes(id)
        ) as readonly DeviceAuthorizationScenarioResult[]
      ),
    ]);
  } catch {
    throw new Error(`Phase 2 stage failed: ${descriptor.kind}-controls`);
  }
  const evidence = Object.freeze({
    target: descriptor.kind,
    scenarios,
    discovery,
    controls,
  });
  try {
    assertPhase2TargetEvidenceIsSanitized(evidence);
  } catch (error: unknown) {
    if (error instanceof Phase2SanitizerFailure) {
      throw new TypeError(`Phase 2 stage failed: ${descriptor.kind}-sanitizer-${error.stage}`);
    }
    throw new Error(`Phase 2 stage failed: ${descriptor.kind}-sanitizer`);
  }
  return evidence;
};

const executeOracle = async (
  input: Readonly<{
    profile: Phase2ProfileRegistries;
    target: PreparedPhase2Target;
    sessionRoot: string;
  }>
): Promise<unknown> => {
  if (input.target.descriptor.kind !== 'oracle') {
    return fail();
  }
  const target = await runTargetScenarios(input.profile, input.target);
  return Object.freeze({ schemaVersion: 1, mode: 'oracle', target });
};

const projectionHasKind = (value: unknown): boolean =>
  typeof value === 'object' && value !== null && 'kind' in value;

const statusScopeClass = (value: unknown): 'short' | 'full' | 'resource' | 'offline' | 'other' => {
  switch (value) {
    case 'openid profile': {
      return 'short';
    }
    case 'openid profile email address phone': {
      return 'full';
    }
    case 'openid profile email address phone read:profile': {
      return 'resource';
    }
    case 'openid offline_access profile email address phone': {
      return 'offline';
    }
    default: {
      return 'other';
    }
  }
};

export const executeDifferential = async (
  input: Readonly<{
    profile: Phase2ProfileRegistries;
    oracle: TargetScenarioEvidence;
    candidate: PreparedPhase2Target;
    sessionRoot: string;
  }>,
  executeScenarios: typeof runTargetScenarios = runTargetScenarios
): Promise<unknown> => {
  if (input.oracle.target !== 'oracle' || input.candidate.descriptor.kind !== 'candidate') {
    return fail();
  }
  const { oracle } = input;
  const candidate = await executeScenarios(input.profile, input.candidate);
  const comparisons = oracle.scenarios.map((oracleScenario, index) => {
    const candidateScenario = candidate.scenarios[index];
    if (!candidateScenario || candidateScenario.id !== oracleScenario.id) {
      return fail();
    }
    if (
      ([...customJwtScenarioIds, ...customJwtFetchScenarioIds] as readonly string[]).includes(
        oracleScenario.id
      )
    ) {
      if (
        !compareCustomJwtProjections(
          oracleScenario.projection as CustomJwtScenarioEvidence['projection'],
          candidateScenario.projection as CustomJwtScenarioEvidence['projection']
        )
      ) {
        throw new Error(`Phase 2 stage failed: candidate-custom-jwt:${oracleScenario.id}`);
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    const isTokenStatus = (tokenStatusScenarioIds as readonly string[]).includes(oracleScenario.id);
    const isLogoutSession = (logoutSessionScenarioIds as readonly string[]).includes(
      oracleScenario.id
    );
    const isDevice = (deviceAuthorizationScenarioIds as readonly string[]).includes(
      oracleScenario.id
    );
    const isVerificationCode = (verificationCodeScenarioIds as readonly string[]).includes(
      oracleScenario.id
    );
    const isCommonNative = (commonNativeScenarioIds as readonly string[]).includes(
      oracleScenario.id
    );
    const isCommonEmailPassword = (commonEmailPasswordScenarioIds as readonly string[]).includes(
      oracleScenario.id
    );
    const isCommonEmailCode = (commonEmailCodeScenarioIds as readonly string[]).includes(
      oracleScenario.id
    );
    if ((commonGoogleExistingOwnerScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonGoogleExistingOwnerProjections(
        oracleScenario.projection as CommonGoogleExistingOwnerScenarioResult['projection'],
        candidateScenario.projection as CommonGoogleExistingOwnerScenarioResult['projection']
      );
      if (found.length > 0) {
        return commonGoogleProjectionScenarioFailure(
          oracleScenario.projection,
          candidateScenario.projection
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonGoogleRegistrationScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonGoogleRegistrationProjections(
        oracleScenario.projection as CommonGoogleRegistrationScenarioResult['projection'],
        candidateScenario.projection as CommonGoogleRegistrationScenarioResult['projection']
      );
      if (found.length > 0) {
        return commonAdditionProjectionScenarioFailure(
          'google-registration',
          oracleScenario.projection,
          candidateScenario.projection
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonWechatWebScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonWechatWebProjections(
        oracleScenario.projection as CommonWechatWebScenarioResult['projection'],
        candidateScenario.projection as CommonWechatWebScenarioResult['projection']
      );
      if (found.length > 0) {
        return commonAdditionProjectionScenarioFailure(
          'wechat-web',
          oracleScenario.projection,
          candidateScenario.projection
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonAccountPasswordUpdateScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonAccountPasswordUpdateProjections(
        oracleScenario.projection as CommonAccountPasswordUpdateScenarioResult['projection'],
        candidateScenario.projection as CommonAccountPasswordUpdateScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(
          `Phase 2 scenario failed: candidate/${commonAccountPasswordUpdateScenarioIds[0]}`
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonPhoneCodeScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const id = oracleScenario.id as CommonPhoneCodeScenarioResult['id'];
      const found = compareCommonPhoneCodeProjections(
        id,
        oracleScenario.projection as CommonPhoneCodeScenarioResult['projection'],
        candidateScenario.projection as CommonPhoneCodeScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 scenario failed: candidate/${id}`);
      }
      return Object.freeze({ scenarioId: id, differenceCount: 0 });
    }
    if ((commonAccountEmailChangeScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonAccountEmailChangeProjections(
        oracleScenario.projection as CommonAccountEmailChangeScenarioResult['projection'],
        candidateScenario.projection as CommonAccountEmailChangeScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(
          `Phase 2 scenario failed: candidate/${commonAccountEmailChangeScenarioIds[0]}`
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonAccountPhoneChangeScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonAccountPhoneChangeProjections(
        oracleScenario.projection as CommonAccountPhoneChangeScenarioResult['projection'],
        candidateScenario.projection as CommonAccountPhoneChangeScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(
          `Phase 2 scenario failed: candidate/${commonAccountPhoneChangeScenarioIds[0]}`
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonCompletionScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const id = oracleScenario.id as CommonCompletionScenarioId;
      const found = compareCommonCompletionProjections(
        id,
        oracleScenario.projection,
        candidateScenario.projection
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 scenario failed: candidate/${id}`);
      }
      return Object.freeze({ scenarioId: id, differenceCount: 0 });
    }
    if ((commonManagementUserScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const id = oracleScenario.id as CommonManagementUserScenarioResult['id'];
      const found = compareCommonManagementUserProjections(
        id,
        oracleScenario.projection,
        candidateScenario.projection
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 scenario failed: candidate/${id}`);
      }
      return Object.freeze({ scenarioId: id, differenceCount: 0 });
    }
    if (
      (commonEmailPasswordRegistrationScenarioIds as readonly string[]).includes(oracleScenario.id)
    ) {
      const found = compareCommonEmailPasswordRegistrationProjections(
        oracleScenario.projection as CommonEmailPasswordRegistrationScenarioResult['projection'],
        candidateScenario.projection as CommonEmailPasswordRegistrationScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(
          `Phase 2 scenario failed: candidate/${commonEmailPasswordRegistrationScenarioIds[0]}`
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if ((commonPasswordRecoveryScenarioIds as readonly string[]).includes(oracleScenario.id)) {
      const found = compareCommonPasswordRecoveryProjections(
        oracleScenario.projection as CommonPasswordRecoveryScenarioResult['projection'],
        candidateScenario.projection as CommonPasswordRecoveryScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(
          `Phase 2 scenario failed: candidate/${commonPasswordRecoveryScenarioIds[0]}`
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    const isCommonEmailCodeRegistration = (
      commonEmailCodeRegistrationScenarioIds as readonly string[]
    ).includes(oracleScenario.id);
    if (isCommonEmailCodeRegistration) {
      const found = compareCommonEmailCodeRegistrationProjections(
        oracleScenario.projection as CommonEmailCodeRegistrationScenarioResult['projection'],
        candidateScenario.projection as CommonEmailCodeRegistrationScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(
          `Phase 2 scenario failed: candidate/${commonEmailCodeRegistrationScenarioIds[0]}`
        );
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if (isCommonEmailCode) {
      const found = compareCommonEmailCodeProjections(
        oracleScenario.projection as CommonEmailCodeScenarioResult['projection'],
        candidateScenario.projection as CommonEmailCodeScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 scenario failed: candidate/${commonEmailCodeScenarioIds[0]}`);
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if (isCommonEmailPassword) {
      const found = compareCommonEmailPasswordProjections(
        oracleScenario.projection as CommonEmailPasswordScenarioResult['projection'],
        candidateScenario.projection as CommonEmailPasswordScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 scenario failed: candidate/${commonEmailPasswordScenarioIds[0]}`);
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if (isCommonNative) {
      const found = compareCommonNativeCodePkceProjections(
        oracleScenario.projection as CommonNativeScenarioResult['projection'],
        candidateScenario.projection as CommonNativeScenarioResult['projection']
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 scenario failed: candidate/${commonNativeScenarioIds[0]}`);
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    if (isVerificationCode) {
      const found = compareVerificationCodeProjections(
        oracleScenario.projection,
        candidateScenario.projection,
        oracleScenario.id
      );
      if (found.length > 0) {
        throw new Error(`Phase 2 stage failed: candidate-verification-code:${oracleScenario.id}`);
      }
      return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
    }
    const found = isLogoutSession
      ? compareLogoutSessionProjections(
          oracleScenario.projection as LogoutSessionScenarioResult['projection'],
          candidateScenario.projection as LogoutSessionScenarioResult['projection']
        )
      : isDevice
        ? compareDeviceScenarioProjections(
            oracleScenario.projection as DeviceAuthorizationScenarioResult['projection'],
            candidateScenario.projection as DeviceAuthorizationScenarioResult['projection'],
            oracleScenario.id as DeviceAuthorizationScenarioId
          )
        : isTokenStatus &&
            projectionHasKind(oracleScenario.projection) &&
            projectionHasKind(candidateScenario.projection)
          ? compareTokenStatus(
              oracleScenario.projection as TokenStatusScenarioResult['projection'],
              candidateScenario.projection as TokenStatusScenarioResult['projection']
            )
          : !isTokenStatus &&
              !projectionHasKind(oracleScenario.projection) &&
              !projectionHasKind(candidateScenario.projection)
            ? compareClientCredentialsProjections(
                oracleScenario.projection as ClientCredentialsScenarioResult['projection'],
                candidateScenario.projection as ClientCredentialsScenarioResult['projection']
              )
            : fail();
    if (found.length > 0) {
      const statusIndex = (tokenStatusScenarioIds as readonly string[]).indexOf(oracleScenario.id);
      if (statusIndex >= 0) {
        const first =
          found.find(
            (path) =>
              typeof path === 'string' &&
              /^\/body\/(sub|client_id|exp|iat|iss|scope|token_type)$/u.test(path)
          ) ?? found[0];
        if (
          first === '/body/scope' &&
          projectionHasKind(oracleScenario.projection) &&
          projectionHasKind(candidateScenario.projection)
        ) {
          const oracleStatus = oracleScenario.projection as TokenStatusScenarioResult['projection'];
          const candidateStatus =
            candidateScenario.projection as TokenStatusScenarioResult['projection'];
          throw new Error(
            'Phase 2 stage failed: candidate-status-scope-' +
              statusIndex +
              '-' +
              statusScopeClass(oracleStatus.body?.scope) +
              '-' +
              statusScopeClass(candidateStatus.body?.scope)
          );
        }
        if (
          typeof first === 'string' &&
          /^\/(kind|status|headers|body(?:\/(?:sub|client_id|exp|iat|iss|scope|token_type))?|grant)$/u.test(
            first
          )
        ) {
          throw new Error(
            'Phase 2 stage failed: candidate-status-case-' +
              statusIndex +
              '-' +
              first.slice(1).replace('/', '-')
          );
        }
      }
      if (isLogoutSession || isDevice) {
        if (isDevice) {
          throw deviceScenarioProjectionFailure(
            oracleScenario.id as DeviceAuthorizationScenarioId,
            found[0],
            oracleScenario.projection,
            candidateScenario.projection
          );
        }
        throw new Error(`Phase 2 scenario failed: candidate/${oracleScenario.id}`);
      }
      throw new Error('Phase 2 stage failed: candidate-comparison');
    }
    return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
  });
  if (
    JSON.stringify(oracle.discovery) !== JSON.stringify(candidate.discovery) ||
    JSON.stringify(oracle.controls) !== JSON.stringify(candidate.controls)
  ) {
    return fail();
  }
  return Object.freeze({
    schemaVersion: 1,
    mode: 'differential',
    oracle,
    candidate,
    comparisons: Object.freeze(comparisons),
  });
};

export const issueCandidateInvariantUserTokens = async <Owner, CrossClient>(
  issuePublic: () => Promise<Owner>,
  issueConfidential: () => Promise<CrossClient>
): Promise<Readonly<{ verificationOwner: Owner; verificationCrossClient: CrossClient }>> => {
  const verificationOwner = await issuePublic();
  const verificationCrossClient = await issueConfidential();
  return Object.freeze({ verificationOwner, verificationCrossClient });
};

const executeCandidateInvariants = async (
  input: Readonly<{
    profile: Phase2ProfileRegistries;
    target: PreparedPhase2Target;
    sessionRoot: string;
  }>
): Promise<unknown> => {
  const prepared = input.target;
  const { descriptor: target } = prepared;
  if (target.kind !== 'candidate' || !target.invariantDriver || !target.fixtureSocket) {
    return fail();
  }
  const { invariantDriver } = target;
  const provisioner = provisionerFor(prepared, phase2FixtureRecipeForMode('candidate-invariants'));
  const state = await createCommandPhase2ScenarioStateDriver({
    descriptor: target,
    identityFence: prepared.fence,
  });
  const invariants: ReadonlyArray<
    | CandidateInvariantControlEvidence
    | VerificationCodeCandidateInvariantControlEvidence
    | DeviceCandidateInvariantControlEvidence
    | CustomJwtCandidateInvariantControlEvidence
    | CustomJwtFetchPolicyControlEvidence
  > = await runWithPhase2Fixture(provisioner, async (fixture: ProvisionedPhase2Fixture) => {
    await waitForClientCredentialsFixtureReady(target.target, fixture.public);
    const legacy = await runClientCredentialsCandidateInvariants(input.profile, {
      target: target.target,
      foreignTarget: target.foreignTarget,
      fixture,
      driverPath: invariantDriver.path,
      controlSocket: invariantDriver.controlSocket,
      topology: prepared.topology,
      identityFence: prepared.fence,
    });
    const { verificationOwner, verificationCrossClient } = await issueCandidateInvariantUserTokens(
      async () => issuePublicUserTokens(target.target, fixture),
      async () => issueConfidentialUserTokens(target.target, fixture)
    );
    const verification = await withPhase2AdminManagementBearer(
      target.target,
      fixture,
      async (crossTenantBearer, lease) => {
        const wrongAudienceBearer = await (async () => {
          const response = await fetch(new URL('/oidc/token', target.target.coreUrl), {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
              grant_type: 'client_credentials',
              client_id: fixture.public.clients.post.id,
              client_secret: lease.getClientSecret('post'),
              resource: fixture.public.resources.primary.indicator,
              scope: fixture.public.scopes.read.name,
            }),
            redirect: 'manual',
            signal: AbortSignal.timeout(10_000),
          });
          const body = (await response.json()) as Record<string, unknown>;
          return response.status === 200 && typeof body.access_token === 'string'
            ? body.access_token
            : fail();
        })();
        const persistenceProbe = createCommandVerificationCodePersistenceProbe({
          target: target.target,
          foreignTarget: target.foreignTarget,
          fixture,
          driverPath: invariantDriver.path,
          controlSocket: invariantDriver.controlSocket,
          topology: prepared.topology,
          identityFence: prepared.fence,
        });
        return runVerificationCodeCandidateInvariants(
          input.profile,
          await createLiveVerificationCodeCandidateInvariantExecutor({
            target: target.target,
            fixture,
            lease,
            ownerBearer: verificationOwner.access,
            crossClientBearer: verificationCrossClient.access,
            crossTenantBearer,
            wrongAudienceBearer,
            persistenceProbe,
          })
        );
      }
    );
    const deviceExecutor = await createLiveDeviceCandidateInvariantExecutor({
      profile: input.profile,
      target: target.target,
      foreignTarget: target.foreignTarget,
      fixture,
      driverPath: invariantDriver.path,
      controlSocket: invariantDriver.controlSocket,
      topology: prepared.topology,
      state,
      jwks: await fetchPhase2PublicJwks(target.target),
      identityFence: prepared.fence,
    });
    const device = await runDeviceCandidateInvariants(input.profile, deviceExecutor);
    const jwks = await fetchPhase2PublicJwks(target.target);
    const customJwt = await withPhase2AdminManagementBearer(
      target.target,
      fixture,
      async (bearer, lease) => {
        const managementPath = 'configs/jwt-customizer';
        const clientPath = `${managementPath}/client-credentials`;
        const userPath = `${managementPath}/access-token`;
        const managementRequest = async (
          method: 'GET' | 'PUT' | 'DELETE',
          requestPath: string,
          body?: unknown
        ) =>
          requestPhase2Json({
            url: new URL(`/api/${requestPath}`, target.target.coreUrl),
            method,
            headers: {
              authorization: `Bearer ${bearer}`,
              ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            signal: AbortSignal.timeout(10_000),
          });
        const capture = async (requestPath: string) => {
          const response = await managementRequest('GET', requestPath);
          if (response.status !== 200 && response.status !== 404) {
            return fail();
          }
          if (response.status === 404) {
            return Object.freeze({ exists: false, body: undefined });
          }
          const source =
            typeof response.body === 'object' && response.body !== null
              ? (response.body as Record<string, unknown>)
              : fail();
          const body = Object.freeze({
            script: source.script,
            blockIssuanceOnError: source.blockIssuanceOnError,
            environmentVariables: source.environmentVariables,
            contextSample: source.contextSample,
            tokenSample: source.tokenSample,
          });
          if (
            typeof body.script !== 'string' ||
            typeof body.blockIssuanceOnError !== 'boolean' ||
            typeof body.environmentVariables !== 'object' ||
            body.environmentVariables === null ||
            typeof body.contextSample !== 'object' ||
            body.contextSample === null ||
            typeof body.tokenSample !== 'object' ||
            body.tokenSample === null
          ) {
            return fail();
          }
          return Object.freeze({ exists: true, body });
        };
        const restore = async (
          requestPath: string,
          snapshot: Readonly<{ exists: boolean; body: unknown }>
        ) => {
          const response = snapshot.exists
            ? await managementRequest('PUT', requestPath, snapshot.body)
            : await managementRequest('DELETE', requestPath);
          if (
            (snapshot.exists && response.status !== 200 && response.status !== 201) ||
            (!snapshot.exists && response.status !== 204 && response.status !== 404)
          ) {
            return fail();
          }
        };
        const put = async (requestPath: string, body: unknown) => {
          const response = await managementRequest('PUT', requestPath, body);
          if (response.status !== 200 && response.status !== 201) {
            return fail();
          }
        };
        const clientSample = Object.freeze({
          contextSample: Object.freeze({
            application: Object.freeze({ id: 'sample', name: 'sample' }),
          }),
          tokenSample: Object.freeze({
            kind: 'ClientCredentials',
            aud: 'sample',
            scope: 'read',
            clientId: 'sample',
          }),
        });
        const userSample = Object.freeze({
          contextSample: Object.freeze({
            user: Object.freeze({ id: 'sample', hasPassword: true }),
            application: Object.freeze({ id: 'sample', name: 'sample' }),
          }),
          tokenSample: Object.freeze({
            kind: 'AccessToken',
            aud: 'sample',
            scope: 'read',
            clientId: 'sample',
            accountId: 'sample',
          }),
        });
        const issueM2M = async () => {
          const body = new URLSearchParams({
            grant_type: 'client_credentials',
            resource: fixture.public.resources.primary.indicator,
            scope: 'read write',
          });
          return requestPhase2Json({
            url: new URL('oidc/token', target.target.coreUrl),
            method: 'POST',
            headers: {
              authorization: `Basic ${Buffer.from(
                `${fixture.public.clients.basic.id}:${lease.getClientSecret('basic')}`
              ).toString('base64')}`,
              'content-type': 'application/x-www-form-urlencoded',
            },
            body,
            signal: AbortSignal.timeout(10_000),
          });
        };
        const receiptPort = createCustomJwtHttpPort({
          assertInvocationFence: async () => prepared.fence.assertStable(),
          managementRequest: async () => fail(),
          withM2MSecret: async () => fail(),
          issueClientCredentials: async () => fail(),
          verifyAccessToken: async () => fail(),
          issueUserTokens: async () => fail(),
          exchangeUserRefresh: async () => fail(),
          observeDeviceResourceRefresh: async () => fail(),
          readAndResetFetchReceipts: async ({ accept }) =>
            readAndResetPhase2FetchReceipts(prepared, accept),
        });
        const customJwtExecutor = await createCustomJwtCandidateInvariantExecutor({
          target: target.target,
          foreignTarget: target.foreignTarget,
          fixture,
          driverPath: invariantDriver.path,
          controlSocket: invariantDriver.controlSocket,
          topology: prepared.topology,
          identityFence: prepared.fence,
          workflow: Object.freeze({
            withStorageCanary: async (use) => {
              const snapshot = await capture(clientPath);
              const canary = `AsterStorageCanary${randomBytes(24).toString('hex')}`;
              const script = `const getCustomJwtClaims = async ({ environmentVariables }) => ({ canary: environmentVariables.canary === '${canary}' });`;
              try {
                await put(clientPath, {
                  script,
                  blockIssuanceOnError: true,
                  environmentVariables: { canary },
                  ...clientSample,
                });
                const roundTrip = await managementRequest('GET', clientPath);
                const body =
                  typeof roundTrip.body === 'object' && roundTrip.body !== null
                    ? (roundTrip.body as Record<string, unknown>)
                    : fail();
                const environment =
                  typeof body.environmentVariables === 'object' &&
                  body.environmentVariables !== null
                    ? (body.environmentVariables as Record<string, unknown>)
                    : fail();
                if (
                  roundTrip.status !== 200 ||
                  body.script !== script ||
                  environment.canary !== canary
                ) {
                  return fail();
                }
                return await use(canary, true);
              } finally {
                await restore(clientPath, snapshot);
              }
            },
            withRefreshCredential: async (use) => {
              const issued = await issuePublicUserResourceTokensWithPassword(
                target.target,
                fixture,
                lease.getSubjectPassword?.() ?? fail(),
                AbortSignal.timeout(10_000)
              );
              return use(issued.refresh);
            },
            withBlockingCustomizer: async (use) => {
              const snapshot = await capture(userPath);
              try {
                await put(userPath, {
                  script: `const getCustomJwtClaims = async () => { throw new Error('blocked'); };`,
                  blockIssuanceOnError: true,
                  environmentVariables: {},
                  ...userSample,
                });
                return await use();
              } finally {
                await restore(userPath, snapshot);
              }
            },
            installCorrectedCustomizer: async () =>
              put(userPath, {
                script: `const getCustomJwtClaims = async () => ({ corrected: true });`,
                blockIssuanceOnError: true,
                environmentVariables: {},
                ...userSample,
              }),
            exchangeRefresh: async (refreshCredential) => {
              const status = fixture.status ?? fail();
              const response = await requestPhase2Json({
                url: new URL('/oidc/token', target.target.coreUrl),
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                  grant_type: 'refresh_token',
                  refresh_token: refreshCredential,
                  client_id: status.client.id,
                  resource: status.resource.indicator,
                }),
                signal: AbortSignal.timeout(10_000),
              });
              const body =
                typeof response.body === 'object' && response.body !== null
                  ? (response.body as Record<string, unknown>)
                  : fail();
              return Object.freeze({
                status: response.status,
                ...(typeof body.error === 'string' ? { error: body.error } : {}),
                tokenPublished: typeof body.access_token === 'string',
              });
            },
          }),
        });
        const stateResults = [];
        for (const id of customJwtCandidateInvariantIds) {
          stateResults.push(
            runCustomJwtCandidateInvariantControls(id, await customJwtExecutor.execute(id))
          );
        }
        const fetchSnapshot = await capture(clientPath);
        const assertDeniedOriginReachable = async () => {
          const result = await prepared.fence.run(async () =>
            runPhase1FixtureCommand({
              command: invariantDriver.path,
              args: Object.freeze([]),
              stdin: JSON.stringify({
                schemaVersion: 1,
                kind: phase2InvariantRequestKind,
                invariantId: 'custom-jwt.fetch-policy-boundary',
                operation: 'probe',
                target: Object.freeze({ primary: target.target, foreign: target.foreignTarget }),
                fixture: fixture.public,
                private: Object.freeze({}),
                observation: Object.freeze({}),
              }),
              env: Object.freeze({
                ASTER_PHASE2_CONTROL_SOCKET: invariantDriver.controlSocket,
                ASTER_CORE_URL: target.target.coreUrl,
                ASTER_ADMIN_URL: target.target.adminUrl,
                ASTER_FOREIGN_CORE_URL: target.foreignTarget.coreUrl,
                ASTER_FOREIGN_ADMIN_URL: target.foreignTarget.adminUrl,
                LC_ALL: 'C',
              }),
              timeoutMs: 120_000,
              maxStdoutBytes: 65_536,
              maxStderrBytes: 65_536,
              shell: false,
            })
          );
          if (
            result.exitCode !== 0 ||
            result.signal !== null ||
            result.stderr !== '' ||
            result.timedOut ||
            result.killed ||
            !result.reaped ||
            result.stdout.length === 0 ||
            /[\r\n]/u.test(result.stdout)
          ) {
            return fail();
          }
          let terminal: unknown;
          try {
            terminal = JSON.parse(result.stdout) as unknown;
          } catch {
            return fail();
          }
          const record =
            typeof terminal === 'object' && terminal !== null && !Array.isArray(terminal)
              ? (terminal as Record<string, unknown>)
              : fail();
          if (
            record.schemaVersion !== 1 ||
            record.kind !== 'phase2-custom-jwt-candidate-invariant-control' ||
            record.invariantId !== 'custom-jwt.fetch-policy-boundary' ||
            record.operation !== 'probe' ||
            JSON.stringify(record.attestation) !== JSON.stringify(prepared.topology) ||
            typeof record.ok !== 'boolean' ||
            !record.ok ||
            Object.keys(record).length !== 6
          ) {
            return fail();
          }
        };
        const fetchResult = await runCustomJwtFetchPolicyCandidateInvariant({
          assertDeniedOriginReachable,
          installCustomizer: async (kind) =>
            put(clientPath, {
              script:
                kind === 'allowed-fetch'
                  ? `const getCustomJwtClaims = async () => { const response = await fetch('https://fetch-observer.aster.test:8443/text'); return { policy_claim: response.status === 200 && (await response.text()) === 'bounded-text' ? 'bounded-response' : 'mismatch' }; };`
                  : `const getCustomJwtClaims = async () => { try { await fetch('https://fetch-observer.aster.test:8444/text'); } catch (error) { return { policy_claim: error?.name === 'TypeError' ? 'caught-TypeError' : 'other' }; } return { policy_claim: 'unexpected' }; };`,
              blockIssuanceOnError: true,
              environmentVariables: {},
              ...clientSample,
            }),
          issueM2MAndVerifyClaim: async () => {
            const response = await issueM2M();
            if (response.status !== 200) {
              return fail();
            }
            const body =
              typeof response.body === 'object' && response.body !== null
                ? (response.body as Record<string, unknown>)
                : fail();
            const token = typeof body.access_token === 'string' ? body.access_token : fail();
            const verified = await jwtVerify(token, createLocalJWKSet(jwks));
            return verified.payload.policy_claim;
          },
          readAndResetSanitizedReceipts: async () => receiptPort.readAndResetFetchReceipts(),
          restoreConfiguration: async () => restore(clientPath, fetchSnapshot),
        });
        return Object.freeze([...stateResults, fetchResult]);
      }
    );
    const combined = Object.freeze([...legacy, ...verification, ...device, ...customJwt]);
    if (
      combined.length !== input.profile.candidateInvariantScenarios.length ||
      combined.some(({ id }, index) => id !== input.profile.candidateInvariantScenarios[index])
    ) {
      return fail();
    }
    return combined;
  });
  return Object.freeze({ schemaVersion: 1, mode: 'candidate-invariants', invariants });
};

const defaultDependencies: Phase2CliDependencies = Object.freeze({
  loadProfile: loadPhase2Profile,
  readTarget: readPhase2TargetDescriptor,
  readOracleArtifact: readPhase2OracleArtifact,
  executeOracle,
  executeDifferential,
  executeCandidateInvariants,
  publish: async (outputPath, value) => {
    await writeSecureJsonArtifact(outputPath, value);
  },
  removeSessionRoot: async (sessionRoot) => {
    const before = await lstat(sessionRoot).catch(fail);
    if (before.isSymbolicLink() || !before.isDirectory() || before.uid !== currentUid()) {
      return fail();
    }
    await rm(sessionRoot, { force: true, recursive: true });
    try {
      await lstat(sessionRoot);
      return fail();
    } catch (error: unknown) {
      if (
        typeof error !== 'object' ||
        error === null ||
        Object.getOwnPropertyDescriptor(error, 'code')?.value !== 'ENOENT'
      ) {
        return fail();
      }
    }
  },
  stdout: (message) => {
    process.stdout.write(message);
  },
  stderr: (message) => {
    process.stderr.write(message);
  },
  inspectHarness: async (runtimeCapability) =>
    inspectLaunchedPhase2HarnessSource(repositoryRoot, runtimeEntryPath, runtimeCapability),
  recheckHarness: recheckCleanPhase2HarnessSource,
  verifyTarget: verifyPhase2Target,
  prepareTarget: preparePhase2TargetForExecution,
});

const safeWrite = async (
  writer: (message: string) => void | Promise<void>,
  message: string
): Promise<void> => {
  try {
    await writer(message);
  } catch {
    // Fixed diagnostics must not be replaced by reporting failures.
  }
};

export const runPhase2Cli = async (
  arguments_: readonly string[],
  dependencies: Phase2CliDependencies = defaultDependencies,
  runtimeCapability?: string
): Promise<void> => {
  const command = parsePhase2Arguments(arguments_);
  const temporaryRoot = await validatePrivateRoot(command.tempRoot);
  const [profilePath, schemaPath] = await Promise.all([
    validateInputFile(command.profilePath),
    validateInputFile(command.schemaPath),
  ]);
  if (profilePath === schemaPath) {
    return fail();
  }
  const outputPath = await validateOutputPath(command.mode, command.outputPath, temporaryRoot);
  const sessionRoot = await mkdtemp(path.join(temporaryRoot, 'phase2-client-credentials-run-'));
  await chmod(sessionRoot, 0o700);
  let evidence: ReturnType<typeof createPhase2EvidenceEnvelope> | undefined;
  let executionError: unknown;
  try {
    const profile = await dependencies.loadProfile({ profilePath, schemaPath });
    const harness = await dependencies.inspectHarness(runtimeCapability);
    const execution = await (async () => {
      if (command.mode === 'differential') {
        const [oracleEvidencePath, candidateTargetPath] = await Promise.all([
          validateInputFile(command.oracleEvidencePath),
          validateInputFile(command.candidateTargetPath),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-path');
        });
        if (oracleEvidencePath === candidateTargetPath) {
          return fail();
        }
        const [oracleArtifact, candidate] = await Promise.all([
          dependencies.readOracleArtifact(oracleEvidencePath, profile, harness),
          dependencies.readTarget(candidateTargetPath),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-read');
        });
        const oracleProvenance = oracleArtifact.provenance.oracle ?? fail();
        if (
          oracleProvenance.sourceCommit === candidate.sourceCommit ||
          oracleProvenance.imageDigest === candidate.imageDigest
        ) {
          throw new Error('Phase 2 command stage failed: differential-target-pair');
        }
        const candidateCapability = await dependencies.verifyTarget(candidate).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-verify');
        });
        const preparedCandidate = await dependencies
          .prepareTarget(candidateCapability, sessionRoot, 'candidate')
          .catch(() => {
            throw new Error('Phase 2 command stage failed: differential-target-prepare');
          });
        const oraclePayload = oracleArtifact.payload as unknown as Readonly<{
          target: TargetScenarioEvidence;
        }>;
        const payload = await dependencies
          .executeDifferential({
            profile,
            oracle: oraclePayload.target,
            candidate: preparedCandidate,
            sessionRoot,
          })
          .catch((error: unknown) => {
            if (
              error instanceof Error &&
              (scenarioFailurePattern.test(error.message) ||
                customJwtStageFailurePattern.test(error.message) ||
                candidateAdminBearerStageFailurePattern.test(error.message) ||
                candidateAdminConsumerStageFailurePattern.test(error.message) ||
                commonReadyStageFailurePattern.test(error.message) ||
                accountReadyStageFailurePattern.test(error.message) ||
                commonManagementReadyStageFailurePattern.test(error.message) ||
                googleProjectionStageFailurePattern.test(error.message) ||
                commonAdditionProjectionStageFailurePattern.test(error.message) ||
                commonPhoneStageFailurePattern.test(error.message) ||
                stageFailurePattern.test(error.message))
            ) {
              throw error;
            }
            throw new Error('Phase 2 command stage failed: differential-execution');
          });
        await preparedCandidate.fence.assertStable().catch(() => {
          throw new Error('Phase 2 command stage failed: differential-harness');
        });
        return {
          payload,
          oracle: oracleProvenance,
          candidate: publicTargetProvenance(candidateCapability),
        };
      }
      const role = command.mode === 'oracle' ? 'oracle' : 'candidate';
      const targetPath = await validateInputFile(command.targetPath).catch(() => {
        throw new Error(`Phase 2 command stage failed: ${role}-target-path`);
      });
      const target = await dependencies.readTarget(targetPath).catch(() => {
        throw new Error(`Phase 2 command stage failed: ${role}-target-read`);
      });
      const capability = await dependencies.verifyTarget(target).catch(() => {
        throw new Error(`Phase 2 command stage failed: ${role}-target-verify`);
      });
      const prepared = await dependencies.prepareTarget(capability, sessionRoot, role).catch(() => {
        throw new Error(`Phase 2 command stage failed: ${role}-target-prepare`);
      });
      const payload = await (
        command.mode === 'oracle'
          ? dependencies.executeOracle({ profile, target: prepared, sessionRoot })
          : dependencies.executeCandidateInvariants({ profile, target: prepared, sessionRoot })
      ).catch((error: unknown) => {
        if (
          error instanceof Error &&
          (scenarioFailurePattern.test(error.message) ||
            customJwtStageFailurePattern.test(error.message) ||
            candidateAdminBearerStageFailurePattern.test(error.message) ||
            candidateAdminConsumerStageFailurePattern.test(error.message) ||
            commonReadyStageFailurePattern.test(error.message) ||
            accountReadyStageFailurePattern.test(error.message) ||
            commonManagementReadyStageFailurePattern.test(error.message) ||
            googleProjectionStageFailurePattern.test(error.message) ||
            commonAdditionProjectionStageFailurePattern.test(error.message) ||
            commonPhoneStageFailurePattern.test(error.message) ||
            stageFailurePattern.test(error.message) ||
            (command.mode === 'candidate-invariants' &&
              candidateInvariantStageFailurePattern.test(error.message)))
        ) {
          throw error;
        }
        throw new Error(`Phase 2 command stage failed: ${role}-execution`);
      });
      await prepared.fence.assertStable().catch(() => {
        throw new Error(`Phase 2 command stage failed: ${role}-harness`);
      });
      return command.mode === 'oracle'
        ? { payload, oracle: publicTargetProvenance(capability) }
        : { payload, candidate: publicTargetProvenance(capability) };
    })();
    try {
      await dependencies.recheckHarness(harness);
    } catch {
      if (command.mode === 'differential') {
        throw new Error('Phase 2 command stage failed: differential-harness');
      }
      const role = command.mode === 'oracle' ? 'oracle' : 'candidate';
      throw new Error(`Phase 2 command stage failed: ${role}-harness`);
    }
    try {
      evidence = createPhase2EvidenceEnvelope({
        mode: command.mode,
        profile,
        harness,
        payload: execution.payload as JsonValue,
        ...('oracle' in execution && execution.oracle ? { oracle: execution.oracle } : {}),
        ...('candidate' in execution && execution.candidate
          ? { candidate: execution.candidate }
          : {}),
      });
    } catch {
      if (command.mode === 'differential') {
        throw new Error('Phase 2 command stage failed: differential-evidence');
      }
      const role = command.mode === 'oracle' ? 'oracle' : 'candidate';
      throw new Error(`Phase 2 command stage failed: ${role}-evidence`);
    }
  } catch (error: unknown) {
    executionError = error;
  }
  try {
    await dependencies.removeSessionRoot(sessionRoot);
  } catch {
    const role =
      command.mode === 'oracle'
        ? 'oracle'
        : command.mode === 'differential'
          ? 'differential'
          : 'candidate';
    if (executionError !== undefined) {
      throw new AggregateError(
        [executionError, new Error(`Phase 2 command stage failed: ${role}-cleanup`)],
        runFailure.trim()
      );
    }
    throw new Error(`Phase 2 command stage failed: ${role}-cleanup`);
  }
  if (executionError !== undefined) {
    throw executionError instanceof Error ? executionError : new Error(runFailure.trim());
  }
  try {
    await dependencies.publish(outputPath, evidence as unknown as JsonValue);
  } catch {
    if (command.mode === 'differential') {
      throw new Error('Phase 2 command stage failed: differential-publish');
    }
    const role = command.mode === 'oracle' ? 'oracle' : 'candidate';
    throw new Error(`Phase 2 command stage failed: ${role}-publish`);
  }
  await safeWrite(dependencies.stdout, successMessages[command.mode]);
};

export const runPhase2CliMain = async (
  arguments_: readonly string[] = process.argv.slice(2),
  runtimeCapability?: string,
  dependencies: Phase2CliDependencies = defaultDependencies
): Promise<number> => {
  try {
    await runPhase2Cli(arguments_, dependencies, runtimeCapability);
    return 0;
  } catch (error: unknown) {
    const original = error instanceof AggregateError ? (error.errors[0] as unknown) : error;
    const cleanup = error instanceof AggregateError ? (error.errors[1] as unknown) : undefined;
    const match = original instanceof Error ? scenarioFailurePattern.exec(original.message) : null;
    const customJwtStage =
      original instanceof Error ? customJwtStageFailurePattern.exec(original.message) : null;
    const stage =
      original instanceof Error
        ? (stageFailurePattern.exec(original.message) ??
          candidateAdminBearerStageFailurePattern.exec(original.message) ??
          candidateAdminConsumerStageFailurePattern.exec(original.message) ??
          commonReadyStageFailurePattern.exec(original.message) ??
          accountReadyStageFailurePattern.exec(original.message) ??
          commonManagementReadyStageFailurePattern.exec(original.message) ??
          googleProjectionStageFailurePattern.exec(original.message) ??
          commonAdditionProjectionStageFailurePattern.exec(original.message) ??
          commonPhoneStageFailurePattern.exec(original.message))
        : null;
    const candidateInvariantStage =
      original instanceof Error
        ? candidateInvariantStageFailurePattern.exec(original.message)
        : null;
    const commandStage =
      original instanceof Error ? commandFailurePattern.exec(original.message) : null;
    const cleanupStage =
      cleanup instanceof Error ? commandFailurePattern.exec(cleanup.message) : null;
    const structuralDiagnostic =
      original instanceof DeviceScenarioProjectionFailure
        ? original.structuralDiagnostic
        : undefined;
    await safeWrite(
      dependencies.stderr,
      error instanceof TypeError && error.message === invalidArguments.trim()
        ? invalidArguments
        : match?.[1] && match[2] && profileScenarioIdIsClosed(match[2])
          ? `Phase 2 client credentials command failed (${match[1]}/${match[2]}${match[3] ? `:${match[3]}` : ''}).\n${structuralDiagnostic ? `${structuralDiagnostic}\n` : ''}`
          : customJwtStage?.[1] && customJwtStage[2]
            ? `Phase 2 client credentials command failed (${customJwtStage[1]}-${customJwtStage[2]}).\n`
            : candidateInvariantStage?.[1] && candidateInvariantStage[2]
              ? `Phase 2 client credentials command failed (${candidateInvariantStage[1]}-${candidateInvariantStage[2]}).\n`
              : stage?.[1] && stage[2]
                ? `Phase 2 client credentials command failed (${stage[1]}-${stage[2]}).\n`
                : commandStage?.[1] && commandStage[2]
                  ? `Phase 2 client credentials command failed (${commandStage[1]}-${commandStage[2]}).\n`
                  : cleanupStage?.[1] && cleanupStage[2] === 'cleanup'
                    ? `Phase 2 client credentials command failed (${cleanupStage[1]}-cleanup).\n`
                    : runFailure
    );
    return 1;
  }
};

const directEntry = typeof process.argv[1] === 'string' ? path.resolve(process.argv[1]) : undefined;
if (directEntry === fileURLToPath(import.meta.url) || directEntry === runtimeEntryPath) {
  process.exitCode = await runPhase2CliMain();
}

/* eslint-enable complexity, max-lines, no-restricted-syntax, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
