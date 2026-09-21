/* eslint-disable @typescript-eslint/ban-types -- Safe browser-network facts preserve JSON null to distinguish an absent protocol field from an empty string. */
import type { TargetConfig } from '../../model.js';
import type { JsonObject } from '../../normalize.js';
import type {
  Phase1FixtureSecretLease,
  ProvisionedPhase1Fixture,
  SemanticStateProjection,
} from '../fixtures.js';
import type { Phase1SourceEvidenceRef as Phase1SourceEvidenceReference } from '../model.js';
import type { Phase1Profile } from '../profile-types.js';

import type { Phase1LastSignInState } from './activity-reader.js';

export type {
  Phase1BrowserActivityReader,
  Phase1BrowserFixtureProvisioner,
  Phase1LastSignInState,
  Phase1UserActivityState,
} from './activity-reader.js';

export const phase1BrowserFlowIds = Object.freeze([
  'experience.password-pkce-consent',
  'console.clean-authentication',
  'console.application-read',
  'console.user-read',
] as const);

export type Phase1BrowserFlowId = (typeof phase1BrowserFlowIds)[number];
export type Phase1BrowserGroupId = 'experience' | 'console';
export type Phase1BrowserEndpoint = 'core' | 'admin';
export type Phase1BrowserAuthority = Phase1BrowserEndpoint;

export type Phase1ProfiledDemoConfiguration = Readonly<{
  appId: string;
  prompt: string;
  scope: string;
  resource: string;
}>;

export type Phase1BrowserCompactAccess = Readonly<{
  issuer: string;
  subject: string;
  audience: string | readonly string[];
  clientId: string;
  scope: string;
  organizationIdPresent: boolean;
}>;

export type Phase1BrowserSignInFact = Readonly<{
  authority: Phase1BrowserAuthority;
  status: number;
  queryShapeExact: boolean;
  clientId: string | null;
  redirectUri: string | null;
  responseType: string | null;
  prompt: string | null;
  scope: string | null;
  resources: readonly string[];
  pkceMethod: string | null;
  stateFormatValid: boolean;
  challengeFormatValid: boolean;
}>;

export type Phase1BrowserCallbackFact = Readonly<{
  authority: Phase1BrowserAuthority;
  path: '/console/callback' | '/demo-app';
  status: number;
  queryShapeExact: boolean;
  stateMatches: boolean;
  issuer: string | null;
  codePresent: boolean;
  fragmentEmpty: boolean;
}>;

export type Phase1BrowserEndpointDiscoveryFact = Readonly<{
  authority: Phase1BrowserAuthority;
  status: number;
  queryShapeExact: boolean;
  accessAbsent: boolean;
  userOriginMatchesCore: boolean;
}>;

export type Phase1BrowserExchangeFact = Readonly<{
  kind: 'initial' | 'management' | 'organization' | 'other';
  authority: Phase1BrowserAuthority;
  status: number;
  requestShapeExact: boolean;
  requestCorrelationValid: boolean;
  clientId: string | null;
  redirectUri: string | null;
  initialRefreshPresent: boolean;
  replacementFresh: boolean;
  resource: string | null;
  organizationId: string | null;
  responseScope: string | null;
  accessKind: 'opaque' | 'compact' | 'missing';
  compactAccess?: Phase1BrowserCompactAccess;
}>;

export type Phase1BrowserAccountFact = Readonly<{
  authority: Phase1BrowserAuthority;
  status: number;
  queryShapeExact: boolean;
  accessMatchesInitial: boolean;
  id: string;
  username: string;
  primaryEmail: string;
}>;

export type Phase1BrowserApplicationReadFact = Readonly<{
  authority: Phase1BrowserAuthority;
  status: number;
  queryShapeExact: boolean;
  originMatches: boolean;
  languageMatches: boolean;
  accessMatchesManagement: boolean;
  isThirdParty: boolean;
  isSamlProbe: boolean;
  total: number;
  rows: ReadonlyArray<Readonly<{ id: string; name: string }>>;
}>;

export type Phase1BrowserUserReadFact = Readonly<{
  authority: Phase1BrowserAuthority;
  status: number;
  queryShapeExact: boolean;
  originMatches: boolean;
  languageMatches: boolean;
  accessMatchesManagement: boolean;
  total: number;
  rows: ReadonlyArray<
    Readonly<{
      id: string;
      name: string | null;
      username: string | null;
      primaryEmail: string | null;
      lastSignInState: Phase1LastSignInState;
    }>
  >;
}>;

export type Phase1BrowserNetworkFacts = Readonly<{
  signIns: readonly Phase1BrowserSignInFact[];
  callbacks: readonly Phase1BrowserCallbackFact[];
  endpointDiscoveries: readonly Phase1BrowserEndpointDiscoveryFact[];
  exchanges: readonly Phase1BrowserExchangeFact[];
  accountReads: readonly Phase1BrowserAccountFact[];
  applicationReads: readonly Phase1BrowserApplicationReadFact[];
  userReads: readonly Phase1BrowserUserReadFact[];
}>;

export type Phase1BrowserSession = {
  preloadDemoConfiguration(
    stepId: string,
    storageKey: string,
    value: Phase1ProfiledDemoConfiguration
  ): Promise<void>;
  navigate(stepId: string, endpoint: Phase1BrowserEndpoint, path: string): Promise<void>;
  waitForRoute(
    stepId: string,
    endpoint: Phase1BrowserEndpoint,
    paths: readonly string[]
  ): Promise<void>;
  waitForExactRoute(stepId: string, endpoint: Phase1BrowserEndpoint, path: string): Promise<void>;
  assertRoute(
    stepId: string,
    endpoint: Phase1BrowserEndpoint,
    paths: readonly string[]
  ): Promise<void>;
  assertExactRoute(stepId: string, endpoint: Phase1BrowserEndpoint, path: string): Promise<void>;
  fill(
    stepId: string,
    selector: string,
    value: string,
    route: Readonly<{ endpoint: Phase1BrowserEndpoint; paths: readonly string[] }>
  ): Promise<void>;
  click(
    stepId: string,
    selector: string,
    route?: Readonly<{ endpoint: Phase1BrowserEndpoint; paths: readonly string[] }>
  ): Promise<void>;
  expectText(stepId: string, selector: string, expected: string): Promise<void>;
  expectCount(stepId: string, selector: string, expected: number): Promise<void>;
  clickAndObserveObject<Projection extends JsonObject>(
    stepId: string,
    selector: string,
    project: (value: JsonObject) => Projection
  ): Promise<Readonly<Projection>>;
  waitForNetworkFacts(
    stepId: string,
    accept: (facts: Phase1BrowserNetworkFacts) => boolean
  ): Promise<Phase1BrowserNetworkFacts>;
};

export type Phase1BrowserGroupObserver = {
  runInFreshContext<Result>(
    groupId: Phase1BrowserGroupId,
    signal: AbortSignal,
    target: TargetConfig,
    use: (session: Phase1BrowserSession) => Promise<Result>
  ): Promise<Result>;
};

export type Phase1BrowserFlowContext = Readonly<{
  profile: Readonly<Phase1Profile>;
  target: TargetConfig;
  fixture: ProvisionedPhase1Fixture;
  lease: Phase1FixtureSecretLease;
  session: Phase1BrowserSession;
  readActivityState: (
    logicalUserId: string
  ) => Promise<Readonly<{ lastSignInState: Phase1LastSignInState }>>;
  projectState: () => Promise<SemanticStateProjection>;
  signal: AbortSignal;
}>;

export type Phase1BrowserFlowModule = Readonly<{
  id: Phase1BrowserFlowId;
  executionGroup: Phase1BrowserGroupId;
  sourcePaths: readonly string[];
  run(context: Phase1BrowserFlowContext): Promise<JsonObject>;
}>;

export type Phase1BrowserFlowEvidence = Readonly<{
  id: Phase1BrowserFlowId;
  executionGroup: Phase1BrowserGroupId;
  sourceEvidence: readonly Phase1SourceEvidenceReference[];
  observation: JsonObject;
}>;

export type Phase1BrowserGroupEvidence = Readonly<{
  id: Phase1BrowserGroupId;
  flows: readonly Phase1BrowserFlowEvidence[];
}>;

export type Phase1BrowserRunEvidence = Readonly<{
  groups: readonly Phase1BrowserGroupEvidence[];
}>;

/* eslint-enable @typescript-eslint/ban-types */
