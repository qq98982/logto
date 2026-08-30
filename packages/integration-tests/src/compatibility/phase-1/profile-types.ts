/* eslint-disable max-lines, @typescript-eslint/ban-types, @typescript-eslint/array-type -- The canonical profile's closed JSON shape is one auditable type module; null and readonly arrays are part of that schema. */
export type Phase1ProfileSchemaLock = Readonly<{
  sourceCommit: string;
  sha256: string;
}>;

export type Phase1ProfilePaths = Readonly<{
  profilePath: string;
  schemaPath: string;
}>;

export type Phase1ProfileValidationStage =
  | 'json'
  | 'schema-hash'
  | 'schema'
  | 'semantic'
  | 'provenance';

export type Phase1ProfileSemanticContext = Readonly<{
  baselineCapabilityIds: ReadonlySet<string>;
  differentialRegistryIds: readonly string[];
  candidateInvariantRegistryIds: readonly string[];
}>;

export type Phase1ProvenanceMode = 'review-candidate' | 'accepted-harness';

type EmptyObject = Readonly<Record<string, never>>;
type StringList = readonly string[];

export type Phase1Reference = Readonly<{
  oracleRepository: string;
  oracleCommit: string;
  phase0HarnessCommit: string;
  phase0PullRequest: string;
  phase0EvidencePath: string;
  phase0EvidenceAuthority: string;
  phase0HostedRunId: number;
  phase0ArtifactId: number;
  phase0ArtifactRole: string;
  phase0ArtifactSha256: Readonly<{
    'discovery.json': string;
    'negative-control.json': string;
    'password-code.json': string;
    'run.json': string;
  }>;
}>;

type Phase1CanonicalSchemaBase = Readonly<{
  repository: string;
  path: string;
}>;

export type Phase1CanonicalSchema = Phase1CanonicalSchemaBase &
  (
    | Readonly<{
        sourceCommit: null;
        sha256: null;
        lockState: 'design-unlocked; the canonical schema source commit and SHA-256 must be pinned before the Phase 1 harness is pinned';
      }>
    | Readonly<{
        sourceCommit: string;
        sha256: string;
        lockState: 'locked; sourceCommit and sha256 pin the sole canonical Phase 1 profile schema';
      }>
  );

type Phase1HarnessLockBase = Readonly<{
  repository: string;
  baseCommit: string;
  plannedBranch: string;
  plannedArtifacts: Readonly<{
    profileLoader: string;
    scenarioRegistry: string;
    candidateInvariantRegistry: string;
    fixtureProvisioner: string;
    semanticProjectionRegistry: string;
    normalizerRegistry: string;
    browserRunner: string;
    oracleSnapshotDirectory: string;
    acceptanceRecordDirectory: string;
  }>;
  phase0NormalizerSources: StringList;
  requiredControls: StringList;
  responseContractPolicy: string;
  fixtureIdPolicy: string;
  fixtureIsolationPolicy: string;
  sensitiveObservationPolicy: Readonly<{
    redirectTo: string;
    cookies: string;
    browserAndConformanceArtifacts: string;
    artifactAllowlist: string;
    evidence: string;
  }>;
}>;

export type Phase1HarnessLock = Phase1HarnessLockBase &
  (
    | Readonly<{
        commit: null;
        lockState: 'design-unlocked; a reviewed descendant commit must be pinned before Rust behavior implementation';
      }>
    | Readonly<{
        commit: string;
        lockState: 'locked; commit pins the reviewed Phase 1 harness descendant';
      }>
  );

export type Phase1UiSource = Readonly<{
  repository: string;
  commit: string;
  consoleTree: string;
  experienceTree: string;
  demoAppTree: string;
  pnpmLockBlob: string;
}>;

type Phase1UiAssetBase = Readonly<{
  baseUrl: string;
  htmlFallbackRoutes: StringList;
  assetPrefix: string;
}>;

export type Phase1ExperienceUiAsset = Phase1UiAssetBase &
  Readonly<{
    application: 'experience-user' | 'experience-admin';
    tenant: string;
    sourceTreeField: 'experienceTree';
  }>;

export type Phase1StaticUiAsset = Phase1UiAssetBase &
  Readonly<{
    application: 'demo-app' | 'console';
    sourceTreeField: 'demoAppTree' | 'consoleTree';
  }>;

export type Phase1UiAssetContract = Phase1ExperienceUiAsset | Phase1StaticUiAsset;

export type Phase1Routing = Readonly<{
  userEndpoint: string;
  adminEndpoint: string;
  customDomains: boolean;
  pathBasedTenancy: boolean;
  subdomainTenancy: boolean;
}>;

export type Phase1LocalhostCookiePortContract = Readonly<{
  browserRule: string;
  compatibilityRule: string;
  keyIsolation: string;
  interleavings: StringList;
  requiredOutcome: string;
}>;

type OidcClientMetadata = Readonly<{
  redirectUris: StringList;
  postLogoutRedirectUris: StringList;
}>;

type FirstPartyApplication = Readonly<{
  id: string;
  name: string;
  type: string;
  isThirdParty: false;
  oidcClientMetadata: OidcClientMetadata;
  customClientMetadata: EmptyObject;
}>;

type ThirdPartyApplication = Readonly<{
  id: string;
  name: string;
  type: string;
  isThirdParty: true;
  oidcClientMetadata: OidcClientMetadata;
  customClientMetadata: EmptyObject;
  userConsentScopes: StringList;
  resourceConsentScopes: StringList;
}>;

export type Phase1Application = FirstPartyApplication | ThirdPartyApplication;

export type Phase1Fixtures = Readonly<{
  adminTenant: Readonly<{
    id: string;
    operator: Readonly<{
      id: string;
      username: string;
      primaryEmail: string;
      roles: StringList;
      customData: Readonly<{ ossOnboarding: Readonly<{ isOnboardingDone: boolean }> }>;
    }>;
    application: Readonly<{
      id: string;
      type: string;
      oidcClientMetadata: OidcClientMetadata;
      customClientMetadata: EmptyObject;
    }>;
    resources: readonly Readonly<{ indicator: string; scopes: StringList }>[];
    tenantOrganization: Readonly<{
      id: string;
      name: string;
      memberUserIds: StringList;
      scopes: StringList;
      organizationRoles: readonly Readonly<{
        id: string;
        name: string;
        type: string;
        scopeNames: StringList;
        userIds: StringList;
      }>[];
    }>;
  }>;
  dataTenant: Readonly<{
    id: string;
    subject: Readonly<{
      id: string;
      username: string;
      name: string;
      primaryEmail: string;
      primaryPhone: string;
      profile: Readonly<{
        address: Readonly<{ formatted: string; country: string }>;
      }>;
      applicationId: string | null;
    }>;
    applications: readonly Phase1Application[];
    resource: Readonly<{
      id: string;
      name: string;
      indicator: string;
      scopes: readonly Readonly<{ id: string; name: string; description: string }>[];
    }>;
    resourceScopeRole: Readonly<{
      id: string;
      name: string;
      description: string;
      type: string;
      isDefault: boolean;
      scopeIds: StringList;
      userIds: StringList;
    }>;
    browserClientConfiguration: Readonly<{
      route: string;
      localStorageKey: string;
      localStorageValue: Readonly<{
        appId: string;
        prompt: string;
        scope: string;
        resource: string;
      }>;
      effectiveScopes: StringList;
      scopeDerivation: string;
      scopeDerivationSources: StringList;
    }>;
  }>;
}>;

export type Phase1ConsoleAuthentication = Readonly<{
  endpoint: string;
  issuer: string;
  managementDataTenant: string;
  applicationId: string;
  redirectUri: string;
  prompt: StringList;
  grants: StringList;
  configuredResources: StringList;
  effectiveResources: StringList;
  configuredScopes: StringList;
  effectiveScopes: StringList;
  scopeDerivation: string;
  resourceDerivation: string;
  requiresResourceTokenRefresh: boolean;
  requiresOrganizationTokenRefresh: boolean;
}>;

export type Phase1ConsoleOrganizationTokenRequest = Readonly<{
  sourceEvidence: StringList;
  sourceCapabilities: StringList;
  trigger: string;
  method: string;
  url: string;
  contentType: string;
  form: Readonly<{
    client_id: string;
    grant_type: string;
    refresh_token: string;
    organization_id: string;
    resource: string | null;
    scope: string | null;
  }>;
  expectedStatus: number;
  requiredTokenResponseProjection: Readonly<{ token_type: string; scope: string }>;
  requiredAccessTokenProjection: Readonly<{
    format: string;
    iss: string;
    sub: string;
    aud: string;
    client_id: string;
    scope: string;
  }>;
  requiredAccessTokenOmissions: StringList;
  requiredPersistedOutcome: string;
}>;

export type Phase1OidcConfiguration = Readonly<{
  issuerPath: string;
  discoveryPath: string;
  oauthAuthorizationServerDiscoveryPath: string;
  authorizationPath: string;
  tokenPath: string;
  userinfoPath: string;
  jwksPath: string;
  grants: StringList;
  responseTypes: StringList;
  responseModes: StringList;
  pkceCodeChallengeMethods: StringList;
  tokenEndpointAuthMethods: StringList;
  scopesSupported: StringList;
  claimsParameterSupported: boolean;
  claimsSupported: StringList;
  subjectTypesSupported: StringList;
  idTokenSigningAlgorithmsSupported: StringList;
  authorizationResponseIssParameterSupported: boolean;
  requestUriParameterSupported: boolean;
  claimTypesSupported: StringList;
  jwksKeyMetadata: Readonly<{ kty: string; use: string; alg: string; crv: string }>;
  discoveryProjectionRule: string;
}>;

export type Phase1ConsoleTokenAuthorization = Readonly<{
  issuer: string;
  resource: string;
  scope: string;
}>;

export type Phase1AccountTokenAuthorization = Readonly<{
  issuer: string;
  resource: string | null;
  tokenFormat: string;
}>;

export type Phase1ApplicationReadQuery = Readonly<{
  page: string;
  page_size: string;
  isThirdParty: string;
  types?: string;
}>;

export type Phase1UserReadQuery = Readonly<{
  page: string;
  page_size: string;
}>;

type ConsoleEndpointBootstrapRequest = Readonly<{
  method: string;
  baseUrl: string;
  path: '/api/.well-known/endpoints/default';
  query: EmptyObject;
  authorization: Phase1ConsoleTokenAuthorization | null;
  expectedStatus: number;
  requiredProjection: Readonly<{ user: string }>;
}>;

type ApplicationProjection = Readonly<{
  id: string;
  name: string;
  type: string;
  isThirdParty: boolean;
  customClientMetadata: EmptyObject;
}>;

type UserProjection = Readonly<{
  id: string;
  username: string;
  name: string;
  primaryEmail: string;
  primaryPhone: string;
  avatar: string | null;
  applicationId: string | null;
  lastSignInAt: number | null;
  isSuspended: boolean;
  hasPassword: boolean;
}>;

type ConsoleListRequestBase = Readonly<{
  method: string;
  baseUrl: string;
  baseUrlField: string;
  origin: string;
  headers: Readonly<{ 'Accept-Language': string }>;
  authorization: Phase1ConsoleTokenAuthorization;
  expectedStatus: number;
  requiredResponseHeaders: StringList;
  requiredHeaderValues: Readonly<{ 'Total-Number': string }>;
  requiredBodyLength: number;
}>;

type ConsoleApplicationReadRequest = ConsoleListRequestBase &
  Readonly<{
    path: '/api/applications';
    query: Phase1ApplicationReadQuery;
    requiredProjection: readonly ApplicationProjection[];
  }>;

type ConsoleUserReadRequest = ConsoleListRequestBase &
  Readonly<{
    path: '/api/users';
    query: Phase1UserReadQuery;
    requiredProjection: readonly UserProjection[];
  }>;

export type Phase1ConsoleReadRequest =
  | ConsoleEndpointBootstrapRequest
  | ConsoleApplicationReadRequest
  | ConsoleUserReadRequest;

type ExperienceSettingsRequest = Readonly<{
  method: string;
  baseUrl: string;
  path: '/api/.well-known/sign-in-exp';
  query: Readonly<{ appId: string; uiLocales: string }>;
  expectedStatus: number;
  requiredProjection: string;
}>;

type ExperiencePhraseRequest = Readonly<{
  method: string;
  baseUrl: string;
  path: '/api/.well-known/phrases';
  query: Readonly<{ lng: string }>;
  headers: Readonly<{ 'Accept-Language': string }>;
  expectedStatus: number;
  requiredProjection: string;
}>;

export type Phase1ExperienceBootstrapRequest = ExperienceSettingsRequest | ExperiencePhraseRequest;

export type Phase1ConsoleAccountRequest = Readonly<{
  method: string;
  url: string;
  authorization: Phase1AccountTokenAuthorization;
  expectedStatus: number;
  requiredProjection: Readonly<{ id: string; username: string; primaryEmail: string }>;
}>;

export type Phase1CorsContract = Readonly<{
  origin: string;
  target: string;
  methods: StringList;
  allowedRequestHeaders: StringList;
  allowOriginResponse: string;
  exposeHeadersResponse: string;
  browserReadableHeader: string;
  preflightPaths: StringList;
  preflightStatus: number;
}>;

export type Phase1HostIdentityInfrastructure = Readonly<{
  certManager: string;
  csiDriverSpiffe: string;
  trustManager: string;
  defaultCertificateRequestApproverDisabled: boolean;
  overlappingApproverPoliciesAllowed: boolean;
}>;

type ConsentOperationBase = Readonly<{
  id: string;
  sourceEvidence: StringList;
  sourceCapabilities: StringList;
  baseUrl: string;
  path: string;
  authorization: string;
  cookieJarContinuity: string;
  expectedStatus: number;
  errorStatuses: readonly number[];
}>;

type ConsentGetOperation = ConsentOperationBase &
  Readonly<{
    method: 'GET';
    requiredProjection: Readonly<{
      application: Readonly<{ id: string; name: string }>;
      user: Readonly<{
        id: string;
        username: string;
        name: string;
        primaryEmail: string;
        primaryPhone: string;
      }>;
      organizations: StringList;
      missingOIDCScope: StringList;
      missingResourceScopes: readonly Readonly<{
        resource: Readonly<{ id: string; name: string; indicator: string }>;
        scopes: readonly Readonly<{ id: string; name: string; description: string }>[];
      }>[];
      redirectUri: string;
    }>;
  }>;

type ConsentPostOperation = ConsentOperationBase &
  Readonly<{
    method: 'POST';
    body: EmptyObject;
    requiredProjection: Readonly<{
      redirectTo: Readonly<{
        scheme: string;
        origin: string;
        pathTemplate: string;
        queryKeys: StringList;
        fragment: string;
      }>;
    }>;
    requiredPersistedOutcome: Readonly<{
      applicationId: string;
      userId: string;
      oidcScopes: StringList;
      resource: string;
      resourceScopes: StringList;
      userFirstConsentedApplicationId: string;
      sessionExtension: Readonly<{ accountId: string; clientId: string; lastSubmission: string }>;
    }>;
  }>;

export type Phase1InteractionOperation = ConsentGetOperation | ConsentPostOperation;

export type Phase1ConsentSessionBoundaryContract = Readonly<{
  scenarioId: string;
  rejectionVariants: StringList;
  positiveIsolationVariant: string;
  rejectionObservableComparison: string;
  positiveObservableComparison: string;
  rejectionPersistedOutcome: string;
  positivePersistedOutcome: string;
  credentialHandling: string;
}>;

type BrowserFlowBase = Readonly<{
  id: string;
  executionGroup: string;
  sourceEvidence: StringList;
  routes: StringList;
  assertions: StringList;
}>;

type ConsoleAuthenticationBrowserFlow = BrowserFlowBase &
  Readonly<{
    id: 'console.clean-authentication';
    startRoute: string;
    postAuthenticationRoute: string;
  }>;

type StandardBrowserFlow = BrowserFlowBase &
  Readonly<{
    id: 'experience.password-pkce-consent' | 'console.application-read' | 'console.user-read';
  }>;

export type Phase1BrowserFlow = ConsoleAuthenticationBrowserFlow | StandardBrowserFlow;

export type Phase1BrowserExecutionGroup = Readonly<{
  id: string;
  fixtureState: string;
  browserContext: string;
  orderedFlows: StringList;
  postconditions: StringList;
}>;

type BasicConformancePlan = Readonly<{
  testPlanName: 'oidcc-basic-certification-test-plan';
  displayName: string;
  variants: Readonly<{
    serverMetadata: string;
    clientRegistration: string;
    responseType: string;
    responseMode: string;
    clientAuthTypes: StringList;
  }>;
}>;

type ConfigConformancePlan = Readonly<{
  testPlanName: 'oidcc-config-certification-test-plan';
  displayName: string;
  variants: Readonly<{ clientRegistration: string; serverMetadata: string }>;
}>;

export type Phase1Conformance = Readonly<{
  suiteRepository: string;
  suiteCommit: string;
  target: Readonly<{
    namespace: string;
    issuer: string;
    discoveryUrl: string;
    suiteBaseUrl: string;
    alias: string;
    callbackUri: string;
    tls: Readonly<{
      trustDomain: string;
      issuer: string;
      asterMaterial: string;
      suiteMaterial: string;
      lifecycle: string;
    }>;
  }>;
  staticClients: readonly Readonly<{
    id: string;
    tokenEndpointAuthMethod: string;
    redirectUris: StringList;
  }>[];
  plans: readonly (BasicConformancePlan | ConfigConformancePlan)[];
}>;

export type Phase1Profile = Readonly<{
  schemaVersion: 1;
  profileId: string;
  reference: Phase1Reference;
  profileSchema: Phase1CanonicalSchema;
  phase1Harness: Phase1HarnessLock;
  uiSource: Phase1UiSource;
  uiAssetContracts: readonly Phase1UiAssetContract[];
  routing: Phase1Routing;
  localhostCookiePortContract: Phase1LocalhostCookiePortContract;
  fixtures: Phase1Fixtures;
  consoleAuthentication: Phase1ConsoleAuthentication;
  consoleOrganizationTokenRequest: Phase1ConsoleOrganizationTokenRequest;
  oidc: Phase1OidcConfiguration;
  managementOperations: StringList;
  accountOperations: StringList;
  experienceBootstrapOperations: StringList;
  consoleBootstrapOperations: StringList;
  consoleReadRequests: readonly Phase1ConsoleReadRequest[];
  experienceBootstrapRequests: readonly Phase1ExperienceBootstrapRequest[];
  consoleAccountRequests: readonly Phase1ConsoleAccountRequest[];
  cors: Phase1CorsContract;
  hostIdentityInfrastructure: Phase1HostIdentityInfrastructure;
  experienceOperations: StringList;
  interactionOperations: readonly Phase1InteractionOperation[];
  consentSessionBoundaryContract: Phase1ConsentSessionBoundaryContract;
  browserFlows: readonly Phase1BrowserFlow[];
  browserExecutionGroups: readonly Phase1BrowserExecutionGroup[];
  differentialScenarios: StringList;
  candidateInvariantScenarios: StringList;
  semanticStateInvariants: StringList;
  conformance: Phase1Conformance;
}>;

/* eslint-enable max-lines, @typescript-eslint/ban-types, @typescript-eslint/array-type */
