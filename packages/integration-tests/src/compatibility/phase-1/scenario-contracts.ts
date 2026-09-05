/* eslint-disable max-lines, no-restricted-syntax -- The complete 22-row observation authority stays in one auditable table and uses bounded readonly assertions at its construction boundary. */
import {
  cloneAndDeepFreeze,
  differentialScenarioIds,
  snapshotClosedDataGraph,
  snapshotDensePlainArray,
  type Phase1DifferentialScenarioId,
  type Phase1ObservationContract,
  type Phase1ObservationKind,
  type Phase1ScenarioStep,
} from './model.js';

export const commonNormalizationPointers = Object.freeze([
  '/steps/*/value/headers/date/*',
  '/steps/*/value/headers/content-length/*',
  '/steps/*/value/cookies/*/expires',
  '/steps/*/value/error/iss',
  '/steps/*/value/error/issuer',
  '/steps/*/value/body/iss',
  '/steps/*/value/body/issuer',
  '/steps/*/value/redirect/origin',
  '/steps/*/value/redirect/query/app_id/*',
  '/steps/*/value/redirect/query/iss/*',
  '/steps/*/value/urls/*/origin',
  '/steps/*/value/urls/*/query/app_id/*',
  '/steps/*/value/urls/*/query/iss/*',
  '/steps/*/value/tokens/*/header/kid',
  '/steps/*/value/tokens/*/claims/iss',
  '/steps/*/value/tokens/*/claims/iat',
  '/steps/*/value/tokens/*/claims/exp',
  '/steps/*/value/tokens/*/claims/auth_time',
  '/steps/*/value/tokens/*/claims/jti',
  '/steps/*/value/tokens/*/claims/sid',
] as const);

export type CommonNormalizationPointer = (typeof commonNormalizationPointers)[number];
export type Phase1ScenarioContract = Readonly<{
  id: Phase1DifferentialScenarioId;
  orderedSteps: readonly Phase1ScenarioStep[];
  observationContract: Phase1ObservationContract;
  normalizablePointers: readonly string[];
  explicitNormalizablePointers: readonly string[];
}>;
export type CompiledPhase1ScenarioContract = Readonly<{
  id: Phase1DifferentialScenarioId;
  normalizablePointers: readonly string[];
  resolvedProjectionPaths: Readonly<Record<string, readonly string[]>>;
  projectionSchema: readonly Phase1ProjectionLeaf[];
}>;
export type Phase1ProjectionLeaf = Readonly<{
  path: string;
  normalization:
    | 'exact'
    | 'bounded-timestamp'
    | 'sanitized-body-byte-length'
    | 'target-symbol'
    | 'generated-id'
    | 'stable-semantic-sort';
}>;

type RawContract = Readonly<{
  id: Phase1DifferentialScenarioId;
  steps: ReadonlyArray<readonly [string, readonly Phase1ObservationKind[]]>;
  explicit: readonly string[];
}>;

const rawContracts: readonly RawContract[] = [
  {
    id: 'discovery.config',
    steps: [
      ['oidc-discovery', ['http']],
      ['oauth-discovery', ['http']],
      ['jwks', ['http']],
    ],
    explicit: [
      '/steps/jwks/value/body/keys/*/kid',
      '/steps/jwks/value/body/keys/*/publicKeyFingerprint',
    ],
  },
  {
    id: 'authorization.password-pkce-consent',
    steps: [
      ['authorize', ['redirect', 'cookie-metadata']],
      ['experience-bootstrap', ['http', 'cookie-metadata']],
      ['password', ['http', 'cookie-metadata']],
      ['identify', ['http', 'cookie-metadata']],
      ['submit', ['http', 'cookie-metadata']],
      ['consent-get', ['http', 'cookie-metadata']],
      ['consent-post', ['http', 'redirect', 'cookie-metadata']],
      ['resume', ['redirect', 'cookie-metadata']],
      ['callback', ['redirect']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/authorize/value/generatedIds/interaction',
      '/steps/consent-post/value/redirect/resumeCredential',
      '/steps/state/value/semanticState/session/updatedAt',
    ],
  },
  {
    id: 'token.authorization-code',
    steps: [
      ['token', ['http', 'jwt-header', 'jwt-claims']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/token/value/tokens/*/claims/iat',
      '/steps/token/value/tokens/*/claims/exp',
      '/steps/token/value/tokens/*/claims/auth_time',
      '/steps/token/value/tokens/*/claims/created_at',
      '/steps/token/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'token.refresh-rotation',
    steps: [
      ['code-token', ['http']],
      ['refresh-token', ['http', 'jwt-header', 'jwt-claims']],
      ['family-state', ['semantic-state']],
    ],
    explicit: [
      '/steps/refresh-token/value/tokens/*/claims/iat',
      '/steps/refresh-token/value/tokens/*/claims/exp',
      '/steps/refresh-token/value/tokens/*/claims/created_at',
      '/steps/refresh-token/value/tokens/*/claims/updated_at',
      '/steps/family-state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'userinfo.openid',
    steps: [
      ['userinfo', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: ['/steps/userinfo/value/body/created_at', '/steps/userinfo/value/body/updated_at'],
  },
  {
    id: 'management.application-read',
    steps: [
      ['first-party', ['http']],
      ['third-party', ['http']],
      ['saml', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/first-party/value/body/*/createdAt',
      '/steps/third-party/value/body/*/createdAt',
    ],
  },
  {
    id: 'management.user-read',
    steps: [
      ['users', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: ['/steps/users/value/body/*/createdAt', '/steps/users/value/body/*/updatedAt'],
  },
  {
    id: 'console.admin-auth-resource-refresh',
    steps: [
      ['authorize', ['redirect', 'cookie-metadata']],
      ['code-token', ['http']],
      ['management-refresh', ['http', 'jwt-header', 'jwt-claims']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/authorize/value/generatedIds/interaction',
      '/steps/management-refresh/value/tokens/*/claims/iat',
      '/steps/management-refresh/value/tokens/*/claims/exp',
      '/steps/management-refresh/value/tokens/*/claims/created_at',
      '/steps/management-refresh/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'console.admin-organization-token-refresh',
    steps: [
      ['organization-refresh', ['http', 'jwt-header', 'jwt-claims']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/organization-refresh/value/tokens/*/claims/iat',
      '/steps/organization-refresh/value/tokens/*/claims/exp',
      '/steps/organization-refresh/value/tokens/*/claims/created_at',
      '/steps/organization-refresh/value/tokens/*/claims/updated_at',
    ],
  },
  {
    id: 'account.admin-operator-read',
    steps: [
      ['account', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/account/value/body/createdAt',
      '/steps/account/value/body/updatedAt',
      '/steps/account/value/body/lastSignInAt',
    ],
  },
  {
    id: 'cors.management-list',
    steps: [
      ['applications-preflight', ['http']],
      ['users-preflight', ['http']],
      ['applications-get', ['http']],
      ['users-get', ['http']],
    ],
    explicit: [],
  },
  {
    id: 'cookie.localhost-port-interleaving',
    steps: [
      ['admin-start', ['redirect', 'cookie-metadata']],
      ['data-start', ['redirect', 'cookie-metadata']],
      ['admin-finish', ['redirect', 'cookie-metadata']],
      ['data-finish', ['redirect', 'cookie-metadata']],
      ['data-start-reverse', ['redirect', 'cookie-metadata']],
      ['admin-start-reverse', ['redirect', 'cookie-metadata']],
      ['data-finish-reverse', ['redirect', 'cookie-metadata']],
      ['admin-finish-reverse', ['redirect', 'cookie-metadata']],
      ['state', ['semantic-state']],
    ],
    explicit: ['/steps/*/value/generatedIds/interaction'],
  },
  {
    id: 'authorization.redirect-uri-rejected',
    steps: [
      ['authorize', ['http', 'cookie-metadata']],
      ['state', ['semantic-state']],
    ],
    explicit: [],
  },
  {
    id: 'authorization.pkce-method-rejected',
    steps: [
      ['authorize', ['http', 'redirect', 'cookie-metadata']],
      ['state', ['semantic-state']],
    ],
    explicit: [],
  },
  {
    id: 'token.pkce-verifier-rejected',
    steps: [
      ['bad-verifier', ['http']],
      ['valid-verifier-probe', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: ['/steps/state/value/generatedIds/tokenFamily'],
  },
  {
    id: 'token.code-reuse-rejected',
    steps: [
      ['first-exchange', ['http', 'jwt-header', 'jwt-claims']],
      ['replay', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/first-exchange/value/tokens/*/claims/iat',
      '/steps/first-exchange/value/tokens/*/claims/exp',
      '/steps/first-exchange/value/tokens/*/claims/created_at',
      '/steps/first-exchange/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'interaction.password-rejected',
    steps: [
      ['experience-bootstrap', ['http', 'cookie-metadata']],
      ['password', ['http', 'cookie-metadata']],
      ['state', ['semantic-state']],
    ],
    explicit: ['/steps/experience-bootstrap/value/generatedIds/interaction'],
  },
  {
    id: 'interaction.consent-session-boundary',
    steps: [
      ['get-absent', ['http', 'cookie-metadata']],
      ['get-partial', ['http', 'cookie-metadata']],
      ['get-tampered', ['http', 'cookie-metadata']],
      ['get-spliced', ['http', 'cookie-metadata']],
      ['get-replayed', ['http', 'cookie-metadata']],
      ['get-foreign', ['http', 'cookie-metadata']],
      ['post-absent', ['http', 'cookie-metadata']],
      ['post-partial', ['http', 'cookie-metadata']],
      ['post-tampered', ['http', 'cookie-metadata']],
      ['post-spliced', ['http', 'cookie-metadata']],
      ['post-replayed', ['http', 'cookie-metadata']],
      ['post-foreign', ['http', 'cookie-metadata']],
      ['get-valid-b', ['http', 'cookie-metadata']],
      ['post-valid-b', ['http', 'redirect', 'cookie-metadata']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/post-valid-b/value/redirect/resumeCredential',
      '/steps/state/value/semanticState/session/updatedAt',
    ],
  },
  {
    id: 'token.refresh-reuse-rejected',
    steps: [
      ['code-token', ['http']],
      ['rotate', ['http']],
      ['replay-old', ['http']],
      ['probe-descendant', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/rotate/value/tokens/*/claims/iat',
      '/steps/rotate/value/tokens/*/claims/exp',
      '/steps/rotate/value/tokens/*/claims/created_at',
      '/steps/rotate/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'token.issuer-audience-scope-rejected',
    steps: [
      ['wrong-issuer', ['http']],
      ['wrong-audience', ['http']],
      ['missing-scope', ['http']],
      ['state', ['semantic-state']],
    ],
    explicit: [],
  },
  {
    id: 'token.concurrent-code-single-winner',
    steps: [
      ['attempt-a', ['http']],
      ['attempt-b', ['http']],
      ['race', ['semantic-state']],
      ['state', ['semantic-state']],
    ],
    explicit: ['/steps/race/value/outcomes'],
  },
  {
    id: 'token.concurrent-refresh-single-winner',
    steps: [
      ['attempt-a', ['http']],
      ['attempt-b', ['http']],
      ['race', ['semantic-state']],
      ['state', ['semantic-state']],
    ],
    explicit: [
      '/steps/race/value/outcomes',
      '/steps/state/value/generatedIds/tokenFamily',
      '/steps/*/value/tokens/*/claims/iat',
      '/steps/*/value/tokens/*/claims/exp',
      '/steps/*/value/tokens/*/claims/created_at',
      '/steps/*/value/tokens/*/claims/updated_at',
    ],
  },
];

const explicitProjectionLeaves = {
  'discovery.config': [
    '/steps/jwks/value/body/keys/0/kid',
    '/steps/jwks/value/body/keys/0/publicKeyFingerprint',
  ],
  'authorization.password-pkce-consent': [
    '/steps/authorize/value/generatedIds/interaction',
    '/steps/consent-post/value/redirect/resumeCredential',
    '/steps/state/value/semanticState/session/updatedAt',
  ],
  'token.authorization-code': [
    '/steps/token/value/tokens/0/claims/iat',
    '/steps/token/value/tokens/0/claims/exp',
    '/steps/token/value/tokens/0/claims/auth_time',
    '/steps/token/value/tokens/0/claims/created_at',
    '/steps/token/value/tokens/0/claims/updated_at',
    '/steps/state/value/generatedIds/tokenFamily',
  ],
  'token.refresh-rotation': [
    '/steps/refresh-token/value/tokens/0/claims/iat',
    '/steps/refresh-token/value/tokens/0/claims/exp',
    '/steps/refresh-token/value/tokens/0/claims/created_at',
    '/steps/refresh-token/value/tokens/0/claims/updated_at',
    '/steps/family-state/value/generatedIds/tokenFamily',
  ],
  'userinfo.openid': [
    '/steps/userinfo/value/body/created_at',
    '/steps/userinfo/value/body/updated_at',
  ],
  'management.application-read': [
    '/steps/first-party/value/body/0/createdAt',
    '/steps/third-party/value/body/0/createdAt',
  ],
  'management.user-read': [
    '/steps/users/value/body/0/createdAt',
    '/steps/users/value/body/0/updatedAt',
  ],
  'console.admin-auth-resource-refresh': [
    '/steps/authorize/value/generatedIds/interaction',
    '/steps/management-refresh/value/tokens/0/claims/iat',
    '/steps/management-refresh/value/tokens/0/claims/exp',
    '/steps/management-refresh/value/tokens/0/claims/created_at',
    '/steps/management-refresh/value/tokens/0/claims/updated_at',
    '/steps/state/value/generatedIds/tokenFamily',
  ],
  'console.admin-organization-token-refresh': [
    '/steps/organization-refresh/value/tokens/0/claims/iat',
    '/steps/organization-refresh/value/tokens/0/claims/exp',
    '/steps/organization-refresh/value/tokens/0/claims/created_at',
    '/steps/organization-refresh/value/tokens/0/claims/updated_at',
  ],
  'account.admin-operator-read': [
    '/steps/account/value/body/createdAt',
    '/steps/account/value/body/updatedAt',
    '/steps/account/value/body/lastSignInAt',
  ],
  'cors.management-list': [],
  'cookie.localhost-port-interleaving': [
    '/steps/admin-start/value/generatedIds/interaction',
    '/steps/data-start/value/generatedIds/interaction',
    '/steps/admin-finish/value/generatedIds/interaction',
    '/steps/data-finish/value/generatedIds/interaction',
    '/steps/data-start-reverse/value/generatedIds/interaction',
    '/steps/admin-start-reverse/value/generatedIds/interaction',
    '/steps/data-finish-reverse/value/generatedIds/interaction',
    '/steps/admin-finish-reverse/value/generatedIds/interaction',
  ],
  'authorization.redirect-uri-rejected': [],
  'authorization.pkce-method-rejected': [],
  'token.pkce-verifier-rejected': ['/steps/state/value/generatedIds/tokenFamily'],
  'token.code-reuse-rejected': [
    '/steps/first-exchange/value/tokens/0/claims/iat',
    '/steps/first-exchange/value/tokens/0/claims/exp',
    '/steps/first-exchange/value/tokens/0/claims/created_at',
    '/steps/first-exchange/value/tokens/0/claims/updated_at',
    '/steps/state/value/generatedIds/tokenFamily',
  ],
  'interaction.password-rejected': ['/steps/experience-bootstrap/value/generatedIds/interaction'],
  'interaction.consent-session-boundary': [
    '/steps/post-valid-b/value/redirect/resumeCredential',
    '/steps/state/value/semanticState/session/updatedAt',
  ],
  'token.refresh-reuse-rejected': [
    '/steps/rotate/value/tokens/0/claims/iat',
    '/steps/rotate/value/tokens/0/claims/exp',
    '/steps/rotate/value/tokens/0/claims/created_at',
    '/steps/rotate/value/tokens/0/claims/updated_at',
    '/steps/state/value/generatedIds/tokenFamily',
  ],
  'token.issuer-audience-scope-rejected': [],
  'token.concurrent-code-single-winner': ['/steps/race/value/outcomes'],
  'token.concurrent-refresh-single-winner': [
    '/steps/race/value/outcomes',
    '/steps/state/value/generatedIds/tokenFamily',
    '/steps/attempt-a/value/tokens/0/claims/iat',
    '/steps/attempt-b/value/tokens/0/claims/iat',
    '/steps/attempt-a/value/tokens/0/claims/exp',
    '/steps/attempt-b/value/tokens/0/claims/exp',
    '/steps/attempt-a/value/tokens/0/claims/created_at',
    '/steps/attempt-b/value/tokens/0/claims/created_at',
    '/steps/attempt-a/value/tokens/0/claims/updated_at',
    '/steps/attempt-b/value/tokens/0/claims/updated_at',
  ],
} as const satisfies Record<Phase1DifferentialScenarioId, readonly string[]>;

type NormalizationTreatment = Phase1ProjectionLeaf['normalization'];

const leaf = (path: string, normalization: NormalizationTreatment): Phase1ProjectionLeaf => ({
  path,
  normalization,
});

const stepProjectionLeaves = ({
  id,
  kinds,
}: Phase1ScenarioStep): readonly Phase1ProjectionLeaf[] => [
  ...(kinds.includes('http')
    ? [
        leaf(`/steps/${id}/value/status`, 'exact'),
        leaf(`/steps/${id}/value/mediaType/**`, 'exact'),
        leaf(`/steps/${id}/value/mediaType/type`, 'exact'),
        leaf(`/steps/${id}/value/mediaType/subtype`, 'exact'),
        leaf(`/steps/${id}/value/mediaType/parameters/*/*`, 'exact'),
        leaf(`/steps/${id}/value/error/**`, 'exact'),
        leaf(`/steps/${id}/value/error/iss`, 'target-symbol'),
        leaf(`/steps/${id}/value/error/issuer`, 'target-symbol'),
        // Structured Location/Set-Cookie mirrors remain under the exact header envelope, but the
        // HTTP projection guard requires them to equal the canonical redirect/cookie projections.
        leaf(`/steps/${id}/value/headers/*/*`, 'exact'),
        leaf(`/steps/${id}/value/headers/date/*`, 'bounded-timestamp'),
        leaf(`/steps/${id}/value/headers/content-length/*`, 'sanitized-body-byte-length'),
        // Projectors that publish a structured body redirect mirror must prove it equals redirect.
        leaf(`/steps/${id}/value/body/**`, 'exact'),
        leaf(`/steps/${id}/value/body/iss`, 'target-symbol'),
        leaf(`/steps/${id}/value/body/issuer`, 'target-symbol'),
        leaf(`/steps/${id}/value/sideEffects/**`, 'exact'),
        leaf(`/steps/${id}/value/urls/*/**`, 'exact'),
        leaf(`/steps/${id}/value/urls/*/scheme`, 'exact'),
        leaf(`/steps/${id}/value/urls/*/origin`, 'target-symbol'),
        leaf(`/steps/${id}/value/urls/*/path`, 'exact'),
        leaf(`/steps/${id}/value/urls/*/query/*/*`, 'exact'),
        leaf(`/steps/${id}/value/urls/*/query/app_id/*`, 'generated-id'),
        leaf(`/steps/${id}/value/urls/*/query/iss/*`, 'target-symbol'),
        leaf(`/steps/${id}/value/urls/*/fragment`, 'exact'),
      ]
    : []),
  ...(kinds.includes('redirect')
    ? [
        leaf(`/steps/${id}/value/redirect/**`, 'exact'),
        leaf(`/steps/${id}/value/redirect/scheme`, 'exact'),
        leaf(`/steps/${id}/value/redirect/origin`, 'target-symbol'),
        leaf(`/steps/${id}/value/redirect/path`, 'exact'),
        leaf(`/steps/${id}/value/redirect/query/*/*`, 'exact'),
        leaf(`/steps/${id}/value/redirect/query/app_id/*`, 'generated-id'),
        leaf(`/steps/${id}/value/redirect/query/iss/*`, 'target-symbol'),
        leaf(`/steps/${id}/value/redirect/fragment`, 'exact'),
      ]
    : []),
  ...(kinds.includes('cookie-metadata')
    ? [
        leaf(`/steps/${id}/value/cookies/*/**`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/name`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/httpOnly`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/secure`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/sameSite`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/path`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/domain`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/maxAge`, 'exact'),
        leaf(`/steps/${id}/value/cookies/*/expires`, 'bounded-timestamp'),
      ]
    : []),
  ...(kinds.includes('jwt-header')
    ? [
        leaf(`/steps/${id}/value/tokens/*/header/**`, 'exact'),
        leaf(`/steps/${id}/value/tokens/*/header/alg`, 'exact'),
        leaf(`/steps/${id}/value/tokens/*/header/kid`, 'generated-id'),
      ]
    : []),
  ...(kinds.includes('jwt-claims')
    ? [
        leaf(`/steps/${id}/value/tokens/*/claims/**`, 'exact'),
        leaf(`/steps/${id}/value/tokens/*/claims/iss`, 'target-symbol'),
        leaf(`/steps/${id}/value/tokens/*/claims/aud`, 'exact'),
        leaf(`/steps/${id}/value/tokens/*/claims/scope`, 'exact'),
        leaf(`/steps/${id}/value/tokens/*/claims/iat`, 'bounded-timestamp'),
        leaf(`/steps/${id}/value/tokens/*/claims/exp`, 'bounded-timestamp'),
        leaf(`/steps/${id}/value/tokens/*/claims/auth_time`, 'bounded-timestamp'),
        leaf(`/steps/${id}/value/tokens/*/claims/jti`, 'generated-id'),
        leaf(`/steps/${id}/value/tokens/*/claims/sid`, 'generated-id'),
      ]
    : []),
  ...(kinds.includes('semantic-state')
    ? [
        leaf(`/steps/${id}/value/**`, 'exact'),
        leaf(`/steps/${id}/value/persistedState/**`, 'exact'),
        leaf(`/steps/${id}/value/sideEffects/**`, 'exact'),
      ]
    : []),
];

const explicitTreatment = (path: string): Exclude<NormalizationTreatment, 'exact'> => {
  if (path.endsWith('/outcomes')) {
    return 'stable-semantic-sort';
  }
  if (
    /\/(?:iat|exp|auth_time|createdAt|created_at|updatedAt|updated_at|lastSignInAt)$/u.test(path)
  ) {
    return 'bounded-timestamp';
  }

  return 'generated-id';
};

const schemaPatternMatches = (pattern: string, candidate: string): boolean => {
  const patternSegments = pattern.split('/');
  const candidateSegments = candidate.split('/');
  const visit = (patternIndex: number, candidateIndex: number): boolean => {
    const patternSegment = patternSegments[patternIndex];

    if (patternSegment === undefined) {
      return candidateIndex === candidateSegments.length;
    }
    if (patternSegment === '**') {
      return (
        patternIndex === patternSegments.length - 1 ||
        Array.from(
          { length: candidateSegments.length - candidateIndex + 1 },
          (_, offset) => candidateIndex + offset
        ).some((nextIndex) => visit(patternIndex + 1, nextIndex))
      );
    }
    const candidateSegment = candidateSegments[candidateIndex];

    return (
      candidateSegment !== undefined &&
      (patternSegment === '*' || patternSegment === candidateSegment) &&
      visit(patternIndex + 1, candidateIndex + 1)
    );
  };

  return visit(0, 0);
};

const ruleSpecificity = (path: string): number =>
  path
    .split('/')
    .reduce((score, segment) => score + (segment === '**' ? 0 : segment === '*' ? 10 : 100), 0);

const effectiveNormalization = (
  schema: readonly Phase1ProjectionLeaf[],
  path: string
): NormalizationTreatment => {
  const matches = schema.filter((rule) => schemaPatternMatches(rule.path, path));
  const highestSpecificity = Math.max(
    ...matches.map(({ path: rulePath }) => ruleSpecificity(rulePath))
  );
  const winners = matches.filter(
    ({ path: rulePath }) => ruleSpecificity(rulePath) === highestSpecificity
  );
  const treatments = new Set(winners.map(({ normalization }) => normalization));
  const winner = winners[0];

  if (matches.length === 0 || treatments.size !== 1 || !winner) {
    throw new TypeError('Invalid phase 1 projection schema');
  }

  return winner.normalization;
};

const effectiveNormalizableRules = (
  schema: readonly Phase1ProjectionLeaf[]
): readonly Phase1ProjectionLeaf[] =>
  schema.filter(
    (rule) =>
      rule.normalization !== 'exact' &&
      effectiveNormalization(schema, rule.path) === rule.normalization
  );

const buildProjectionSchema = (
  id: Phase1DifferentialScenarioId,
  steps: readonly Phase1ScenarioStep[]
): readonly Phase1ProjectionLeaf[] => {
  const candidates = [
    ...steps.flatMap((step) => stepProjectionLeaves(step)),
    ...explicitProjectionLeaves[id].map((path) => leaf(path, explicitTreatment(path))),
  ];
  const conflicts = candidates.some((candidate, index) =>
    candidates.some(
      (other, otherIndex) =>
        index !== otherIndex &&
        candidate.path === other.path &&
        candidate.normalization !== other.normalization
    )
  );

  if (conflicts) {
    throw new TypeError('Invalid phase 1 projection schema');
  }
  const schema = candidates.filter(
    (candidate, index) => candidates.findIndex(({ path }) => path === candidate.path) === index
  );

  effectiveNormalizableRules(schema);

  return cloneAndDeepFreeze(schema) as readonly Phase1ProjectionLeaf[];
};

const pointerMatchesPath = (pointer: string, path: string): boolean => {
  const pointerSegments = pointer.split('/');
  const pathSegments = path.split('/');

  return (
    pointerSegments.length === pathSegments.length &&
    pointerSegments.every((segment, index) => segment === '*' || segment === pathSegments[index])
  );
};

const supportedCommonPointers = (
  projectionSchema: readonly Phase1ProjectionLeaf[]
): readonly string[] =>
  commonNormalizationPointers.filter((pointer) =>
    effectiveNormalizableRules(projectionSchema).some(({ path }) =>
      pointerMatchesPath(pointer, path)
    )
  );

const observationContract = (steps: readonly Phase1ScenarioStep[]): Phase1ObservationContract => {
  const forKind = (kind: Phase1ObservationKind) =>
    steps.filter(({ kinds }) => kinds.includes(kind)).map(({ id }) => id);
  const http = forKind('http');

  return {
    status: http,
    mediaType: http,
    headers: http,
    cookies: forKind('cookie-metadata'),
    redirects: forKind('redirect'),
  };
};

const buildContract = ({ id, steps: rawSteps, explicit }: RawContract): Phase1ScenarioContract => {
  const steps = rawSteps.map(([stepId, kinds]) => ({ id: stepId, kinds }));
  const projectionSchema = buildProjectionSchema(id, steps);
  const pointers = [...supportedCommonPointers(projectionSchema), ...explicit];

  return cloneAndDeepFreeze({
    id,
    orderedSteps: steps,
    observationContract: observationContract(steps),
    normalizablePointers: pointers.filter((pointer, index) => pointers.indexOf(pointer) === index),
    explicitNormalizablePointers: explicit,
  }) as Phase1ScenarioContract;
};

export const phase1ScenarioContracts = cloneAndDeepFreeze(
  rawContracts.map((rawContract) => buildContract(rawContract))
) as readonly Phase1ScenarioContract[];
export const phase1ScenarioStepIds = Object.freeze([
  ...new Set(
    phase1ScenarioContracts.flatMap(({ orderedSteps }) => orderedSteps.map(({ id }) => id))
  ),
]);

const contractDiagnostic = 'Invalid phase 1 scenario contract';
const registryDiagnostic = 'Invalid phase 1 scenario contract registry';

const equalArrays = <Value>(left: readonly Value[], right: readonly Value[]) => {
  const leftSnapshot = snapshotDensePlainArray<Value>(left);
  const rightSnapshot = snapshotDensePlainArray<Value>(right);

  if (!leftSnapshot || !rightSnapshot || leftSnapshot.length !== rightSnapshot.length) {
    return false;
  }
  for (const [index, value] of leftSnapshot.entries()) {
    if (value !== rightSnapshot[index]) {
      return false;
    }
  }

  return true;
};

const equalSteps = (left: readonly Phase1ScenarioStep[], right: readonly Phase1ScenarioStep[]) => {
  const leftSnapshot = snapshotDensePlainArray<Phase1ScenarioStep>(left);
  const rightSnapshot = snapshotDensePlainArray<Phase1ScenarioStep>(right);

  if (!leftSnapshot || !rightSnapshot || leftSnapshot.length !== rightSnapshot.length) {
    return false;
  }
  for (const [index, leftStep] of leftSnapshot.entries()) {
    const rightStep = rightSnapshot[index];

    if (
      !rightStep ||
      leftStep.id !== rightStep.id ||
      !equalArrays(leftStep.kinds, rightStep.kinds)
    ) {
      return false;
    }
  }

  return true;
};

const equalObservation = (left: Phase1ObservationContract, right: Phase1ObservationContract) =>
  equalArrays(left.status, right.status) &&
  equalArrays(left.mediaType, right.mediaType) &&
  equalArrays(left.headers, right.headers) &&
  equalArrays(left.cookies, right.cookies) &&
  equalArrays(left.redirects, right.redirects);

// eslint-disable-next-line complexity -- Exact recursive equality handles primitives, arrays, records, and descriptors without executing caller code.
const equalClosedData = (left: unknown, right: unknown): boolean => {
  if (Object.is(left, right)) {
    return true;
  }
  if (typeof left !== 'object' || left === null || typeof right !== 'object' || right === null) {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    for (const [index, value] of left.entries()) {
      if (!equalClosedData(value, right[index])) {
        return false;
      }
    }

    return true;
  }
  const leftKeys = Reflect.ownKeys(left);
  const rightKeys = Reflect.ownKeys(right);

  if (leftKeys.length !== rightKeys.length || leftKeys.some((key) => !rightKeys.includes(key))) {
    return false;
  }
  for (const key of leftKeys) {
    const leftDescriptor = Object.getOwnPropertyDescriptor(left, key);
    const rightDescriptor = Object.getOwnPropertyDescriptor(right, key);

    if (
      !leftDescriptor ||
      !rightDescriptor ||
      !Object.hasOwn(leftDescriptor, 'value') ||
      !Object.hasOwn(rightDescriptor, 'value') ||
      !equalClosedData(leftDescriptor.value, rightDescriptor.value)
    ) {
      return false;
    }
  }

  return true;
};

const isExactContract = (
  candidate: Phase1ScenarioContract,
  expected: Phase1ScenarioContract
): boolean =>
  equalClosedData(candidate, expected) &&
  candidate.id === expected.id &&
  equalSteps(candidate.orderedSteps, expected.orderedSteps) &&
  equalObservation(candidate.observationContract, expected.observationContract) &&
  equalArrays(candidate.normalizablePointers, expected.normalizablePointers) &&
  equalArrays(candidate.explicitNormalizablePointers, expected.explicitNormalizablePointers);

export const assertExactScenarioContracts = (
  contracts: readonly Phase1ScenarioContract[]
): void => {
  try {
    const snapshot = snapshotDensePlainArray<Phase1ScenarioContract>(contracts);

    if (!snapshot || snapshot.length !== phase1ScenarioContracts.length) {
      throw new TypeError(registryDiagnostic);
    }
    for (const [index, contract] of snapshot.entries()) {
      const expected = phase1ScenarioContracts[index];

      if (!expected || !isExactContract(contract, expected)) {
        throw new TypeError(registryDiagnostic);
      }
    }
  } catch {
    throw new TypeError(registryDiagnostic);
  }
};

const projectionSchemaDiagnostic = 'Invalid phase 1 projection schema';

export const assertExactScenarioProjectionSchema = (
  id: Phase1DifferentialScenarioId,
  schema: readonly Phase1ProjectionLeaf[]
): void => {
  try {
    const snapshot = snapshotDensePlainArray<Phase1ProjectionLeaf>(schema);
    const contract = phase1ScenarioContracts.find((candidate) => candidate.id === id);

    if (!snapshot || !contract) {
      throw new TypeError(projectionSchemaDiagnostic);
    }
    const expected = buildProjectionSchema(contract.id, contract.orderedSteps);

    if (snapshot.length !== expected.length) {
      throw new TypeError(projectionSchemaDiagnostic);
    }
    for (const [index, rule] of snapshot.entries()) {
      const expectedRule = expected[index];

      if (!expectedRule || !equalClosedData(rule, expectedRule)) {
        throw new TypeError(projectionSchemaDiagnostic);
      }
    }
    effectiveNormalizableRules(snapshot);
  } catch {
    throw new TypeError(projectionSchemaDiagnostic);
  }
};

export const compileScenarioNormalizablePointers = (
  id: Phase1DifferentialScenarioId,
  pointers: readonly string[]
): CompiledPhase1ScenarioContract => {
  try {
    const pointerSnapshot = snapshotDensePlainArray<string>(pointers);
    const contract = phase1ScenarioContracts.find((candidate) => candidate.id === id);

    if (!pointerSnapshot || !contract || new Set(pointerSnapshot).size !== pointerSnapshot.length) {
      throw new TypeError(contractDiagnostic);
    }
    const allowedPointers = new Set(contract.normalizablePointers);
    const projectionSchema = buildProjectionSchema(contract.id, contract.orderedSteps);
    assertExactScenarioProjectionSchema(contract.id, projectionSchema);
    const normalizableLeaves = effectiveNormalizableRules(projectionSchema);
    const entries = pointerSnapshot.map((pointer) => {
      if (!allowedPointers.has(pointer)) {
        throw new TypeError(contractDiagnostic);
      }
      const resolved = normalizableLeaves
        .filter(({ path }) => pointerMatchesPath(pointer, path))
        .map(({ path }) => path);

      if (resolved.length === 0) {
        throw new TypeError(contractDiagnostic);
      }

      return [pointer, resolved] as const;
    });
    const resolvedProjectionPaths = Object.fromEntries(entries);
    const coveredPaths = new Set(entries.flatMap(([, paths]) => paths));

    if (
      Object.keys(resolvedProjectionPaths).length !== entries.length ||
      normalizableLeaves.some(({ path }) => !coveredPaths.has(path))
    ) {
      throw new TypeError(contractDiagnostic);
    }

    return cloneAndDeepFreeze({
      id,
      normalizablePointers: pointerSnapshot,
      resolvedProjectionPaths,
      projectionSchema,
    }) as CompiledPhase1ScenarioContract;
  } catch {
    throw new TypeError(contractDiagnostic);
  }
};

export const compileScenarioContract = (
  contract: Phase1ScenarioContract
): CompiledPhase1ScenarioContract => {
  try {
    const snapshot = snapshotClosedDataGraph<Phase1ScenarioContract>(contract);

    if (!snapshot || Array.isArray(snapshot)) {
      throw new TypeError(contractDiagnostic);
    }
    const expectedIndex = differentialScenarioIds.indexOf(snapshot.id);
    const expected = phase1ScenarioContracts[expectedIndex];

    if (!expected || !isExactContract(snapshot, expected)) {
      throw new TypeError(contractDiagnostic);
    }
    return compileScenarioNormalizablePointers(snapshot.id, snapshot.normalizablePointers);
  } catch {
    throw new TypeError(contractDiagnostic);
  }
};

for (const contract of phase1ScenarioContracts) {
  compileScenarioContract(contract);
}

/* eslint-enable max-lines, no-restricted-syntax */
