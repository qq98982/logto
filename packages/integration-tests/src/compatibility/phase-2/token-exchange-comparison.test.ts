/* eslint-disable @typescript-eslint/consistent-type-assertions -- These negative tests deliberately forge invalid capabilities and extra runtime input. */
import type { ProvisionedPhase2Fixture } from './fixtures.js';
import {
  assertTokenExchangeComparisonEvidence,
  createTokenExchangeComparisonTarget,
  runTokenExchangeComparison,
} from './token-exchange-comparison.js';

const projection = Object.freeze({
  responseKeys: ['access_token', 'expires_in', 'scope', 'token_type'],
  tokenType: 'Bearer',
  outputKind: 'jwt',
  sourceReusable: true,
  subjectPreserved: true,
  clientPreserved: true,
  audienceIsResource: true,
  scopeMatchesFixtureAuthority: true,
  lifetimeSeconds: 3600,
  managedSubject: {
    creationKeys: ['expiresIn', 'subjectToken'],
    expiresIn: 600,
    badTarget: { status: 400, error: 'invalid_target', sourcePreserved: true },
    successAfterBadTarget: true,
    replay: { status: 400, error: 'invalid_grant' },
    badActor: { status: 400, error: 'invalid_grant', sourcePreserved: true },
    successAfterBadActor: true,
  },
  personalAccessToken: {
    publicKeys: ['createdAt', 'expiresAt', 'name', 'tenantId', 'userId', 'value'],
    expiresAtNull: true,
    listedWithValue: true,
    repeatedResourceExchange: true,
    deleteStatus: 204,
    rejectedAfterDelete: { status: 400, error: 'invalid_grant' },
  },
  opaque: {
    responseKeys: ['access_token', 'expires_in', 'scope', 'token_type'],
    lifetimeSeconds: 3600,
    compact: 'opaque',
    scope: 'openid profile',
    userinfoSubject: true,
    introspectionActive: true,
    subjectToResourceJwt: true,
    openidActorClaim: true,
    profileActorRejected: { status: 400, error: 'invalid_grant', sourcePreserved: true },
    profileSubjectAccepted: true,
    revokedSubjectRejected: { status: 400, error: 'invalid_grant' },
    revokedActorRejected: { status: 400, error: 'invalid_grant', sourcePreserved: true },
    priorOpaqueOutputRemainsActive: true,
  },
  admissionGrammar: {
    disabled: {
      status: 400,
      error: 'invalid_request',
      errorDescription: 'grant request is invalid',
    },
    unknownClientMasksMissingSubject: {
      status: 400,
      error: 'invalid_client',
      errorDescription: 'invalid client unknown-client',
    },
    publicMissingSubject: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "missing required parameter 'subject_token'",
    },
    publicMissingSubjectType: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "missing required parameter 'subject_token_type'",
    },
    confidentialMissingProof: {
      status: 400,
      error: 'invalid_request',
      errorDescription: 'no client authentication mechanism provided',
    },
    confidentialWrongProof: {
      status: 401,
      error: 'invalid_client',
      errorDescription: 'client authentication failed',
    },
    confidentialCorrectProofMasksMissingSubject: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "missing required parameters 'subject_token' and 'subject_token_type'",
    },
    duplicateSubject: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'subject_token' parameter must not be provided twice",
    },
    duplicateSubjectType: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'subject_token_type' parameter must not be provided twice",
    },
    duplicateActor: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'actor_token' parameter must not be provided twice",
    },
    duplicateActorType: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'actor_token_type' parameter must not be provided twice",
    },
    repeatedResourceSelectsOpaque: true,
    requestedTokenTypeIgnored: true,
    metadataRestored: true,
  },
  organization: {
    organizationOnly: {
      lifetimeSeconds: 3600,
      scope: '',
      audienceMapped: true,
      organizationIdClaimAbsent: true,
    },
    resourceAndOrganization: {
      lifetimeSeconds: 3600,
      scopePreserved: true,
      audienceIsResource: true,
      organizationIdClaim: true,
    },
  },
  customizer: {
    managedTokenShape: true,
    managedUserContext: true,
    managedApplicationContext: true,
    managedOrganizationContext: true,
    managedSubjectTokenContext: true,
    ordinaryJwtSubjectTokenContextAbsent: true,
    personalAccessTokenSubjectTokenContextAbsent: true,
    deny: { status: 400, error: 'access_denied', sourcePreserved: true },
    configurationRestored: true,
  },
  scopeCanonicalization: {
    opaque: {
      duplicateNamesCollapsed: true,
      unknownNamesFiltered: true,
      scope: 'openid profile',
    },
    resource: {
      duplicateNamesCollapsed: true,
      unknownNamesFiltered: true,
      scopeMatchesFixtureAuthority: true,
    },
    organization: {
      duplicateNamesCollapsed: true,
      unauthorizedNamesFiltered: true,
      scope: '',
      lifetimeSeconds: 3600,
    },
  },
});
const evidence = Object.freeze({
  schemaVersion: 1,
  kind: 'aster-token-exchange-supplemental-comparison',
  scenarioId: 'token-exchange.user-jwt-reuse',
  oracle: {
    binding: {
      sourceCommit: 'a'.repeat(40),
      imageDigest: `sha256:${'b'.repeat(64)}`,
      stateDriverSha256: 'c'.repeat(64),
    },
    projection,
  },
  candidate: {
    binding: {
      sourceCommit: 'd'.repeat(40),
      imageDigest: `sha256:${'e'.repeat(64)}`,
      stateDriverSha256: 'f'.repeat(64),
    },
    projection,
  },
  differences: [],
});

it('validates serialized publication evidence and rejects a nested lifecycle mismatch', () => {
  expect(assertTokenExchangeComparisonEvidence(JSON.parse(JSON.stringify(evidence)))).toEqual(
    evidence
  );
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          managedSubject: { ...projection.managedSubject, successAfterBadActor: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          admissionGrammar: {
            ...projection.admissionGrammar,
            confidentialCorrectProofMasksMissingSubject: {
              ...projection.admissionGrammar.confidentialCorrectProofMasksMissingSubject,
              errorDescription:
                "missing required parameters 'subject_token_type' and 'subject_token'",
            },
          },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          opaque: { ...projection.opaque, priorOpaqueOutputRemainsActive: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          admissionGrammar: { ...projection.admissionGrammar, metadataRestored: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          customizer: { ...projection.customizer, managedSubjectTokenContext: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          scopeCanonicalization: {
            ...projection.scopeCanonicalization,
            resource: {
              ...projection.scopeCanonicalization.resource,
              duplicateNamesCollapsed: false,
            },
          },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          organization: {
            ...projection.organization,
            resourceAndOrganization: {
              ...projection.organization.resourceAndOrganization,
              lifetimeSeconds: 300,
            },
          },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
});

const fixture = Object.freeze({
  public: Object.freeze({}) as ProvisionedPhase2Fixture['public'],
  withSecretLease: async () => {
    throw new Error('unused');
  },
}) satisfies ProvisionedPhase2Fixture;

it('rejects caller-forged prepared targets before executing evidence', async () => {
  const forged = Object.freeze({ descriptor: Object.freeze({}) }) as never;
  expect(() => createTokenExchangeComparisonTarget(forged, fixture)).toThrow(
    'Invalid Phase 2 runtime'
  );
});

it('rejects extra authoritative execution properties', async () => {
  await expect(
    runTokenExchangeComparison({
      oracle: {} as never,
      candidate: {} as never,
      signal: new AbortController().signal,
      fetch: () => {
        throw new Error('must not execute');
      },
    } as never)
  ).rejects.toThrow('Invalid token-exchange supplemental comparison');
});
/* eslint-enable @typescript-eslint/consistent-type-assertions */
