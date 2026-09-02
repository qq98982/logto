/* eslint-disable max-lines, complexity, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-restricted-syntax -- Strict evidence guards, closed token schemas, and adversarial controls require closed-data narrowing plus isolated in-memory mutation. */
import { compactVerify, createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet } from 'jose';
import { z } from 'zod';

import { compareJson } from '../compare.js';
import { assertEvidenceIsSanitized } from '../evidence.js';
import {
  differenceGuard,
  jsonValueGuard,
  observationGuard,
  targetEvidenceGuard,
  type Difference,
  type Observation,
} from '../model.js';
import type { JsonObject, JsonValue, NormalizationContext } from '../normalize.js';

import * as candidateEvidence from './candidate-invariants/evidence.js';
import {
  differentialScenarioIdGuard,
  oracleCommit,
  phase0HarnessCommit,
  snapshotClosedDataGraph,
} from './model.js';
import { normalizeTokenResponse } from './normalizers.js';
import { phase1ScenarioStepIds } from './scenario-contracts.js';

const strictObservationGuard = observationGuard.strict();
const strictTargetEvidenceGuard = targetEvidenceGuard
  .extend({ observations: z.array(strictObservationGuard) })
  .strict();
const strictDifferenceGuard = differenceGuard.strict();
const provenanceGuard = z
  .object({
    referenceCommit: z.literal(oracleCommit),
    harnessCommit: z.literal(phase0HarnessCommit),
  })
  .strict();
export const differentialEvidenceGuard = z
  .object({
    schemaVersion: z.literal(1),
    evidenceKind: z.literal('differential'),
    scenarioId: differentialScenarioIdGuard,
    provenance: provenanceGuard,
    oracle: strictTargetEvidenceGuard.extend({ target: z.literal('oracle') }).strict(),
    candidate: strictTargetEvidenceGuard.extend({ target: z.literal('candidate') }).strict(),
    differences: z.array(strictDifferenceGuard),
  })
  .strict();

export const phase1EvidenceGuard = z.union([
  differentialEvidenceGuard,
  candidateEvidence.candidateInvariantEvidenceGuard,
]);

export type DifferentialEvidence = z.infer<typeof differentialEvidenceGuard>;
export type Phase1Evidence = z.infer<typeof phase1EvidenceGuard>;

export {
  candidateInvariantEvidenceGuard,
  createCandidateInvariantEvidence,
  type CandidateInvariantEvidence,
} from './candidate-invariants/evidence.js';

const verifiedJwtBrand: unique symbol = Symbol('verified-phase-1-jwt');
const verifiedJwtValues = new WeakMap<VerifiedJwtObservation, string>();
const verifiedTokenArrays = new WeakSet<readonly unknown[]>();
const createdPhase1Evidence = new WeakSet<Record<string, unknown>>();

export type VerifiedJwtObservation = Readonly<{ [verifiedJwtBrand]: true }>;

export const verifyObservedJwt = async (
  compactJwt: string,
  jwks: JSONWebKeySet
): Promise<VerifiedJwtObservation> => {
  try {
    if (compactJwt.split('.').length !== 3) {
      throw new TypeError('invalid compact JWT');
    }
    await compactVerify(compactJwt, createLocalJWKSet(jwks));
    const proof = Object.freeze({ [verifiedJwtBrand]: true as const });
    verifiedJwtValues.set(proof, compactJwt);

    return proof;
  } catch {
    throw new TypeError('Invalid phase 1 observed JWT signature');
  }
};

export const createVerifiedTokenObservations = (
  value: unknown,
  context: NormalizationContext,
  options: Readonly<{
    boundedClaimTimestampPaths: readonly string[];
    proofs: readonly VerifiedJwtObservation[];
  }>
): Readonly<{ body: JsonObject; tokens: readonly JsonValue[] }> => {
  try {
    const response = snapshotClosedDataGraph<JsonObject>(value);

    if (!isPlainJsonObject(response)) {
      throw new TypeError('invalid token response');
    }
    const compactJwts = ['access_token', 'id_token'].flatMap((field) => {
      const token = response[field];

      if (typeof token !== 'string' || token.split('.').length !== 3) {
        return [];
      }
      try {
        const header = decodeProtectedHeader(token);

        return typeof header.alg === 'string' && header.alg.length > 0 ? [token] : [];
      } catch {
        return [];
      }
    });

    if (
      compactJwts.some(
        (token) => !options.proofs.some((proof) => verifiedJwtValues.get(proof) === token)
      )
    ) {
      throw new TypeError('unverified compact JWT');
    }
    const normalized = normalizeTokenResponse(response, context, {
      boundedClaimTimestampPaths: options.boundedClaimTimestampPaths,
    });
    const tokenFields = ['access', 'id', 'refresh'] as const;
    const lifted = tokenFields.reduce<Readonly<{ body: JsonObject; tokens: readonly JsonValue[] }>>(
      (state, kind) => {
        const token = state.body[kind];

        if (!isPlainJsonObject(token)) {
          return state;
        }
        const projection: JsonObject =
          kind === 'refresh'
            ? { kind, format: 'opaque', ...token }
            : token.format === 'jwt'
              ? { kind, ...token, signatureVerified: true }
              : { kind, ...token };

        return {
          body: { ...state.body, [kind]: { $observation: state.tokens.length } },
          tokens: [...state.tokens, projection],
        };
      },
      { body: normalized, tokens: [] }
    );
    const result =
      snapshotClosedDataGraph<Readonly<{ body: JsonObject; tokens: readonly JsonValue[] }>>(lifted);

    if (!result) {
      throw new TypeError('invalid token observation');
    }
    const jwtCount = result.tokens.filter(
      (token) => isPlainJsonObject(token) && token.format === 'jwt'
    ).length;

    if (jwtCount !== compactJwts.length) {
      throw new TypeError('normalized JWT mismatch');
    }
    verifiedTokenArrays.add(result.tokens);

    return result;
  } catch {
    throw new TypeError('Invalid phase 1 token verification capability');
  }
};

const allowedMetadataKeys = new Set([
  'cookies',
  'setcookie',
  'cookiemetadata',
  'localauthenticationpolicy',
  'localauthenticationpresent',
  'haspassword',
  'tokentype',
  'tokens',
  'tokenlifetimeseconds',
  'tokenfamily',
  'resumecredential',
]);
const safeBooleanMetadataKeys = new Set(['cookiesealing', 'cookieverification', 'tokensigning']);
const normalizedKey = (key: string) => key.replaceAll(/[_\s-]/gu, '').toLowerCase();
const forbiddenEphemeralEvidenceKeys = new Set([
  'code',
  'state',
  'nonce',
  'codeverifier',
  'codechallenge',
  'verificationid',
  'verificationcredential',
  'verificationtoken',
]);
const symbolOnlyEvidenceKeys = new Set([
  'interaction',
  'resume',
  'resumecredential',
  'tokenfamily',
]);
const logicalSymbolPattern = /^<[A-Za-z0-9][A-Za-z0-9._-]*>$/u;
const containsOnlyLogicalSymbols = (value: unknown): boolean =>
  typeof value === 'string'
    ? logicalSymbolPattern.test(value)
    : Array.isArray(value) &&
      value.length > 0 &&
      value.every((item) => containsOnlyLogicalSymbols(item));
const isPlainJsonObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const isSafeConsumedCodeProjection = (value: unknown): boolean =>
  isPlainJsonObject(value) &&
  Object.keys(value).length === 1 &&
  Object.keys(value)[0] === 'consumed' &&
  typeof value.consumed === 'boolean';
const privateJwkMemberNames = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const containsUnsafeJwk = (value: unknown): boolean => {
  if (Array.isArray(value)) {
    return value.some((item) => containsUnsafeJwk(item));
  }
  if (!isPlainJsonObject(value)) {
    return false;
  }
  if (
    typeof value.kty === 'string' &&
    Object.keys(value).some((member) => privateJwkMemberNames.has(member))
  ) {
    return true;
  }

  return Object.entries(value).some(([key, nested]) => {
    if (key === 'jwk') {
      return (
        !isPlainJsonObject(nested) ||
        Object.keys(nested).some((member) => privateJwkMemberNames.has(member))
      );
    }

    return containsUnsafeJwk(nested);
  });
};
const normalizedJwtHeaderGuard = jsonValueGuard.superRefine((value, context) => {
  if (
    !isPlainJsonObject(value) ||
    typeof value.alg !== 'string' ||
    value.alg.length === 0 ||
    containsUnsafeJwk(value)
  ) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid token header' });
  }
});
const normalizedJwtClaimsGuard = jsonValueGuard.superRefine((value, context) => {
  if (!isPlainJsonObject(value) || containsUnsafeJwk(value)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid token claims' });
  }
});
const normalizedTokenObservationGuard = z.array(
  z.union([
    z
      .object({
        kind: z.enum(['access', 'id']),
        format: z.literal('jwt'),
        header: normalizedJwtHeaderGuard,
        claims: normalizedJwtClaimsGuard,
        signatureVerified: z.literal(true),
      })
      .strict(),
    z
      .object({
        kind: z.enum(['access', 'id']),
        format: z.literal('opaque'),
        characterCount: z.number().int().positive(),
      })
      .strict(),
    z
      .object({
        kind: z.literal('refresh'),
        format: z.literal('opaque'),
        characterCount: z.number().int().positive(),
        present: z.literal(true),
      })
      .strict(),
  ])
);

const transferVerifiedTokenArrayProof = (source: unknown, snapshot: unknown): void => {
  if (typeof source !== 'object' || source === null) {
    return;
  }

  if (Array.isArray(source)) {
    if (!Array.isArray(snapshot) || source.length !== snapshot.length) {
      throw new TypeError('Invalid phase 1 evidence snapshot');
    }
    if (verifiedTokenArrays.has(source)) {
      if (!normalizedTokenObservationGuard.safeParse(snapshot).success) {
        throw new TypeError('Invalid phase 1 evidence snapshot');
      }
      verifiedTokenArrays.add(snapshot);
    }
    for (const [index, item] of source.entries()) {
      transferVerifiedTokenArrayProof(item, snapshot[index]);
    }
    return;
  }
  if (!isPlainJsonObject(source) || !isPlainJsonObject(snapshot)) {
    throw new TypeError('Invalid phase 1 evidence snapshot');
  }
  const sourceKeys = Object.keys(source);

  if (
    sourceKeys.length !== Object.keys(snapshot).length ||
    sourceKeys.some((key) => !Object.hasOwn(snapshot, key))
  ) {
    throw new TypeError('Invalid phase 1 evidence snapshot');
  }
  for (const key of sourceKeys) {
    transferVerifiedTokenArrayProof(source[key], snapshot[key]);
  }
};

export const snapshotPhase1EvidencePreservingVerifiedTokens = <Value>(
  value: unknown
): Readonly<Value> => {
  try {
    const snapshot = snapshotClosedDataGraph<Value>(value);

    if (snapshot === undefined) {
      throw new TypeError('Invalid phase 1 evidence snapshot');
    }
    transferVerifiedTokenArrayProof(value, snapshot);

    return snapshot;
  } catch {
    throw new TypeError('Invalid phase 1 evidence snapshot');
  }
};

const assertPhase1EvidenceIsSanitizedInternal = (
  value: unknown,
  allowSerializedTokens: boolean
): void => {
  if (!jsonValueGuard.safeParse(value).success || containsUnsafeJwk(value)) {
    throw new TypeError('Invalid phase 1 evidence');
  }
  const visit = (candidate: unknown, parentKey?: string): void => {
    if (typeof candidate === 'string') {
      assertEvidenceIsSanitized({ value: candidate });
      return;
    }
    if (Array.isArray(candidate)) {
      for (const item of candidate) {
        visit(item, parentKey);
      }
      return;
    }
    if (typeof candidate === 'object' && candidate !== null) {
      for (const [key, nested] of Object.entries(candidate)) {
        const evidenceKey = normalizedKey(key);
        const registeredScenarioStep =
          parentKey === 'steps' &&
          phase1ScenarioStepIds.includes(key) &&
          isPlainJsonObject(nested) &&
          Reflect.ownKeys(nested).length === 1 &&
          Object.hasOwn(nested, 'value');

        if (
          !registeredScenarioStep &&
          ((forbiddenEphemeralEvidenceKeys.has(evidenceKey) &&
            !(evidenceKey === 'code' && isSafeConsumedCodeProjection(nested))) ||
            (safeBooleanMetadataKeys.has(evidenceKey) && typeof nested !== 'boolean') ||
            (evidenceKey === 'verificationcode' && typeof nested !== 'boolean') ||
            (symbolOnlyEvidenceKeys.has(evidenceKey) && !containsOnlyLogicalSymbols(nested)) ||
            (evidenceKey === 'tokens' &&
              (!normalizedTokenObservationGuard.safeParse(nested).success ||
                (Array.isArray(nested) &&
                  nested.length > 0 &&
                  !allowSerializedTokens &&
                  !verifiedTokenArrays.has(nested)))))
        ) {
          throw new TypeError('Invalid phase 1 evidence');
        }
        assertEvidenceIsSanitized({
          [registeredScenarioStep ||
          allowedMetadataKeys.has(evidenceKey) ||
          safeBooleanMetadataKeys.has(evidenceKey)
            ? 'metadata'
            : key]: null,
        });
        visit(nested, key);
      }
    }
  };

  try {
    visit(value);
  } catch {
    throw new TypeError('Invalid phase 1 evidence');
  }
};

export const assertPhase1EvidenceIsSanitized = (value: unknown): void => {
  assertPhase1EvidenceIsSanitizedInternal(
    value,
    isPlainJsonObject(value) && createdPhase1Evidence.has(value)
  );
};

export const assertSerializedPhase1EvidenceIsSanitized = (value: unknown): void => {
  assertPhase1EvidenceIsSanitizedInternal(value, phase1EvidenceGuard.safeParse(value).success);
};

export const assertSerializedPhase1ArtifactEvidenceIsSanitized = (value: unknown): void => {
  assertPhase1EvidenceIsSanitizedInternal(value, true);
};

const parseEvidence = <Evidence extends Phase1Evidence>(value: unknown): Evidence => {
  try {
    assertPhase1EvidenceIsSanitizedInternal(value, false);
  } catch {
    throw new TypeError('Invalid phase 1 evidence');
  }
  const snapshot = snapshotClosedDataGraph<unknown>(value);

  if (snapshot === undefined) {
    throw new TypeError('Invalid phase 1 evidence');
  }
  try {
    assertPhase1EvidenceIsSanitizedInternal(snapshot, true);
  } catch {
    throw new TypeError('Invalid phase 1 evidence');
  }
  const parsed = phase1EvidenceGuard.safeParse(snapshot);

  if (!parsed.success) {
    throw new TypeError('Invalid phase 1 evidence');
  }
  const result = snapshotClosedDataGraph<Evidence>(parsed.data);

  if (result === undefined) {
    throw new TypeError('Invalid phase 1 evidence');
  }
  createdPhase1Evidence.add(result);

  return result;
};

export const createDifferentialEvidence = (
  input: Omit<DifferentialEvidence, 'schemaVersion' | 'evidenceKind'>
): DifferentialEvidence =>
  parseEvidence<DifferentialEvidence>({
    schemaVersion: 1,
    evidenceKind: 'differential',
    ...input,
  });

type NegativeControlInput = Observation &
  Readonly<{ control?: 'observation-kind' | 'discovery-extra-field' }>;

const mutateObservation = (input: NegativeControlInput): Observation => {
  const observation = strictObservationGuard.parse({
    stepId: input.stepId,
    kind: input.kind,
    value: input.value,
  });
  const value = JSON.parse(JSON.stringify(observation.value)) as Record<string, unknown>;

  if (input.control === 'discovery-extra-field') {
    const { body } = value;

    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new TypeError('Invalid phase 1 negative control');
    }
    Object.defineProperty(body, 'aster_extra_field', {
      configurable: true,
      enumerable: true,
      value: true,
      writable: true,
    });
  } else {
    switch (observation.kind) {
      case 'http': {
        value.status = typeof value.status === 'number' ? value.status + 1 : 599;
        break;
      }
      case 'redirect': {
        value.path = `${typeof value.path === 'string' ? value.path : ''}-control`;
        break;
      }
      case 'cookie-metadata': {
        value.sameSite = value.sameSite === 'Lax' ? 'Strict' : 'Lax';
        break;
      }
      case 'jwt-header': {
        value.alg = value.alg === 'RS256' ? 'ES256' : 'RS256';
        break;
      }
      case 'jwt-claims': {
        value.aud = typeof value.aud === 'string' ? `${value.aud}-control` : 'control-audience';
        break;
      }
      case 'semantic-state': {
        const { grants } = value;

        if (!Array.isArray(grants) || typeof grants[0] !== 'object' || grants[0] === null) {
          throw new TypeError('Invalid phase 1 negative control');
        }
        const { scopes } = grants[0] as Record<string, unknown>;

        if (!Array.isArray(scopes) || typeof scopes[0] !== 'string') {
          throw new TypeError('Invalid phase 1 negative control');
        }
        scopes[0] = `${scopes[0]}-control`;
        break;
      }
    }
  }

  return strictObservationGuard.parse({ ...observation, value });
};

export const runObservationNegativeControl = (
  input: NegativeControlInput
): Readonly<{ differencePath: string; differences: readonly Difference[] }> => {
  try {
    const original = strictObservationGuard.parse({
      stepId: input.stepId,
      kind: input.kind,
      value: input.value,
    });
    const mutated = mutateObservation(input);
    const differences = compareJson({ observations: [original] }, { observations: [mutated] });

    if (differences.length !== 1 || !differences[0]) {
      throw new TypeError('Invalid phase 1 negative control');
    }

    return Object.freeze({ differencePath: differences[0].path, differences });
  } catch {
    throw new TypeError('Invalid phase 1 negative control');
  }
};

/* eslint-enable max-lines, complexity, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-restricted-syntax */
