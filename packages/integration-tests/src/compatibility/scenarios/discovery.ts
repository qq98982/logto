import { compareJson } from '../compare.js';
import { jsonValueGuard } from '../model.js';
import type { JsonObject, JsonValue } from '../normalize.js';
import { normalizeJson } from '../normalize.js';
import type { CompatibilityScenario, ScenarioContext } from '../scenario.js';

const setLikeDiscoveryFields = new Set([
  'claim_types_supported',
  'claims_supported',
  'code_challenge_methods_supported',
  'grant_types_supported',
  'id_token_signing_alg_values_supported',
  'response_modes_supported',
  'response_types_supported',
  'scopes_supported',
  'subject_types_supported',
  'token_endpoint_auth_methods_supported',
  'token_endpoint_auth_signing_alg_values_supported',
]);
const permittedJwkMetadata = ['kid', 'kty', 'use', 'alg', 'crv'] as const;

const isJsonObject = (value: JsonValue): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isFaithfulJsonValue = (value: unknown): value is JsonValue =>
  jsonValueGuard.safeParse(value).success;

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const prototype: unknown = Object.getPrototypeOf(value);

  return prototype === Object.prototype || prototype === null;
};

const compareCanonicalJson = (left: JsonValue, right: JsonValue) => {
  const leftText = JSON.stringify(left);
  const rightText = JSON.stringify(right);

  return leftText < rightText ? -1 : leftText > rightText ? 1 : 0;
};

const sortDocumentedSets = (value: JsonValue, propertyName?: string): JsonValue => {
  if (Array.isArray(value)) {
    const normalized = value.map((item) => sortDocumentedSets(item));

    return propertyName !== undefined && setLikeDiscoveryFields.has(propertyName)
      ? normalized.toSorted(compareCanonicalJson)
      : normalized;
  }

  if (isJsonObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nestedValue]) => [key, sortDocumentedSets(nestedValue, key)])
    );
  }

  return value;
};

export const sortDiscoveryDocument = (value: unknown): JsonObject => {
  if (!isFaithfulJsonValue(value) || !isJsonObject(value)) {
    throw new TypeError('Invalid discovery document');
  }

  const sorted = sortDocumentedSets(value);

  if (!isJsonObject(sorted)) {
    throw new TypeError('Invalid discovery document');
  }

  return sorted;
};

const normalizeDiscoveryDocument = (
  value: JsonObject,
  context: Pick<ScenarioContext, 'target' | 'symbols'>
): JsonObject => {
  const normalized = normalizeJson(value, context, []);

  if (!isJsonObject(normalized)) {
    throw new TypeError('Invalid discovery document');
  }

  return normalized;
};

export const sanitizeJwks = (
  value: unknown,
  context: Pick<ScenarioContext, 'target' | 'symbols'>
): JsonObject[] => {
  if (
    !jsonValueGuard.safeParse(value).success ||
    !isPlainRecord(value) ||
    !Array.isArray(value.keys) ||
    value.keys.length === 0
  ) {
    throw new TypeError('Invalid discovery JWKS');
  }

  const metadataKeys = value.keys.map((key): JsonObject => {
    if (!isPlainRecord(key)) {
      throw new TypeError('Invalid discovery JWKS');
    }

    return Object.fromEntries(
      permittedJwkMetadata.flatMap((property) => {
        if (!Object.hasOwn(key, property)) {
          return [];
        }

        const propertyValue = key[property];

        if (typeof propertyValue !== 'string') {
          throw new TypeError('Invalid discovery JWKS');
        }

        return [[property, propertyValue]];
      })
    );
  });
  const nonemptyKids = metadataKeys.flatMap(({ kid }) =>
    typeof kid === 'string' && kid.length > 0 ? [kid] : []
  );

  if (new Set(nonemptyKids).size !== nonemptyKids.length) {
    throw new TypeError('Invalid discovery JWKS');
  }

  return metadataKeys
    .toSorted((left, right) => {
      const { kid: _leftKid, ...leftIdentity } = left;
      const { kid: _rightKid, ...rightIdentity } = right;

      return compareCanonicalJson(leftIdentity, rightIdentity) || compareCanonicalJson(left, right);
    })
    .map((metadata) => {
      const { kid } = metadata;

      if (typeof kid === 'string' && kid.length > 0) {
        context.symbols.bindOccurrence('signing-key.kid', kid);
      }

      return metadata;
    });
};

type CanonicalJsonMediaType = 'application/json' | 'application/jwk-set+json';
type PublicJsonResponse = { status: number; mediaType: CanonicalJsonMediaType; body: unknown };

const jsonMediaTypes = ['application/json'] as const;
const jwksMediaTypes = ['application/jwk-set+json', 'application/json'] as const;

const readPublicJson = async (
  context: ScenarioContext,
  route: string,
  acceptedMediaTypes: readonly CanonicalJsonMediaType[] = jsonMediaTypes
): Promise<PublicJsonResponse> => {
  try {
    const response = await context.client.core.get(route, {
      throwHttpErrors: false,
      redirect: 'manual',
    });
    const mediaType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
    const canonicalMediaType = acceptedMediaTypes.find((accepted) => accepted === mediaType);

    if (response.status !== 200 || canonicalMediaType === undefined) {
      throw new Error('Invalid response');
    }

    return {
      status: response.status,
      mediaType: canonicalMediaType,
      body: JSON.parse(await response.text()),
    };
  } catch {
    throw new Error('Discovery endpoint read failed');
  }
};

const run = async (context: ScenarioContext): Promise<void> => {
  const openidResponse = await readPublicJson(context, 'oidc/.well-known/openid-configuration');
  const openid = sortDiscoveryDocument(openidResponse.body);
  const rfc8414Response = await readPublicJson(
    context,
    'oidc/.well-known/oauth-authorization-server'
  );
  const rfc8414 = sortDiscoveryDocument(rfc8414Response.body);

  if (
    compareJson(
      normalizeDiscoveryDocument(openid, context),
      normalizeDiscoveryDocument(rfc8414, context)
    ).length > 0
  ) {
    throw new Error('Discovery documents are not semantically equal');
  }

  context.observe({
    stepId: 'discovery.openid',
    kind: 'http',
    value: { ...openid, status: openidResponse.status, mediaType: openidResponse.mediaType },
  });
  context.observe({
    stepId: 'discovery.rfc8414-equivalence',
    kind: 'semantic-state',
    value: { equal: true },
  });

  const jwksResponse = await readPublicJson(context, 'oidc/jwks', jwksMediaTypes);
  const keys = sanitizeJwks(jwksResponse.body, context);

  context.observe({
    stepId: 'discovery.jwks',
    kind: 'http',
    value: { status: jwksResponse.status, mediaType: jwksResponse.mediaType, keys },
  });
};

export default { id: 'discovery', run } satisfies CompatibilityScenario;
