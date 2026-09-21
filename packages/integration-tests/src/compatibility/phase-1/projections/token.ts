import type { NormalizationContext } from '../../normalize.js';
import { createVerifiedTokenObservations, type VerifiedJwtObservation } from '../evidence.js';

import {
  boundedTimestampPathsFor,
  projectHttpObservation,
  requireProjectionJson,
  type Phase1ProjectionCoordinates,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export { verifyObservedJwt } from '../evidence.js';
export type { VerifiedJwtObservation } from '../evidence.js';

type TokenProjectionOptions = Readonly<{
  coordinates?: Phase1ProjectionCoordinates;
  verifiedJwts?: readonly VerifiedJwtObservation[];
}>;

export const projectTokenObservation = (
  value: RawHttpObservation,
  context: NormalizationContext,
  options: TokenProjectionOptions = {}
): Phase1HttpProjection => {
  if (Object.hasOwn(value, 'tokens')) {
    throw new TypeError('Invalid phase 1 token projection');
  }
  const verified = (() => {
    try {
      return createVerifiedTokenObservations(value.body, context, {
        boundedClaimTimestampPaths: boundedTimestampPathsFor(
          options.coordinates,
          ['tokens', '*', 'claims'],
          new Set(['iat', 'exp', 'auth_time', 'created_at', 'updated_at'])
        ),
        proofs: options.verifiedJwts ?? [],
      });
    } catch {
      throw new TypeError('Invalid phase 1 token projection');
    }
  })();
  const base = projectHttpObservation({ ...value, body: verified.body }, context);
  const projection = Object.freeze({ ...base, tokens: verified.tokens });
  requireProjectionJson(projection, 'Invalid phase 1 token projection');

  return projection;
};
