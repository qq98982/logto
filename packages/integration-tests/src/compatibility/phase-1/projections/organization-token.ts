import type { NormalizationContext } from '../../normalize.js';

import type {
  Phase1HttpProjection,
  Phase1ProjectionCoordinates,
  RawHttpObservation,
} from './http.js';
import { projectTokenObservation, type VerifiedJwtObservation } from './token.js';

export const projectOrganizationTokenObservation = (
  value: RawHttpObservation,
  context: NormalizationContext,
  options: Readonly<{
    coordinates?: Phase1ProjectionCoordinates;
    verifiedJwts?: readonly VerifiedJwtObservation[];
  }> = {}
): Phase1HttpProjection => projectTokenObservation(value, context, options);
