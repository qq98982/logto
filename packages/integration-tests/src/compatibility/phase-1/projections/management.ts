import type { NormalizationContext } from '../../normalize.js';

import {
  boundedTimestampPathsFor,
  projectLogicalHttpObservation,
  type Phase1HttpProjection,
  type Phase1ProjectionCoordinates,
  type RawHttpObservation,
} from './http.js';

export const projectManagementObservation = (
  value: RawHttpObservation,
  context: NormalizationContext,
  coordinates?: Phase1ProjectionCoordinates
): Phase1HttpProjection =>
  projectLogicalHttpObservation(value, context, {
    boundedTimestampPaths: boundedTimestampPathsFor(
      coordinates,
      ['body'],
      new Set(['createdAt', 'updatedAt'])
    ),
  });
