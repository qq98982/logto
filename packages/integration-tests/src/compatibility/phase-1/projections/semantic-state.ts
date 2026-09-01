import type { NormalizationContext } from '../../normalize.js';
import { normalizeLogicalFixtureIds } from '../normalizers.js';

import {
  boundedTimestampPathsFor,
  projectHttpObservation,
  type Phase1HttpProjection,
  type Phase1ProjectionCoordinates,
  type RawHttpObservation,
} from './http.js';

export const projectSemanticStateObservation = (
  value: RawHttpObservation,
  context: NormalizationContext,
  coordinates?: Phase1ProjectionCoordinates
): Phase1HttpProjection =>
  projectHttpObservation(
    {
      ...value,
      semanticState: normalizeLogicalFixtureIds(value.semanticState, context, {
        boundedTimestampPaths: boundedTimestampPathsFor(
          coordinates,
          [],
          new Set(['createdAt', 'created_at', 'updatedAt', 'updated_at'])
        ),
      }),
    },
    context
  );
