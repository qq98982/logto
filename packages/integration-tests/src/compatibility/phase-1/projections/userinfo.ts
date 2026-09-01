import type { NormalizationContext } from '../../normalize.js';
import { normalizeClaims } from '../normalizers.js';

import {
  boundedTimestampPathsFor,
  projectHttpObservation,
  type Phase1HttpProjection,
  type Phase1ProjectionCoordinates,
  type RawHttpObservation,
} from './http.js';

export const projectUserInfoObservation = (
  value: RawHttpObservation,
  context: NormalizationContext,
  coordinates?: Phase1ProjectionCoordinates
): Phase1HttpProjection =>
  projectHttpObservation(
    {
      ...value,
      body: normalizeClaims(value.body, context, 'access-token', {
        profile: 'userinfo',
        boundedTimestampPaths: boundedTimestampPathsFor(
          coordinates,
          ['body'],
          new Set(['created_at', 'updated_at'])
        ),
      }),
    },
    context
  );
