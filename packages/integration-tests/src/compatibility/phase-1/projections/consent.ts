import type { NormalizationContext } from '../../normalize.js';
import { normalizeLogicalFixtureIds, normalizeResumeRedirect } from '../normalizers.js';

import {
  projectHttpObservation,
  requireProjectionJson,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectConsentObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => {
  const body = requireProjectionJson(
    normalizeLogicalFixtureIds(value.body, context),
    'Invalid phase 1 consent projection'
  );

  if (
    typeof body === 'object' &&
    body !== null &&
    !Array.isArray(body) &&
    typeof body.redirectTo === 'string'
  ) {
    return projectHttpObservation(
      {
        ...value,
        body: { ...body, redirectTo: normalizeResumeRedirect(body.redirectTo, context) },
        resumeRedirect: body.redirectTo,
      },
      context
    );
  }

  return projectHttpObservation(value, context);
};
