import type { NormalizationContext } from '../../normalize.js';
import { normalizeOAuthError } from '../normalizers.js';

import {
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectTokenErrorObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => {
  const error = normalizeOAuthError(value.body);

  return projectHttpObservation({ ...value, body: error, error }, context);
};
