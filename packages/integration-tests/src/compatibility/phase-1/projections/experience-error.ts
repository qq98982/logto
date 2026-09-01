import type { NormalizationContext } from '../../normalize.js';
import { normalizeExperienceError } from '../normalizers.js';

import {
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectExperienceErrorObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => {
  const error = normalizeExperienceError(value.body);

  return projectHttpObservation({ ...value, body: error, error }, context);
};
