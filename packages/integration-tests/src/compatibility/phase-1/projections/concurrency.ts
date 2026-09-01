import type { NormalizationContext } from '../../normalize.js';
import { normalizeConcurrentOutcomes } from '../normalizers.js';

import {
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectConcurrencyObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => {
  const outcomes = normalizeConcurrentOutcomes(value.body, context);

  return projectHttpObservation(
    { ...value, body: { $observation: 'outcomes' }, outcomes },
    context
  );
};
