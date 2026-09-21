import type { NormalizationContext } from '../../normalize.js';

import {
  projectLogicalHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectConsoleObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => projectLogicalHttpObservation(value, context);
