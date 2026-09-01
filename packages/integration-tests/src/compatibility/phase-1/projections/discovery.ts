import type { NormalizationContext } from '../../normalize.js';
import { normalizeDiscovery } from '../normalizers.js';

import {
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectDiscoveryObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection =>
  projectHttpObservation({ ...value, body: normalizeDiscovery(value.body, context) }, context);
