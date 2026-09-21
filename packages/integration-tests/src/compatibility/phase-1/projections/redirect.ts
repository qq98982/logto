import type { NormalizationContext } from '../../normalize.js';
import { normalizeRedirect } from '../normalizers.js';

import {
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectRedirectObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection => {
  if (typeof value.body !== 'string') {
    throw new TypeError('Invalid phase 1 redirect projection');
  }

  return projectHttpObservation(
    { ...value, body: normalizeRedirect(value.body, context), redirect: value.body },
    context
  );
};
