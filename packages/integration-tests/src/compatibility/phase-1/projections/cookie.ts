import type { NormalizationContext } from '../../normalize.js';
import { normalizeCookieContinuity } from '../normalizers.js';

import {
  projectHttpObservation,
  type Phase1HttpProjection,
  type RawHttpObservation,
} from './http.js';

export const projectCookieObservation = (
  value: RawHttpObservation,
  context: NormalizationContext
): Phase1HttpProjection =>
  projectHttpObservation(
    {
      ...value,
      body: normalizeCookieContinuity(value.body, {
        nativeSurfaceImplementation: context.nativeSurfaceImplementation,
      }),
    },
    context
  );
