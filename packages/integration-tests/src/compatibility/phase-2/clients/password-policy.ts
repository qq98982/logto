/* eslint-disable complexity -- Public policy observations preserve exact issue ordering and omit submitted credentials. */
import type { CommonExperienceResponse, CommonExperienceSession } from './common-experience.js';

export type PasswordPolicyIssueCode =
  | 'password_rejected.too_short'
  | 'password_rejected.too_long'
  | 'password_rejected.character_types'
  | 'password_rejected.unsupported_characters'
  | 'password_rejected.pwned'
  | 'password_rejected.restricted.repetition'
  | 'password_rejected.restricted.sequence'
  | 'password_rejected.restricted.user_info'
  | 'password_rejected.restricted.words';
export type PasswordPolicyObservation = Readonly<{
  status: number;
  error:
    | 'none'
    | 'password.rejected'
    | 'user.same_password'
    | 'temporarily_unavailable'
    | 'unknown';
  issues: ReadonlyArray<
    Readonly<{
      code: PasswordPolicyIssueCode;
      minimum?: number;
      maximum?: number;
    }>
  >;
}>;
const fail = (): never => {
  throw new TypeError('Invalid Common password policy response');
};
const codes = new Set<string>([
  'password_rejected.too_short',
  'password_rejected.too_long',
  'password_rejected.character_types',
  'password_rejected.unsupported_characters',
  'password_rejected.pwned',
  'password_rejected.restricted.repetition',
  'password_rejected.restricted.sequence',
  'password_rejected.restricted.user_info',
  'password_rejected.restricted.words',
]);
const isIssueCode = (value: unknown): value is PasswordPolicyIssueCode =>
  typeof value === 'string' && codes.has(value);
const positiveInteger = (value: unknown): number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 4096
    ? value
    : fail();

export const projectPasswordPolicyResponse = (
  response: CommonExperienceResponse
): PasswordPolicyObservation => {
  const status = response.getStatus();
  const record = response.getRecord();
  const rawError = record.code ?? record.error;
  const error =
    rawError === undefined
      ? 'none'
      : rawError === 'password.rejected' ||
          rawError === 'user.same_password' ||
          rawError === 'temporarily_unavailable'
        ? rawError
        : 'unknown';
  if (error !== 'password.rejected') {
    return Object.freeze({ status, error, issues: Object.freeze([]) });
  }
  const { data } = record;
  if (!Array.isArray(data) || data.length === 0 || data.length > 16) {
    return fail();
  }
  const issues = data.map((raw: unknown) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return fail();
    }
    const code: unknown = Reflect.get(raw, 'code');
    if (!isIssueCode(code)) {
      return fail();
    }
    const interpolation: unknown = Reflect.get(raw, 'interpolation');
    const fields = Object.keys(raw);
    if (fields.some((field) => !['code', 'interpolation'].includes(field))) {
      return fail();
    }
    if (
      code === 'password_rejected.too_short' ||
      code === 'password_rejected.character_types' ||
      code === 'password_rejected.too_long'
    ) {
      if (
        typeof interpolation !== 'object' ||
        interpolation === null ||
        Array.isArray(interpolation)
      ) {
        return fail();
      }
      const key = code === 'password_rejected.too_long' ? 'max' : 'min';
      if (Object.keys(interpolation).length !== 1 || !Object.hasOwn(interpolation, key)) {
        return fail();
      }
      return Object.freeze({
        code,
        ...(key === 'min'
          ? { minimum: positiveInteger(Reflect.get(interpolation, key)) }
          : { maximum: positiveInteger(Reflect.get(interpolation, key)) }),
      });
    }
    if (interpolation !== undefined) {
      return fail();
    }
    return Object.freeze({ code });
  });
  return Object.freeze({ status, error, issues: Object.freeze(issues) });
};

export const observeExperiencePasswordProfile = async (
  session: CommonExperienceSession,
  password: string
): Promise<PasswordPolicyObservation> => {
  if (!password || Buffer.byteLength(password) > 4096) {
    return fail();
  }
  return projectPasswordPolicyResponse(
    await session.request('/api/experience/profile', 'POST', { type: 'password', value: password })
  );
};

export const observeExperienceRecoveryPassword = async (
  session: CommonExperienceSession,
  password: string
): Promise<PasswordPolicyObservation> => {
  if (!password || Buffer.byteLength(password) > 4096) {
    return fail();
  }
  return projectPasswordPolicyResponse(
    await session.request('/api/experience/profile/password', 'PUT', { password })
  );
};
/* eslint-enable complexity */
