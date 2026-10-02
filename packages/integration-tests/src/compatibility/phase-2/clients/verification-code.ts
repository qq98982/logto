/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, unicorn/no-await-expression-member, @typescript-eslint/ban-types -- The closed projector parses one bounded response exactly once and keeps private handle material out of its public projection. */
import type { TargetConfig } from '../../model.js';

export type VerificationCodeObservation = Readonly<
  | {
      target: TargetConfig;
      surface: 'experience';
      operation: 'request';
      identifier: string;
      event: 'SignIn' | 'Register' | 'ForgotPassword';
      cookie: string;
      clientId: string;
    }
  | {
      target: TargetConfig;
      surface: 'experience';
      operation: 'verify';
      identifier: string;
      handle: string;
      code: string;
      cookie: string;
      clientId: string;
    }
  | {
      target: TargetConfig;
      surface: 'account';
      operation: 'request';
      identifier: string;
      bearer: string;
    }
  | {
      target: TargetConfig;
      surface: 'account';
      operation: 'verify';
      identifier: string;
      handle: string;
      code: string;
      bearer: string;
    }
>;

export type VerificationCodeProjection = Readonly<{
  status: number;
  contentType: string | null;
  cacheControl: string | null;
  outcome: 'created' | 'verified' | 'empty' | 'error';
  handleField: 'verificationId' | 'verificationRecordId' | null;
  expiresAt: boolean;
  error?: string | null;
  message?: string;
  data?: Readonly<{ message: 'Message failed: 550 controlled rejection' }>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 verification-code observation');
};

const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length &&
  Object.keys(value).every((key) => keys.includes(key));

const mediaType = (value: string | null): string | null =>
  value?.split(';', 1)[0]?.trim().toLowerCase() ?? null;

const readBody = async (response: Response): Promise<string> => {
  const maximumBytes = 64 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)) {
    return fail();
  }
  const body = await response.text();
  return Buffer.byteLength(body) <= maximumBytes ? body : fail();
};

const project = async (
  surface: VerificationCodeObservation['surface'],
  operation: VerificationCodeObservation['operation'],
  response: Response
): Promise<Readonly<{ projection: VerificationCodeProjection; handle?: string }>> => {
  const body = await readBody(response);
  const base = {
    status: response.status,
    contentType: mediaType(response.headers.get('content-type')),
    cacheControl: response.headers.get('cache-control'),
  };
  if (body.length === 0) {
    if (response.status !== 204) {
      return fail();
    }
    return Object.freeze({
      projection: Object.freeze({
        ...base,
        outcome: 'empty' as const,
        handleField: null,
        expiresAt: false,
      }),
    });
  }
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch {
    return fail();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  const record = value as Record<string, unknown>;
  const handleField = surface === 'experience' ? 'verificationId' : 'verificationRecordId';
  const expectedSuccessStatus =
    surface === 'experience' ? 200 : operation === 'request' ? 201 : 200;
  if (response.status === expectedSuccessStatus && typeof record[handleField] === 'string') {
    const requestKeys =
      surface === 'account' && operation === 'request' ? [handleField, 'expiresAt'] : [handleField];
    if (
      !exactKeys(record, requestKeys) ||
      (requestKeys.length === 2 &&
        (typeof record.expiresAt !== 'string' || Number.isNaN(Date.parse(record.expiresAt))))
    ) {
      return fail();
    }
    return Object.freeze({
      projection: Object.freeze({
        ...base,
        outcome: operation === 'request' ? ('created' as const) : ('verified' as const),
        handleField,
        expiresAt: requestKeys.length === 2,
      }),
      handle: record[handleField],
    });
  }
  const controlledConnectorData =
    exactKeys(record, ['code', 'message', 'data']) &&
    record.code === 'connector.general' &&
    record.message ===
      'Error occurred in connector: {"message":"Message failed: 550 controlled rejection"}' &&
    typeof record.data === 'object' &&
    record.data !== null &&
    !Array.isArray(record.data) &&
    exactKeys(record.data as Record<string, unknown>, ['message']) &&
    (record.data as Record<string, unknown>).message === 'Message failed: 550 controlled rejection';
  if (
    (exactKeys(record, ['code', 'message']) || controlledConnectorData) &&
    typeof record.code === 'string' &&
    record.code.length > 0 &&
    record.code.length <= 128 &&
    /^[a-z0-9_.-]+$/u.test(record.code) &&
    typeof record.message === 'string' &&
    record.message.length <= 2048
  ) {
    return Object.freeze({
      projection: Object.freeze({
        ...base,
        outcome: 'error' as const,
        handleField: null,
        expiresAt: false,
        error: record.code,
        message: record.message,
        ...(controlledConnectorData && {
          data: Object.freeze({ message: 'Message failed: 550 controlled rejection' as const }),
        }),
      }),
    });
  }
  return fail();
};

export const observeVerificationCodePrivate = async (
  input: VerificationCodeObservation,
  requestFetch: typeof fetch = fetch
): Promise<Readonly<{ projection: VerificationCodeProjection; handle?: string }>> => {
  const path =
    input.surface === 'experience'
      ? `/api/experience/verification/verification-code${input.operation === 'verify' ? '/verify' : ''}`
      : `/api/verifications/verification-code${input.operation === 'verify' ? '/verify' : ''}`;
  const headers = new Headers({ 'content-type': 'application/json; charset=utf-8' });
  if (input.surface === 'experience') {
    headers.set('cookie', input.cookie);
    headers.set('aster-app-id', input.clientId);
  } else {
    headers.set('authorization', `Bearer ${input.bearer}`);
  }
  const body =
    input.operation === 'request'
      ? {
          identifier: { type: 'email', value: input.identifier },
          ...(input.surface === 'experience' ? { interactionEvent: input.event } : {}),
        }
      : {
          identifier: { type: 'email', value: input.identifier },
          verificationId: input.handle,
          code: input.code,
        };
  const response = await requestFetch(new URL(path, input.target.coreUrl), {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    redirect: 'manual',
    signal: AbortSignal.timeout(30_000),
  });
  return project(input.surface, input.operation, response);
};

export const observeVerificationCode = async (
  input: VerificationCodeObservation,
  requestFetch: typeof fetch = fetch
): Promise<VerificationCodeProjection> =>
  (await observeVerificationCodePrivate(input, requestFetch)).projection;
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, unicorn/no-await-expression-member, @typescript-eslint/ban-types */
