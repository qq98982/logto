/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-constant-condition, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition -- Fresh interaction cookies and private proof handles remain inside this bounded HTTP control. */
import { randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import type { CommonPhoneCodeControls, PhoneCodePurpose } from './common-phone-code.js';
import type { CommonPhoneCodeProviderLease } from './selected-phone-code-fixture.js';

type Event = 'SignIn' | 'Register';
type PublicResult = Readonly<{ status: number; code: string }>;
type Interaction = Readonly<{ cookie: string; clientId: string; event: Event }>;

const fail = (): never => {
  throw new TypeError('Invalid Common phone code controls');
};

const readJson = async (response: Response): Promise<Record<string, unknown>> => {
  const maximum = 16 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    return fail();
  }
  const reader = response.body?.getReader();
  if (!reader) {
    return fail();
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      size += chunk.value.byteLength;
      if (size > maximum) {
        await reader.cancel().catch(() => false);
        return fail();
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let body: string;
  try {
    body = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  } catch {
    return fail();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return fail();
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return fail();
  }
  return parsed as Record<string, unknown>;
};

const publicResult = async (response: Response): Promise<PublicResult> => {
  const body = await readJson(response);
  const code = Reflect.get(body, 'code');
  if (typeof code !== 'string' || !/^[a-z0-9_.-]{1,128}$/u.test(code)) {
    return fail();
  }
  return Object.freeze({ status: response.status, code });
};

const initialize = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  redirectUri: string,
  event: Event,
  requestFetch: typeof fetch
): Promise<Interaction> => {
  const status = fixture.status ?? fail();
  const authorization = new URL('/oidc/auth', target.coreUrl);
  authorization.search = new URLSearchParams({
    client_id: status.client.id,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid profile phone',
    code_challenge: randomBytes(32).toString('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  const admitted = await requestFetch(authorization, {
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  const cookies = admitted.headers.getSetCookie().map((value) => value.split(';', 1)[0] ?? '');
  await admitted.body?.cancel();
  if (
    admitted.status !== 303 ||
    cookies.length < 2 ||
    cookies.length > 16 ||
    cookies.some((value) => !/^[^=;\s]{1,128}=[^;\u0000-\u001F\u007F]{1,4096}$/u.test(value))
  ) {
    return fail();
  }
  const cookie = cookies.join('; ');
  const initialized = await requestFetch(new URL('/api/experience', target.coreUrl), {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      cookie,
      [target.label === 'candidate' ? 'aster-app-id' : 'logto-app-id']: status.client.id,
    },
    body: JSON.stringify({ interactionEvent: event }),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  await initialized.body?.cancel();
  if (initialized.status !== 204) {
    return fail();
  }
  return Object.freeze({ cookie, clientId: status.client.id, event });
};

const post = async (
  target: TargetConfig,
  interaction: Interaction,
  path: string,
  body: Record<string, unknown>,
  requestFetch: typeof fetch
): Promise<Response> =>
  requestFetch(new URL(path, target.coreUrl), {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      cookie: interaction.cookie,
      [target.label === 'candidate' ? 'aster-app-id' : 'logto-app-id']: interaction.clientId,
    },
    body: JSON.stringify(body),
    redirect: 'manual',
    signal: AbortSignal.timeout(30_000),
  });

const requestCode = async (
  target: TargetConfig,
  interaction: Interaction,
  phone: string,
  lease: CommonPhoneCodeProviderLease,
  requestFetch: typeof fetch
): Promise<string> => {
  const purpose: PhoneCodePurpose = interaction.event;
  await lease.arm(phone, purpose);
  const response = await post(
    target,
    interaction,
    '/api/experience/verification/verification-code',
    { identifier: { type: 'phone', value: phone }, interactionEvent: interaction.event },
    requestFetch
  );
  const body = await readJson(response);
  const handle = Reflect.get(body, 'verificationId');
  if (response.status !== 200 || typeof handle !== 'string' || !handle) {
    return fail();
  }
  return handle;
};

const verify = async (
  target: TargetConfig,
  interaction: Interaction,
  phone: string,
  handle: string,
  code: string,
  requestFetch: typeof fetch
): Promise<Readonly<{ response: Response; proof?: string }>> => {
  const response = await post(
    target,
    interaction,
    '/api/experience/verification/verification-code/verify',
    { identifier: { type: 'phone', value: phone }, verificationId: handle, code },
    requestFetch
  );
  if (response.status !== 200) {
    return Object.freeze({ response });
  }
  const body = await readJson(response.clone());
  const proof = Reflect.get(body, 'verificationId');
  if (typeof proof !== 'string' || !proof) {
    return fail();
  }
  await response.body?.cancel();
  return Object.freeze({ response, proof });
};

const identify = async (
  target: TargetConfig,
  interaction: Interaction,
  proof: string,
  requestFetch: typeof fetch
): Promise<PublicResult> =>
  publicResult(
    await post(
      target,
      interaction,
      '/api/experience/identification',
      { verificationId: proof },
      requestFetch
    )
  );

const ownerIds = async (request: Phase2AdminRequestFunction, phone: string): Promise<string[]> => {
  const users = await request({
    method: 'GET',
    path: 'users',
    query: { page: '1', page_size: '100' },
    expectedStatuses: [200],
    responseKind: 'array',
  });
  if (!Array.isArray(users) || users.length >= 100) {
    return fail();
  }
  return Array.from<unknown>(users)
    .filter(
      (user) =>
        typeof user === 'object' && user !== null && Reflect.get(user, 'primaryPhone') === phone
    )
    .map((user) => Reflect.get(user as Record<string, unknown>, 'id'))
    .filter((id): id is string => typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(id));
};

export const runCommonPhoneCodeHttpControls = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    lease: CommonPhoneCodeProviderLease;
    owner: Readonly<{ id: string; primaryPhone: string }>;
    collisionOwner: Readonly<{ id: string; primaryPhone: string }>;
    suspended: Readonly<{ id: string; primaryPhone: string }>;
    redirectUri: string;
    fetch?: typeof fetch;
  }>
): Promise<CommonPhoneCodeControls> => {
  const requestFetch = input.fetch ?? fetch;
  const mismatchInteraction = await initialize(
    input.target,
    input.fixture,
    input.redirectUri,
    'SignIn',
    requestFetch
  );
  const mismatchHandle = await requestCode(
    input.target,
    mismatchInteraction,
    input.owner.primaryPhone,
    input.lease,
    requestFetch
  );
  const mismatchCode = await input.lease.takeCode(input.owner.primaryPhone, 'SignIn');
  const mismatch = await verify(
    input.target,
    mismatchInteraction,
    input.suspended.primaryPhone,
    mismatchHandle,
    mismatchCode,
    requestFetch
  );
  const mismatchResult = await publicResult(mismatch.response);
  const ownerRetry = await verify(
    input.target,
    mismatchInteraction,
    input.owner.primaryPhone,
    mismatchHandle,
    mismatchCode,
    requestFetch
  );
  if (
    mismatchResult.status !== 400 ||
    mismatchResult.code !== 'verification_code.phone_mismatch' ||
    !ownerRetry.proof
  ) {
    return fail();
  }

  const replay = await verify(
    input.target,
    mismatchInteraction,
    input.owner.primaryPhone,
    mismatchHandle,
    mismatchCode,
    requestFetch
  );
  const replayResult = await publicResult(replay.response);

  const ownersBefore = await ownerIds(input.request, input.collisionOwner.primaryPhone);
  const occupiedInteraction = await initialize(
    input.target,
    input.fixture,
    input.redirectUri,
    'Register',
    requestFetch
  );
  const occupiedHandle = await requestCode(
    input.target,
    occupiedInteraction,
    input.collisionOwner.primaryPhone,
    input.lease,
    requestFetch
  );
  const occupiedCode = await input.lease.takeCode(input.collisionOwner.primaryPhone, 'Register');
  const occupiedProof = await verify(
    input.target,
    occupiedInteraction,
    input.collisionOwner.primaryPhone,
    occupiedHandle,
    occupiedCode,
    requestFetch
  );
  if (!occupiedProof.proof) {
    return fail();
  }
  const occupied = await identify(
    input.target,
    occupiedInteraction,
    occupiedProof.proof,
    requestFetch
  );
  const ownersAfter = await ownerIds(input.request, input.collisionOwner.primaryPhone);

  const suspendedInteraction = await initialize(
    input.target,
    input.fixture,
    input.redirectUri,
    'SignIn',
    requestFetch
  );
  const suspendedHandle = await requestCode(
    input.target,
    suspendedInteraction,
    input.suspended.primaryPhone,
    input.lease,
    requestFetch
  );
  const suspendedCode = await input.lease.takeCode(input.suspended.primaryPhone, 'SignIn');
  const suspendedProof = await verify(
    input.target,
    suspendedInteraction,
    input.suspended.primaryPhone,
    suspendedHandle,
    suspendedCode,
    requestFetch
  );
  if (!suspendedProof.proof) {
    return fail();
  }
  const suspended = await identify(
    input.target,
    suspendedInteraction,
    suspendedProof.proof,
    requestFetch
  );

  if (
    replayResult.status !== 400 ||
    replayResult.code !== 'verification_code.not_found' ||
    ownersBefore.length !== 1 ||
    ownersBefore[0] !== input.collisionOwner.id ||
    ownersAfter.length !== 1 ||
    ownersAfter[0] !== input.collisionOwner.id ||
    occupied.status !== 422 ||
    occupied.code !== 'user.phone_already_in_use' ||
    suspended.status !== 401 ||
    suspended.code !== 'user.suspended'
  ) {
    return fail();
  }
  return Object.freeze({
    occupiedRegistration: Object.freeze({
      status: 422,
      code: 'user.phone_already_in_use',
      ownerUnchanged: true,
    }),
    consumedReplay: Object.freeze({ status: 400, code: 'verification_code.not_found' }),
    recipientMismatch: Object.freeze({
      status: 400,
      code: 'verification_code.phone_mismatch',
      ownerRetained: true,
    }),
    suspendedOwner: Object.freeze({ status: 401, code: 'user.suspended' }),
  });
};
/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-constant-condition, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition */
