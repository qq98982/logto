/* eslint-disable complexity, no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Bounded, secret-bearing HTTP requests stay inside this client; only validated projections leave it. */
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import {
  projectTokenStatus,
  type TokenStatusKind,
  type TokenStatusProjection,
} from '../projections/token-status.js';

import { containsCompactJwt } from './client-credentials.js';

export type TokenStatusProof =
  | Readonly<{ method: 'basic' | 'post'; clientId: string; clientSecret: string }>
  | Readonly<{ method: 'public'; clientId: string }>
  | Readonly<{ method: 'none' }>;

export type TokenStatusRequest = Readonly<{
  target: TargetConfig;
  kind: TokenStatusKind;
  token: string;
  hint?: string;
  proof: TokenStatusProof;
  subjectId: string;
  ownerClientId: string;
  resourceScopeName: string;
  grant: 'unchanged' | 'revoked';
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 token status HTTP observation');
};

const text = (value: unknown, maximum = 4096): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum
    ? value
    : fail();

const responseHeaders = (headers: Headers): Readonly<Record<string, string>> => {
  const values: Record<string, string> = {};
  let total = 0;
  for (const [key, value] of headers) {
    total += Buffer.byteLength(key) + Buffer.byteLength(value);
    if (total > 16 * 1024 || key === 'set-cookie' || key === 'authorization') {
      return fail();
    }
    values[key] = value;
  }
  return values;
};

const boundedBody = async (response: Response): Promise<string> => {
  const maximum = 16 * 1024;
  const length = response.headers.get('content-length');
  if (length !== null && (!/^\d+$/u.test(length) || Number(length) > maximum)) {
    await response.body?.cancel();
    return fail();
  }
  if (!response.body) {
    return '';
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    // eslint-disable-next-line no-constant-condition, @typescript-eslint/no-unnecessary-condition -- The reader terminates on its done flag.
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        return fail();
      }
      chunks.push(value);
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
  return new TextDecoder('utf8', { fatal: true }).decode(bytes);
};

export const observeTokenStatus = async (
  request: TokenStatusRequest,
  requestFetch: typeof fetch = fetch
): Promise<TokenStatusProjection> => {
  if (
    nodeTypes.isProxy(request) ||
    Object.getPrototypeOf(request) !== Object.prototype ||
    !['introspection', 'revocation'].includes(request.kind) ||
    typeof requestFetch !== 'function' ||
    (request.hint !== undefined &&
      (typeof request.hint !== 'string' || Buffer.byteLength(request.hint) > 256))
  ) {
    return fail();
  }
  const target = validateTargetConfig(request.target);
  const token = text(request.token, 8192);
  const subjectId = text(request.subjectId);
  const ownerClientId = text(request.ownerClientId);
  const resourceScopeName = text(request.resourceScopeName);
  const { proof } = request;
  if (nodeTypes.isProxy(proof) || !['basic', 'post', 'public', 'none'].includes(proof.method)) {
    return fail();
  }
  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
  const form = new URLSearchParams({ token });
  if (request.hint !== undefined) {
    form.set('token_type_hint', request.hint);
  }
  if (proof.method === 'basic' || proof.method === 'post') {
    const clientId = text(proof.clientId);
    const secret = text(proof.clientSecret);
    if (proof.method === 'basic') {
      headers.set(
        'authorization',
        `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`
      );
    } else {
      form.set('client_id', clientId);
      form.set('client_secret', secret);
    }
  } else if (proof.method === 'public') {
    form.set('client_id', text(proof.clientId));
  }
  const endpoint = new URL(`/oidc/token/${request.kind}`, target.coreUrl);
  const response = await requestFetch(endpoint, {
    method: 'POST',
    headers,
    body: form,
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  if (response.redirected || ![200, 400, 401].includes(response.status)) {
    await response.body?.cancel();
    return fail();
  }
  const selectedHeaders = responseHeaders(response.headers);
  const body = await boundedBody(response);
  if (
    body.includes(token) ||
    ((proof.method === 'basic' || proof.method === 'post') && body.includes(proof.clientSecret)) ||
    containsCompactJwt(body)
  ) {
    return fail();
  }
  let parsed: unknown = null;
  if (!(request.kind === 'revocation' && response.status === 200)) {
    try {
      parsed = JSON.parse(body) as unknown;
    } catch {
      return fail();
    }
  } else if (body !== '') {
    return fail();
  }
  return projectTokenStatus({
    target,
    kind: request.kind,
    status: response.status,
    headers: selectedHeaders,
    body: parsed,
    subjectId,
    clientId: ownerClientId,
    resourceScopeName,
    grant: request.grant,
  });
};
/* eslint-enable complexity, no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
