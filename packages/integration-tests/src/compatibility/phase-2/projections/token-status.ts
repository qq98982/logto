/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types -- A bounded hostile HTTP projection validates fields and normalizes only authenticated runtime identifiers and an empty revocation body. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';

import { assertClientCredentialsEvidenceIsSanitized } from './client-credentials.js';

export type TokenStatusKind = 'introspection' | 'revocation';
export type TokenStatusProjection = Readonly<{
  kind: TokenStatusKind;
  status: number;
  headers: Readonly<Record<string, string>>;
  body: Readonly<Record<string, unknown>> | null;
  grant: 'unchanged' | 'revoked';
}>;

type StatusInput = Readonly<{
  target: TargetConfig;
  kind: TokenStatusKind;
  status: number;
  headers: Readonly<Record<string, string>>;
  body: unknown;
  subjectId: string;
  clientId: string;
  grant: 'unchanged' | 'revoked';
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 token status projection');
};

const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  return value as Record<string, unknown>;
};

const normalizedIssuer = (target: TargetConfig, issuer: unknown): '<target-issuer>' => {
  if (issuer !== new URL('oidc', target.coreUrl).href.replace(/\/$/u, '')) {
    return fail();
  }
  return '<target-issuer>';
};

const ignoredTransportHeaders = new Set([
  'content-length',
  'date',
  'connection',
  'keep-alive',
  'vary',
  'access-control-expose-headers',
  'cross-origin-resource-policy',
  'origin-agent-cluster',
  'referrer-policy',
  'strict-transport-security',
  'x-content-type-options',
  'x-download-options',
  'x-frame-options',
  'x-permitted-cross-domain-policies',
  'x-xss-protection',
  'logto-core-request-id',
  'aster-core-request-id',
]);
const comparedResponseHeaders = new Set([
  'content-type',
  'cache-control',
  'access-control-allow-origin',
  'www-authenticate',
]);

export const projectTokenStatus = (input: StatusInput): TokenStatusProjection => {
  const headers = record(input.headers);
  const selected: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (
      key !== key.toLowerCase() ||
      typeof value !== 'string' ||
      (!ignoredTransportHeaders.has(key) && !comparedResponseHeaders.has(key))
    ) {
      return fail();
    }
    if (comparedResponseHeaders.has(key)) {
      selected[key] =
        key === 'www-authenticate'
          ? value.replaceAll(
              new URL('oidc', input.target.coreUrl).href.replace(/\/$/u, ''),
              '<target-issuer>'
            )
          : value;
    }
  }
  if (
    selected['access-control-allow-origin'] !== '*' ||
    selected['content-type'] !==
      (input.kind === 'introspection' || input.status !== 200
        ? 'application/json; charset=utf-8'
        : 'text/plain; charset=utf-8') ||
    (input.kind === 'introspection' && selected['cache-control'] !== 'no-store') ||
    (input.kind === 'revocation' && selected['cache-control'] !== undefined) ||
    (input.status !== 401 && selected['www-authenticate'] !== undefined) ||
    (selected['www-authenticate'] !== undefined &&
      !/^Basic realm="<target-issuer>", error="invalid_client", error_description="[A-Za-z0-9 -]{1,128}"$/u.test(
        selected['www-authenticate']
      ))
  ) {
    return fail();
  }

  let body: TokenStatusProjection['body'];
  if (input.kind === 'revocation' && input.status === 200) {
    if (input.body !== null) {
      return fail();
    }
    body = null;
  } else {
    const source = record(input.body);
    if (input.status === 200) {
      if (input.kind !== 'introspection' || typeof source.active !== 'boolean') {
        return fail();
      }
      if (source.active) {
        const {
          sub,
          client_id: clientId,
          exp,
          iat,
          iss,
          scope,
          token_type: tokenType,
          ...rest
        } = source;
        if (
          sub !== input.subjectId ||
          clientId !== input.clientId ||
          !Number.isSafeInteger(exp) ||
          !Number.isSafeInteger(iat) ||
          (exp as number) <= (iat as number) ||
          typeof scope !== 'string' ||
          (tokenType !== undefined && tokenType !== 'Bearer') ||
          !isDeepStrictEqual(rest, { active: true })
        ) {
          return fail();
        }
        body = Object.freeze({
          active: true,
          sub: '<subject>',
          client_id: '<client>',
          exp: Object.freeze({ afterIssuedAtSeconds: (exp as number) - (iat as number) }),
          iat: '<issued-at>',
          iss: normalizedIssuer(input.target, iss),
          scope,
          ...(tokenType === undefined ? {} : { token_type: tokenType }),
        });
      } else {
        if (!isDeepStrictEqual(source, { active: false })) {
          return fail();
        }
        body = Object.freeze({ active: false });
      }
    } else {
      const { code, message, error, error_description: description, ...rest } = source;
      if (
        (input.status !== 400 && input.status !== 401) ||
        typeof code !== 'string' ||
        code !== `oidc.${error as string}` ||
        typeof message !== 'string' ||
        typeof error !== 'string' ||
        typeof description !== 'string' ||
        !isDeepStrictEqual(rest, {})
      ) {
        return fail();
      }
      body = Object.freeze({ code, message, error, error_description: description });
    }
  }
  const result = Object.freeze({
    kind: input.kind,
    status: input.status,
    headers: Object.freeze(selected),
    body,
    grant: input.grant,
  });
  assertClientCredentialsEvidenceIsSanitized(result);
  return result;
};

export const compareTokenStatus = (
  oracle: TokenStatusProjection,
  candidate: TokenStatusProjection
): readonly string[] => {
  const differences = (['kind', 'status', 'headers', 'body', 'grant'] as const)
    .filter((key) => !isDeepStrictEqual(oracle[key], candidate[key]))
    .map((key) => `/${key}`);
  const bodyDifferences =
    oracle.body?.active === true && candidate.body?.active === true
      ? (['sub', 'client_id', 'exp', 'iat', 'iss', 'scope', 'token_type'] as const)
          .filter(
            (key) =>
              Object.hasOwn(oracle.body ?? {}, key) !== Object.hasOwn(candidate.body ?? {}, key) ||
              !isDeepStrictEqual(oracle.body?.[key], candidate.body?.[key])
          )
          .map((key) => `/body/${key}`)
      : [];
  return Object.freeze([...differences, ...bodyDifferences]);
};
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types */
