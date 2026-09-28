/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake HTTP queue records a single authorization and revocation timeline. */
import path from 'node:path';

import type { TargetConfig } from '../../model.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import { loadPhase2Profile } from '../profile.js';

import { runTokenStatusScenarios, tokenStatusScenarioIds } from './token-status.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const canonicalProfilePaths = Object.freeze({
  profilePath: path.resolve(
    process.cwd(),
    'src/compatibility/phase-2/testing/phase-2-profile.json'
  ),
  schemaPath: path.resolve(
    process.cwd(),
    'src/compatibility/phase-2/testing/phase-2-profile.schema.json'
  ),
});
const fixture: ProvisionedPhase2Fixture = {
  public: {
    allocationId: 'status-test',
    clients: {
      basic: { id: 'machine-basic', method: 'client_secret_basic' },
      post: { id: 'machine-post', method: 'client_secret_post' },
    },
    deviceClients: {
      firstParty: {
        id: 'device-first',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      },
      thirdParty: {
        id: 'device-third',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: true,
        deviceGrantEnabled: true,
      },
      missingGrant: {
        id: 'device-nogrant',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: false,
      },
    },
    resources: {
      primary: { id: 'machine-resource', indicator: 'https://machine.example/api' },
      default: { id: 'machine-default', indicator: 'https://machine.example/default' },
    },
    organization: { id: 'organization', scopeName: 'organization:read' },
    scopes: {
      read: { id: 'read', name: 'read' },
      write: { id: 'write', name: 'write' },
      unassigned: { id: 'unassigned', name: 'unassigned' },
    },
    boundary: { primary: 'provisioned', foreign: 'unchanged' },
  },
  status: {
    user: { id: 'user', username: 'status-user' },
    client: { id: 'public-client', redirectUri: 'https://client.example/callback' },
    confidentialClient: {
      id: 'confidential-client',
      redirectUri: 'https://client.example/callback',
    },
    resource: { id: 'resource', indicator: 'https://api.example.com', scopeName: 'read:profile' },
  },
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use({
      getClientSecret: () => 'unused-secret',
      getStatusClientSecret: () => 'private-status-client-secret',
      getSubjectPassword: () => 'private-password',
      toJSON: (): never => {
        throw new Error('secret lease');
      },
    }),
};
const json = (body: unknown, status = 200, revocation = false): Response =>
  new Response(revocation && status === 200 ? '' : JSON.stringify(body), {
    status,
    headers: {
      'content-type':
        revocation && status === 200
          ? 'text/plain; charset=utf-8'
          : 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      ...(revocation ? {} : { 'cache-control': 'no-store' }),
    },
  });
const active = (tokenType?: 'Bearer', clientId = 'public-client') =>
  json({
    active: true,
    sub: 'user',
    client_id: clientId,
    exp: 4600,
    iat: 1000,
    iss: 'https://candidate.example/oidc',
    scope: 'openid offline_access profile email address phone',
    ...(tokenType ? { token_type: tokenType } : {}),
  });
const unsupported = (kind: 'introspection' | 'revocation') =>
  json(
    {
      code: 'oidc.unsupported_token_type',
      message: 'An OIDC error occurred: oidc.unsupported_token_type.',
      error: 'unsupported_token_type',
      error_description:
        kind === 'introspection'
          ? 'Structured JWT Tokens cannot be introspected via the introspection_endpoint'
          : 'Structured JWT Tokens cannot be revoked via the revocation_endpoint',
    },
    400,
    kind === 'revocation'
  );

it('compares a public JWT rejection and consumed-refresh grant cascade without evidence credentials', async () => {
  const canonicalProfile = await loadPhase2Profile(canonicalProfilePaths);
  const replies = [
    new Response(null, {
      status: 303,
      headers: { 'set-cookie': 'aster-session=private-cookie; Path=/' },
    }),
    new Response(null, { status: 204 }),
    json({ verificationId: 'private-verification' }),
    new Response(null, { status: 204 }),
    json({ redirectTo: 'https://candidate.example/oidc/bridge' }),
    new Response(null, { status: 303 }),
    json({}),
    json({ redirectTo: 'https://candidate.example/oidc/resume' }),
    new Response(null, {
      status: 303,
      headers: { location: 'https://client.example/callback?code=private-code' },
    }),
    json({
      access_token: 'sentinel-access-credential',
      refresh_token: 'sentinel-initial-credential',
      token_type: 'Bearer',
    }),
    active('Bearer'),
    active(),
    active('Bearer'),
    active(),
    json({
      access_token: 'header.payload.signature',
      refresh_token: 'sentinel-successor-credential',
      token_type: 'Bearer',
    }),
    unsupported('introspection'),
    unsupported('revocation'),
    active(),
    active(),
    json(null, 200, true),
    json({ active: false }),
    json({ active: false }),
    new Response(null, {
      status: 303,
      headers: { 'set-cookie': 'aster-session=private-cookie-2; Path=/' },
    }),
    new Response(null, { status: 204 }),
    json({ verificationId: 'private-verification-2' }),
    new Response(null, { status: 204 }),
    json({ redirectTo: 'https://candidate.example/oidc/bridge' }),
    new Response(null, { status: 303 }),
    json({}),
    json({ redirectTo: 'https://candidate.example/oidc/resume' }),
    new Response(null, {
      status: 303,
      headers: { location: 'https://client.example/callback?code=private-code-2' },
    }),
    json({
      access_token: 'sentinel-second-access',
      refresh_token: 'sentinel-second-refresh',
      token_type: 'Bearer',
    }),
    json({ active: false }),
    json(
      {
        code: 'oidc.invalid_request',
        message: 'Request is invalid.',
        error: 'invalid_request',
        error_description: 'no client authentication mechanism provided',
      },
      400
    ),
    json(null, 200, true),
    json({ active: false }),
    json({ active: false }),
    json(
      {
        code: 'oidc.invalid_request',
        message: 'Request is invalid.',
        error: 'invalid_request',
        error_description: "missing required parameter 'token'",
      },
      400
    ),
    json(
      {
        code: 'oidc.invalid_request',
        message: 'Request is invalid.',
        error: 'invalid_request',
        error_description: "'token' parameter must not be provided twice",
      },
      400
    ),
    json({ active: false }),
    json({ active: false }),
    json(
      {
        code: 'oidc.invalid_request',
        message: 'Request is invalid.',
        error: 'invalid_request',
        error_description: 'no client authentication mechanism provided',
      },
      400
    ),
    new Response(null, {
      status: 303,
      headers: { 'set-cookie': 'aster-session=private-cookie-3; Path=/' },
    }),
    new Response(null, { status: 204 }),
    json({ verificationId: 'private-verification-3' }),
    new Response(null, { status: 204 }),
    json({ redirectTo: 'https://candidate.example/oidc/bridge' }),
    new Response(null, { status: 303 }),
    json({}),
    json({ redirectTo: 'https://candidate.example/oidc/resume' }),
    new Response(null, {
      status: 303,
      headers: { location: 'https://client.example/callback?code=private-code-3' },
    }),
    json({
      access_token: 'sentinel-confidential-access',
      refresh_token: 'sentinel-confidential-refresh',
      token_type: 'Bearer',
    }),
    active('Bearer', 'confidential-client'),
    active('Bearer', 'confidential-client'),
    new Response(
      JSON.stringify({
        code: 'oidc.invalid_client',
        message: 'An OIDC error occurred: oidc.invalid_client.',
        error: 'invalid_client',
        error_description: 'client authentication failed',
      }),
      {
        status: 401,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'access-control-allow-origin': '*',
          'www-authenticate':
            'Basic realm="https://candidate.example/oidc", error="invalid_client", error_description="client authentication failed"',
        },
      }
    ),
    json({ active: false }),
    json(null, 200, true),
    active('Bearer', 'confidential-client'),
  ];
  let next = 0;
  const requests: string[] = [];
  const requestFetch = (async (input: URL | RequestInfo) => {
    requests.push(new URL(String(input)).pathname);
    const reply = replies[next];
    next += 1;
    return reply ?? json({ unexpected: true }, 500);
  }) as typeof fetch;
  const results = await runTokenStatusScenarios(canonicalProfile, target, fixture, requestFetch);
  expect(results.map(({ id }) => id)).toEqual(tokenStatusScenarioIds);
  expect(tokenStatusScenarioIds.slice(-6)).toEqual([
    'token-status.confidential-basic-access-active',
    'token-status.confidential-post-access-active',
    'token-status.confidential-wrong-secret-rejected',
    'token-status.confidential-public-cross-client-inactive',
    'token-status.confidential-public-cross-client-revoked',
    'token-status.confidential-owner-after-cross-client-active',
  ]);
  expect(requests).toHaveLength(58);
  expect(results[4]?.projection.status).toBe(400);
  expect(results[5]?.projection.status).toBe(400);
  expect(results[6]?.projection.body?.active).toBe(true);
  expect(results[8]?.projection).toMatchObject({
    kind: 'revocation',
    status: 200,
    body: null,
    grant: 'revoked',
  });
  expect(results[9]?.projection.body).toEqual({ active: false });
  expect(results[10]?.projection.body).toEqual({ active: false });
  expect(results[11]?.projection.body).toEqual({ active: false });
  expect(results[12]?.projection.status).toBe(400);
  expect(results[13]?.projection).toMatchObject({
    kind: 'revocation',
    body: null,
    grant: 'revoked',
  });
  expect(results[14]?.projection.body).toEqual({ active: false });
  expect(results[15]?.projection.body).toEqual({ active: false });
  expect(results[16]?.projection.body).toMatchObject({
    error_description: "missing required parameter 'token'",
  });
  expect(results[17]?.projection.body).toMatchObject({
    error_description: "'token' parameter must not be provided twice",
  });
  expect(results[18]?.projection.body).toEqual({ active: false });
  expect(results[19]?.projection.body).toEqual({ active: false });
  expect(results[20]?.projection.body).toMatchObject({
    error_description: 'no client authentication mechanism provided',
  });
  expect(results[21]?.projection.body).toMatchObject({
    active: true,
    client_id: '<client>',
    token_type: 'Bearer',
  });
  expect(results[22]?.projection.body).toMatchObject({ active: true, token_type: 'Bearer' });
  expect(results[23]?.projection).toMatchObject({
    status: 401,
    body: { error: 'invalid_client', error_description: 'client authentication failed' },
  });
  expect(results[24]?.projection.body).toEqual({ active: false });
  expect(results[25]?.projection).toMatchObject({ body: null, grant: 'unchanged' });
  expect(results[26]?.projection.body).toMatchObject({ active: true, token_type: 'Bearer' });
  expect(JSON.stringify(results)).not.toMatch(
    /sentinel-access-credential|sentinel-initial-credential|sentinel-successor-credential|sentinel-second-access|sentinel-second-refresh|sentinel-confidential-access|sentinel-confidential-refresh|private-code/u
  );
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
