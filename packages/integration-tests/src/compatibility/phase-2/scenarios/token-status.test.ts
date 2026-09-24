/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake HTTP queue records a single authorization and revocation timeline. */
import type { TargetConfig } from '../../model.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from '../profile.js';

import { clientCredentialsScenarioIds } from './client-credentials.js';
import { runTokenStatusScenarios, tokenStatusScenarioIds } from './token-status.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const fixture: ProvisionedPhase2Fixture = {
  public: {
    allocationId: 'status-test',
    clients: {
      basic: { id: 'machine-basic', method: 'client_secret_basic' },
      post: { id: 'machine-post', method: 'client_secret_post' },
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
    resource: { id: 'resource', indicator: 'https://api.example.com', scopeName: 'read:profile' },
  },
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use({
      getClientSecret: () => 'unused-secret',
      getSubjectPassword: () => 'private-password',
      toJSON: (): never => {
        throw new Error('secret lease');
      },
    }),
};
const profile: Phase2ProfileRegistries = {
  ...phase2ExpectedProfileAuthority,
  differentialScenarios: [...clientCredentialsScenarioIds, ...tokenStatusScenarioIds],
  candidateInvariantScenarios: [
    'client-credentials.cross-tenant-authority-rejected',
    'client-credentials.request-role-write-rejected',
    'client-credentials.signing-failure-rolls-back',
    'client-credentials.user-authority-unchanged',
  ],
  discovery: {
    grantTypesSupportedAppend: ['client_credentials'],
    endpointFieldsAppend: ['introspection_endpoint', 'revocation_endpoint'],
    stillAbsent: ['device_authorization_endpoint', 'registration_endpoint'],
  },
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
const active = (tokenType?: 'Bearer') =>
  json({
    active: true,
    sub: 'user',
    client_id: 'public-client',
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
  ];
  let next = 0;
  const requests: string[] = [];
  const requestFetch = (async (input: URL | RequestInfo) => {
    requests.push(new URL(String(input)).pathname);
    const reply = replies[next];
    next += 1;
    return reply ?? json({ unexpected: true }, 500);
  }) as typeof fetch;
  const results = await runTokenStatusScenarios(profile, target, fixture, requestFetch);
  expect(results.map(({ id }) => id)).toEqual(tokenStatusScenarioIds);
  expect(requests).toHaveLength(37);
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
  expect(JSON.stringify(results)).not.toMatch(
    /sentinel-access-credential|sentinel-initial-credential|sentinel-successor-credential|sentinel-second-access|sentinel-second-refresh|private-code/u
  );
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
