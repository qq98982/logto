/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful HTTP fake proves three independent Register interactions and secret privacy. */
import { createEmailPasswordRegistrationControlRuntime } from './common-email-password-registration-control-runtime.js';

test('runs missing-profile, duplicate, and policy controls in fresh verified Register interactions', async () => {
  let interaction = 0;
  const calls: string[] = [];
  const runtime = createEmailPasswordRegistrationControlRuntime({
    target: { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
    clientId: 'app',
    redirectUri: 'https://core.example/demo-app',
    request: async () => [{ id: 'owner', primaryEmail: 'duplicate@example.invalid' }],
    takePasscode: async (recipient) => {
      calls.push(`code:${recipient}`);
      return '123456';
    },
    fetch: async (input, init) => {
      const url = new URL(String(input));
      const method = init?.method ?? 'GET';
      calls.push(`${method}:${url.pathname}`);
      if (url.pathname === '/oidc/auth') {
        interaction += 1;
        expect(Object.fromEntries(url.searchParams)).toMatchObject({
          client_id: 'app',
          redirect_uri: 'https://core.example/demo-app',
          response_type: 'code',
          code_challenge_method: 'S256',
        });
        expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
        const headers = new Headers();
        headers.append('set-cookie', `_interaction=i${interaction}; Path=/`);
        headers.append('set-cookie', `_interaction.sig=s${interaction}; Path=/`);
        return new Response(null, { status: 303, headers });
      }
      if (url.pathname === '/api/experience' && method === 'PUT') {
        expect(JSON.parse(String(init?.body))).toEqual({ interactionEvent: 'Register' });
        return new Response(null, { status: 204 });
      }
      if (url.pathname === '/api/experience/verification/verification-code') {
        return new Response(JSON.stringify({ verificationId: `handle-${interaction}` }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.pathname.endsWith('/verification-code/verify')) {
        expect(JSON.parse(String(init?.body))).toMatchObject({
          code: '123456',
          verificationId: `handle-${interaction}`,
        });
        return new Response(JSON.stringify({ verificationId: `proof-${interaction}` }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.pathname === '/api/experience/profile') {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        expect(body.type).toBe('password');
        expect(typeof body.value).toBe('string');
        expect(String(body.value)).toHaveLength(1);
        return new Response(JSON.stringify({ code: 'password.rejected' }), {
          status: 422,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.pathname === '/api/experience/identification') {
        expect(JSON.parse(String(init?.body))).toEqual({ verificationId: `proof-${interaction}` });
        const error = interaction === 1 ? 'user.missing_profile' : 'user.email_already_in_use';
        return new Response(JSON.stringify({ code: error }), {
          status: 422,
          headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error('private unexpected request');
    },
  });
  await expect(runtime.authenticatedLookupExactEmail('duplicate@example.invalid')).resolves.toEqual(
    ['owner']
  );
  const incomplete = await runtime.runVerifiedRegistration(
    'incomplete',
    'incomplete@example.invalid'
  );
  const duplicate = await runtime.runVerifiedRegistration('duplicate', 'duplicate@example.invalid');
  const policy = await runtime.runVerifiedRegistration('policy', 'policy@example.invalid');
  expect({ incomplete, duplicate, policy }).toMatchObject({
    incomplete: { actionStatus: 422, actionError: 'user.missing_profile' },
    duplicate: { actionStatus: 422, actionError: 'user.email_already_in_use' },
    policy: { actionStatus: 422, actionError: 'password.rejected' },
  });
  expect(calls.filter((value) => value === 'GET:/oidc/auth')).toHaveLength(3);
  expect(JSON.stringify({ incomplete, duplicate, policy })).not.toMatch(
    /123456|handle-|proof-|example\.invalid|_interaction/u
  );
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
