/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful HTTP fake proves independent cookie jars and secret privacy. */
import type { Phase2AdminRequest } from '../fixtures.js';

import { createEmailCodeRegistrationControlRuntime } from './email-code-registration-control-runtime.js';

test('runs independent SignIn and Register interactions without publishing private material', async () => {
  const calls: string[] = [];
  const events: string[] = [];
  const interactionCookies: string[] = [];
  const authQueries: URLSearchParams[] = [];
  const management: Phase2AdminRequest[] = [];
  let interaction = 0;
  const runtime = createEmailCodeRegistrationControlRuntime({
    target: { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
    clientId: 'app',
    redirectUri: 'https://core.example/demo-app',
    request: async (request) => {
      management.push(request);
      return [
        { id: 'owner', primaryEmail: 'occupied@example.invalid' },
        { id: 'foreign', primaryEmail: 'foreign@example.invalid' },
      ];
    },
    takePasscode: async (recipient) => {
      calls.push(`code:${recipient}`);
      return '123456';
    },
    fetch: async (url, init) => {
      const parsed = new URL(String(url));
      const method = init?.method ?? 'GET';
      calls.push(`${method}:${parsed.pathname}:${String(init?.headers ?? '')}`);
      if (parsed.pathname === '/oidc/auth') {
        interaction += 1;
        authQueries.push(parsed.searchParams);
        const headers = new Headers();
        headers.append('set-cookie', `_interaction=i${interaction}; Path=/`);
        headers.append('set-cookie', `_interaction.sig=s${interaction}; Path=/`);
        return new Response(null, { status: 303, headers });
      }
      if (parsed.pathname === '/api/experience' && method === 'PUT') {
        events.push(JSON.parse(String(init?.body)).interactionEvent as string);
        interactionCookies.push((init?.headers as Record<string, string>).cookie ?? '');
        return new Response(null, { status: 204 });
      }
      if (
        parsed.pathname === '/api/experience/verification/verification-code' &&
        method === 'POST'
      ) {
        const requestHeaders = new Headers(init?.headers);
        expect(requestHeaders.get('aster-app-id')).toBe('app');
        expect(requestHeaders.get('cookie')).toBe(
          `_interaction=i${interaction}; _interaction.sig=s${interaction}`
        );
        const responseHeaders = new Headers({ 'content-type': 'application/json' });
        responseHeaders.append('set-cookie', `_interaction=i${interaction}-request; Path=/`);
        responseHeaders.append('set-cookie', `_interaction.sig=s${interaction}-request; Path=/`);
        return new Response(JSON.stringify({ verificationId: `handle-${interaction}` }), {
          status: 200,
          headers: responseHeaders,
        });
      }
      if (parsed.pathname.includes('/verify')) {
        const requestHeaders = new Headers(init?.headers);
        expect(requestHeaders.get('cookie')).toBe(
          `_interaction=i${interaction}-request; _interaction.sig=s${interaction}-request`
        );
        expect(JSON.parse(String(init?.body))).toMatchObject({
          code: '123456',
          verificationId: `handle-${interaction}`,
        });
        const responseHeaders = new Headers({ 'content-type': 'application/json' });
        responseHeaders.append('set-cookie', `_interaction=i${interaction}-verify; Path=/`);
        responseHeaders.append('set-cookie', `_interaction.sig=s${interaction}-verify; Path=/`);
        return new Response(JSON.stringify({ verificationId: `proof-${interaction}` }), {
          status: 200,
          headers: responseHeaders,
        });
      }
      if (parsed.pathname === '/api/experience/identification') {
        expect(new Headers(init?.headers).get('cookie')).toBe(
          `_interaction=i${interaction}-verify; _interaction.sig=s${interaction}-verify`
        );
        expect(JSON.parse(String(init?.body))).toEqual({ verificationId: `proof-${interaction}` });
        return new Response(
          JSON.stringify({
            code: interaction === 1 ? 'user.user_not_exist' : 'user.email_already_in_use',
          }),
          { status: interaction === 1 ? 404 : 422, headers: { 'content-type': 'application/json' } }
        );
      }
      throw new Error('unexpected');
    },
  });
  expect(await runtime.authenticatedLookupExactEmail('occupied@example.invalid')).toEqual([
    'owner',
  ]);
  const signIn = await runtime.runFreshVerifiedIdentification('SignIn', 'missing@example.invalid');
  const register = await runtime.runFreshVerifiedIdentification(
    'Register',
    'occupied@example.invalid'
  );
  expect(signIn).toMatchObject({
    identificationStatus: 404,
    identificationError: 'user.user_not_exist',
  });
  expect(register).toMatchObject({
    identificationStatus: 422,
    identificationError: 'user.email_already_in_use',
  });
  expect(calls.filter((value) => value.startsWith('GET:/oidc/auth'))).toHaveLength(2);
  expect(events).toEqual(['SignIn', 'Register']);
  expect(interactionCookies).toEqual([
    '_interaction=i1; _interaction.sig=s1',
    '_interaction=i2; _interaction.sig=s2',
  ]);
  for (const query of authQueries) {
    expect(Object.fromEntries(query)).toMatchObject({
      client_id: 'app',
      redirect_uri: 'https://core.example/demo-app',
      response_type: 'code',
      code_challenge_method: 'S256',
    });
    expect(query.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  }
  expect(authQueries[0]?.get('code_challenge')).not.toBe(authQueries[1]?.get('code_challenge'));
  expect(calls.map((value) => value.split(':').slice(0, 2).join(':'))).toEqual([
    'GET:/oidc/auth',
    'PUT:/api/experience',
    'POST:/api/experience/verification/verification-code',
    'code:missing@example.invalid',
    'POST:/api/experience/verification/verification-code/verify',
    'POST:/api/experience/identification',
    'GET:/oidc/auth',
    'PUT:/api/experience',
    'POST:/api/experience/verification/verification-code',
    'code:occupied@example.invalid',
    'POST:/api/experience/verification/verification-code/verify',
    'POST:/api/experience/identification',
  ]);
  expect(JSON.stringify({ signIn, register })).not.toMatch(
    /123456|handle-|_interaction|missing@example|occupied@example/u
  );
  expect(management[0]).toMatchObject({
    method: 'GET',
    path: 'users',
    query: { page: '1', page_size: '100' },
  });
});

test('rejects HTTP and malformed delivery without returning secrets', async () => {
  const runtime = createEmailCodeRegistrationControlRuntime({
    target: { label: 'oracle', coreUrl: 'https://core.example', adminUrl: 'https://admin.example' },
    clientId: 'app',
    redirectUri: 'https://core.example/demo-app',
    request: async () => [],
    takePasscode: async () => {
      throw new Error('private code');
    },
    fetch: async () => new Response(null, { status: 500 }),
  });
  await expect(
    runtime.runFreshVerifiedIdentification('SignIn', 'missing@example.invalid')
  ).rejects.toThrow('Email code registration control runtime failed: auth-s500-other');
});

test('reports a failed code request before reading private delivery', async () => {
  let codeCalls = 0;
  const runtime = createEmailCodeRegistrationControlRuntime({
    target: {
      label: 'candidate',
      coreUrl: 'https://core.example',
      adminUrl: 'https://admin.example',
    },
    clientId: 'app',
    redirectUri: 'https://core.example/demo-app',
    request: async () => [],
    takePasscode: async () => {
      codeCalls += 1;
      return '123456';
    },
    fetch: async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path === '/oidc/auth') {
        const headers = new Headers();
        headers.append('set-cookie', '_interaction=i; Path=/');
        headers.append('set-cookie', '_interaction.sig=s; Path=/');
        return new Response(null, { status: 303, headers });
      }
      if (path === '/api/experience' && init?.method === 'PUT') {
        return new Response(null, { status: 204 });
      }
      return new Response(
        JSON.stringify({ code: 'request.message_rate_limited', message: 'private' }),
        { status: 429, headers: { 'content-type': 'application/json' } }
      );
    },
  });
  await expect(
    runtime.runFreshVerifiedIdentification('SignIn', 'missing@example.invalid')
  ).rejects.toThrow(
    'Email code registration control runtime failed: request-s429-request-message-rate-limited'
  );
  expect(codeCalls).toBe(0);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
