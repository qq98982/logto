/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, unicorn/consistent-function-scoping -- Request capture verifies the private transport boundary. */
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';

import { createCommonExperienceSession } from './common-experience.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://core.example/',
  adminUrl: 'https://admin.example/',
};

describe('Common Experience interaction transport', () => {
  test.each([
    ['candidate', 'aster-app-id', 'logto-app-id'],
    ['oracle', 'logto-app-id', 'aster-app-id'],
  ] as const)(
    'retains cookie boundaries while binding %s Experience and consent requests',
    async (label, ownedHeader, foreignHeader) => {
      const calls: Array<{ url: string; headers: Headers; redirect?: RequestRedirect }> = [];
      const requestFetch: typeof fetch = async (input, init) => {
        const url = String(input);
        calls.push({ url, headers: new Headers(init?.headers), redirect: init?.redirect });
        return new Response('{}', {
          status: 200,
          headers: {
            'content-type': 'application/json',
            ...(calls.length === 1
              ? {
                  'set-cookie':
                    'interaction=private-cookie; Path=/api/experience; Secure; HttpOnly',
                }
              : {}),
          },
        });
      };
      const session = createCommonExperienceSession({
        target: { ...target, label },
        clientId: 'owned-client',
        fetch: requestFetch,
      });
      await session.request('/api/experience', 'PUT', { interactionEvent: 'SignIn' });
      await session.request('/api/experience/identification', 'POST', {});
      await session.request('/api/interaction/consent', 'GET');
      await session.request('/api/interaction/consent', 'POST', {});
      await session.request('/api/interaction/consent/foreign', 'GET');
      await session.request('/oidc/auth', 'GET');
      expect(calls.map(({ headers }) => headers.get('cookie'))).toEqual([
        null,
        'interaction=private-cookie',
        null,
        null,
        null,
        null,
      ]);
      expect(calls.map(({ headers }) => headers.get(ownedHeader))).toEqual([
        'owned-client',
        'owned-client',
        'owned-client',
        'owned-client',
        null,
        null,
      ]);
      expect(calls.every(({ redirect }) => redirect === 'manual')).toBe(true);
      expect(calls.every(({ headers }) => headers.get(foreignHeader) === null)).toBe(true);
      session.close();
    }
  );

  test('rejects foreign destinations before a cookie or credential leaves the target', async () => {
    let calls = 0;
    const requestFetch: typeof fetch = async () => {
      calls += 1;
      return new Response(null, { status: 204 });
    };
    const session = createCommonExperienceSession({
      target,
      clientId: 'owned-client',
      fetch: requestFetch,
    });
    for (const destination of [
      'https://foreign.example/api/experience',
      '//foreign.example/',
      'https://user@core.example/',
      '/api/experience#private',
    ]) {
      await expect(session.request(destination, 'POST', {})).rejects.toThrow(
        'Invalid Common Experience transport'
      );
    }
    expect(calls).toBe(0);
  });

  test('keeps credentials private and invalidates every response after the interaction closes', async () => {
    const requestFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ verificationId: 'private-proof' }), {
        headers: { 'content-type': 'application/json' },
      });
    const session = createCommonExperienceSession({
      target,
      clientId: 'owned-client',
      fetch: requestFetch,
    });
    const response = await session.request('/api/experience', 'GET');
    expect(response.getRecord().verificationId).toBe('private-proof');
    expect(inspect(session)).not.toContain('owned-client');
    expect(inspect(response)).not.toContain('private-proof');
    expect(() => JSON.stringify(session)).toThrow();
    expect(() => JSON.stringify(response)).toThrow();
    session.close();
    expect(() => response.getStatus()).toThrow();
    expect(() => response.getRecord()).toThrow();
    await expect(session.request('/api/experience', 'GET')).rejects.toThrow();
  });

  test('bounds declared and streamed response bodies and does not expose malformed JSON', async () => {
    for (const response of [
      new Response('{}', {
        headers: { 'content-type': 'application/json', 'content-length': '65537' },
      }),
      new Response('x'.repeat(65_537), { headers: { 'content-type': 'application/json' } }),
      new Response('[]', { headers: { 'content-type': 'application/json' } }),
      new Response('{"verificationId":', { headers: { 'content-type': 'application/json' } }),
    ]) {
      const requestFetch: typeof fetch = async () => response;
      const session = createCommonExperienceSession({
        target,
        clientId: 'owned-client',
        fetch: requestFetch,
      });
      await expect(session.request('/api/experience', 'GET')).rejects.toThrow();
      session.close();
    }
  });

  test('preserves empty and whitespace identification bodies without inventing fields', async () => {
    const bodies: unknown[] = [];
    const requestFetch: typeof fetch = async (_, init) => {
      bodies.push(init?.body);
      return new Response(null, { status: 204 });
    };
    const session = createCommonExperienceSession({
      target,
      clientId: 'owned-client',
      fetch: requestFetch,
    });
    await session.request('/api/experience/identification', 'POST', {});
    await session.request('/api/experience/identification', 'POST', ' \n {} \t ');
    expect(bodies).toEqual(['{}', ' \n {} \t ']);
    session.close();
  });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, unicorn/consistent-function-scoping */
