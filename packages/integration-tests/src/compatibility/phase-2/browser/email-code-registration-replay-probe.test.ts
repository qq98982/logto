/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Ordered call capture proves two identical private verification attempts without exposing their material. */
import type { TargetConfig } from '../../model.js';

import { observeRegisterVerificationReplay } from './email-code-registration-replay-probe.js';

const json = (value: unknown, status = 200): Response =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });

test.each(['oracle', 'candidate'] as const)(
  'observes the exact consumed Register verification replay for %s without publishing private material',
  async (label) => {
    const calls: string[] = [];
    const verificationBodies: unknown[] = [];
    const verificationCookies: string[] = [];
    const result = await observeRegisterVerificationReplay({
      target: {
        label,
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      clientId: 'browser-app',
      redirectUri: 'https://core.example/demo-app',
      email: 'private-registration@example.invalid',
      takePasscode: async () => '654321',
      fetch: async (request, init) => {
        const url = new URL(String(request));
        const method = init?.method ?? 'GET';
        calls.push(`${method}:${url.pathname}`);
        if (url.pathname === '/oidc/auth') {
          const headers = new Headers();
          headers.append('set-cookie', '_interaction=private-cookie; Path=/');
          headers.append('set-cookie', '_interaction.sig=private-signature; Path=/');
          return new Response(null, { status: 303, headers });
        }
        if (url.pathname === '/api/experience') {
          expect(JSON.parse(String(init?.body))).toEqual({ interactionEvent: 'Register' });
          expect(new Headers(init?.headers).get('cookie')).toBe(
            '_interaction=private-cookie; _interaction.sig=private-signature'
          );
          const headers = new Headers();
          headers.append('set-cookie', '_interaction=initialized-cookie; Path=/');
          headers.append('set-cookie', '_interaction.sig=initialized-signature; Path=/');
          return new Response(null, { status: 204, headers });
        }
        if (url.pathname.endsWith('/verification-code/verify')) {
          const body: unknown = JSON.parse(String(init?.body));
          verificationBodies.push(body);
          verificationCookies.push(new Headers(init?.headers).get('cookie') ?? '');
          if (verificationBodies.length === 1) {
            const headers = new Headers({ 'content-type': 'application/json' });
            headers.append('set-cookie', '_interaction=verified-cookie; Path=/');
            headers.append('set-cookie', '_interaction.sig=verified-signature; Path=/');
            return new Response(JSON.stringify({ verificationId: 'private-handle' }), {
              status: 200,
              headers,
            });
          }
          return json(
            { code: 'verification_code.not_found', message: 'private replay detail' },
            400
          );
        }
        if (url.pathname.endsWith('/verification-code')) {
          expect(new Headers(init?.headers).get('cookie')).toBe(
            '_interaction=initialized-cookie; _interaction.sig=initialized-signature'
          );
          const headers = new Headers({ 'content-type': 'application/json' });
          headers.append('set-cookie', '_interaction=requested-cookie; Path=/');
          headers.append('set-cookie', '_interaction.sig=requested-signature; Path=/');
          return new Response(JSON.stringify({ verificationId: 'private-handle' }), {
            status: 200,
            headers,
          });
        }
        throw new Error('unexpected private route');
      },
    });
    expect(result).toEqual({
      first: { status: 's200', outcome: 'verified', error: 'none' },
      second: { status: 's400', outcome: 'error', error: 'verification_code.not_found' },
    });
    expect(verificationBodies).toHaveLength(2);
    expect(verificationBodies[0]).toEqual(verificationBodies[1]);
    expect(verificationCookies).toEqual([
      '_interaction=requested-cookie; _interaction.sig=requested-signature',
      '_interaction=verified-cookie; _interaction.sig=verified-signature',
    ]);
    expect(calls).toEqual([
      'GET:/oidc/auth',
      'PUT:/api/experience',
      'POST:/api/experience/verification/verification-code',
      'POST:/api/experience/verification/verification-code/verify',
      'POST:/api/experience/verification/verification-code/verify',
    ]);
    expect(JSON.stringify(result)).not.toMatch(
      /private|654321|verificationId|cookie|signature|example\.invalid/u
    );
  }
);

test.each([
  ['accepted again', json({ verificationId: 'private-handle' })],
  [
    'unknown error',
    json({ code: 'provider.private_condition', message: 'private provider detail' }, 409),
  ],
  [
    'wrong status for the pinned error',
    json({ code: 'verification_code.not_found', message: 'private replay detail' }, 404),
  ],
  [
    'wrong error for the pinned status',
    json({ code: 'guard.invalid_input', message: 'private replay detail' }, 400),
  ],
] as const)('rejects a %s replay result', async (_name, replay) => {
  let verificationCalls = 0;
  await expect(
    observeRegisterVerificationReplay({
      target: {
        label: 'candidate',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      clientId: 'browser-app',
      redirectUri: 'https://core.example/demo-app',
      email: 'private-registration@example.invalid',
      takePasscode: async () => '654321',
      fetch: async (request) => {
        const url = new URL(String(request));
        if (url.pathname === '/oidc/auth') {
          const headers = new Headers();
          headers.append('set-cookie', '_interaction=private-cookie; Path=/');
          headers.append('set-cookie', '_interaction.sig=private-signature; Path=/');
          return new Response(null, { status: 303, headers });
        }
        if (url.pathname === '/api/experience') {
          return new Response(null, { status: 204 });
        }
        if (url.pathname.endsWith('/verification-code/verify')) {
          verificationCalls += 1;
          return verificationCalls === 1 ? json({ verificationId: 'private-handle' }) : replay;
        }
        if (url.pathname.endsWith('/verification-code')) {
          return json({ verificationId: 'private-handle' });
        }
        throw new Error('unexpected private route');
      },
    })
  ).rejects.toThrow('Invalid email code registration replay probe');
  expect(verificationCalls).toBe(2);
});

test('requires the first Register verification to succeed before probing replay', async () => {
  let verifyCalls = 0;
  await expect(
    observeRegisterVerificationReplay({
      target: {
        label: 'oracle',
        coreUrl: 'https://core.example',
        adminUrl: 'https://admin.example',
      },
      clientId: 'browser-app',
      redirectUri: 'https://core.example/demo-app',
      email: 'private-registration@example.invalid',
      takePasscode: async () => '654321',
      fetch: async (request, init) => {
        const url = new URL(String(request));
        if (url.pathname === '/oidc/auth') {
          const headers = new Headers();
          headers.append('set-cookie', '_interaction=private-cookie; Path=/');
          headers.append('set-cookie', '_interaction.sig=private-signature; Path=/');
          return new Response(null, { status: 303, headers });
        }
        if (url.pathname === '/api/experience') {
          return new Response(null, { status: 204 });
        }
        if (url.pathname.endsWith('/verification-code/verify')) {
          verifyCalls += 1;
          return json({ code: 'guard.invalid_input', message: 'private first failure' }, 400);
        }
        if (url.pathname.endsWith('/verification-code')) {
          return json({ verificationId: 'private-handle' });
        }
        throw new Error(`unexpected ${String(init?.method)} route`);
      },
    })
  ).rejects.toThrow('Invalid email code registration replay probe');
  expect(verifyCalls).toBe(1);
});

test('rejects an unvetted target label before starting an interaction', async () => {
  let fetchCalls = 0;
  const target: TargetConfig = {
    label: 'candidate',
    coreUrl: 'https://core.example',
    adminUrl: 'https://admin.example',
  };
  Object.defineProperty(target, 'label', { value: 'private-target' });
  await expect(
    observeRegisterVerificationReplay({
      target,
      clientId: 'browser-app',
      redirectUri: 'https://core.example/demo-app',
      email: 'private-registration@example.invalid',
      takePasscode: async () => '654321',
      fetch: async () => {
        fetchCalls += 1;
        throw new Error('unreachable private request');
      },
    })
  ).rejects.toThrow('Invalid email code registration replay probe');
  expect(fetchCalls).toBe(0);
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
