/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Stateful fetch fake checks four independent HTTP interactions. */
import type { TargetConfig } from '../../model.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

import { runCommonPhoneCodeHttpControls } from './common-phone-code-controls.js';

const json = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

test('observes exact phone mismatch, replay, occupied-owner, and suspension controls', async () => {
  let interaction = 0;
  const events: string[] = [];
  const verifyCounts = new Map<number, number>();
  const requestFetch = async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
    const url = input instanceof URL ? input : new URL(String(input));
    if (url.pathname === '/oidc/auth') {
      expect(url.searchParams.get('redirect_uri')).toBe('https://core.example/demo-app');
      interaction += 1;
      const headers = new Headers();
      headers.append('set-cookie', `_interaction=i${interaction}; Path=/`);
      headers.append('set-cookie', `_interaction.sig=s${interaction}; Path=/`);
      return new Response(null, {
        status: 303,
        headers,
      });
    }
    if (url.pathname === '/api/experience' && init?.method === 'PUT') {
      const body = JSON.parse(String(init.body)) as { interactionEvent: string };
      events.push(body.interactionEvent);
      return new Response(null, { status: 204 });
    }
    if (url.pathname.endsWith('/verification-code')) {
      const body = JSON.parse(String(init?.body)) as { identifier: { type: string } };
      expect(body.identifier.type).toBe('phone');
      return json(200, { verificationId: `challenge-${interaction}` });
    }
    if (url.pathname.endsWith('/verification-code/verify')) {
      const count = (verifyCounts.get(interaction) ?? 0) + 1;
      verifyCounts.set(interaction, count);
      if (interaction === 1 && count === 1) {
        return json(400, { code: 'verification_code.phone_mismatch', message: 'closed' });
      }
      if (interaction === 1 && count === 3) {
        return json(400, { code: 'verification_code.not_found', message: 'closed' });
      }
      return json(200, { verificationId: `proof-${interaction}` });
    }
    if (url.pathname === '/api/experience/identification') {
      return interaction === 2
        ? json(422, { code: 'user.phone_already_in_use', message: 'closed' })
        : json(401, { code: 'user.suspended', message: 'closed' });
    }
    throw new Error('unexpected request');
  };
  const armed: string[] = [];
  const target: TargetConfig = {
    label: 'oracle',
    coreUrl: 'https://core.example',
    adminUrl: 'https://admin.example',
  };
  const result = await runCommonPhoneCodeHttpControls({
    target,
    fixture: {
      status: { client: { id: 'client', redirectUri: 'https://core.example/demo-app' } },
    } as unknown as ProvisionedPhase2Fixture,
    request: async () => [{ id: 'collision', primaryPhone: '8614000000000' }],
    lease: {
      configuration: { accessKeyId: 'x', accessKeySecret: 'y', signName: 'z', templates: [] },
      arm: async (recipient, purpose) => {
        armed.push(`${recipient}:${purpose}`);
      },
      takeCode: async () => '123456',
    },
    owner: { id: 'owner', primaryPhone: '8613800138000' },
    collisionOwner: { id: 'collision', primaryPhone: '8614000000000' },
    suspended: { id: 'suspended', primaryPhone: '8613900139000' },
    redirectUri: 'https://core.example/demo-app',
    fetch: requestFetch as typeof fetch,
  });
  expect(events).toEqual(['SignIn', 'Register', 'SignIn']);
  expect(armed).toHaveLength(3);
  expect(result).toEqual({
    occupiedRegistration: { status: 422, code: 'user.phone_already_in_use', ownerUnchanged: true },
    consumedReplay: { status: 400, code: 'verification_code.not_found' },
    recipientMismatch: {
      status: 400,
      code: 'verification_code.phone_mismatch',
      ownerRetained: true,
    },
    suspendedOwner: { status: 401, code: 'user.suspended' },
  });
  expect(JSON.stringify(result)).not.toMatch(/123456|challenge|proof/u);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
