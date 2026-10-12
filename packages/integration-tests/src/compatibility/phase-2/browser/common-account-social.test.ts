/* eslint-disable @silverhand/fp/no-mutating-methods -- The ordered fake transport consumes its response script and records requests. */
import type { TargetConfig } from '../../model.js';
import type { AccountVerificationLease } from '../clients/account-settings.js';

import {
  runCommonAccountSocial,
  type CommonAccountSocialFixture,
} from './common-account-social.js';

const target = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.test/',
  adminUrl: 'https://candidate-admin.test/',
}) as TargetConfig;
const lease = (id: string): AccountVerificationLease =>
  Object.freeze({
    getVerificationRecordId: () => id,
    toJSON: () => {
      throw new TypeError('redacted');
    },
  });

test.each(['google', 'wechat'] as const)(
  'runs current and owned %s proofs through link, profile, replay, unlink and controls',
  async (provider) => {
    const calls: string[] = [];
    const responses: Array<readonly [number, Readonly<Record<string, unknown>>]> = [
      [201, { verificationRecordId: 'current' }],
      [401, { code: 'verification_record.permission_denied' }],
      [201, { verificationRecordId: 'wrong' }],
      [401, { code: 'verification_record.permission_denied' }],
      [204, {}],
      [200, { id: 'owner', identities: { [provider]: { userId: `${provider}-subject` } } }],
      [404, { code: 'session.verification_session_not_found' }],
      [204, {}],
      [200, { id: 'owner', identities: {} }],
      [422, { code: 'user.identity_already_in_use' }],
    ];
    const requestFetch: typeof fetch = async (input, init) => {
      calls.push(`${init?.method ?? 'GET'} ${new URL(String(input)).pathname}`);
      const next = responses.shift();
      if (!next) {
        throw new TypeError('unexpected request');
      }
      return new Response(next[0] === 204 ? null : JSON.stringify(next[1]), {
        status: next[0],
        headers: { 'content-type': 'application/json' },
      });
    };
    const fixture: CommonAccountSocialFixture = {
      provider,
      ownerId: 'owner',
      socialSubject: `${provider}-subject`,
      ownerPassword: 'owner-password',
      foreignPassword: 'foreign-password',
      ownerTokens: {
        access: 'owner-access',
        refresh: 'owner-refresh',
        toJSON: () => {
          throw new TypeError('redacted');
        },
      },
      foreignTokens: {
        access: 'foreign-access',
        refresh: 'foreign-refresh',
        toJSON: () => {
          throw new TypeError('redacted');
        },
      },
      withDestinationProof: async (use) => use(lease('destination')),
      withForeignOwnedDestinationProof: async (use) => use(lease('foreign-destination')),
      observeLastMethod: async () => ({ status: 400, error: 'user.last_sign_in_method_required' }),
      providerRequestExact: () => true,
    };
    const projection = await runCommonAccountSocial(target, fixture, requestFetch);
    expect(projection.provider).toBe(provider);
    expect(calls).toEqual([
      'POST /api/verifications/password',
      'POST /api/my-account/identities',
      'POST /api/verifications/password',
      'POST /api/my-account/identities',
      'POST /api/my-account/identities',
      'GET /api/my-account',
      'POST /api/my-account/identities',
      `DELETE /api/my-account/identities/${provider}`,
      'GET /api/my-account',
      'POST /api/my-account/identities',
    ]);
  }
);
/* eslint-enable @silverhand/fp/no-mutating-methods */
