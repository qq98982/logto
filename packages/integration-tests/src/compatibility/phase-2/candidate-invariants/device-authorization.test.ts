/* eslint-disable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, unicorn/consistent-function-scoping -- The mutation controls deliberately exercise hostile evidence shapes and ordered invocation counts. */
import type { DeviceAuthorizationProjection } from '../clients/device-authorization.js';
import { createDeviceAuthorizationTransportLease } from '../clients/device-authorization.js';
import type { Phase2ProfileRegistries } from '../profile.js';

import {
  createDeviceCandidateInvariantRegistry,
  deviceCandidateInvariantExpectedProjection,
  deviceCandidateInvariantIds,
  observeConsumedReplayRevocation,
  projectDeviceConcurrencyInvariant,
  runDeviceCandidateInvariantControls,
  runDeviceCandidateInvariants,
} from './device-authorization.js';

const legacyIds = [
  'client-credentials.cross-tenant-authority-rejected',
  'client-credentials.request-role-write-rejected',
  'client-credentials.signing-failure-rolls-back',
  'client-credentials.user-authority-unchanged',
  'logout-session.verification-storage-closed',
] as const;

const profile = (ids: readonly string[] = [...legacyIds, ...deviceCandidateInvariantIds]) =>
  ({ candidateInvariantScenarios: ids }) as unknown as Phase2ProfileRegistries;

describe('Phase 2 device candidate invariant registry', () => {
  it('closes the exact ordered eight-ID suffix of the thirteen-ID profile', () => {
    const registry = createDeviceCandidateInvariantRegistry(profile());
    expect(registry.map(({ id }) => id)).toEqual(deviceCandidateInvariantIds);
    expect(Object.isFrozen(registry)).toBe(true);

    for (const ids of [
      [...legacyIds, ...deviceCandidateInvariantIds.slice(1)],
      [
        ...legacyIds,
        deviceCandidateInvariantIds[1],
        deviceCandidateInvariantIds[0],
        ...deviceCandidateInvariantIds.slice(2),
      ],
      [...legacyIds, ...deviceCandidateInvariantIds, deviceCandidateInvariantIds[0]],
      [...deviceCandidateInvariantIds, ...legacyIds],
    ]) {
      expect(() => createDeviceCandidateInvariantRegistry(profile(ids))).toThrow(
        'Invalid Phase 2 device candidate invariant'
      );
    }
  });

  it('publishes one fixed candidate projection and mutation pointer per invariant', () => {
    expect(
      deviceCandidateInvariantIds.map((id) =>
        runDeviceCandidateInvariantControls(id, deviceCandidateInvariantExpectedProjection(id))
      )
    ).toEqual([
      expect.objectContaining({
        id: deviceCandidateInvariantIds[0],
        negativeControl: { detected: true, pointer: '/catalog/forcedRowSecurity' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[1],
        negativeControl: { detected: true, pointer: '/row/deviceDigestBytes' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[2],
        negativeControl: { detected: true, pointer: '/foreignPoll/error' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[3],
        negativeControl: { detected: true, pointer: '/rollback/deviceState' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[4],
        negativeControl: { detected: true, pointer: '/trials/0/winnerCount' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[5],
        negativeControl: { detected: true, pointer: '/authority/grant' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[6],
        negativeControl: { detected: true, pointer: '/cleanup/deletedExpired' },
      }),
      expect.objectContaining({
        id: deviceCandidateInvariantIds[7],
        negativeControl: { detected: true, pointer: '/evidence' },
      }),
    ]);
  });

  it('rejects a projection with an accessor, extra property, or wrong value', () => {
    const id = deviceCandidateInvariantIds[0];
    const expected = deviceCandidateInvariantExpectedProjection(id);
    if (expected.invariant !== 'forced-rls-isolation') {
      throw new TypeError('test fixture drift');
    }
    expect(() =>
      runDeviceCandidateInvariantControls(id, { ...expected, extra: true } as never)
    ).toThrow('Invalid Phase 2 device candidate invariant');
    expect(() =>
      runDeviceCandidateInvariantControls(
        id,
        Object.defineProperty({}, 'invariant', {
          enumerable: true,
          get: () => 'forced-rls-isolation',
        }) as never
      )
    ).toThrow('Invalid Phase 2 device candidate invariant');
    expect(() =>
      runDeviceCandidateInvariantControls(id, {
        ...expected,
        catalog: { ...expected.catalog, forcedRowSecurity: false },
      } as never)
    ).toThrow('Invalid Phase 2 device candidate invariant');
  });

  it('executes every device proof in exact profile order and attaches both controls', async () => {
    const calls: string[] = [];
    const evidence = await runDeviceCandidateInvariants(profile(), {
      execute: async (id) => {
        calls.push(id);
        return deviceCandidateInvariantExpectedProjection(id);
      },
    });
    expect(calls).toEqual(deviceCandidateInvariantIds);
    expect(evidence.map(({ id }) => id)).toEqual(deviceCandidateInvariantIds);
    expect(
      evidence.every(
        ({ positiveControl, negativeControl }) =>
          positiveControl.detected && negativeControl.detected
      )
    ).toBe(true);

    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) =>
          id === deviceCandidateInvariantIds[3]
            ? ({ ...deviceCandidateInvariantExpectedProjection(id), retry: 'failed' } as never)
            : deviceCandidateInvariantExpectedProjection(id),
      })
    ).rejects.toThrow('Phase 2 stage failed: candidate-invariant-device-3');
  });

  it('reports only the closed registry position when device execution fails', async () => {
    const privateDetail = 'private-device-credential';
    await expect(
      runDeviceCandidateInvariants(profile(), {
        execute: async (id) => {
          if (id === deviceCandidateInvariantIds[7]) {
            throw new Error(privateDetail);
          }
          return deviceCandidateInvariantExpectedProjection(id);
        },
      })
    ).rejects.toMatchObject({
      message: 'Phase 2 stage failed: candidate-invariant-device-7',
    });
  });

  it('projects exactly three independent candidate one-winner trials', async () => {
    let calls = 0;
    const response = (winner: boolean): DeviceAuthorizationProjection =>
      ({
        status: winner ? 200 : 400,
        oauthError: winner
          ? { category: undefined, description: undefined }
          : { category: 'invalid_grant', description: 'grant request is invalid' },
      }) as DeviceAuthorizationProjection;
    const projection = await projectDeviceConcurrencyInvariant(async () => {
      calls += 1;
      return Object.freeze({
        winnerCount: 1,
        responses: Object.freeze([response(true), response(false)]) as readonly [
          DeviceAuthorizationProjection,
          DeviceAuthorizationProjection,
        ],
      });
    });
    expect(calls).toBe(3);
    expect(projection).toEqual(
      deviceCandidateInvariantExpectedProjection('device-token.concurrent-poll-one-winner')
    );
    await expect(
      projectDeviceConcurrencyInvariant(async () =>
        Object.freeze({
          winnerCount: 2,
          responses: Object.freeze([response(true), response(true)]) as readonly [
            DeviceAuthorizationProjection,
            DeviceAuthorizationProjection,
          ],
        })
      )
    ).rejects.toThrow('Invalid Phase 2 device candidate invariant');
  });

  it('observes replay, both introspections, and refresh serially on the real transport lease', async () => {
    const calls: Array<Readonly<{ url: string; body: string }>> = [];
    const responses = [
      new Response(
        JSON.stringify({
          device_code: 'private-device-code',
          user_code: 'BCDF-GHJK',
          verification_uri: 'https://candidate.example/oidc/device',
          expires_in: 600,
          interval: 5,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      ),
      new Response(
        JSON.stringify({
          access_token: 'private-access-token',
          refresh_token: 'private-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      ),
      new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(JSON.stringify({ active: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
      new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      }),
    ];
    const lease = createDeviceAuthorizationTransportLease({
      target: {
        label: 'candidate',
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      },
      fetch: (async (input, init) => {
        calls.push(
          Object.freeze({
            url: String(input),
            body: String(init?.body ?? ''),
          })
        );
        return responses.shift() ?? Promise.reject(new TypeError('unexpected fetch'));
      }) as typeof fetch,
    });
    await lease.requestAuthorization({
      encoding: 'form',
      fields: [['client_id', 'device-client']],
    });
    await lease.pollToken({ proof: { method: 'public', clientId: 'device-client' } });

    const observed = await observeConsumedReplayRevocation(
      lease,
      'device-client',
      'private-subject'
    );

    expect(observed).toEqual({
      replayStatus: 400,
      replayError: 'invalid_grant',
      accessActive: false,
      refreshActive: false,
      refreshStatus: 400,
      refreshError: 'invalid_grant',
    });
    expect(calls.slice(2).map(({ url }) => new URL(url).pathname)).toEqual([
      '/oidc/token',
      '/oidc/token/introspection',
      '/oidc/token/introspection',
      '/oidc/token',
    ]);
    expect(calls.slice(2).map(({ body }) => new URLSearchParams(body).get('grant_type'))).toEqual([
      'urn:ietf:params:oauth:grant-type:device_code',
      null,
      null,
      'refresh_token',
    ]);
    expect(JSON.stringify(observed)).not.toMatch(/private-(?:device|access|refresh)/u);
    lease.clear();
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition, unicorn/consistent-function-scoping */
