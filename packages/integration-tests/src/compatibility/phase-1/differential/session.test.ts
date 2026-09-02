import { type OidcClient } from '../clients/oidc.js';
import { createPhase1FixtureMap } from '../fixture-map.js';
import { createProvisionedPhase1Fixture } from '../fixtures.js';

import { createPhase1ProtocolSessionBinding } from './session.js';

const target = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'http://localhost:3311/',
  adminUrl: 'http://localhost:3411/',
});
const foreignTarget = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'http://localhost:3312/',
  adminUrl: 'http://localhost:3412/',
});

const allocation = (
  role: 'data' | 'foreign',
  targetKind: 'primary' | 'foreign',
  allocationId: string,
  entities: ReadonlyArray<
    Readonly<{
      kind: 'tenant' | 'user' | 'application' | 'resource' | 'scope' | 'role';
      logicalId: string;
      runtimeId: string;
    }>
  >
) => ({
  allocationId,
  role,
  target: targetKind,
  isolation: {
    persistenceId: `${allocationId}-persistence`,
    cookieKeyId: `${allocationId}-cookie`,
    signingKeyId: `${allocationId}-signing`,
  },
  entities,
});

const fixture = () =>
  createProvisionedPhase1Fixture({
    public: createPhase1FixtureMap({
      schemaVersion: 1,
      recipe: 'consentBoundary',
      allocations: [
        allocation('data', 'primary', 'data-allocation', [
          { kind: 'tenant', logicalId: 'default', runtimeId: 'default' },
          { kind: 'user', logicalId: 'phase1-user', runtimeId: 'data-user' },
          { kind: 'user', logicalId: 'consent.primary.user-b', runtimeId: 'data-user-b' },
          { kind: 'application', logicalId: 'phase1-app', runtimeId: 'data-app' },
          { kind: 'application', logicalId: 'phase1-browser', runtimeId: 'data-browser' },
          {
            kind: 'application',
            logicalId: 'consent.primary.client-b',
            runtimeId: 'data-browser-b',
          },
          { kind: 'resource', logicalId: 'phase1-api', runtimeId: 'data-resource' },
          { kind: 'scope', logicalId: 'phase1-read-profile', runtimeId: 'data-scope' },
          { kind: 'role', logicalId: 'phase1-role', runtimeId: 'data-role' },
        ]),
        allocation('foreign', 'foreign', 'foreign-allocation', [
          { kind: 'tenant', logicalId: 'default', runtimeId: 'foreign-default' },
          { kind: 'user', logicalId: 'consent.foreign.user-b', runtimeId: 'foreign-user-b' },
          {
            kind: 'application',
            logicalId: 'consent.foreign.client-b',
            runtimeId: 'foreign-browser-b',
          },
        ]),
      ],
    }),
    foreignTarget,
    passwords: [],
    clientSecrets: [],
  });

describe('Phase 1 differential protocol session', () => {
  it('shares one private store per allocation while keeping primary foreign and public clients isolated', () => {
    const provisioned = fixture();
    const binding = createPhase1ProtocolSessionBinding({
      target,
      fixture: provisioned,
      signal: new AbortController().signal,
    });
    const data = binding.session.forAllocation('data');
    const foreign = binding.session.forAllocation('foreign');
    const dataOidc = data.oidc as OidcClient;
    const foreignOidc = foreign.oidc as OidcClient;
    const publicOidc = binding.session.publicOidc as OidcClient;

    expect(data.oidc.store).toBe(data.experience.store);
    expect(data.oidc.store).toBe(data.consent.store);
    expect(data.oidc.store).toBe(data.management.store);
    expect(data.oidc.store).toBe(data.account.store);
    expect(data.oidc.store).toBe(data.state.store);
    expect(foreign.oidc.store).not.toBe(data.oidc.store);
    expect(dataOidc.target).toEqual(target);
    expect(foreignOidc.target).toEqual(foreignTarget);
    expect(binding.session.publicOidc.allocationRole).toBeUndefined();
    expect(publicOidc.target).toEqual(target);
    expect(binding.symbols.get('data-allocation')?.getLogicalName('data-user')).toBe(
      'user.phase1-user'
    );
    expect(binding.symbols.get('foreign-allocation')?.getLogicalName('foreign-user-b')).toBe(
      'user.consent.foreign.user-b'
    );
    expect(() => binding.session.forAllocation('admin')).toThrow(
      /^Invalid phase 1 protocol allocation$/u
    );
  });
});
