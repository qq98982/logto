import type { TargetConfig } from '../../model.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2ProfileRegistries } from '../profile.js';

import { logoutSessionScenarioIds, runLogoutSessionScenarios } from './logout-session.js';

const target: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});

it('reports the exact logout scenario when an observation fails', async () => {
  const profile = {
    differentialScenarios: logoutSessionScenarioIds,
  } as unknown as Phase2ProfileRegistries;
  const fixture = {
    status: { client: { id: 'public-client' } },
  } as unknown as ProvisionedPhase2Fixture;
  const requestFetch = (async () => {
    throw new TypeError('transport failed');
  }) as typeof fetch;

  await expect(runLogoutSessionScenarios(profile, target, fixture, requestFetch)).rejects.toThrow(
    'Phase 2 scenario failed: oracle/logout.anonymous-get'
  );
});
