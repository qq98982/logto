import path from 'node:path';

import type { TargetConfig } from '../../model.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import { loadPhase2Profile, type Phase2ProfileRegistries } from '../profile.js';

import { logoutSessionScenarioIds, runLogoutSessionScenarios } from './logout-session.js';

const target: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});
const canonicalProfilePaths = Object.freeze({
  profilePath: path.resolve(
    process.cwd(),
    'src/compatibility/phase-2/testing/phase-2-profile.json'
  ),
  schemaPath: path.resolve(
    process.cwd(),
    'src/compatibility/phase-2/testing/phase-2-profile.schema.json'
  ),
});
const fixture = {
  status: { client: { id: 'public-client' } },
} as unknown as ProvisionedPhase2Fixture;

it('reports the exact logout scenario when an observation fails', async () => {
  const profile = await loadPhase2Profile(canonicalProfilePaths);
  const requestFetch = (async () => {
    throw new TypeError('transport failed');
  }) as typeof fetch;

  await expect(runLogoutSessionScenarios(profile, target, fixture, requestFetch)).rejects.toThrow(
    'Phase 2 scenario failed: oracle/logout.anonymous-get'
  );
});

it('rejects a missing or reordered logout registry segment in the canonical profile', async () => {
  const profile = await loadPhase2Profile(canonicalProfilePaths);
  const first = profile.differentialScenarios.indexOf(logoutSessionScenarioIds[0]);
  const missing = profile.differentialScenarios.filter((_, index) => index !== first);
  const reordered = profile.differentialScenarios.toSpliced(
    first,
    2,
    profile.differentialScenarios[first + 1]!,
    profile.differentialScenarios[first]!
  );
  const requestFetch = (async () => {
    throw new Error('registry validation did not fail closed');
  }) as typeof fetch;

  await Promise.all(
    [missing, reordered].map(async (differentialScenarios) =>
      expect(
        runLogoutSessionScenarios(
          { ...profile, differentialScenarios } as Phase2ProfileRegistries,
          target,
          fixture,
          requestFetch
        )
      ).rejects.toThrow('Invalid Phase 2 logout session registry')
    )
  );
});
