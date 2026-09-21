import type { Phase1FixtureAllocationRole } from '../fixture-map.js';
import type { Phase1FixtureProvisioner, ProvisionedPhase1Fixture } from '../fixtures.js';
import { snapshotClosedDataGraph } from '../model.js';

export type Phase1LastSignInState = 'never' | 'present';

export type Phase1UserActivityState = Readonly<{
  lastSignInState: Phase1LastSignInState;
}>;

export type Phase1BrowserActivityReader = Readonly<{
  readUserActivityState(
    fixture: ProvisionedPhase1Fixture,
    logicalUserId: string
  ): Promise<Phase1UserActivityState>;
}>;

export type Phase1BrowserFixtureProvisioner = Phase1FixtureProvisioner &
  Phase1BrowserActivityReader;

export type Phase1FixtureUserActivityTarget = Readonly<{
  targetRole: Extract<Phase1FixtureAllocationRole, 'data' | 'admin'>;
  runtimeUserId: string;
}>;

const invalidFixtureUser = 'Invalid Phase 1 browser activity fixture user';
const invalidActivityState = 'Invalid Phase 1 browser activity state';

export const resolvePhase1FixtureUserActivityTarget = (
  fixture: ProvisionedPhase1Fixture,
  logicalUserId: string
): Phase1FixtureUserActivityTarget => {
  const matches = fixture.public.allocations.flatMap((allocation) => {
    if (allocation.role !== 'data' && allocation.role !== 'admin') {
      return [];
    }
    const targetRole = allocation.role;

    return allocation.entities
      .filter((entity) => entity.kind === 'user' && entity.logicalId === logicalUserId)
      .map((entity) => ({ targetRole, runtimeUserId: entity.runtimeId }));
  });

  if (matches.length !== 1 || !matches[0]) {
    throw new TypeError(invalidFixtureUser);
  }

  return Object.freeze(matches[0]);
};

export const projectPhase1UserActivityTimestamp = (
  lastSignInAt: unknown
): Phase1UserActivityState => {
  if (lastSignInAt === null) {
    return Object.freeze({ lastSignInState: 'never' });
  }
  if (typeof lastSignInAt === 'number' && Number.isSafeInteger(lastSignInAt) && lastSignInAt > 0) {
    return Object.freeze({ lastSignInState: 'present' });
  }

  throw new TypeError(invalidActivityState);
};

export const parsePhase1UserActivityState = (value: unknown): Phase1UserActivityState => {
  const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);

  if (
    !snapshot ||
    Array.isArray(snapshot) ||
    Reflect.ownKeys(snapshot).length !== 1 ||
    !Object.hasOwn(snapshot, 'lastSignInState')
  ) {
    throw new TypeError(invalidActivityState);
  }
  const descriptor = Object.getOwnPropertyDescriptor(snapshot, 'lastSignInState');
  const state: unknown =
    descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;

  if (state !== 'never' && state !== 'present') {
    throw new TypeError(invalidActivityState);
  }

  return Object.freeze({ lastSignInState: state });
};
