/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One lifecycle owns an idempotent cleanup promise around the secret lease. */
import path from 'node:path';

import { validateTargetConfig } from '../config.js';
import type { TargetConfig } from '../model.js';
import type { PasswordCodeFixtureLifecycle } from '../scenarios/password-code.js';

import {
  createCommandPhase1FixtureProvisioner,
  runPhase1FixtureCommand,
} from './clients/command-provisioner.js';
import { getPhase1FixtureRuntimeId, getPhase1FixtureRuntimeUsername } from './fixture-map.js';
import type { Phase1Profile } from './profile-types.js';

type CandidatePhase0FixtureOptions = Readonly<{
  profile: Pick<Phase1Profile, 'fixtures'>;
  target: TargetConfig;
  fixtureSocket: string;
  managementLifecycle: PasswordCodeFixtureLifecycle;
  createProvisioner?: typeof createCommandPhase1FixtureProvisioner;
  runFixtureCommand?: typeof runPhase1FixtureCommand;
  environment?: Readonly<Record<string, string | undefined>>;
}>;

const diagnostic = 'Candidate Phase 0 fixture failed';
const maximumSocketPathBytes = 4096;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const validateSocket = (value: string): string => {
  if (
    typeof value !== 'string' ||
    !path.isAbsolute(value) ||
    path.resolve(value) !== value ||
    Buffer.byteLength(value, 'utf8') > maximumSocketPathBytes ||
    value.includes('\0') ||
    Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;

      return codePoint <= 31 || codePoint === 127;
    })
  ) {
    return fail();
  }

  return value;
};

const sameTarget = (left: TargetConfig, right: TargetConfig): boolean =>
  left.label === right.label && left.coreUrl === right.coreUrl && left.adminUrl === right.adminUrl;

export const createCandidatePhase0FixtureLifecycle = (
  options: CandidatePhase0FixtureOptions
): PasswordCodeFixtureLifecycle => {
  try {
    const target = validateTargetConfig(options.target);

    if (target.label !== 'candidate') {
      return fail();
    }
    const fixtureSocket = validateSocket(options.fixtureSocket);
    const commandPath = options.environment?.PATH ?? process.env.PATH ?? '/usr/bin:/bin';
    const runFixtureCommand = options.runFixtureCommand ?? runPhase1FixtureCommand;
    const provisioner = (options.createProvisioner ?? createCommandPhase1FixtureProvisioner)({
      profile: options.profile,
      target,
      environment: Object.freeze({ PATH: commandPath, ASTER_FIXTURE_SOCKET: fixtureSocket }),
      runner: async (request) =>
        runFixtureCommand({
          ...request,
          env: Object.freeze({ PATH: commandPath, ASTER_FIXTURE_SOCKET: fixtureSocket }),
        }),
    });
    const { subject } = options.profile.fixtures.dataTenant;
    const firstPartyApplications = options.profile.fixtures.dataTenant.applications.filter(
      ({ isThirdParty }) => !isThirdParty
    );

    if (firstPartyApplications.length !== 1) {
      return fail();
    }
    const firstPartyApplication = firstPartyApplications[0] ?? fail();

    return async (context, use) => {
      if (context.target.label === 'oracle') {
        return options.managementLifecycle(context, use);
      }
      if (!sameTarget(context.target, target)) {
        return fail();
      }
      let cleanupPromise: Promise<void> | undefined;

      try {
        const fixture = await provisioner.provision('dataProtocol');
        const [allocation] = fixture.public.allocations;

        if (
          fixture.public.recipe !== 'dataProtocol' ||
          fixture.public.allocations.length !== 1 ||
          !allocation ||
          allocation.role !== 'data' ||
          allocation.target !== 'primary'
        ) {
          return fail();
        }
        const userId = getPhase1FixtureRuntimeId(
          fixture.public,
          allocation.allocationId,
          'user',
          subject.id
        );
        const applicationId = getPhase1FixtureRuntimeId(
          fixture.public,
          allocation.allocationId,
          'application',
          firstPartyApplication.id
        );
        const cleanup = async (): Promise<void> => {
          cleanupPromise ??= provisioner.cleanup(fixture);
          await cleanupPromise;
        };

        try {
          return await fixture.withSecretLease(async (lease) => {
            const password = lease.getPassword(subject.id);
            const createdUser = await context.client.getUser(userId);

            return use({
              username: getPhase1FixtureRuntimeUsername(subject.username, allocation.allocationId),
              password,
              applicationId,
              createdUser,
              readUser: async () => context.client.getUser(userId),
              cleanup,
            });
          });
        } finally {
          await cleanup();
        }
      } catch {
        return fail();
      }
    };
  } catch {
    return fail();
  }
};

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
