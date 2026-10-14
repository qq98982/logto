/* eslint-disable no-await-in-loop, promise/prefer-await-to-then, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- One verified machine authority owns the sequential completion rows and independent cleanup; the terminal catch records its exact rejected object. */
import type { Browser, BrowserType } from '@playwright/test';
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { createPlaywrightBrowserGroupObserver } from '../../phase-1/browser/playwright-session.js';
import { withCommonManagementMachineBearer } from '../clients/common-management-machine-bearer.js';
import { createBearerPhase2AdminRequest, type ProvisionedPhase2Fixture } from '../fixtures.js';
import {
  CommonCompletionScenarioFailure,
  runCommonCompletionScenariosForTarget,
} from '../scenarios/common-completion-runner.js';
import type { CommonCompletionScenarioId } from '../scenarios/common-completion.js';

import { readCommonCompletionFixtureRuntime } from './common-completion-fixture-runtime.js';
import { withManagementProvisioningFixtureRuntime } from './management-provisioning-fixture-runtime.js';

const fail = (): never => {
  throw new TypeError('Invalid bound Common completion target');
};

export const commonCompletionBoundaryPhases = [
  'machine-authority',
  'runtime-read',
  'required-controls',
  'scenarios',
  'owned-app-cleanup',
  'machine-cleanup-result',
] as const;
export type CommonCompletionBoundaryPhase = (typeof commonCompletionBoundaryPhases)[number];
type CommonCompletionBoundaryFailure = Readonly<{
  phase: CommonCompletionBoundaryPhase;
  scenarioId?: CommonCompletionScenarioId;
}>;
const boundaryFailures = new WeakMap<WeakKey, CommonCompletionBoundaryFailure>();

const errorObject = (error: unknown): WeakKey | undefined =>
  (typeof error === 'object' && error !== null) || typeof error === 'function' ? error : undefined;

const directBoundaryFailure = (error: unknown): CommonCompletionBoundaryFailure | undefined => {
  try {
    const key = errorObject(error);
    if (!key) {
      return undefined;
    }
    const recorded = boundaryFailures.get(key);
    if (recorded) {
      return recorded;
    }
    if (error instanceof CommonCompletionScenarioFailure) {
      return Object.freeze({ phase: 'scenarios', scenarioId: error.scenarioId });
    }
  } catch {
    return undefined;
  }
  return undefined;
};

export const recordCommonCompletionBoundaryFailure = <T>(
  error: T,
  phase: CommonCompletionBoundaryPhase,
  scenarioId?: CommonCompletionScenarioId
): T => {
  const key = errorObject(error);
  if (!key) {
    return error;
  }
  const direct = directBoundaryFailure(error);
  const selectedScenarioId = scenarioId ?? direct?.scenarioId;
  boundaryFailures.set(
    key,
    Object.freeze({ phase, ...(selectedScenarioId ? { scenarioId: selectedScenarioId } : {}) })
  );
  return error;
};

export const getCommonCompletionBoundaryFailure = (
  error: unknown
): CommonCompletionBoundaryFailure | undefined => directBoundaryFailure(error);

export const runBoundCommonCompletionScenarios = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    jwks: Readonly<JSONWebKeySet>;
    browserType: Pick<BrowserType<Browser>, 'launch'>;
    runtimeFile: string;
    controlSocket: string;
    signal: AbortSignal;
  }>
) => {
  let phase: CommonCompletionBoundaryPhase = 'machine-authority';
  let scenarioId: CommonCompletionScenarioId | undefined;
  return withCommonManagementMachineBearer(input, async (bearer) => {
    const request = createBearerPhase2AdminRequest(input.target, bearer);
    phase = 'runtime-read';
    const runtime = await readCommonCompletionFixtureRuntime({
      filePath: input.runtimeFile,
      controlSocket: input.controlSocket,
      target: input.target,
      managementRequest: request,
      h5BrowserType: input.browserType,
    });
    const applications = new Set<string>();
    phase = 'required-controls';
    const foreignControls = input.fixture.withForeignManagementControls ?? fail();
    const cleanupProvisioningRows = async (
      rows: Readonly<{
        resourceId: string;
        applicationIds: readonly [string, string];
      }>
    ): Promise<void> => {
      if (input.target.label === 'candidate') {
        const cleanup = input.fixture.cleanupManagementProvisioningRows ?? fail();
        await cleanup(rows);
        return;
      }
      for (const applicationId of rows.applicationIds) {
        await request({
          method: 'DELETE',
          path: `applications/${encodeURIComponent(applicationId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        });
      }
      await request({
        method: 'DELETE',
        path: `resources/${encodeURIComponent(rows.resourceId)}`,
        expectedStatuses: [204, 404],
        responseKind: 'status',
      });
    };
    const cleanupOwnershipControlApplication = async (applicationId: string): Promise<void> => {
      if (input.target.label === 'candidate') {
        await (input.fixture.cleanupManagementOwnershipControlApplication ?? fail())(applicationId);
        return;
      }
      await request({
        method: 'DELETE',
        path: `applications/${encodeURIComponent(applicationId)}`,
        expectedStatuses: [204, 404],
        responseKind: 'status',
      });
    };
    const removeProvisioningRoleScope = async ({
      roleId,
      scopeId,
    }: Readonly<{ roleId: string; scopeId: string }>): Promise<void> => {
      if (input.target.label === 'candidate') {
        await (input.fixture.removeManagementProvisioningRoleScope ?? fail())({
          roleId,
          scopeId,
        });
        return;
      }
      await request({
        method: 'DELETE',
        path: `roles/${encodeURIComponent(roleId)}/scopes/${encodeURIComponent(scopeId)}`,
        expectedStatuses: [204],
        responseKind: 'status',
      });
    };
    let result: Awaited<ReturnType<typeof runCommonCompletionScenariosForTarget>> | undefined;
    let bodyError: unknown;
    phase = 'scenarios';
    try {
      result = await runCommonCompletionScenariosForTarget({
        target: input.target,
        fixture: input.fixture,
        jwks: input.jwks,
        observer: createPlaywrightBrowserGroupObserver(input.browserType),
        signal: input.signal,
        runtime: {
          ...runtime,
          management: {
            withManagementBearer: async (use) => use(bearer),
            captureOwnedApplication: (id) => {
              applications.add(id);
            },
            observeForeignApplicationPreserved: async (use) =>
              foreignControls(async (controls) => {
                await use(controls.applicationId);
                return true;
              }),
            observeForeignUserPreserved: async (use) =>
              foreignControls(async (controls) => {
                await use(controls.userId);
                // The fixture returns only after the real foreign preservation check and cleanup.
                return true;
              }),
            observeForeignConnectorPreserved: async (use) =>
              foreignControls(async (controls) => {
                await use(controls.connectorId);
                return true;
              }),
            withProvisioningFixture: async (activeBearer, use) => {
              if (activeBearer !== bearer || input.signal.aborted) {
                return fail();
              }
              return runtime.withProvisioningEnvironments(async (environments) =>
                withManagementProvisioningFixtureRuntime(
                  {
                    target: input.target,
                    request,
                    bearer,
                    withForeignManagementControls: foreignControls,
                    cleanupProvisioningRows,
                    cleanupOwnershipControlApplication,
                    removeProvisioningRoleScope,
                    ...environments,
                  },
                  use
                )
              );
            },
          },
        },
      });
    } catch (error: unknown) {
      bodyError = recordCommonCompletionBoundaryFailure(error, 'scenarios');
      scenarioId = getCommonCompletionBoundaryFailure(error)?.scenarioId;
    }
    phase = 'owned-app-cleanup';
    const failures: TypeError[] = [];
    for (const id of applications) {
      try {
        await request({
          method: 'DELETE',
          path: `applications/${encodeURIComponent(id)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        });
      } catch {
        failures.push(new TypeError('Owned Common completion application cleanup failed'));
      }
    }
    if (failures.length > 0) {
      throw recordCommonCompletionBoundaryFailure(
        new AggregateError(
          [...(bodyError === undefined ? [] : [bodyError]), ...failures],
          'Bound Common completion cleanup failed'
        ),
        'owned-app-cleanup',
        scenarioId
      );
    }
    phase = 'machine-cleanup-result';
    if (bodyError !== undefined) {
      throw bodyError instanceof Error
        ? bodyError
        : new TypeError('Bound Common completion execution failed');
    }
    return result ?? fail();
  }).catch((error: unknown) => {
    if (getCommonCompletionBoundaryFailure(error)) {
      throw error;
    }
    throw recordCommonCompletionBoundaryFailure(error, phase, scenarioId);
  });
};
/* eslint-enable no-await-in-loop, promise/prefer-await-to-then, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
