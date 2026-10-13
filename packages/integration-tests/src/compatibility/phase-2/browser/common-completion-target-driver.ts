/* eslint-disable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- One verified machine authority owns the sequential completion rows and independent cleanup. */
import type { Browser, BrowserType } from '@playwright/test';
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { createPlaywrightBrowserGroupObserver } from '../../phase-1/browser/playwright-session.js';
import { withCommonManagementMachineBearer } from '../clients/common-management-machine-bearer.js';
import { createBearerPhase2AdminRequest, type ProvisionedPhase2Fixture } from '../fixtures.js';
import { runCommonCompletionScenariosForTarget } from '../scenarios/common-completion-runner.js';

import { readCommonCompletionFixtureRuntime } from './common-completion-fixture-runtime.js';
import { withManagementProvisioningFixtureRuntime } from './management-provisioning-fixture-runtime.js';

const fail = (): never => {
  throw new TypeError('Invalid bound Common completion target');
};

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
) =>
  withCommonManagementMachineBearer(input, async (bearer) => {
    const request = createBearerPhase2AdminRequest(input.target, bearer);
    const runtime = await readCommonCompletionFixtureRuntime({
      filePath: input.runtimeFile,
      controlSocket: input.controlSocket,
      target: input.target,
      managementRequest: request,
      h5BrowserType: input.browserType,
    });
    const applications = new Set<string>();
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
    let result: Awaited<ReturnType<typeof runCommonCompletionScenariosForTarget>> | undefined;
    let bodyError: unknown;
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
      bodyError = error;
    }
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
      throw new AggregateError(
        [...(bodyError === undefined ? [] : [bodyError]), ...failures],
        'Bound Common completion cleanup failed'
      );
    }
    if (bodyError !== undefined) {
      throw bodyError instanceof Error
        ? bodyError
        : new TypeError('Bound Common completion execution failed');
    }
    return result ?? fail();
  });
/* eslint-enable no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
