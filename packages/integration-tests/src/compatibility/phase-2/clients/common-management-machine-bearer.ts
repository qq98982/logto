/* eslint-disable no-await-in-loop -- One real machine bearer owns its public Reference setup and cleanup. */
import type { TargetConfig } from '../../model.js';
import {
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';
import { fetchPhase2Discovery, fetchPhase2PublicJwks } from '../runtime.js';

import { withManagementCompletionBearer } from './management-completion-bearer.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Management machine authority');
};
const object = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail();
const issuerFrom = (value: unknown, baseUrl: string): string => {
  if (typeof value !== 'string') {
    return fail();
  }
  const issuer = new URL(value);
  if (
    issuer.origin !== new URL(baseUrl).origin ||
    issuer.pathname !== '/oidc' ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash
  ) {
    return fail();
  }
  return issuer.href.replace(/\/$/u, '');
};

export const withCommonManagementMachineBearer = async <Result>(
  input: Readonly<{
    target: TargetConfig;
    fixture: Pick<ProvisionedPhase2Fixture, 'withCandidateManagementMachineClient'>;
    fetch?: typeof fetch;
  }>,
  use: (bearer: string) => Promise<Result>
): Promise<Result> => {
  const requestFetch = input.fetch ?? fetch;
  const baseUrl = input.target.label === 'candidate' ? input.target.adminUrl : input.target.coreUrl;
  const tokenTarget = { ...input.target, coreUrl: baseUrl };
  const discovery = await fetchPhase2Discovery(tokenTarget, requestFetch);
  const issuer = issuerFrom(discovery.issuer, baseUrl);
  const jwks = await fetchPhase2PublicJwks(tokenTarget, requestFetch);
  const setupRequest: Phase2AdminRequestFunction =
    input.target.label === 'oracle'
      ? createReferencePhase2AdminRequest(input.target, requestFetch)
      : async () => fail();
  const resource =
    input.target.label === 'candidate'
      ? 'urn:aster:resource:management'
      : 'https://default.logto.app/api';
  const scopeId =
    input.target.label === 'candidate'
      ? 'aster-management-all'
      : await (async () => {
          const resources = await setupRequest({
            method: 'GET',
            path: 'resources',
            query: { includeScopes: 'true' },
            expectedStatuses: [200],
            responseKind: 'array',
          });
          if (!Array.isArray(resources) || resources.length > 100) {
            return fail();
          }
          const selected = resources
            .map((value: unknown) => object(value))
            .filter((value) => value.indicator === resource);
          const scopes = selected.length === 1 ? selected[0]?.scopes : undefined;
          if (!Array.isArray(scopes)) {
            return fail();
          }
          const all = scopes
            .map((value: unknown) => object(value))
            .filter((value) => value.name === 'all');
          const id = all.length === 1 ? all[0]?.id : undefined;
          return typeof id === 'string' && id.length > 0 && id.length <= 128 ? id : fail();
        })();
  const applications = new Set<string>();
  try {
    return await withManagementCompletionBearer({
      target: input.target,
      setupRequest,
      jwks,
      fetch: requestFetch,
      authority: {
        resource,
        scopeId,
        scopeName: 'all',
        issuer,
        audience: resource,
        algorithm: 'ES384',
        tokenType: 'at+jwt',
        accessTokenTtlSeconds: 3600,
      },
      captureOwnedApplication: (id) => {
        applications.add(id);
      },
      bindOwnedApplicationRole: async (applicationId, roleId) => {
        if (input.target.label !== 'oracle' || !applications.has(applicationId)) {
          return fail();
        }
        await setupRequest({
          method: 'POST',
          path: `applications/${encodeURIComponent(applicationId)}/roles`,
          body: { roleIds: [roleId] },
          expectedStatuses: [201],
          responseKind: 'status',
        });
      },
      withCandidateManagementMachineClient: input.fixture.withCandidateManagementMachineClient,
      use,
    });
  } finally {
    for (const id of applications) {
      await setupRequest({
        method: 'DELETE',
        path: `applications/${encodeURIComponent(id)}`,
        expectedStatuses: [204, 404],
        responseKind: 'status',
      });
    }
  }
};
/* eslint-enable no-await-in-loop */
