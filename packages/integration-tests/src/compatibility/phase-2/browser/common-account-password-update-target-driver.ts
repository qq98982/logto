import type { TargetConfig } from '../../model.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type Phase2FixtureSecretLease,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runCommonAccountPasswordUpdate,
  type CommonAccountPasswordUpdateProjection,
} from './common-account-password-update.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Account password update target');
};

export const runCommonAccountPasswordUpdateForTarget = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>
): Promise<CommonAccountPasswordUpdateProjection> => {
  if (!input.fixture.status || input.signal.aborted) {
    return fail();
  }
  const requestFetch = input.fetch ?? fetch;
  const execute = async (
    managementRequest: Phase2AdminRequestFunction,
    lease: Phase2FixtureSecretLease
  ) => {
    const getPassword = () => lease.getSubjectPassword?.() ?? fail();
    return runCommonAccountPasswordUpdate({
      ...input,
      managementRequest,
      getSelectedPassword: getPassword,
      getStatusSubjectPassword: getPassword,
    });
  };
  if (input.target.label === 'candidate') {
    return withPhase2AdminManagementBearer(
      input.target,
      input.fixture,
      async (bearer, lease) =>
        execute(createBearerPhase2AdminRequest(input.target, bearer, requestFetch), lease),
      { fetch: requestFetch }
    );
  }
  return input.fixture.withSecretLease(async (lease) =>
    execute(createReferencePhase2AdminRequest(input.target, requestFetch), lease)
  );
};
