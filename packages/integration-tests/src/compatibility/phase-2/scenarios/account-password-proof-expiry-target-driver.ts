import type { TargetConfig } from '../../model.js';
import { withPhase2AdminManagementBearer } from '../clients/admin-management-bearer.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

import {
  runAccountPasswordProofExpiry,
  type AccountPasswordProofExpiryProjection,
  type AccountPasswordProofStateDriver,
} from './account-password-proof-expiry.js';

const fail = (): never => {
  throw new TypeError('Invalid Account password-proof expiry target');
};

export const runAccountPasswordProofExpiryForTarget = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    state: AccountPasswordProofStateDriver;
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>
): Promise<AccountPasswordProofExpiryProjection> => {
  if (!input.fixture.status || input.signal.aborted) {
    return fail();
  }
  const requestFetch = input.fetch ?? fetch;
  const execute = async (
    request: ReturnType<typeof createReferencePhase2AdminRequest>,
    getPassword: () => string
  ) =>
    runAccountPasswordProofExpiry({
      ...input,
      managementRequest: request,
      getPassword,
    });
  if (input.target.label === 'candidate') {
    return withPhase2AdminManagementBearer(
      input.target,
      input.fixture,
      async (bearer, lease) =>
        execute(
          createBearerPhase2AdminRequest(input.target, bearer, requestFetch),
          () => lease.getSubjectPassword?.() ?? fail()
        ),
      { fetch: requestFetch }
    );
  }
  return input.fixture.withSecretLease(async (lease) =>
    execute(
      createReferencePhase2AdminRequest(input.target, requestFetch),
      () => lease.getSubjectPassword?.() ?? fail()
    )
  );
};
