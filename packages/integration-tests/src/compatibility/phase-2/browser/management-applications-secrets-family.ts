/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The closed family projection verifies each selected public operation before reporting success. */
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  createManagementApplication,
  createManagementApplicationSecret,
  observeClientSecretAuthentication,
  patchManagementApplication,
  readManagementApplication,
  withManagementApplicationSecrets,
} from '../clients/management-applications-family.js';
import type { ManagementCompletionObservation } from '../clients/management-completion-observer.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

export const managementApplicationsSecretsFamilyId = 'common.management.applications-secrets';
export type ManagementApplicationsSecretsProjection = Readonly<{
  applicationStable: true;
  metadataRoundTrip: true;
  initialSecretAuthenticated: true;
  additionalSecretAuthenticated: true;
  secretCatalogStable: true;
  credentialFreeProjection: true;
  repeatedProvisioningStable: true;
  malformedRejected: true;
  foreignRejected: true;
  authFirstDenied: true;
}>;
export const managementApplicationsSecretsExpectedProjection: ManagementApplicationsSecretsProjection =
  Object.freeze({
    applicationStable: true,
    metadataRoundTrip: true,
    initialSecretAuthenticated: true,
    additionalSecretAuthenticated: true,
    secretCatalogStable: true,
    credentialFreeProjection: true,
    repeatedProvisioningStable: true,
    malformedRejected: true,
    foreignRejected: true,
    authFirstDenied: true,
  });
const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management applications family (${stage})`);
};
export const runManagementApplicationsSecretsFamily = async (
  input: Readonly<{
    target: TargetConfig;
    request: Phase2AdminRequestFunction;
    fetch?: typeof fetch;
    captureOwnedApplication(id: string): void;
    observeForeignApplicationPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
    observeMutation(
      input: Readonly<{
        method: 'GET' | 'POST' | 'PATCH';
        path: string;
        body?: unknown;
        validAuthorization?: boolean;
      }>
    ): Promise<ManagementCompletionObservation>;
  }>
): Promise<ManagementApplicationsSecretsProjection> => {
  const marker = `phase2-management-${randomBytes(12).toString('hex')}`;
  const redirectUri = `https://${marker}.example.invalid/callback`;
  const postLogoutRedirectUri = `https://${marker}.example.invalid/logout`;
  const backchannelLogoutUri = `https://${marker}.example.invalid/backchannel`;
  const description = `Owned ${marker}`;
  const created = await createManagementApplication(
    input.request,
    { name: marker, description, redirectUri, postLogoutRedirectUri, backchannelLogoutUri },
    input.captureOwnedApplication
  );
  const read = await readManagementApplication(input.request, created.id);
  const patched = await patchManagementApplication(input.request, {
    id: created.id,
    name: marker,
    description,
    redirectUri,
    postLogoutRedirectUri,
    backchannelLogoutUri,
  });
  const repeated = await patchManagementApplication(input.request, {
    id: created.id,
    name: marker,
    description,
    redirectUri,
    postLogoutRedirectUri,
    backchannelLogoutUri,
  });
  const initial = await withManagementApplicationSecrets(
    input.request,
    created.id,
    async ({ metadata, secrets }) => ({
      metadata,
      accepted: await Promise.all(
        secrets.map(async (secret) =>
          observeClientSecretAuthentication(input.target, created.id, secret, {
            redirectUri,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          })
        )
      ),
    })
  );
  const added = await createManagementApplicationSecret(
    input.request,
    created.id,
    `${marker}-secondary`,
    async ({ metadata, getSecret }) => ({
      metadata,
      accepted: await observeClientSecretAuthentication(input.target, created.id, getSecret(), {
        redirectUri,
        ...(input.fetch ? { fetch: input.fetch } : {}),
      }),
    })
  );
  const finalCatalog = await withManagementApplicationSecrets(
    input.request,
    created.id,
    async ({ metadata }) => metadata
  );
  const malformed = await input.observeMutation({
    method: 'POST',
    path: 'applications',
    body: { type: 'Traditional', oidcClientMetadata: { redirectUris: 'not-an-array' } },
  });
  let foreign: ManagementCompletionObservation | undefined;
  const foreignPreserved = await input.observeForeignApplicationPreserved(async (foreignId) => {
    foreign = await input.observeMutation({
      method: 'GET',
      path: `applications/${encodeURIComponent(foreignId)}`,
    });
  });
  const authFirst = await input.observeMutation({
    method: 'PATCH',
    path: `applications/${encodeURIComponent(created.id)}`,
    body: 'not-a-valid-application',
    validAuthorization: false,
  });
  if (
    !isDeepStrictEqual(created, read) ||
    !isDeepStrictEqual(created, patched) ||
    !isDeepStrictEqual(patched, repeated) ||
    initial.accepted.some(({ accepted }) => !accepted) ||
    !added.accepted.accepted ||
    malformed.status !== 400 ||
    malformed.code !== 'guard.invalid_input' ||
    foreign?.status !== 404 ||
    foreign.code !== 'entity.not_found' ||
    !foreignPreserved ||
    authFirst.status !== 401 ||
    !finalCatalog.some(({ name }) => name === added.metadata.name) ||
    finalCatalog.length !== initial.metadata.length + 1
  ) {
    return fail('projection');
  }
  return managementApplicationsSecretsExpectedProjection;
};
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
