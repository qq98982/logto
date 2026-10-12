/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The fixture restores an exact Experience snapshot and independently deletes its connector. */
import { randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { ManagementCompletionObservation } from '../clients/management-completion-observer.js';
import {
  createManagementConnector,
  deleteManagementConnector,
  patchManagementConnector,
  patchManagementExperience,
  readManagementConnectorFactoryIds,
  readManagementConnectors,
  readManagementExperience,
  readManagementPublicExperience,
} from '../clients/management-connectors-family.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

export const managementConnectorsExperienceFamilyId = 'common.management.connectors-experience';
export type ManagementConnectorsExperienceProjection = Readonly<{
  connectorIdStable: true;
  factorySubsetPresent: true;
  experienceRoundTrip: true;
  orderedMethodsPreserved: true;
  signUpPreserved: true;
  brandingLanguageContentPreserved: true;
  passwordPolicyPreserved: true;
  publicBootstrapMatches: true;
  duplicateRejected: true;
  authFirstDenied: true;
  invalidIdentifierRejected: true;
  foreignConnectorPreserved: true;
  repeatDeleteNotFound: true;
  credentialFreeProjection: true;
  targetOwnedCleanup: true;
}>;
export const managementConnectorsExperienceExpectedProjection: ManagementConnectorsExperienceProjection =
  Object.freeze({
    connectorIdStable: true,
    factorySubsetPresent: true,
    experienceRoundTrip: true,
    orderedMethodsPreserved: true,
    signUpPreserved: true,
    brandingLanguageContentPreserved: true,
    passwordPolicyPreserved: true,
    publicBootstrapMatches: true,
    duplicateRejected: true,
    authFirstDenied: true,
    invalidIdentifierRejected: true,
    foreignConnectorPreserved: true,
    repeatDeleteNotFound: true,
    credentialFreeProjection: true,
    targetOwnedCleanup: true,
  });
const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common Management connectors family (${stage})`);
};
const record = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : fail('record');
const restorableExperience = (value: Readonly<Record<string, unknown>>) =>
  Object.fromEntries(
    [
      'signIn',
      'signUp',
      'socialSignInConnectorTargets',
      'socialSignIn',
      'branding',
      'languageInfo',
      'customContent',
      'passwordPolicy',
      'forgotPasswordMethods',
    ].flatMap((key) => (Object.hasOwn(value, key) ? [[key, value[key]]] : []))
  );

export const runManagementConnectorsExperienceFamily = async (
  input: Readonly<{
    target: TargetConfig;
    request: Phase2AdminRequestFunction;
    fetch?: typeof fetch;
    createManagementHeaders(): Headers;
    observeMutation(
      input: Readonly<{
        method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
        path: string;
        body?: unknown;
        validAuthorization?: boolean;
      }>
    ): Promise<ManagementCompletionObservation>;
    observeForeignConnectorPreserved(use: (foreignId: string) => Promise<void>): Promise<boolean>;
  }>
): Promise<ManagementConnectorsExperienceProjection> => {
  const previous = await readManagementExperience(input.request);
  const factories = await readManagementConnectorFactoryIds(
    input.target,
    input.createManagementHeaders,
    input.fetch
  );
  const marker = randomBytes(12).toString('hex');
  const config = Object.freeze({
    clientId: `123456789-${marker}.apps.googleusercontent.com`,
    clientSecret: `Fixture${marker}`,
  });
  let connectorId: string | undefined;
  try {
    const created = await createManagementConnector(
      input.request,
      { factoryId: 'google-universal', config },
      (id) => {
        connectorId = id;
      }
    );
    const patched = await patchManagementConnector(input.request, created.id, config);
    const duplicate = await input.observeMutation({
      method: 'POST',
      path: 'connectors',
      body: { connectorId: 'google-universal', config },
    });
    const authFirst = await input.observeMutation({
      method: 'POST',
      path: 'connectors',
      body: 'not-a-valid-connector',
      validAuthorization: false,
    });
    const connectors = await readManagementConnectors(input.request);
    const desired = Object.freeze({
      signIn: {
        methods: [
          { identifier: 'email', password: true, verificationCode: false, isPasswordPrimary: true },
        ],
      },
      signUp: { identifiers: ['username'], password: true, verify: false },
      socialSignInConnectorTargets: ['google'],
      socialSignIn: record(previous).socialSignIn,
      branding: {
        logoUrl: 'https://assets.common206.aster.test/logo.png',
        darkLogoUrl: 'https://assets.common206.aster.test/dark-logo.png',
      },
      languageInfo: { autoDetect: false, fallbackLanguage: 'en' },
      customContent: {},
      passwordPolicy: {
        length: { min: 12, max: 64 },
        characterTypes: { min: 3 },
        rejects: {
          pwned: false,
          repetitionAndSequence: true,
          userInfo: true,
          words: ['common206'],
        },
      },
      forgotPasswordMethods: [],
    });
    const configured = await patchManagementExperience(input.request, desired);
    const readback = await readManagementExperience(input.request);
    const omitted = await patchManagementExperience(input.request, {
      branding: {
        logoUrl: 'https://assets.common206.aster.test/logo-2.png',
        darkLogoUrl: 'https://assets.common206.aster.test/dark-logo-2.png',
      },
    });
    const publicBootstrap = await readManagementPublicExperience(input.target, input.fetch);
    const publicTargets = Reflect.get(publicBootstrap, 'socialSignInConnectorTargets');
    const invalidIdentifier = await input.observeMutation({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { signIn: { methods: [{ identifier: 'invalid-selected-identifier' }] } },
    });
    let foreignDetail: ManagementCompletionObservation | undefined;
    let foreignDelete: ManagementCompletionObservation | undefined;
    const foreignPreserved = await input.observeForeignConnectorPreserved(async (foreignId) => {
      foreignDetail = await input.observeMutation({
        method: 'GET',
        path: `connectors/${encodeURIComponent(foreignId)}`,
      });
      foreignDelete = await input.observeMutation({
        method: 'DELETE',
        path: `connectors/${encodeURIComponent(foreignId)}`,
      });
    });
    await input.request({
      method: 'GET',
      path: `connectors/${encodeURIComponent(created.id)}`,
      expectedStatuses: [200],
      responseKind: 'object',
    });
    await deleteManagementConnector(input.request, created.id);
    connectorId = undefined;
    const repeatDetail = await input.observeMutation({
      method: 'GET',
      path: `connectors/${encodeURIComponent(created.id)}`,
    });
    const repeatDelete = await input.observeMutation({
      method: 'DELETE',
      path: `connectors/${encodeURIComponent(created.id)}`,
    });
    if (
      patched.id !== created.id ||
      !['google-universal', 'wechat-web', 'wechat-native'].every((id) => factories.includes(id)) ||
      duplicate.status !== 422 ||
      duplicate.code !== 'connector.multiple_instances_not_supported' ||
      authFirst.status !== 401 ||
      authFirst.code !== 'auth.authorization_header_missing' ||
      !connectors.some(({ id }) => id === created.id) ||
      !Object.entries(desired).every(([key, value]) =>
        isDeepStrictEqual(record(configured)[key], value)
      ) ||
      !Object.entries(desired).every(([key, value]) =>
        isDeepStrictEqual(record(readback)[key], value)
      ) ||
      ![
        'signIn',
        'signUp',
        'socialSignInConnectorTargets',
        'socialSignIn',
        'languageInfo',
        'customContent',
        'passwordPolicy',
        'forgotPasswordMethods',
      ].every((key) => isDeepStrictEqual(record(omitted)[key], record(readback)[key])) ||
      !isDeepStrictEqual(publicTargets, ['google']) ||
      ![
        'branding',
        'customContent',
        'languageInfo',
        'passwordPolicy',
        'signIn',
        'signUp',
        'socialSignIn',
        'socialSignInConnectorTargets',
      ].every((key) => isDeepStrictEqual(publicBootstrap[key], record(omitted)[key])) ||
      Object.hasOwn(publicBootstrap, 'forgotPasswordMethods') ||
      invalidIdentifier.status !== 400 ||
      invalidIdentifier.code !== 'guard.invalid_input' ||
      foreignDetail?.status !== 404 ||
      foreignDetail.code !== 'entity.not_found' ||
      foreignDelete?.status !== 404 ||
      foreignDelete.code !== 'entity.not_found' ||
      !foreignPreserved ||
      repeatDetail.status !== 404 ||
      repeatDetail.code !== 'entity.not_found' ||
      repeatDelete.status !== 404 ||
      repeatDelete.code !== 'entity.not_found'
    ) {
      return fail('projection');
    }
    return managementConnectorsExperienceExpectedProjection;
  } finally {
    let restoreFailed = false;
    try {
      await patchManagementExperience(input.request, restorableExperience(previous));
    } catch {
      restoreFailed = true;
    }
    let deleteFailed = false;
    if (connectorId) {
      try {
        await deleteManagementConnector(input.request, connectorId);
      } catch {
        deleteFailed = true;
      }
    }
    if (restoreFailed || deleteFailed) {
      fail(restoreFailed ? 'restore-experience' : 'delete-connector');
    }
  }
};
/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
