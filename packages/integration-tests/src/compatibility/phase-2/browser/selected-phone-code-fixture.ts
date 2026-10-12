/* eslint-disable complexity, max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- Snapshot, setup, use, and reverse compensation are one fixture boundary; reflected Management values are narrowed before use. */
import { isDeepStrictEqual } from 'node:util';

import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import type { PhoneCodePurpose } from './common-phone-code.js';

type AccountPhonePurpose = PhoneCodePurpose | 'ForgotPassword' | 'Generic';

export type PhoneConnectorConfiguration = Readonly<{
  accessKeyId: string;
  accessKeySecret: string;
  signName: string;
  templates: ReadonlyArray<
    Readonly<{
      usageType: 'SignIn' | 'Register' | 'ForgotPassword' | 'Generic';
      templateCode: string;
    }>
  >;
}>;

export type CommonPhoneCodeProviderLease = Readonly<{
  configuration: PhoneConnectorConfiguration;
  arm(recipient: string, purpose: AccountPhonePurpose): Promise<void>;
  takeCode(recipient: string, purpose: AccountPhonePurpose): Promise<string>;
}>;

export type SelectedPhoneCodeFixtureValue = Readonly<{
  owner: Readonly<{ id: string; primaryPhone: string; isSuspended: false }>;
  controlOwner: Readonly<{ id: string; primaryPhone: string; isSuspended: false }>;
  collisionOwner: Readonly<{ id: string; primaryPhone: string; isSuspended: false }>;
  suspended: Readonly<{ id: string; primaryPhone: string; isSuspended: true }>;
  registrationPhone: string;
  registrationNationalPhone: string;
  captureRegisteredUser(id: string): Promise<void>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid selected phone code fixture');
};

const phoneFlowStage = (error: unknown): string | undefined => {
  if (!(error instanceof Error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const message: unknown = descriptor?.value;
  if (typeof message !== 'string') {
    return undefined;
  }
  return /^Common phone code stage failed: ((?:sign-in|registration)-(?:input|initialization|identifier|delivery|code-format|code-fill|consent|callback|profile|refresh|subject))$/u.exec(
    message
  )?.[1];
};

const phoneSuffix = (allocationId: string): string => {
  const digits = [...allocationId]
    .map((value) => String(value.codePointAt(0) ?? 0))
    .join('')
    .padEnd(9, '0')
    .slice(0, 9);
  return digits;
};

const assertConnectorConfiguration = (value: PhoneConnectorConfiguration): void => {
  const usages = value.templates.map(({ usageType }) => usageType);
  if (
    !value.accessKeyId ||
    !value.accessKeySecret ||
    !value.signName ||
    value.templates.length !== 4 ||
    new Set(usages).size !== 4 ||
    !['SignIn', 'Register', 'ForgotPassword', 'Generic'].every((usage) =>
      usages.includes(usage as (typeof usages)[number])
    ) ||
    value.templates.some(({ templateCode }) => !templateCode)
  ) {
    fail();
  }
};

export const withSelectedPhoneCodeFixture = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    browser: Readonly<{ clientId: string; redirectUri: string }>;
    lease: CommonPhoneCodeProviderLease;
    use(value: SelectedPhoneCodeFixtureValue): Promise<Result>;
  }>
): Promise<Result> => {
  const resource = input.fixture.status?.resource ?? fail();
  assertConnectorConfiguration(input.lease.configuration);
  let previousSie: Record<string, unknown> | undefined;
  let previousMetadata: Record<string, unknown> | undefined;
  let connectorId: string | undefined;
  let roleId: string | undefined;
  let ownerId: string | undefined;
  let controlOwnerId: string | undefined;
  let collisionOwnerId: string | undefined;
  let suspendedId: string | undefined;
  let registeredId: string | undefined;
  let registrationAbsenceProved = false;
  let result: Result | undefined;
  let stage = 'read-sie';
  let failed = false;
  const cleanup: string[] = [];
  const suffix = phoneSuffix(input.fixture.public.allocationId);
  const ownerPhone = `8613${suffix}`;
  const controlOwnerPhone = `8618${suffix}`;
  const collisionOwnerPhone = `8614${suffix}`;
  const suspendedPhone = `8617${suffix}`;
  const registrationPhone = `8615${suffix}`;
  const findRegistrationOwners = async (): Promise<string[]> => {
    const users = await input.request({
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (!Array.isArray(users) || users.length >= 100) {
      return fail();
    }
    const matches = Array.from<unknown>(users).filter(
      (user) =>
        typeof user === 'object' &&
        user !== null &&
        Reflect.get(user, 'primaryPhone') === registrationPhone
    );
    const ids: unknown[] = [];
    for (const user of matches) {
      if (typeof user !== 'object' || user === null) {
        ids.push(null);
        continue;
      }
      ids.push(Reflect.get(user, 'id'));
    }
    if (
      ids.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) ||
      new Set(ids).size !== ids.length
    ) {
      return fail();
    }
    return ids as string[];
  };
  try {
    previousSie = (await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    const previousSignIn: unknown = Reflect.get(previousSie, 'signIn');
    if (
      typeof previousSignIn !== 'object' ||
      previousSignIn === null ||
      !Array.isArray(Reflect.get(previousSignIn, 'methods')) ||
      typeof previousSie.signUp !== 'object' ||
      previousSie.signUp === null
    ) {
      return fail();
    }
    stage = 'get-app';
    const applicationPath = `applications/${encodeURIComponent(input.browser.clientId)}`;
    const application = (await input.request({
      method: 'GET',
      path: applicationPath,
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    const metadata = application.oidcClientMetadata;
    if (
      application.id !== input.browser.clientId ||
      application.type !== 'SPA' ||
      typeof metadata !== 'object' ||
      metadata === null ||
      Array.isArray(metadata)
    ) {
      return fail();
    }
    previousMetadata = metadata as Record<string, unknown>;
    const selectedMetadata = { ...previousMetadata, redirectUris: [input.browser.redirectUri] };
    stage = 'patch-app';
    const patchedApp = (await input.request({
      method: 'PATCH',
      path: applicationPath,
      body: { oidcClientMetadata: selectedMetadata },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (!isDeepStrictEqual(patchedApp.oidcClientMetadata, selectedMetadata)) {
      return fail();
    }
    stage = 'read-resource';
    const resources = await input.request({
      method: 'GET',
      path: 'resources',
      query: { includeScopes: 'true' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    const selected = Array.isArray(resources)
      ? Array.from<unknown>(resources).filter(
          (value) =>
            typeof value === 'object' && value !== null && Reflect.get(value, 'id') === resource.id
        )
      : [];
    const selectedResource: unknown = selected[0];
    const scopes =
      selected.length === 1 && typeof selectedResource === 'object' && selectedResource !== null
        ? Reflect.get(selectedResource, 'scopes')
        : undefined;
    const selectedScopes = Array.isArray(scopes)
      ? scopes.filter(
          (value) =>
            typeof value === 'object' &&
            value !== null &&
            Reflect.get(value, 'name') === resource.scopeName &&
            Reflect.get(value, 'resourceId') === resource.id
        )
      : [];
    const selectedScope: unknown = selectedScopes[0];
    const scopeId =
      selectedScopes.length === 1 && typeof selectedScope === 'object' && selectedScope !== null
        ? Reflect.get(selectedScope, 'id')
        : undefined;
    if (typeof scopeId !== 'string' || !scopeId) {
      return fail();
    }
    stage = 'create-role';
    const role = (await input.request({
      method: 'POST',
      path: 'roles',
      body: {
        name: `common-phone-code-${input.fixture.public.allocationId}`,
        description: 'Common phone code selected-user authority',
        type: 'User',
        isDefault: true,
        scopeIds: [scopeId],
      },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })) as Record<string, unknown>;
    roleId = typeof role.id === 'string' ? role.id : undefined;
    if (!roleId) {
      return fail();
    }
    stage = 'create-connector';
    const connector = (await input.request({
      method: 'POST',
      path: 'connectors',
      body: {
        connectorId: 'aliyun-short-message-service',
        config: {
          accessKeyId: input.lease.configuration.accessKeyId,
          accessKeySecret: input.lease.configuration.accessKeySecret,
          signName: input.lease.configuration.signName,
          templates: input.lease.configuration.templates.map(({ usageType, templateCode }) => ({
            usageType,
            templateCode,
          })),
        },
      },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })) as Record<string, unknown>;
    connectorId = typeof connector.id === 'string' ? connector.id : undefined;
    if (!connectorId || connector.connectorId !== 'aliyun-short-message-service') {
      return fail();
    }
    stage = 'patch-sie';
    const selectedSignUp = { identifiers: ['phone'], password: false, verify: true };
    const selectedMethods = [
      { identifier: 'phone', password: false, verificationCode: true, isPasswordPrimary: false },
    ];
    const updated = (await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: {
        branding: {},
        signUp: selectedSignUp,
        signIn: { methods: selectedMethods },
      },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (
      !isDeepStrictEqual(
        Reflect.get(updated.signIn as Record<string, unknown>, 'methods'),
        selectedMethods
      ) ||
      !isDeepStrictEqual(updated.signUp, selectedSignUp)
    ) {
      return fail();
    }
    const createUser = async (phone: string, suspended: boolean, track: (id: string) => void) => {
      const created = (await input.request({
        method: 'POST',
        path: 'users',
        body: { primaryPhone: phone },
        expectedStatuses: [200, 201],
        responseKind: 'object',
      })) as Record<string, unknown>;
      const id = typeof created.id === 'string' ? created.id : fail();
      track(id);
      if (created.primaryPhone !== phone || created.isSuspended !== false) {
        return fail();
      }
      if (suspended) {
        const patched = (await input.request({
          method: 'PATCH',
          path: `users/${encodeURIComponent(id)}/is-suspended`,
          body: { isSuspended: true },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as Record<string, unknown>;
        if (patched.id !== id || patched.isSuspended !== true) {
          return fail();
        }
      }
      return id;
    };
    stage = 'create-owner';
    await createUser(ownerPhone, false, (id) => {
      ownerId = id;
    });
    stage = 'create-control-owner';
    await createUser(controlOwnerPhone, false, (id) => {
      controlOwnerId = id;
    });
    stage = 'create-collision-owner';
    await createUser(collisionOwnerPhone, false, (id) => {
      collisionOwnerId = id;
    });
    stage = 'create-suspended';
    await createUser(suspendedPhone, true, (id) => {
      suspendedId = id;
    });
    if (!ownerId || !controlOwnerId || !collisionOwnerId || !suspendedId) {
      return fail();
    }
    stage = 'assign-role';
    const ownerRoles = await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(ownerId)}/roles`,
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    const selectedOwnerRoles = Array.isArray(ownerRoles)
      ? Array.from<unknown>(ownerRoles).filter(
          (entry) =>
            typeof entry === 'object' &&
            entry !== null &&
            Reflect.get(entry, 'id') === roleId &&
            Reflect.get(entry, 'type') === 'User' &&
            Reflect.get(entry, 'isDefault') === true
        )
      : [];
    if (!Array.isArray(ownerRoles) || ownerRoles.length >= 100 || selectedOwnerRoles.length !== 1) {
      return fail();
    }
    stage = 'registration-owner-before';
    const registrationOwnersBefore = await findRegistrationOwners();
    if (registrationOwnersBefore.length > 0) {
      return fail();
    }
    registrationAbsenceProved = true;
    stage = 'use';
    result = await input.use({
      owner: { id: ownerId, primaryPhone: ownerPhone, isSuspended: false },
      controlOwner: { id: controlOwnerId, primaryPhone: controlOwnerPhone, isSuspended: false },
      collisionOwner: {
        id: collisionOwnerId,
        primaryPhone: collisionOwnerPhone,
        isSuspended: false,
      },
      suspended: { id: suspendedId, primaryPhone: suspendedPhone, isSuspended: true },
      registrationPhone,
      registrationNationalPhone: registrationPhone.slice(2),
      captureRegisteredUser: async (id) => {
        if (registeredId !== undefined || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) {
          fail();
        }
        const user = await input.request({
          method: 'GET',
          path: `users/${encodeURIComponent(id)}`,
          expectedStatuses: [200],
          responseKind: 'object',
        });
        if (
          typeof user !== 'object' ||
          user === null ||
          Reflect.get(user, 'id') !== id ||
          Reflect.get(user, 'primaryPhone') !== registrationPhone
        ) {
          fail();
        }
        registeredId = id;
      },
    });
  } catch (error: unknown) {
    const flowStage = phoneFlowStage(error);
    if (stage === 'use' && flowStage) {
      stage = `use-${flowStage}`;
    }
    failed = true;
  } finally {
    if (registrationAbsenceProved && registeredId === undefined) {
      try {
        const discovered = await findRegistrationOwners();
        if (discovered.length === 1) {
          [registeredId] = discovered;
        } else if (discovered.length > 1) {
          cleanup.push('discover-registered-ambiguous');
        }
      } catch {
        cleanup.push('discover-registered');
      }
    }
    for (const [name, id] of [
      ['delete-registered', registeredId],
      ['delete-suspended', suspendedId],
      ['delete-collision-owner', collisionOwnerId],
      ['delete-control-owner', controlOwnerId],
      ['delete-owner', ownerId],
    ] as const) {
      if (id) {
        await input
          .request({
            method: 'DELETE',
            path: `users/${encodeURIComponent(id)}`,
            expectedStatuses: [204, 404],
            responseKind: 'status',
          })
          .catch(() => cleanup.push(name));
      }
    }
    if (registrationAbsenceProved) {
      try {
        const registrationOwnersAfter = await findRegistrationOwners();
        if (registrationOwnersAfter.length > 0) {
          cleanup.push('registered-owner-remains');
        }
      } catch {
        cleanup.push('read-registered-owner-after');
      }
    }
    if (roleId) {
      await input
        .request({
          method: 'DELETE',
          path: `roles/${encodeURIComponent(roleId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => cleanup.push('delete-role'));
    }
    if (connectorId) {
      await input
        .request({
          method: 'DELETE',
          path: `connectors/${encodeURIComponent(connectorId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => cleanup.push('delete-connector'));
    }
    if (previousSie) {
      try {
        const priorSignIn: unknown = Reflect.get(previousSie, 'signIn');
        const priorMethods =
          typeof priorSignIn === 'object' && priorSignIn !== null
            ? Reflect.get(priorSignIn, 'methods')
            : undefined;
        const restoreBody = {
          branding: previousSie.branding,
          signIn: { methods: priorMethods },
          signUp: previousSie.signUp,
        };
        const restored = (await input.request({
          method: 'PATCH',
          path: 'sign-in-exp',
          body: restoreBody,
          expectedStatuses: [200],
          responseKind: 'object',
        })) as Record<string, unknown>;
        if (
          !isDeepStrictEqual(restored.signIn, previousSie.signIn) ||
          !isDeepStrictEqual(restored.signUp, previousSie.signUp) ||
          !isDeepStrictEqual(restored.branding, previousSie.branding)
        ) {
          cleanup.push('restore-sie');
        }
      } catch {
        cleanup.push('restore-sie');
      }
    }
    if (previousMetadata) {
      try {
        const restored = (await input.request({
          method: 'PATCH',
          path: `applications/${encodeURIComponent(input.browser.clientId)}`,
          body: { oidcClientMetadata: previousMetadata },
          expectedStatuses: [200],
          responseKind: 'object',
        })) as Record<string, unknown>;
        if (!isDeepStrictEqual(restored.oidcClientMetadata, previousMetadata)) {
          cleanup.push('restore-app');
        }
      } catch {
        cleanup.push('restore-app');
      }
    }
  }
  if (cleanup.length > 0) {
    throw new TypeError(`Selected phone code fixture failed: cleanup-${cleanup.join('+')}`);
  }
  if (failed) {
    throw new TypeError(`Selected phone code fixture failed: ${stage}`);
  }
  return result as Result;
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
