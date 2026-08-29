import {
  SignInIdentifier,
  SignInMode,
  type ConnectorFactoryResponse,
  type SignInExperience,
  type SnakeCaseOidcConfig,
  type User,
  type UserProfileResponse,
  type UsersPasswordEncryptionMethod,
} from '@logto/schemas';
import ky, { HTTPError, type KyInstance } from 'ky';
import type { OpenAPIV3 } from 'openapi-types';

import { validateTargetConfig } from './config.js';
import type { TargetConfig } from './model.js';

export type CreateUserPayload = Partial<{
  primaryEmail: string;
  primaryPhone: string;
  username: string;
  password: string;
  name: string;
  passwordDigest: string;
  passwordAlgorithm: UsersPasswordEncryptionMethod;
}>;

export class TargetClientError extends Error {
  readonly operation: string;
  readonly status: number | undefined;

  override get name(): string {
    return 'TargetClientError';
  }

  constructor(operation: string, status?: number) {
    super(
      status === undefined
        ? `Target operation failed: ${operation}`
        : `Target operation failed: ${operation} (HTTP ${status})`
    );
    this.operation = operation;
    this.status = status;
  }
}

const toSafeClientError = (operation: string, error: unknown) =>
  new TargetClientError(operation, error instanceof HTTPError ? error.response.status : undefined);

const requestJson = async <Result>(operation: string, request: () => Promise<Result>) => {
  try {
    return await request();
  } catch (error: unknown) {
    throw toSafeClientError(operation, error);
  }
};

export class TargetClient {
  readonly target: TargetConfig;
  readonly core: KyInstance;
  readonly management: KyInstance;
  readonly experience: KyInstance;

  readonly #trackedUserIds = new Set<string>();

  constructor(target: TargetConfig) {
    this.target = validateTargetConfig(target);

    this.core = ky.create({ prefixUrl: this.target.coreUrl, retry: 0 });
    // Management APIs use the canonical Core origin; adminUrl is presentation-only.
    this.management = ky.create({
      prefixUrl: new URL('/api/', this.target.coreUrl),
      headers: { 'development-user-id': 'integration-test-admin-user' },
      retry: 0,
    });
    this.experience = ky.create({
      prefixUrl: new URL('/api/', this.target.coreUrl),
      retry: 0,
    });
  }

  async getDiscovery(): Promise<SnakeCaseOidcConfig & Record<string, unknown>> {
    return requestJson('getDiscovery', async () =>
      this.core
        .get('oidc/.well-known/openid-configuration')
        .json<SnakeCaseOidcConfig & Record<string, unknown>>()
    );
  }

  async getManagementOpenApi(): Promise<OpenAPIV3.Document> {
    return requestJson('getManagementOpenApi', async () =>
      this.experience.get('.well-known/management.openapi.json').json<OpenAPIV3.Document>()
    );
  }

  async getExperienceOpenApi(): Promise<OpenAPIV3.Document> {
    return requestJson('getExperienceOpenApi', async () =>
      this.experience.get('.well-known/experience.openapi.json').json<OpenAPIV3.Document>()
    );
  }

  async getUserOpenApi(): Promise<OpenAPIV3.Document> {
    return requestJson('getUserOpenApi', async () =>
      this.experience.get('.well-known/user.openapi.json').json<OpenAPIV3.Document>()
    );
  }

  async listConnectorFactories(): Promise<ConnectorFactoryResponse[]> {
    return requestJson('listConnectorFactories', async () =>
      this.management.get('connector-factories').json<ConnectorFactoryResponse[]>()
    );
  }

  async setUsernamePasswordExperience(): Promise<SignInExperience> {
    return requestJson('setUsernamePasswordExperience', async () =>
      this.management
        .patch('sign-in-exp', {
          json: {
            signInMode: SignInMode.SignInAndRegister,
            signUp: {
              identifiers: [SignInIdentifier.Username],
              password: true,
              verify: false,
            },
            signIn: {
              methods: [
                {
                  identifier: SignInIdentifier.Username,
                  password: true,
                  verificationCode: false,
                  isPasswordPrimary: true,
                },
              ],
            },
            passwordPolicy: {},
          } satisfies Partial<SignInExperience>,
        })
        .json<SignInExperience>()
    );
  }

  async createUser(payload: CreateUserPayload = {}): Promise<User> {
    const user = await requestJson('createUser', async () =>
      this.management.post('users', { json: payload }).json<User>()
    );

    if (typeof user.id === 'string' && user.id.trim().length > 0) {
      this.#trackedUserIds.add(user.id);
    }

    return user;
  }

  async getUser(userId: string): Promise<UserProfileResponse> {
    return requestJson('getUser', async () =>
      this.management.get(`users/${encodeURIComponent(userId)}`).json<UserProfileResponse>()
    );
  }

  async deleteUser(userId: string): Promise<void> {
    try {
      await this.management.delete(`users/${encodeURIComponent(userId)}`);
      this.#trackedUserIds.delete(userId);
    } catch (error: unknown) {
      if (error instanceof HTTPError && error.response.status === 404) {
        this.#trackedUserIds.delete(userId);
        return;
      }

      throw toSafeClientError('deleteUser', error);
    }
  }

  async getUserInfo(accessToken: string): Promise<Record<string, unknown>> {
    if (typeof accessToken !== 'string' || accessToken.trim().length === 0) {
      throw new TypeError('Access token must be non-empty');
    }

    return requestJson('getUserInfo', async () =>
      this.core
        .get('oidc/me', { headers: { authorization: `Bearer ${accessToken}` } })
        .json<Record<string, unknown>>()
    );
  }

  async cleanup(): Promise<void> {
    const failures = await Array.from(this.#trackedUserIds)
      .toReversed()
      .reduce<Promise<unknown[]>>(async (previousFailures, userId) => {
        const collectedFailures = await previousFailures;

        try {
          await this.deleteUser(userId);
          return collectedFailures;
        } catch (error: unknown) {
          return [...collectedFailures, error];
        }
      }, Promise.resolve([]));

    if (failures.length > 0) {
      throw new AggregateError(failures, `Failed to clean up ${failures.length} user(s)`);
    }
  }
}
