/* eslint-disable complexity, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unnecessary-condition -- One owned user and immutable social subject are compensated in one scope. */
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid selected Wechat existing-owner fixture');
};

const assertIdentity = (value: unknown, userId: string, wechatSubject: string): void => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Reflect.get(value, 'id') !== userId ||
    typeof Reflect.get(value, 'identities') !== 'object' ||
    Reflect.get(value, 'identities') === null ||
    typeof Reflect.get(Reflect.get(value, 'identities'), 'wechat') !== 'object' ||
    Reflect.get(Reflect.get(value, 'identities'), 'wechat') === null ||
    Reflect.get(Reflect.get(Reflect.get(value, 'identities'), 'wechat'), 'userId') !== wechatSubject
  ) {
    fail();
  }
};

export const withSelectedWechatWebExistingOwner = async <Result>(
  input: Readonly<{
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    wechatSubject: string;
    originalEmail: string;
    connectorId: string;
    connectorData: Readonly<Record<string, unknown>>;
    use(owner: Readonly<{ id: string }>): Promise<Result>;
  }>
): Promise<Result> => {
  let userId: string | undefined;
  let result: Result | undefined;
  let bodyFailed = false;
  let primaryStage = 'create-user';
  let cleanupFailed = false;
  try {
    const created = (await input.request({
      method: 'POST',
      path: 'users',
      body: { primaryEmail: input.originalEmail },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    })) as { id?: unknown };
    if (typeof created.id === 'string' && created.id.length > 0) userId = created.id;
    if (!userId) return fail();
    primaryStage = 'associate';
    const identities = (await input.request({
      method: 'POST',
      path: `users/${encodeURIComponent(userId)}/identities`,
      body: { connectorId: input.connectorId, connectorData: input.connectorData },
      expectedStatuses: [200],
      responseKind: 'object',
    })) as Record<string, unknown>;
    if (
      typeof identities.wechat !== 'object' ||
      identities.wechat === null ||
      Reflect.get(identities.wechat, 'userId') !== input.wechatSubject
    ) {
      return fail();
    }
    primaryStage = 'read-before';
    const before = await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(userId)}`,
      expectedStatuses: [200],
      responseKind: 'object',
    });
    assertIdentity(before, userId, input.wechatSubject);
    primaryStage = 'use';
    result = await input.use(Object.freeze({ id: userId }));
    primaryStage = 'read-after';
    const after = await input.request({
      method: 'GET',
      path: `users/${encodeURIComponent(userId)}`,
      expectedStatuses: [200],
      responseKind: 'object',
    });
    assertIdentity(after, userId, input.wechatSubject);
  } catch {
    bodyFailed = true;
  } finally {
    if (userId) {
      await input
        .request({
          method: 'DELETE',
          path: `users/${encodeURIComponent(userId)}`,
          expectedStatuses: [204, 404],
          responseKind: 'status',
        })
        .catch(() => {
          cleanupFailed = true;
        });
    }
  }
  if (cleanupFailed)
    throw new AggregateError(
      [
        new TypeError('Selected Wechat fixture failed: cleanup-user'),
        ...(bodyFailed ? [new TypeError(`Selected Wechat fixture failed: ${primaryStage}`)] : []),
      ],
      'Selected Wechat fixture cleanup failed'
    );
  if (bodyFailed) throw new TypeError(`Selected Wechat fixture failed: ${primaryStage}`);
  return result as Result;
};
/* eslint-enable complexity, no-restricted-syntax, curly, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unnecessary-condition */
