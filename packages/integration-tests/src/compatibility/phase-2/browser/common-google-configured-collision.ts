/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One sequential fixed enum records the first configured-collision checkpoint without retaining error details. */
import {
  assertCommonGoogleConfiguredCollisionProjection,
  type CommonGoogleConfiguredCollisionProjection,
} from '../scenarios/common-social-account.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Google configured collision flow');
};
export type CommonGoogleConfiguredCollisionCheckpoint =
  | 'composition'
  | 'original-owner-before'
  | 'colliding-user-before'
  | 'preconditions'
  | 'configured-sign-in'
  | 'original-owner-after'
  | 'colliding-user-after'
  | 'projection';
const configuredCollisionFailures = new WeakMap<
  WeakKey,
  CommonGoogleConfiguredCollisionCheckpoint
>();
export const getCommonGoogleConfiguredCollisionCheckpoint = (
  error: unknown
): CommonGoogleConfiguredCollisionCheckpoint | undefined =>
  (typeof error === 'object' && error !== null) || typeof error === 'function'
    ? configuredCollisionFailures.get(error)
    : undefined;
// eslint-disable-next-line complexity -- Closed hostile input admission checks every nested identity boundary.
const exactOwner = (value: unknown): Readonly<{ id: string; googleSubject?: string }> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  const id: unknown = Reflect.get(value, 'id');
  const identities: unknown = Reflect.get(value, 'identities');
  const google: unknown =
    typeof identities === 'object' && identities !== null && !Array.isArray(identities)
      ? Reflect.get(identities, 'google')
      : undefined;
  const googleSubject: unknown =
    typeof google === 'object' && google !== null && !Array.isArray(google)
      ? Reflect.get(google, 'userId')
      : undefined;
  if (
    typeof id !== 'string' ||
    id.length === 0 ||
    (googleSubject !== undefined && typeof googleSubject !== 'string')
  ) {
    return fail();
  }
  return Object.freeze({ id, ...(googleSubject === undefined ? {} : { googleSubject }) });
};

/** Executes one configured SignIn through the owned provider and compares persisted ownership. */
export const runCommonGoogleConfiguredCollision = async (
  input: Readonly<{
    ownerId: string;
    googleSubject: string;
    readOriginalOwner(): Promise<unknown>;
    readCollidingUser(): Promise<unknown>;
    runConfiguredSignIn(): Promise<Readonly<{ status: number; providerRequestExact: boolean }>>;
  }>
): Promise<CommonGoogleConfiguredCollisionProjection> => {
  let checkpoint: CommonGoogleConfiguredCollisionCheckpoint = 'original-owner-before';
  try {
    const beforeOwner = exactOwner(await input.readOriginalOwner());
    checkpoint = 'colliding-user-before';
    const beforeCollision = exactOwner(await input.readCollidingUser());
    checkpoint = 'preconditions';
    if (beforeOwner.id !== input.ownerId || beforeOwner.googleSubject !== input.googleSubject) {
      fail();
    }
    if (beforeCollision.id === beforeOwner.id || beforeCollision.googleSubject !== undefined) {
      fail();
    }
    checkpoint = 'configured-sign-in';
    const signIn = await input.runConfiguredSignIn();
    checkpoint = 'original-owner-after';
    const afterOwner = exactOwner(await input.readOriginalOwner());
    checkpoint = 'colliding-user-after';
    const afterCollision = exactOwner(await input.readCollidingUser());
    checkpoint = 'projection';
    return assertCommonGoogleConfiguredCollisionProjection({
      configured: true,
      signInStatus: signIn.status,
      implicitAssociationAbsent: afterCollision.googleSubject === undefined,
      originalOwnerPreserved:
        afterOwner.id === beforeOwner.id && afterOwner.googleSubject === beforeOwner.googleSubject,
      providerRequestExact: signIn.providerRequestExact,
    });
  } catch {
    const error = new TypeError('Invalid Common Google configured collision flow');
    configuredCollisionFailures.set(error, checkpoint);
    throw error;
  }
};
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
