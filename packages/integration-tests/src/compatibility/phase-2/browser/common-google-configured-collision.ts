import {
  assertCommonGoogleConfiguredCollisionProjection,
  type CommonGoogleConfiguredCollisionProjection,
} from '../scenarios/common-social-account.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Google configured collision flow');
};
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
  const beforeOwner = exactOwner(await input.readOriginalOwner());
  const beforeCollision = exactOwner(await input.readCollidingUser());
  if (beforeOwner.id !== input.ownerId || beforeOwner.googleSubject !== input.googleSubject) {
    fail();
  }
  if (beforeCollision.id === beforeOwner.id || beforeCollision.googleSubject !== undefined) {
    fail();
  }
  const signIn = await input.runConfiguredSignIn();
  const afterOwner = exactOwner(await input.readOriginalOwner());
  const afterCollision = exactOwner(await input.readCollidingUser());
  return assertCommonGoogleConfiguredCollisionProjection({
    configured: true,
    signInStatus: signIn.status,
    implicitAssociationAbsent: afterCollision.googleSubject === undefined,
    originalOwnerPreserved:
      afterOwner.id === beforeOwner.id && afterOwner.googleSubject === beforeOwner.googleSubject,
    providerRequestExact: signIn.providerRequestExact,
  });
};
