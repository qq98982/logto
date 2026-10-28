/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The negative fixture changes persisted association state during simulated SignIn. */
import {
  getCommonGoogleConfiguredCollisionCheckpoint,
  runCommonGoogleConfiguredCollision,
  withCommonGoogleConfiguredCollisionCheckpoint,
} from './common-google-configured-collision.js';

test('accepts only an actual configured SignIn collision that preserves both owners', async () => {
  const original = { id: 'original', identities: { google: { userId: 'google-subject' } } };
  const collision = { id: 'collision', identities: {} };
  await expect(
    runCommonGoogleConfiguredCollision({
      ownerId: 'original',
      googleSubject: 'google-subject',
      readOriginalOwner: async () => structuredClone(original),
      readCollidingUser: async () => structuredClone(collision),
      runConfiguredSignIn: async () => ({ status: 404, providerRequestExact: true }),
    })
  ).resolves.toEqual({
    configured: true,
    signInStatus: 404,
    implicitAssociationAbsent: true,
    originalOwnerPreserved: true,
    providerRequestExact: true,
  });
});
test('rejects a configured collision that silently associates the colliding account', async () => {
  let associated = false;
  const failure = runCommonGoogleConfiguredCollision({
    ownerId: 'original',
    googleSubject: 'google-subject',
    readOriginalOwner: async () => ({
      id: 'original',
      identities: { google: { userId: 'google-subject' } },
    }),
    readCollidingUser: async () => ({
      id: 'collision',
      identities: associated ? { google: { userId: 'google-subject' } } : {},
    }),
    runConfiguredSignIn: async () => {
      associated = true;
      return { status: 404, providerRequestExact: true };
    },
  });
  const error = await failure.then(
    () => null,
    (error_: unknown) => error_
  );
  expect(error).toBeInstanceOf(TypeError);
  expect(getCommonGoogleConfiguredCollisionCheckpoint(error)).toBe('projection');
});
test('retains actual helper checkpoints per invocation without leaking success or unrelated errors', async () => {
  const capture = async (failAfterSignIn: boolean) =>
    withCommonGoogleConfiguredCollisionCheckpoint(async (retain) => {
      let originalReads = 0;
      try {
        await runCommonGoogleConfiguredCollision({
          ownerId: 'original',
          googleSubject: 'google-subject',
          readOriginalOwner: async () => {
            originalReads += 1;
            if (failAfterSignIn && originalReads === 2) {
              throw new TypeError('private persisted owner failure');
            }
            return {
              id: 'original',
              identities: { google: { userId: 'google-subject' } },
            };
          },
          readCollidingUser: async () => ({ id: 'collision', identities: {} }),
          runConfiguredSignIn: async () => {
            if (!failAfterSignIn) {
              throw new TypeError('private configured sign-in failure');
            }
            return { status: 404, providerRequestExact: true };
          },
        });
      } catch (error: unknown) {
        const checkpoint = getCommonGoogleConfiguredCollisionCheckpoint(error);
        if (checkpoint) {
          retain(checkpoint);
        }
        throw new TypeError('fixed outer boundary');
      }
    });
  const first = capture(false);
  const second = capture(true);
  const unrelated = new TypeError('fixed unrelated boundary');
  const [firstError, secondError] = await Promise.all([
    first.catch((error: unknown) => error),
    second.catch((error: unknown) => error),
  ]);
  expect(getCommonGoogleConfiguredCollisionCheckpoint(firstError)).toBe('configured-sign-in');
  expect(getCommonGoogleConfiguredCollisionCheckpoint(secondError)).toBe('original-owner-after');
  expect(getCommonGoogleConfiguredCollisionCheckpoint(unrelated)).toBeUndefined();
  await expect(withCommonGoogleConfiguredCollisionCheckpoint(async () => 'success')).resolves.toBe(
    'success'
  );
  const unretained = await withCommonGoogleConfiguredCollisionCheckpoint(async () => {
    throw new TypeError('fixed setup failure');
  }).catch((error: unknown) => error);
  expect(getCommonGoogleConfiguredCollisionCheckpoint(unretained)).toBeUndefined();
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
