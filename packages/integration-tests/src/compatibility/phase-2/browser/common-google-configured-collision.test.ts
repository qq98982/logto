/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The negative fixture changes persisted association state during simulated SignIn. */
import { runCommonGoogleConfiguredCollision } from './common-google-configured-collision.js';

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
  await expect(
    runCommonGoogleConfiguredCollision({
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
    })
  ).rejects.toThrow(TypeError);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
