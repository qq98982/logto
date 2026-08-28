import { SignInIdentifier } from '@logto/schemas';

import type { ExperienceClient } from '#src/client/experience/index.js';

/**
 * Creates a username/password verification record and identifies the interaction user.
 */
export const identifyUserWithUsernamePassword = async (
  client: ExperienceClient,
  username: string,
  password: string
) => {
  const { verificationId } = await client.verifyPassword({
    identifier: {
      type: SignInIdentifier.Username,
      value: username,
    },
    password,
  });

  await client.identifyUser({ verificationId });

  return { verificationId };
};
