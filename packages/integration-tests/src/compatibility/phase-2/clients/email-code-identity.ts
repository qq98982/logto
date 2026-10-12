import { readCommonExperienceRecord } from './common-experience.js';
import type { NativeSocialIdentityDriver } from './user-token-issuance.js';

const fail = (): never => {
  throw new TypeError('Invalid Common email-code identity entry');
};
const proof = (value: unknown): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096
    ? value
    : fail();

/** Uses the owned delivery once and submits only its real verification handle. */
export const createEmailCodeIdentityDriver =
  (
    input: Readonly<{ email: string; takeCode(email: string): Promise<string> }>
  ): NativeSocialIdentityDriver =>
  async ({ request }) => {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(input.email) || input.email.length > 256) {
      return fail();
    }
    const initialized = await request('/api/experience', 'PUT', { interactionEvent: 'SignIn' });
    await initialized.body?.cancel();
    if (initialized.status !== 204) {
      return fail();
    }
    const identifier = { type: 'email', value: input.email };
    const created = await request('/api/experience/verification/verification-code', 'POST', {
      identifier,
      interactionEvent: 'SignIn',
    });
    const createdRecord = await readCommonExperienceRecord(created);
    if (created.status !== 200 || Object.keys(createdRecord).length !== 1) {
      return fail();
    }
    const verificationId = proof(createdRecord.verificationId);
    const code = await input.takeCode(input.email);
    if (!/^\d{6}$/u.test(code)) {
      return fail();
    }
    const verified = await request(
      '/api/experience/verification/verification-code/verify',
      'POST',
      {
        identifier,
        verificationId,
        code,
      }
    );
    const verifiedRecord = await readCommonExperienceRecord(verified);
    if (
      verified.status !== 200 ||
      Object.keys(verifiedRecord).length !== 1 ||
      verifiedRecord.verificationId !== verificationId
    ) {
      return fail();
    }
    const identified = await request('/api/experience/identification', 'POST', { verificationId });
    await identified.body?.cancel();
    if (identified.status !== 204) {
      return fail();
    }
  };
