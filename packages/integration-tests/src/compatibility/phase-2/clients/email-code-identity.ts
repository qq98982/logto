import { readCommonExperienceRecord } from './common-experience.js';
import type { NativeSocialIdentityDriver } from './user-token-issuance.js';

type EmailCodeStage =
  | 'initialization'
  | 'identifier-submit'
  | 'passcode-retrieval'
  | 'passcode-format'
  | 'verification-route'
  | 'identification';
type EmailCodeDiagnosticStage =
  | EmailCodeStage
  | `passcode-retrieval-${
      | 'env-missing'
      | 'socket-shape'
      | 'recipient'
      | 'connect'
      | 'timeout'
      | 'not-found'
      | 'response'}`;
const ownedDiagnostics = new WeakMap<Error, string>();

const diagnosticError = (stage: EmailCodeDiagnosticStage): TypeError => {
  const error = new TypeError(`Common email code stage failed: ${stage}`);
  ownedDiagnostics.set(error, stage);
  return error;
};

export const readEmailCodeIdentityStage = (error: unknown): string | undefined =>
  error instanceof Error ? ownedDiagnostics.get(error) : undefined;

const fail = (stage: EmailCodeStage): never => {
  throw diagnosticError(stage);
};
const proof = (value: unknown, stage: EmailCodeStage): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096
    ? value
    : fail(stage);

const takeDeliveredCode = async (
  takeCode: (email: string) => Promise<string>,
  email: string
): Promise<string> => {
  try {
    return await takeCode(email);
  } catch (error: unknown) {
    const deliveryStage =
      error instanceof Error
        ? /^Phase 2 verification delivery failed: (env-missing|socket-shape|recipient|connect|timeout|not-found|response)$/u.exec(
            error.message
          )?.[1]
        : undefined;
    const stage = deliveryStage ? `passcode-retrieval-${deliveryStage}` : 'passcode-retrieval';
    const diagnostic = new TypeError(`Common email code stage failed: ${stage}`);
    ownedDiagnostics.set(diagnostic, stage);
    throw diagnostic;
  }
};

/** Uses the owned delivery once and submits only its real verification handle. */
export const createEmailCodeIdentityDriver =
  (
    input: Readonly<{ email: string; takeCode(email: string): Promise<string> }>
  ): NativeSocialIdentityDriver =>
  async ({ request }) => {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(input.email) || input.email.length > 256) {
      return fail('initialization');
    }
    const initialized = await request('/api/experience', 'PUT', { interactionEvent: 'SignIn' });
    await initialized.body?.cancel();
    if (initialized.status !== 204) {
      return fail('initialization');
    }
    const identifier = { type: 'email', value: input.email };
    const created = await request('/api/experience/verification/verification-code', 'POST', {
      identifier,
      interactionEvent: 'SignIn',
    });
    const createdRecord = await readCommonExperienceRecord(created);
    if (created.status !== 200 || Object.keys(createdRecord).length !== 1) {
      return fail('identifier-submit');
    }
    const verificationId = proof(createdRecord.verificationId, 'identifier-submit');
    const code = await takeDeliveredCode(input.takeCode, input.email);
    if (!/^\d{6}$/u.test(code)) {
      return fail('passcode-format');
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
      return fail('verification-route');
    }
    const identified = await request('/api/experience/identification', 'POST', { verificationId });
    await identified.body?.cancel();
    if (identified.status !== 204) {
      return fail('identification');
    }
  };
