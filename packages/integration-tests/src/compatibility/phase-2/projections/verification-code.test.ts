import { compareVerificationCodeProjections } from './verification-code.js';

const oracle = Object.freeze({
  failed: Object.freeze({
    status: 400,
    contentType: 'application/json',
    cacheControl: 'no-store',
    outcome: 'error',
    handleField: null,
    expiresAt: false,
    error: 'connector.general',
    message: 'Error occurred in connector: {"message":"Message failed: 550 controlled rejection"}',
    data: Object.freeze({ message: 'Message failed: 550 controlled rejection' }),
  }),
  previous: Object.freeze({ status: 200, outcome: 'verified' }),
});
const candidate = Object.freeze({
  failed: Object.freeze({
    ...Object.fromEntries(Object.entries(oracle.failed).filter(([key]) => key !== 'data')),
    message: 'The email service could not accept the message.',
  }),
  previous: oracle.previous,
});

describe('Phase 2 verification-code projection comparison', () => {
  it('allows only the approved one-way SMTP diagnostic redaction', () => {
    expect(
      compareVerificationCodeProjections(
        oracle,
        candidate,
        'verification-code.failed-delivery-preserves-current'
      )
    ).toEqual([]);
    expect(oracle.failed.message).toContain('550 controlled rejection');
  });

  it.each([
    [
      'unknown oracle message',
      { ...oracle, failed: { ...oracle.failed, message: 'different' } },
      candidate,
    ],
    ['changed status', oracle, { ...candidate, failed: { ...candidate.failed, status: 503 } }],
    [
      'changed error',
      oracle,
      { ...candidate, failed: { ...candidate.failed, error: 'connector.invalid_config' } },
    ],
    ['changed state', oracle, { ...candidate, previous: { status: 400, outcome: 'error' } }],
    ['candidate reference diagnostic', oracle, oracle],
    [
      'candidate known data',
      oracle,
      { ...candidate, failed: { ...candidate.failed, data: oracle.failed.data } },
    ],
    [
      'unknown oracle data',
      { ...oracle, failed: { ...oracle.failed, data: { message: 'unknown' } } },
      candidate,
    ],
  ])('rejects %s', (_label, reference, actual) => {
    expect(
      compareVerificationCodeProjections(
        reference,
        actual,
        'verification-code.failed-delivery-preserves-current'
      )
    ).not.toEqual([]);
  });

  it('does not apply the mapping to another scenario', () => {
    expect(
      compareVerificationCodeProjections(
        oracle,
        candidate,
        'verification-code.experience-request-verify'
      )
    ).not.toEqual([]);
  });
});
