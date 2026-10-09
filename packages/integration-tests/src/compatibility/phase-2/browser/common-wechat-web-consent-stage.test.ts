/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The invalid-field callback capture proves it runs before the error crosses a wrapper. */
import { closedConsentStageForTesting } from './common-wechat-web-target-driver.js';

const publicCodes = [
  'user.identity_not_exist',
  'user.missing_profile',
  'session.verification_session_not_found',
  'session.interaction_not_found',
  'session.invalid_credentials',
  'user.suspended',
  'user.sign_in_method_not_enabled',
  'session.identity_conflict',
  'user.email_already_in_use',
  'verification_record.permission_denied',
  'guard.invalid_input',
  'connector.general',
  'connector.wechat_unionid_required',
  'connector.social_auth_code_invalid',
  'connector.invalid_response',
  'unknown',
  'none',
] as const;

test.each(publicCodes)('builds the production consent stage for public code %s', (code) => {
  const result = closedConsentStageForTesting({
    route: 'other',
    response: { operation: 'social-verify', status: 400, binding: 'not-applicable', code },
    authorizationBits: '111111100',
    state: 'state-unavailable',
  });
  const detail = `other-social-verify-400-not-applicable-${code.replaceAll('.', '-')}-auth-111111100-state-unavailable`;
  expect(result).toEqual({ stage: `consent-route-${detail}`, detail });
});

test.each([
  { route: 'callback' },
  { operation: 'none' as const },
  { status: 0 as const },
  { binding: 'complete' as const },
  { authorizationBits: '000000000' },
  { state: 'state-stored' },
  { state: 'state-cleared' },
] as const)('builds each non-code closed consent field %#', (change) => {
  expect(
    closedConsentStageForTesting({
      route: 'other',
      response: {
        operation: 'social-verify',
        status: 400,
        binding: 'not-applicable',
        code: 'connector.general',
        ...change,
      },
      authorizationBits:
        ('authorizationBits' in change ? change.authorizationBits : undefined) ?? '111111100',
      state: ('state' in change ? change.state : undefined) ?? 'state-unavailable',
      ...('route' in change && { route: change.route }),
    }).stage
  ).toMatch(/^consent-route-/u);
});

test('reports the exact invalid field before the thrown error can be rewritten', () => {
  let reported: string | undefined;
  expect(() =>
    closedConsentStageForTesting(
      {
        route: 'other',
        response: {
          operation: 'social-verify',
          status: 400,
          binding: 'not-applicable',
          code: 'connector.general',
        },
        authorizationBits: '111111100',
        state: 'private-invalid-state',
      },
      (stage) => {
        reported = stage;
      }
    )
  ).toThrow('Common Wechat existing-owner target failed: consent-field-invalid-state');
  expect(reported).toBe('consent-field-invalid-state');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
