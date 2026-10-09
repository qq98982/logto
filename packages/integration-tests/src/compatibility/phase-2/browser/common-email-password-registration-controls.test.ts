import {
  commonEmailPasswordRegistrationExpectedControls,
  runCommonEmailPasswordRegistrationControls,
  type EmailPasswordRegistrationControlRuntime,
} from './common-email-password-registration-controls.js';

const createRuntime = (
  override: Partial<Record<'incomplete' | 'duplicate' | 'policy', unknown>> = {}
) => {
  const owners = new Map<string, readonly string[]>([
    ['incomplete@example.invalid', []],
    ['duplicate@example.invalid', ['existing-owner']],
    ['policy@example.invalid', []],
  ]);
  const runtime: EmailPasswordRegistrationControlRuntime = {
    authenticatedLookupExactEmail: async (email) => owners.get(email) ?? [],
    runVerifiedRegistration: async (kind) =>
      override[kind] ??
      (kind === 'incomplete'
        ? {
            requestStatus: 200,
            requestOutcome: 'created',
            requestError: '',
            verifyStatus: 200,
            verifyOutcome: 'verified',
            verifyError: '',
            actionStatus: 422,
            actionError: 'user.missing_profile',
          }
        : kind === 'duplicate'
          ? {
              requestStatus: 200,
              requestOutcome: 'created',
              requestError: '',
              verifyStatus: 200,
              verifyOutcome: 'verified',
              verifyError: '',
              actionStatus: 422,
              actionError: 'user.email_already_in_use',
            }
          : {
              requestStatus: 200,
              requestOutcome: 'created',
              requestError: '',
              verifyStatus: 200,
              verifyOutcome: 'verified',
              verifyError: '',
              actionStatus: 422,
              actionError: 'password.rejected',
            }),
  };
  return runtime;
};

const emails = {
  incompleteEmail: 'incomplete@example.invalid',
  duplicateEmail: 'duplicate@example.invalid',
  rejectedPolicyEmail: 'policy@example.invalid',
} as const;

test('proves missing profile, duplicate ownership, and rejected policy without publishing identities', async () => {
  const result = await runCommonEmailPasswordRegistrationControls(createRuntime(), emails);
  expect(result).toEqual(commonEmailPasswordRegistrationExpectedControls);
  expect(JSON.stringify(result)).not.toMatch(/example\.invalid|existing-owner|verificationId/u);
});

test.each([
  [
    'incomplete',
    { actionStatus: 201, actionError: '' },
    'Common email password registration controls failed: incomplete-identification',
  ],
  [
    'duplicate',
    { actionStatus: 422, actionError: 'user.missing_profile' },
    'Common email password registration controls failed: duplicate-identification',
  ],
  [
    'policy',
    { actionStatus: 204, actionError: '' },
    'Common email password registration controls failed: policy-profile',
  ],
] as const)('rejects a mismatched %s control outcome', async (kind, action, expected) => {
  const base = await createRuntime().runVerifiedRegistration(
    kind,
    emails[`${kind === 'policy' ? 'rejectedPolicy' : kind}Email`]
  );
  await expect(
    runCommonEmailPasswordRegistrationControls(
      createRuntime({ [kind]: { ...(base as Record<string, unknown>), ...action } }),
      emails
    )
  ).rejects.toThrow(expected);
});
