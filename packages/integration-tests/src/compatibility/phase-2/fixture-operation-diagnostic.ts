/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One invocation-local slot retains the first closed operation without retaining its error. */
const operations = [
  'issuer-discovery',
  'admin-bearer-admission',
  'admin-bearer-authorization',
  'admin-bearer-bootstrap',
  'admin-bearer-password',
  'admin-bearer-identification',
  'admin-bearer-submit',
  'admin-bearer-bridge',
  'admin-bearer-consent',
  'admin-bearer-resume',
  'admin-bearer-code-token',
  'admin-bearer-management-refresh',
  'admin-bearer-jwks',
  'admin-bearer-consumer',
  'provider-credential-lease',
  'connector-create',
  'connector-provider-prepare',
  'connector-target-select',
  'connector-account-settings',
  'connector-provider-stop',
  'connector-target-restore',
  'connector-delete',
  'account-settings-read-account-center',
  'account-settings-read-sign-in-experience',
  'account-settings-parse-policy',
  'account-settings-configure',
  'account-settings-email-password',
  'account-settings-cleanup',
  'email-password-primary-setup-config',
  'email-password-primary-patch-sie',
  'email-password-primary-read-sie',
  'email-password-primary-get-app',
  'email-password-primary-patch-app',
  'email-password-primary-read-app',
  'email-password-primary-read-resource-scopes',
  'email-password-primary-post-resource-role',
  'email-password-primary-read-resource-role-scopes',
  'email-password-primary-post-user',
  'email-password-primary-assign-resource-role',
  'email-password-primary-read-user-roles',
  'email-password-primary-use',
  'email-password-cleanup-restore-sie',
  'email-password-cleanup-delete-user',
  'email-password-cleanup-delete-role',
  'email-password-cleanup-restore-app-patch',
  'email-password-cleanup-restore-app-read',
  'collision-admission',
  'collision-read-sign-in-settings',
  'collision-create-original-owner',
  'collision-associate-original-owner',
  'collision-update-colliding-email',
  'collision-enable-account-linking',
  'collision-helper',
  'collision-settings-restore',
  'collision-owner-delete',
] as const;
export type Phase2FixtureFailureOperation = (typeof operations)[number];
const escaped = operations.join('|');
export const phase2FixtureFailureOperationPattern = new RegExp(`^(?:${escaped})$`, 'u');
const failures = new WeakMap<WeakKey, Phase2FixtureFailureOperation>();
export type Phase2FixtureOperationDiagnostic = Readonly<{
  run<Result>(
    operation: Phase2FixtureFailureOperation,
    use: () => Promise<Result>
  ): Promise<Result>;
  record(operation: Phase2FixtureFailureOperation): void;
}>;
export const getPhase2FixtureFailureOperation = (
  error: unknown
): Phase2FixtureFailureOperation | undefined =>
  (typeof error === 'object' && error !== null) || typeof error === 'function'
    ? failures.get(error)
    : undefined;
export const withPhase2FixtureOperationDiagnostic = async <Result>(
  use: (diagnostic: Phase2FixtureOperationDiagnostic) => Promise<Result>
): Promise<Result> => {
  let retained: Phase2FixtureFailureOperation | undefined;
  const record = (operation: Phase2FixtureFailureOperation) => {
    retained ??= operation;
  };
  const diagnostic: Phase2FixtureOperationDiagnostic = Object.freeze({
    record,
    run: async <Value>(operation: Phase2FixtureFailureOperation, run: () => Promise<Value>) => {
      try {
        return await run();
      } catch (error: unknown) {
        record(operation);
        throw error;
      }
    },
  });
  try {
    return await use(diagnostic);
  } catch (error: unknown) {
    if (
      retained &&
      ((typeof error === 'object' && error !== null) || typeof error === 'function')
    ) {
      failures.set(error, retained);
    }
    throw error;
  }
};
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
