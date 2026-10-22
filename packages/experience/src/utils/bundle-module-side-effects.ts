const declarativeModulesWithServerOnlyExports = [
  '/packages/toolkit/connector-kit/lib/index.js',
  '/packages/toolkit/connector-kit/lib/types/index.js',
  '/packages/schemas/lib/index.js',
  '/packages/schemas/lib/db-entries/logto-config.js',
  '/packages/schemas/lib/db-entries/sign-in-experience.js',
  '/packages/schemas/lib/db-entries/user.js',
  '/packages/schemas/lib/types/custom-profile-fields.js',
  '/packages/schemas/lib/types/onboarding.js',
] as const;

/**
 * These generated/declarative modules have no import-time registration. Treating them as pure lets
 * Rollup omit server-only exports while retaining every export that Experience actually imports.
 */
export const hasExperienceModuleSideEffects = (id: string): boolean => {
  const normalizedPath = id.replaceAll('\\', '/').split('?', 1)[0];

  return !declarativeModulesWithServerOnlyExports.some((suffix) =>
    normalizedPath?.endsWith(suffix)
  );
};
