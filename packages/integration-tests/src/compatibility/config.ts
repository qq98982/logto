import { targetConfigGuard, type TargetConfig } from './model.js';

type CompatibilityEnvironment = Readonly<Record<string, string | undefined>>;

type TargetVariables = {
  core: string;
  admin: string;
};

const targetVariables = {
  oracle: {
    core: 'ASTER_ORACLE_URL',
    admin: 'ASTER_ORACLE_ADMIN_URL',
  },
  candidate: {
    core: 'ASTER_CANDIDATE_URL',
    admin: 'ASTER_CANDIDATE_ADMIN_URL',
  },
} as const satisfies Record<TargetConfig['label'], TargetVariables>;

const parseRootHttpUrl = (rawValue: string, description: string): string => {
  try {
    const url = new URL(rawValue);

    if (
      (url.protocol !== 'http:' && url.protocol !== 'https:') ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      url.pathname !== '/' ||
      url.search.length > 0 ||
      url.hash.length > 0
    ) {
      throw new Error('Invalid target URL');
    }

    return url.href;
  } catch {
    throw new Error(`Invalid ${description}`);
  }
};

const loadRootHttpUrl = (environment: CompatibilityEnvironment, variable: string): string => {
  const rawValue = environment[variable];

  if (rawValue === undefined || rawValue.trim().length === 0) {
    throw new Error(`Missing ${variable}`);
  }

  return parseRootHttpUrl(rawValue, variable);
};

export const validateTargetConfig = (target: unknown): TargetConfig => {
  const result = targetConfigGuard.safeParse(target);

  if (!result.success) {
    throw new Error('Invalid target configuration');
  }

  return Object.freeze({
    label: result.data.label,
    coreUrl: parseRootHttpUrl(result.data.coreUrl, 'coreUrl'),
    adminUrl: parseRootHttpUrl(result.data.adminUrl, 'adminUrl'),
  });
};

const loadTarget = (
  label: TargetConfig['label'],
  environment: CompatibilityEnvironment
): TargetConfig => {
  const variables = targetVariables[label];

  return validateTargetConfig({
    label,
    coreUrl: loadRootHttpUrl(environment, variables.core),
    adminUrl: loadRootHttpUrl(environment, variables.admin),
  });
};

export const loadCompatibilityConfig = (
  environment: CompatibilityEnvironment = process.env
): { oracle: TargetConfig; candidate: TargetConfig } => {
  const oracle = loadTarget('oracle', environment);
  const candidate = loadTarget('candidate', environment);

  if (oracle.coreUrl === candidate.coreUrl) {
    throw new Error('Oracle and candidate core URLs must differ');
  }

  if (oracle.adminUrl === candidate.adminUrl) {
    throw new Error('Oracle and candidate admin URLs must differ');
  }

  return Object.freeze({ oracle, candidate });
};
