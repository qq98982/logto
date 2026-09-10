import phrases, { builtInLanguages } from '@logto/phrases';

const commonCopyRoots = [
  'actions',
  'applications',
  'application_details.concurrent_device_limit',
  'enterprise_sso_details',
  'errors',
  'get_started',
  'guide',
  'oidc_configs',
  'organizations',
  'oss_onboarding',
  'user_details',
  'user_identity_details',
  'webhooks',
  'webhook_details',
  'welcome',
  'sign_in_exp.content',
  'sign_in_exp.color',
  'sign_in_exp.custom_ui',
  'sign_in_exp.account_center',
  'sign_in_exp.sign_up_and_sign_in',
] as const;

const expectedAsterValueCounts = Object.freeze({
  ar: 44,
  de: 45,
  en: 43,
  es: 45,
  'fa-IR': 43,
  fr: 45,
  it: 45,
  ja: 44,
  ko: 45,
  'pl-PL': 45,
  'pt-BR': 45,
  'pt-PT': 45,
  ru: 45,
  th: 44,
  'tr-TR': 46,
  'zh-CN': 44,
  'zh-HK': 45,
  'zh-TW': 45,
} satisfies Record<(typeof builtInLanguages)[number], number>);

const excludedCopyPaths: ReadonlySet<string> = new Set([
  'oidc_configs.cloud_private_key_rotation_notice',
]);

const getAtPath = (value: unknown, path: string) =>
  path.split('.').reduce<unknown>((current, segment) => {
    if (typeof current !== 'object' || current === null) {
      return;
    }

    return (current as Record<string, unknown>)[segment];
  }, value);

const collectStrings = (value: unknown, path: string): string[] => {
  if (excludedCopyPaths.has(path)) {
    return [];
  }
  if (typeof value === 'string') {
    return [value];
  }
  if (typeof value !== 'object' || value === null) {
    return [];
  }

  return Object.entries(value).flatMap(([key, child]) => collectStrings(child, `${path}.${key}`));
};

const getCommonCopyValues = (language: (typeof builtInLanguages)[number]) => {
  const adminConsole = getAtPath(phrases[language], 'translation.admin_console');

  return commonCopyRoots.flatMap((root) => {
    const value = getAtPath(adminConsole, root);
    if (value === undefined) {
      throw new TypeError(`Missing common Console copy root: ${language}:${root}`);
    }

    return collectStrings(value, root);
  });
};

describe('Aster common Console copy', () => {
  it.each(builtInLanguages)('%s exposes no upstream product marker in common copy', (language) => {
    const values = getCommonCopyValues(language);

    for (const value of values) {
      expect(value).not.toMatch(/Logto|ログト|로그토/u);
    }
    expect(values.filter((value) => value.includes('Aster'))).toHaveLength(
      expectedAsterValueCounts[language]
    );
  });

  it('uses locale-correct product grammar', () => {
    const turkish = getCommonCopyValues('tr-TR').join('\n');
    const french = getCommonCopyValues('fr').join('\n');
    const italian = getCommonCopyValues('it').join('\n');

    expect(turkish).not.toMatch(/Aster(?:yu|['’](?:yu|nun|u|da|daki|dan))/u);
    for (const form of ["Aster'i", "Aster'in", "Aster'de", "Aster'deki", "Aster'den"]) {
      expect(turkish).toContain(form);
    }
    expect(french).not.toMatch(/\b(?:de|le|que) Aster\b/u);
    for (const form of ["d'Aster", "l'Aster", "qu'Aster"]) {
      expect(french).toContain(form);
    }
    expect(italian).not.toMatch(/\b(?:a|dal|Il|il) Aster\b|dad Aster|Usad Aster/u);
    for (const form of ['ad Aster', "dall'Aster", "L'Aster", 'da Aster', 'Usa Aster']) {
      expect(italian).toContain(form);
    }
  });

  it('uses the correct English article before Aster', () => {
    expect(phrases.en.translation.admin_console.user_details.sessions.description).toContain(
      'Revoking an Aster session'
    );
  });

  it('uses Aster-only keys for built-in language labels', () => {
    const manageLanguage = phrases.en.translation.admin_console.sign_in_exp.content.manage_language;

    expect(manageLanguage).toMatchObject({
      aster_provided: 'Aster provided',
      aster_source_values: 'Aster source values',
    });
    expect(manageLanguage).not.toHaveProperty('logto_provided');
    expect(manageLanguage).not.toHaveProperty('logto_source_values');
  });
});
