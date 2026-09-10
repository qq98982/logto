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

const commonCopyExcludedPaths: ReadonlySet<string> = new Set([
  'oidc_configs.cloud_private_key_rotation_notice',
]);

const getAtPath = (value: unknown, path: string) =>
  path.split('.').reduce<unknown>((current, segment) => {
    if (typeof current !== 'object' || current === null) {
      return;
    }

    return (current as Record<string, unknown>)[segment];
  }, value);

const collectStrings = (
  value: unknown,
  path: string,
  excludedPaths: ReadonlySet<string> = new Set()
): string[] => {
  if (excludedPaths.has(path)) {
    return [];
  }
  if (typeof value === 'string') {
    return [value];
  }
  if (typeof value !== 'object' || value === null) {
    return [];
  }

  return Object.entries(value).flatMap(([key, child]) =>
    collectStrings(child, `${path}.${key}`, excludedPaths)
  );
};

const getAdminConsoleValues = (language: (typeof builtInLanguages)[number]) => {
  const adminConsole = getAtPath(phrases[language], 'translation.admin_console');

  if (adminConsole === undefined) {
    throw new TypeError(`Missing Admin Console copy: ${language}`);
  }

  return collectStrings(adminConsole, 'admin_console');
};

const getCommonCopyValues = (language: (typeof builtInLanguages)[number]) => {
  const adminConsole = getAtPath(phrases[language], 'translation.admin_console');

  return commonCopyRoots.flatMap((root) => {
    const value = getAtPath(adminConsole, root);
    if (value === undefined) {
      throw new TypeError(`Missing common Console copy root: ${language}:${root}`);
    }

    return collectStrings(value, root, commonCopyExcludedPaths);
  });
};

describe('Aster common Console copy', () => {
  it.each(builtInLanguages)('%s exposes no upstream marker in any bundled phrase', (language) => {
    for (const value of collectStrings(phrases[language], language)) {
      expect(value).not.toMatch(
        /Logto|ログト|로그토|لاگتو|(?:\*\.)?logto\.app|logto:\/\/|io\.logto/iu
      );
    }
  });

  it.each(builtInLanguages)('%s exposes no upstream product marker in common copy', (language) => {
    const values = getCommonCopyValues(language);

    for (const value of values) {
      expect(value).not.toMatch(/Logto|ログト|로그토/u);
    }
    expect(values.filter((value) => value.includes('Aster'))).toHaveLength(
      expectedAsterValueCounts[language]
    );
  });

  it.each(builtInLanguages)(
    '%s exposes no upstream marker in any Admin Console copy',
    (language) => {
      for (const value of getAdminConsoleValues(language)) {
        expect(value).not.toMatch(
          /Logto|ログト|로그토|لاگتو|(?:\*\.)?logto\.app|logto:\/\/|io\.logto/iu
        );
      }
    }
  );

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

  it('uses Aster-only keys for remaining product-specific copy', () => {
    const adminConsole = phrases.en.translation.admin_console;

    expect(adminConsole.application_details).toHaveProperty('aster_endpoint');
    expect(adminConsole.application_details).not.toHaveProperty('logto_endpoint');
    expect(adminConsole.application_details).not.toHaveProperty('integration_description');
    expect(adminConsole.application_details.saml_app_attribute_mapping).toHaveProperty(
      'col_aster_claims'
    );
    expect(adminConsole.application_details.saml_app_attribute_mapping).not.toHaveProperty(
      'col_logto_claims'
    );
    expect(adminConsole.connector_details).not.toHaveProperty('aster_email');
    expect(adminConsole.connector_details).not.toHaveProperty('logto_email');
    expect(adminConsole.connectors.create_form).not.toHaveProperty('email_connector_upsell');
    expect(adminConsole.upsell.paywall).not.toHaveProperty('aster_pricing_button_text');
    expect(adminConsole.upsell.paywall).not.toHaveProperty('logto_pricing_button_text');
  });

  it.each(builtInLanguages)(
    '%s describes only the self-hosted SAML application cap',
    (language) => {
      const notice = getAtPath(
        phrases[language],
        'translation.admin_console.upsell.paywall.saml_applications_oss_limit_notice'
      );

      expect(typeof notice).toBe('string');
      if (typeof notice !== 'string') {
        return;
      }
      expect(notice).toContain('{{limit}}');
      expect(notice).not.toMatch(/Cloud|Aster Enterprise|contact us/iu);
    }
  );
});
