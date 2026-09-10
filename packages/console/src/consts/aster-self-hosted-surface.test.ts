import fs from 'node:fs';
import path from 'node:path';

const sourceRoot = path.resolve('src');
const repositoryRoot = path.resolve(sourceRoot, '../../..');
const phrasesRoot = path.join(repositoryRoot, 'packages/phrases/src/locales');

const walk = (directory: string): string[] =>
  fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);

    return entry.isDirectory() ? walk(target) : [target];
  });

const textExtensions = new Set(['.html', '.md', '.mdx', '.scss', '.ts', '.tsx']);
const consoleTextFiles = walk(sourceRoot).filter(
  (file) => textExtensions.has(path.extname(file)) && !/\.(?:test|spec)\.[^.]+$/u.test(file)
);

describe('Aster self-hosted Console surface', () => {
  it('does not retain unsupported upstream service authorities or browser markers', () => {
    const source = consoleTextFiles.map((file) => fs.readFileSync(file, 'utf8')).join('\n');

    expect(source).not.toMatch(
      /(?:https?:\/\/|contact@)(?:www\.)?logto\.io|docs\.logto\.io|\.logto\.app|io\.logto:\/\/|logto-dark|file:\/\/\/logto|Logto Cloud|LOGTO_OSS_SURVEY_ENDPOINT|your-logto|logto-session/u
    );
  });

  it('has no product-bearing Console source or asset filename', () => {
    const productBearingFiles = walk(sourceRoot).filter((file) =>
      /logto/iu.test(path.basename(file))
    );

    expect(productBearingFiles).toEqual([]);
  });

  it('keeps standalone upstream names only where an embedded guide names a real dependency', () => {
    const documentationRoot = path.join(sourceRoot, 'assets/docs');
    const occurrences = walk(documentationRoot)
      .filter((file) => ['.md', '.mdx', '.ts', '.tsx'].includes(path.extname(file)))
      .flatMap((file) =>
        fs
          .readFileSync(file, 'utf8')
          .split('\n')
          .filter((line) => /\bLogto\b/u.test(line))
          .map((line) => `${path.relative(documentationRoot, file)}:${line.trim()}`)
      );

    for (const occurrence of occurrences) {
      expect(occurrence).toMatch(
        /(?:import Logto(?: from)?|providers: \[Logto\]|published plugin(?: name "Logto"|'s \*\*Logto\*\* menu|'s \*\*Logto\*\* > \*\*Settings\*\*)|Logto\.AspNetCore\.Authentication|LogtoParameters\.Claims|Logto\\\\Sdk\\\\Logto|classes\/Logto\/Sdk)/u
      );
    }
    expect(occurrences).toHaveLength(12);
  });

  it('keeps embedded guide prose grammatical and self-hosted', () => {
    const documentation = walk(path.join(sourceRoot, 'assets/docs'))
      .filter((file) => ['.md', '.mdx', '.ts', '.tsx'].includes(path.extname(file)))
      .map((file) => fs.readFileSync(file, 'utf8'))
      .join('\n');

    expect(documentation).not.toMatch(/the the upstream SDK|all other the upstream SDK/u);
    expect(documentation).not.toContain('custom domain on hosted service');
  });

  it('does not advertise renamed SDK APIs that the upstream packages do not export', () => {
    const documentation = walk(path.join(sourceRoot, 'assets/docs'))
      .filter((file) => ['.md', '.mdx', '.ts', '.tsx'].includes(path.extname(file)))
      .map((file) => fs.readFileSync(file, 'utf8'))
      .join('\n');

    expect(documentation).not.toMatch(
      /\b(?:AsterClient|AsterConfig|AsterProvider|useAster|makeAster\w*|AsterContext|AsterParameters)\b/u
    );
  });

  it('keeps executable native and M2M guide examples internally consistent', () => {
    const android = fs.readFileSync(
      path.join(sourceRoot, 'assets/docs/guides/native-android/README.mdx'),
      'utf8'
    );
    const chromeExtension = fs.readFileSync(
      path.join(sourceRoot, 'assets/docs/guides/spa-chrome-extension/README.mdx'),
      'utf8'
    );
    const machineToMachine = fs.readFileSync(
      path.join(sourceRoot, 'assets/docs/guides/m2m-general/README.mdx'),
      'utf8'
    );

    expect(android).toContain('defaultUri="aster://com.example.app/callback"');
    expect(android).toContain('manifestPlaceholders["logtoRedirectScheme"] = "aster"');
    expect(chromeExtension).toContain('"host_permissions": ["https://auth.example.com/*"]\n}');
    expect(chromeExtension.match(/endpoint: '<your-aster-endpoint>',/g)).toHaveLength(2);
    expect(machineToMachine).not.toContain('      )}`');
    expect(machineToMachine).not.toContain('const asterEndpoint =');
    expect(machineToMachine).toContain(
      "--header 'Authorization: Bearer eyJhbG...2g' # Access token"
    );
  });

  it('does not compile the upstream Cloud route or hosted email implementation', () => {
    expect(fs.existsSync(path.join(sourceRoot, 'cloud/AppRoutes.tsx'))).toBe(false);
    expect(fs.existsSync(path.join(sourceRoot, 'cloud/pages'))).toBe(false);
    expect(fs.existsSync(path.join(sourceRoot, 'components/HostedEmailCapBanner'))).toBe(false);
    expect(fs.existsSync(path.join(sourceRoot, 'pages/ConnectorDetails/EmailUsage'))).toBe(false);
    expect(
      fs.existsSync(
        path.join(sourceRoot, 'pages/ConnectorDetails/ConnectorContent/EmailServiceConnectorForm')
      )
    ).toBe(false);
  });

  it('does not advertise a hosted plan from the self-hosted SAML limit banner', () => {
    const banner = fs.readFileSync(
      path.join(sourceRoot, 'components/SamlAppLimitBanner/index.tsx'),
      'utf8'
    );

    expect(banner).not.toMatch(/pricingLink|upsell\.view_plans/u);
  });

  it('keeps hosted-email copy out of every built-in locale source', () => {
    const source = walk(phrasesRoot)
      .filter((file) => file.endsWith('/translation/admin-console/connector-details.ts'))
      .map((file) => fs.readFileSync(file, 'utf8'))
      .join('\n');

    expect(source).not.toMatch(/(?:logto|aster)_email/u);
  });
});
