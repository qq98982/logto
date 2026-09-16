import { GlobalValues } from '@logto/shared';
import { createMockUtils } from '@logto/shared/esm';
import { noop } from '@silverhand/essentials';
import type Koa from 'koa';

import type Queries from '#src/tenants/Queries.js';
import createMockContext from '#src/test-utils/jest-koa-mocks/create-mock-context.js';

const { jest } = import.meta;
const { mockEsmWithActual } = createMockUtils(jest);

await mockEsmWithActual('#src/env-set/index.js', () => ({
  EnvSet: {
    get values() {
      return new GlobalValues();
    },
  },
  AdminApps: { Console: 'console', Welcome: 'welcome' },
  UserApps: { AccountCenter: 'account' },
  getTenantEndpoint: () => new URL('https://tenant.example.com'),
}));

const { default: koaSecurityHeaders, koaExperienceSecurityHeaders } = await import(
  './koa-security-headers.js'
);

const koaNoop = noop as unknown as Koa.Next;
const customScriptSource = 'https://scripts.example.com';
const customConnectSource = 'https://api.example.com';
const customUiAssets = Object.freeze({ id: 'custom_ui_assets_id', createdAt: 1 });

type CustomUiSettings = {
  readonly customUiAssets?: { readonly id: string; readonly createdAt: number };
  readonly customUiCsp?: Record<string, string[]>;
};

const createQueries = ({ customUiAssets, customUiCsp = {} }: CustomUiSettings = {}) =>
  ({
    signInExperiences: {
      findDefaultSignInExperience: jest.fn(async () => ({
        customUiAssets: customUiAssets ?? null,
        customUiCsp,
      })),
    },
  }) as unknown as Queries;

const getCsp = (ctx: Koa.Context): string => {
  const value = ctx.res.getHeader('Content-Security-Policy');
  return typeof value === 'string' ? value : '';
};

const getCspDirective = (ctx: Koa.Context, directiveName: string): string | undefined =>
  getCsp(ctx)
    .split(';')
    .map((directive) => directive.trim())
    .find((directive) => directive.startsWith(`${directiveName} `));

const getCspDirectiveSources = (ctx: Koa.Context, directiveName: string): string[] =>
  getCspDirective(ctx, directiveName)?.split(' ').slice(1) ?? [];

describe('koaSecurityHeaders() middleware — experience CSP', () => {
  it('allows the exact Alibaba mainland Captcha V3 origins in hosted experience', async () => {
    const run = koaExperienceSecurityHeaders('default', createQueries());
    const ctx = createMockContext({ method: 'GET', url: '/sign-in' });

    await run(ctx, koaNoop);

    expect(getCspDirectiveSources(ctx, 'script-src')).toEqual(
      expect.arrayContaining([
        'https://o.alicdn.com',
        'https://g.alicdn.com',
        'https://x.alicdn.com',
      ])
    );
    expect(getCspDirectiveSources(ctx, 'connect-src')).toEqual(
      expect.arrayContaining([
        'https://*.captcha-open.aliyuncs.com/',
        'https://*.captcha-open-b.aliyuncs.com/',
        'https://cloudauth-device.aliyuncs.com',
        'https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com',
        'https://cn-shanghai.device.saf.aliyuncs.com',
      ])
    );
    expect(getCspDirectiveSources(ctx, 'img-src')).toEqual(
      expect.arrayContaining([
        'https://o.alicdn.com',
        'https://g.alicdn.com',
        'https://x.alicdn.com',
        'https://static-captcha.aliyuncs.com',
      ])
    );
    expect(getCspDirectiveSources(ctx, 'script-src')).not.toContain('https:');
    expect(getCspDirectiveSources(ctx, 'connect-src')).not.toContain('https:');
  });

  it('does not add Alibaba Captcha sources outside hosted experience', async () => {
    const run = koaSecurityHeaders(['api', 'oidc', '.well-known', 'demo-app'], 'default');
    const urls = ['/console', '/account', '/oidc/auth', '/demo-app'];

    const cspHeaders = await Promise.all(
      urls.map(async (url) => {
        const ctx = createMockContext({ method: 'GET', url });

        await run(ctx, koaNoop);

        return getCsp(ctx);
      })
    );

    for (const cspHeader of cspHeaders) {
      expect(cspHeader).not.toContain('alicdn.com');
      expect(cspHeader).not.toContain('captcha-open.aliyuncs.com');
      expect(cspHeader).not.toContain('captcha-open-b.aliyuncs.com');
      expect(cspHeader).not.toContain('cloudauth-device.aliyuncs.com');
      expect(cspHeader).not.toContain('cloudauth-device-dualstack.cn-shanghai.aliyuncs.com');
      expect(cspHeader).not.toContain('cn-shanghai.device.saf.aliyuncs.com');
      expect(cspHeader).not.toContain('static-captcha.aliyuncs.com');
    }
  });

  it('adds Custom UI CSP sources to the matching experience directives', async () => {
    const run = koaExperienceSecurityHeaders(
      'default',
      createQueries({
        customUiAssets,
        customUiCsp: {
          scriptSrc: [customScriptSource],
          connectSrc: [customConnectSource],
        },
      })
    );
    const ctx = createMockContext({ method: 'GET', url: '/sign-in' });

    await run(ctx, koaNoop);

    const scriptSource = getCspDirective(ctx, 'script-src');
    const connectSource = getCspDirective(ctx, 'connect-src');

    expect(scriptSource).toContain("'self'");
    expect(scriptSource).toContain(customScriptSource);
    expect(scriptSource).not.toContain(customConnectSource);
    expect(connectSource).toContain('https://tenant.example.com');
    expect(connectSource).toContain(customConnectSource);
    expect(connectSource).not.toContain(customScriptSource);
  });

  it('allows local MinIO HTTP origins in experience img-src during development', async () => {
    const run = koaExperienceSecurityHeaders('default', createQueries());
    const ctx = createMockContext({ method: 'GET', url: '/sign-in' });

    await run(ctx, koaNoop);

    const imageSource = getCspDirective(ctx, 'img-src');

    expect(imageSource).toContain('https:');
    expect(imageSource).toContain('http://localhost:9000');
    expect(imageSource).toContain('http://127.0.0.1:9000');
  });

  it('does not add Custom UI CSP sources when Custom UI assets are not configured', async () => {
    const run = koaExperienceSecurityHeaders(
      'default',
      createQueries({
        customUiCsp: {
          scriptSrc: [customScriptSource],
          connectSrc: [customConnectSource],
        },
      })
    );
    const ctx = createMockContext({ method: 'GET', url: '/sign-in' });

    await run(ctx, koaNoop);

    const scriptSource = getCspDirective(ctx, 'script-src');
    const connectSource = getCspDirective(ctx, 'connect-src');

    expect(scriptSource).toContain("'self'");
    expect(scriptSource).not.toContain(customScriptSource);
    expect(connectSource).toContain('https://tenant.example.com');
    expect(connectSource).not.toContain(customConnectSource);
  });

  it('does not leak Custom UI CSP sources outside hosted experience routes', async () => {
    const run = koaSecurityHeaders(['api', 'oidc', '.well-known', 'demo-app'], 'default');
    const urlsWithDedicatedCsp = ['/console', '/account', '/account/callback/social/google'];
    const mountedAppUrls = ['/oidc/auth', '/api/.well-known', '/demo-app'];

    const cspHeaders = await Promise.all(
      urlsWithDedicatedCsp.map(async (url) => {
        const ctx = createMockContext({ method: 'GET', url });

        await run(ctx, koaNoop);

        return getCsp(ctx);
      })
    );

    for (const cspHeader of cspHeaders) {
      expect(cspHeader).not.toContain(customScriptSource);
      expect(cspHeader).not.toContain(customConnectSource);
    }

    const mountedAppCspHeaders = await Promise.all(
      mountedAppUrls.map(async (url) => {
        const ctx = createMockContext({ method: 'GET', url });

        await run(ctx, koaNoop);

        return getCsp(ctx);
      })
    );

    expect(mountedAppCspHeaders).toEqual(['', '', '']);
  });

  it('allows inline scripts in account center for SSR bootstrap', async () => {
    const run = koaSecurityHeaders(['api', 'oidc', '.well-known', 'demo-app'], 'default');
    const ctx = createMockContext({ method: 'GET', url: '/account' });

    await run(ctx, koaNoop);

    const scriptSource = getCspDirective(ctx, 'script-src');
    const scriptSourceAttribute = getCspDirective(ctx, 'script-src-attr');

    expect(scriptSource).toContain("'self'");
    expect(scriptSource).toContain("'unsafe-inline'");
    expect(scriptSource).toContain("'unsafe-hashes'");
    expect(scriptSourceAttribute).toBe("script-src-attr 'unsafe-inline'");
  });

  it('does not override mounted app CSP when the experience middleware is reached later', async () => {
    const queries = createQueries({
      customUiAssets,
      customUiCsp: {
        scriptSrc: [customScriptSource],
      },
    });
    const runSecurityHeaders = koaSecurityHeaders(['console'], 'default');
    const runExperienceSecurityHeaders = koaExperienceSecurityHeaders('default', queries, [
      'console',
    ]);
    const ctx = createMockContext({ method: 'GET', url: '/console/organizations' });

    await runSecurityHeaders(ctx, async () => runExperienceSecurityHeaders(ctx, koaNoop));

    const scriptSource = getCspDirective(ctx, 'script-src');

    expect(scriptSource).toContain('https://cdn.jsdelivr.net/');
    expect(scriptSource).not.toContain(customScriptSource);
    expect(queries.signInExperiences.findDefaultSignInExperience).not.toHaveBeenCalled();
  });
});
