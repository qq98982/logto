/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types -- The closed response projector and recursive structural comparator keep every normalized field explicit. */
export type LogoutSessionProjection = Readonly<{
  status: number;
  contentType: string | null;
  cacheControl: string | null;
  setCookieCount: number;
  clearedCookieCount: number;
  location: Readonly<{
    kind: 'local' | 'external';
    path: string;
    queryKeys: readonly string[];
  }> | null;
  body:
    | Readonly<{
        kind: 'html';
        title: 'Sign Out' | null;
        logoutForm: boolean;
        autoSubmit: boolean;
        success: boolean;
      }>
    | Readonly<{
        kind: 'error';
        error: string | null;
        description: string | null;
        code: string | null;
      }>
    | Readonly<{ kind: 'verification'; expiresAt: true }>
    | Readonly<{
        kind: 'sessions';
        sessionCount: number;
        currentCount: number;
        clientCount: number;
        clientCounts: readonly number[];
      }>
    | Readonly<{ kind: 'empty' }>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 logout session projection');
};

const mediaType = (value: string | null): string | null =>
  value?.split(';', 1)[0]?.trim().toLowerCase() ?? null;

const errorText = (value: unknown): string | null =>
  typeof value === 'string' && value.length <= 2048 && !/\p{Cc}/u.test(value) ? value : null;

const record = (value: unknown): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  return value as Record<string, unknown>;
};

const projectSessions = (value: unknown): LogoutSessionProjection['body'] => {
  const source = record(value);
  if (!Array.isArray(source.sessions) || Object.keys(source).length !== 1) {
    return fail();
  }
  const entries = source.sessions.map((entry) => {
    const session = record(entry);
    const payload = record(session.payload);
    const authorities = record(payload.authorizations);
    if (
      typeof session.isCurrent !== 'boolean' ||
      (session.clientId !== null && typeof session.clientId !== 'string') ||
      typeof session.accountId !== 'string' ||
      typeof session.expiresAt !== 'number' ||
      typeof payload.uid !== 'string' ||
      typeof payload.accountId !== 'string' ||
      payload.kind !== 'Session' ||
      !Number.isSafeInteger(payload.exp) ||
      !Number.isSafeInteger(payload.iat) ||
      !Number.isSafeInteger(payload.loginTs)
    ) {
      return fail();
    }
    return Object.freeze({
      current: session.isCurrent,
      client: typeof session.clientId === 'string',
      clients: Object.keys(authorities).length,
    });
  });
  return Object.freeze({
    kind: 'sessions' as const,
    sessionCount: entries.length,
    currentCount: entries.filter(({ current }) => current).length,
    clientCount: entries.filter(({ client }) => client).length,
    clientCounts: Object.freeze(
      entries.map(({ clients }) => clients).sort((left, right) => left - right)
    ),
  });
};

export const projectLogoutSessionResponse = (
  targetOrigin: string,
  response: Response,
  bodyText: string
): LogoutSessionProjection => {
  if (bodyText.length > 64 * 1024) {
    return fail();
  }
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 8 || cookies.some((cookie) => Buffer.byteLength(cookie) > 8192)) {
    return fail();
  }
  const locationValue = response.headers.get('location');
  const location = locationValue
    ? (() => {
        const target = new URL(targetOrigin);
        const value = new URL(locationValue, target);
        return Object.freeze({
          kind: value.origin === target.origin ? ('local' as const) : ('external' as const),
          path: value.pathname,
          queryKeys: Object.freeze([...new Set(value.searchParams.keys())].sort()),
        });
      })()
    : null;
  const contentType = mediaType(response.headers.get('content-type'));
  let body: LogoutSessionProjection['body'];
  if (bodyText.length === 0) {
    body = Object.freeze({ kind: 'empty' as const });
  } else if (contentType === 'text/html') {
    body = Object.freeze({
      kind: 'html' as const,
      title: /<title>\s*Sign Out\s*<\/title>/iu.test(bodyText) ? ('Sign Out' as const) : null,
      logoutForm:
        /<form\b[^>]*method=["']post["'][^>]*>/iu.test(bodyText) &&
        /name=["']xsrf["']/iu.test(bodyText),
      autoSubmit: /onload=["'][^"']*\.submit\(\)/iu.test(bodyText),
      success: bodyText.includes('You have successfully signed out.'),
    });
  } else {
    let value: unknown;
    try {
      value = JSON.parse(bodyText);
    } catch {
      return fail();
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return fail();
    }
    const source = record(value);
    if (
      response.status === 201 &&
      typeof source.verificationRecordId === 'string' &&
      source.verificationRecordId.length > 0 &&
      typeof source.expiresAt === 'string' &&
      source.expiresAt.length > 0
    ) {
      body = Object.freeze({ kind: 'verification' as const, expiresAt: true as const });
    } else if (response.status === 200 && Object.hasOwn(source, 'sessions')) {
      body = projectSessions(source);
    } else {
      body = Object.freeze({
        kind: 'error' as const,
        error: errorText(source.error),
        description: errorText(source.error_description),
        code: errorText(source.code),
      });
    }
  }
  return Object.freeze({
    status: response.status,
    contentType,
    cacheControl: response.headers.get('cache-control'),
    setCookieCount: cookies.length,
    clearedCookieCount: cookies.filter(
      (cookie) =>
        /expires=thu, 0?1 jan 1970 00:00:00 gmt/iu.test(cookie) || /max-age=0/iu.test(cookie)
    ).length,
    location,
    body,
  });
};

export const compareLogoutSessionProjections = (
  oracle: LogoutSessionProjection,
  candidate: LogoutSessionProjection
): readonly string[] => {
  const differences: string[] = [];
  const visit = (left: unknown, right: unknown, path: string): void => {
    if (typeof left !== 'object' || left === null || typeof right !== 'object' || right === null) {
      if (left !== right) {
        differences.push(path || '/');
      }
      return;
    }
    if (Array.isArray(left) || Array.isArray(right)) {
      if (JSON.stringify(left) !== JSON.stringify(right)) {
        differences.push(path || '/');
      }
      return;
    }
    const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort();
    for (const key of keys) {
      visit(
        (left as Record<string, unknown>)[key],
        (right as Record<string, unknown>)[key],
        `${path}/${key}`
      );
    }
  };
  visit(oracle, candidate, '');
  return Object.freeze(differences);
};

/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types */
