import { createCommonExperienceSession } from './common-experience.js';
import { observeExperiencePasswordProfile } from './password-policy.js';

const observe = async (status: number, body?: unknown) => {
  const session = createCommonExperienceSession({
    target: {
      label: 'candidate',
      coreUrl: 'https://core.example/',
      adminUrl: 'https://admin.example/',
    },
    clientId: 'owned-client',
    fetch: async (url, init) => {
      expect(new URL(String(url)).pathname).toBe('/api/experience/profile');
      expect(JSON.parse(String(init?.body))).toEqual({
        type: 'password',
        value: 'private-password',
      });
      return new Response(body === undefined ? null : JSON.stringify(body), {
        status,
        ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' } }),
      });
    },
  });
  try {
    return await observeExperiencePasswordProfile(session, 'private-password');
  } finally {
    session.close();
  }
};

test('Password policy reports exact local issue names, bounds and order without submitted credentials', async () => {
  expect(
    await observe(422, {
      code: 'password.rejected',
      data: [
        { code: 'password_rejected.too_short', interpolation: { min: 12 } },
        { code: 'password_rejected.character_types', interpolation: { min: 3 } },
        { code: 'password_rejected.restricted.words' },
      ],
    })
  ).toEqual({
    status: 422,
    error: 'password.rejected',
    issues: [
      { code: 'password_rejected.too_short', minimum: 12 },
      { code: 'password_rejected.character_types', minimum: 3 },
      { code: 'password_rejected.restricted.words' },
    ],
  });
});

test('Password policy preserves compromise denial, successful staging and same-password recovery outcomes', async () => {
  expect(
    await observe(422, { code: 'password.rejected', data: [{ code: 'password_rejected.pwned' }] })
  ).toEqual({
    status: 422,
    error: 'password.rejected',
    issues: [{ code: 'password_rejected.pwned' }],
  });
  expect(await observe(503, { error: 'temporarily_unavailable' })).toEqual({
    status: 503,
    error: 'temporarily_unavailable',
    issues: [],
  });
  expect(await observe(204)).toEqual({ status: 204, error: 'none', issues: [] });
  expect(await observe(422, { code: 'user.same_password' })).toEqual({
    status: 422,
    error: 'user.same_password',
    issues: [],
  });
});

test.each(
  [
    [],
    [{ code: 'unknown.private-secret' }],
    [{ code: 'password_rejected.too_short', interpolation: { min: 0 } }],
    [{ code: 'password_rejected.too_short', interpolation: { min: 12, secret: 'private-value' } }],
    [{ code: 'password_rejected.pwned', password: 'private-value' }],
    [{ code: 'password_rejected.pwned', interpolation: { value: 'private-value' } }],
  ].map((data) => ({ data }))
)('Password policy refuses malformed or credential-bearing issue data %j', async ({ data }) => {
  await expect(observe(422, { code: 'password.rejected', data })).rejects.toThrow(
    'Invalid Common password policy response'
  );
});
