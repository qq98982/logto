/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The fake transport captures its requested URL. */
import { observeManagementCompletionRequest } from './management-completion-observer.js';

const target = {
  label: 'oracle' as const,
  coreUrl: 'https://reference.example/',
  adminUrl: 'https://reference-admin.example/',
};

test('preserves actual status and public code for an auth-first malformed request', async () => {
  let requestedUrl = '';
  await expect(
    observeManagementCompletionRequest({
      target,
      createHeaders: () => new Headers({ authorization: 'Bearer invalid' }),
      method: 'PATCH',
      path: 'applications/owned',
      body: 'malformed-selected-body',
      fetch: async (url) => {
        requestedUrl = String(url);
        return new Response(JSON.stringify({ code: 'unauthorized' }), {
          status: 401,
        });
      },
    })
  ).resolves.toEqual({ status: 401, code: 'unauthorized' });
  expect(requestedUrl).toBe('https://reference.example/api/applications/owned');
});

test('rejects credential-bearing error bodies', async () => {
  await expect(
    observeManagementCompletionRequest({
      target,
      createHeaders: () => new Headers(),
      method: 'GET',
      path: 'applications/foreign',
      fetch: async () =>
        new Response(JSON.stringify({ code: 'entity.not_found', accessToken: 'private' }), {
          status: 404,
        }),
    })
  ).rejects.toThrow('Invalid Common Management control observation');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
