import { observeCommonGoogleExistingOwnerControls } from './common-google-existing-owner-controls.js';

const fact = (status: unknown, error: unknown, successShape = false, ownerPreserved = true) => ({
  status,
  error,
  successShape,
  ownerPreserved,
});

test('observes wrong-state and callback replay without retaining private proof material', async () => {
  const result = await observeCommonGoogleExistingOwnerControls({
    runWrongStatePublicChain: async () => fact(400, 'state-mismatch'),
    runProviderCallbackReplayPublicChain: async () => ({
      first: fact(200, 'none', true),
      second: fact(404, 'entity-not-found'),
    }),
  });
  expect(result).toEqual({
    wrongState: {
      callbackAccepted: false,
      status: 400,
      error: 'state-mismatch',
      ownerPreserved: true,
    },
    replay: {
      firstStatus: 200,
      firstOutcome: 'verified',
      secondStatus: 404,
      secondError: 'entity-not-found',
      ownerPreserved: true,
    },
  });
  expect(JSON.stringify(result)).not.toMatch(/private-state|private-code|subject|token|cookie/u);
});

test('keeps unobserved outcomes closed as unknown without claiming rejection', async () => {
  const result = await observeCommonGoogleExistingOwnerControls({
    runWrongStatePublicChain: async () => fact('not-a-status', 'private-state-error'),
    runProviderCallbackReplayPublicChain: async () => ({
      first: fact(200, 'none', true),
      second: fact(503, 'private-provider-error'),
    }),
  });
  expect(result.wrongState).toMatchObject({
    callbackAccepted: 'unknown',
    status: 'unavailable',
    error: 'unknown',
  });
  expect(result.replay).toMatchObject({ secondStatus: 503, secondError: 'unknown' });
});

test.each([
  ['changed owner', fact(400, 'state-mismatch', false, false)],
  [
    'first callback failure',
    { first: fact(400, 'invalid-input'), second: fact(404, 'entity-not-found') },
  ],
  ['empty first 200', { first: fact(200, 'none'), second: fact(404, 'entity-not-found') }],
  ['hostile observation', new Proxy(fact(400, 'state-mismatch'), {})],
] as const)('fails closed for %s', async (name, invalid) => {
  await expect(
    observeCommonGoogleExistingOwnerControls({
      runWrongStatePublicChain: async () =>
        name === 'first callback failure' ? fact(400, 'state-mismatch') : invalid,
      runProviderCallbackReplayPublicChain: async () =>
        name === 'first callback failure'
          ? (invalid as { first: unknown; second: unknown })
          : { first: fact(200, 'none', true), second: fact(404, 'entity-not-found') },
    })
  ).rejects.toThrow('Invalid Common Google existing-owner controls');
});
