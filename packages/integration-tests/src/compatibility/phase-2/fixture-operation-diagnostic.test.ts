import {
  getPhase2FixtureFailureOperation,
  phase2FixtureFailureOperationPattern,
  withPhase2FixtureOperationDiagnostic,
} from './fixture-operation-diagnostic.js';

test('retains the first closed operation without reading or replacing hostile errors', async () => {
  // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- A hostile getter proves the diagnostic never inspects the rejection.
  const hostile = Object.defineProperty({}, 'message', {
    get: () => {
      throw new Error('read');
    },
  });
  const final = new TypeError('fixed final');
  const thrown = await withPhase2FixtureOperationDiagnostic(async (diagnostic) => {
    await diagnostic
      .run('collision-create-original-owner', async () => {
        // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Object identity proves the exact hostile rejection is rethrown.
        throw hostile;
      })
      .catch((error: unknown) => {
        expect(error).toBe(hostile);
      });
    await diagnostic
      .run('connector-delete', async () => {
        throw new Error('private');
      })
      .catch(() => {
        // The first recorded operation must survive this later rejection.
      });
    throw final;
  }).catch((error: unknown) => error);
  expect(thrown).toBe(final);
  expect(getPhase2FixtureFailureOperation(thrown)).toBe('collision-create-original-owner');
  expect(phase2FixtureFailureOperationPattern.test('collision-create-original-owner')).toBe(true);
  expect(phase2FixtureFailureOperationPattern.test('collision-create-original-owner/private')).toBe(
    false
  );
});

test('isolates simultaneous invocation slots and leaves successful calls untagged', async () => {
  const invoke = async (operation: 'collision-helper' | 'connector-provider-stop') => {
    try {
      return await withPhase2FixtureOperationDiagnostic(async (diagnostic) => {
        diagnostic.record(operation);
        const error = new TypeError('fixed');
        throw error;
      });
    } catch (error: unknown) {
      return error;
    }
  };
  const [first, second] = await Promise.all([
    invoke('collision-helper'),
    invoke('connector-provider-stop'),
  ]);
  expect(getPhase2FixtureFailureOperation(first)).toBe('collision-helper');
  expect(getPhase2FixtureFailureOperation(second)).toBe('connector-provider-stop');
  await expect(withPhase2FixtureOperationDiagnostic(async () => 'ok')).resolves.toBe('ok');
});
