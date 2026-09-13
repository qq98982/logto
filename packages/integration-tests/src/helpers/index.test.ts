import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const testDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'logto-sms-history-'));
const historyFilePath = path.join(testDirectory, 'send-history.jsonl');
const originalHistoryFilePath = process.env.CONNECTOR_MESSAGE_HISTORY_FILE;
process.env.CONNECTOR_MESSAGE_HISTORY_FILE = historyFilePath;
const { readSmsConnectorSendCount } = await import('./index.js');

describe('readSmsConnectorSendCount', () => {
  afterAll(async () => {
    if (originalHistoryFilePath) {
      process.env.CONNECTOR_MESSAGE_HISTORY_FILE = originalHistoryFilePath;
    } else {
      // eslint-disable-next-line @silverhand/fp/no-delete -- Restore an originally absent variable.
      delete process.env.CONNECTOR_MESSAGE_HISTORY_FILE;
    }
    await fs.rm(testDirectory, { recursive: true });
  });

  it('counts every complete non-empty JSONL record', async () => {
    await fs.writeFile(historyFilePath, '\n{"send":1}\n  \n{"send":2}\n');

    await expect(readSmsConnectorSendCount()).resolves.toBe(2);
  });

  it('rejects a truncated JSONL record instead of counting it', async () => {
    await fs.writeFile(historyFilePath, '{"send":1}\n{"send":');

    await expect(readSmsConnectorSendCount()).rejects.toBeInstanceOf(SyntaxError);
  });
});
