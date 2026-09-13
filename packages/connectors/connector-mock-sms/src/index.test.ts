import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { mockConnectorFilePaths, TemplateType } from '@logto/connector-kit';

import createConnector from './index.js';

const defaultSendHistoryFilePath = `${mockConnectorFilePaths.Sms}.history`;
const testDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'logto-mock-sms-'));
const sendHistoryFilePath = path.join(testDirectory, 'send-history.jsonl');
const getConfig = vi.fn().mockResolvedValue({
  accountSID: 'account-sid-value',
  authToken: 'auth-token-value',
  fromMessagingServiceSID: 'from-messaging-service-sid-value',
  templates: [
    {
      content: 'Your passcode is {{code}}.',
      usageType: TemplateType.SignIn,
    },
  ],
});

describe('mock SMS connector', () => {
  beforeEach(async () => {
    await fs.mkdir('/tmp/logto', { recursive: true });
    await Promise.all([
      fs.writeFile(mockConnectorFilePaths.Sms, ''),
      fs.writeFile(defaultSendHistoryFilePath, ''),
      fs.writeFile(sendHistoryFilePath, ''),
    ]);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  afterAll(async () => {
    await fs.rm(testDirectory, { recursive: true });
  });

  it('keeps only the legacy latest-message behavior when history is not configured', async () => {
    const connector = await createConnector({ getConfig });
    const message = {
      to: '+1234567890',
      type: TemplateType.SignIn,
      payload: { code: '123456' },
    };

    await connector.sendMessage(message);

    await expect(fs.readFile(mockConnectorFilePaths.Sms, 'utf8')).resolves.toBe(
      JSON.stringify({
        phone: message.to,
        code: message.payload.code,
        type: message.type,
        payload: message.payload,
      }) + '\n'
    );
    await expect(fs.readFile(defaultSendHistoryFilePath, 'utf8')).resolves.toBe('');
  });

  it('appends complete JSON records for concurrent sends when history is configured', async () => {
    vi.stubEnv('CONNECTOR_MESSAGE_HISTORY_FILE', sendHistoryFilePath);
    const connector = await createConnector({ getConfig });
    const messages = Array.from({ length: 20 }, (_, index) => ({
      to: `+12345678${String(index).padStart(2, '0')}`,
      type: TemplateType.SignIn,
      payload: { code: String(index).padStart(6, '0') },
    }));

    await Promise.all(messages.map(async (message) => connector.sendMessage(message)));

    const history = await fs.readFile(sendHistoryFilePath, 'utf8');
    const records: unknown[] = history
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    expect(records).toHaveLength(messages.length);
    expect(records).toEqual(
      expect.arrayContaining(
        messages.map(({ to, type, payload }) => ({ phone: to, code: payload.code, type, payload }))
      )
    );
  });
});
