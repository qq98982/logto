/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The control double records exact lifecycle order. */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  createOwnedPasswordCompromiseFixture,
  type OwnedPrivateService,
} from './owned-policy-logout-fixtures.js';

const id = `sha256:${'a'.repeat(64)}`;
const containerId = 'b'.repeat(64);

test('writes only the SHA1 range config, validates one receipt and clears files after stop', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'owned-pwned-'));
  const configFile = path.join(directory, 'config.json');
  const receiptFile = path.join(directory, 'receipt.ndjson');
  await Promise.all([
    writeFile(configFile, '', { mode: 0o600 }),
    writeFile(receiptFile, '', { mode: 0o600 }),
  ]);
  let running = false;
  const order: string[] = [];
  const service: OwnedPrivateService = {
    container: 'candidate-pwned-provider',
    project: 'owned-project',
    service: 'candidate-pwned-provider',
    image: id,
    configFile,
    receiptFile,
    control: {
      run: async (args) => {
        if (args[0] === 'inspect' && args[2] === '{{json .}}') {
          return JSON.stringify({
            Id: containerId,
            Name: '/candidate-pwned-provider',
            Image: id,
            Config: {
              Image: id,
              Labels: {
                'com.docker.compose.project': 'owned-project',
                'com.docker.compose.service': 'candidate-pwned-provider',
              },
            },
            State: { Status: running ? 'running' : 'created', Running: running },
          });
        }
        if (args[0] === 'start') {
          running = true;
          order.push('start');
          return '';
        }
        if (args[0] === 'inspect' && args[2] === '{{json .State}}') {
          return JSON.stringify({
            Status: running ? 'running' : 'exited',
            Running: running,
            Health: { Status: running ? 'healthy' : 'none' },
          });
        }
        if (args[0] === 'stop') {
          running = false;
          order.push('stop');
          return '';
        }
        throw new TypeError('unexpected control command');
      },
    },
  };
  const fixture = createOwnedPasswordCompromiseFixture(
    {
      clear: service,
      compromised: service,
      unavailable: service,
    },
    'candidate'
  );
  try {
    await expect(
      fixture.withAttempt({ password: 'private-password', outcome: 'clear' }, async () => {
        const parsed: unknown = JSON.parse(await readFile(configFile, 'utf8'));
        const config =
          typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
            ? Object.fromEntries(Object.entries(parsed))
            : {};
        expect(Object.keys(config).sort()).toEqual(['prefix', 'responseMode', 'suffix']);
        expect(config.prefix).toMatch(/^[A-F0-9]{5}$/u);
        expect(config.suffix).toMatch(/^[A-F0-9]{35}$/u);
        expect(config.responseMode).toBe('count-zero');
        expect(JSON.stringify(config)).not.toContain('private-password');
        await writeFile(
          receiptFile,
          `${JSON.stringify({
            methodGet: true,
            originMatches: true,
            pathShapeMatches: true,
            prefixMatches: true,
            addPaddingPresent: true,
            userAgentProduct: 'aster',
            status: 200,
          })}\n`
        );
        return 'used';
      })
    ).resolves.toBe('used');
    expect(order).toEqual(['start', 'stop']);
    await expect(readFile(configFile, 'utf8')).resolves.toBe('');
    await expect(readFile(receiptFile, 'utf8')).resolves.toBe('');
    await expect(
      createOwnedPasswordCompromiseFixture(
        { clear: service, compromised: service, unavailable: service },
        'oracle'
      ).withAttempt({ password: 'private-password', outcome: 'unavailable' }, async () => {
        const config = JSON.parse(await readFile(configFile, 'utf8')) as Record<string, unknown>;
        expect(config.responseMode).toBe('transport-reset');
        await writeFile(
          receiptFile,
          `${JSON.stringify({
            methodGet: true,
            originMatches: true,
            pathShapeMatches: true,
            prefixMatches: true,
            addPaddingPresent: false,
            userAgentProduct: 'logto',
            status: 0,
          })}\n`
        );
        return 'denied';
      })
    ).resolves.toBe('denied');
    expect(order).toEqual(['start', 'stop', 'start', 'stop']);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('stops the exact owned service and clears private files when the body fails', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'owned-pwned-failure-'));
  const configFile = path.join(directory, 'config.json');
  const receiptFile = path.join(directory, 'receipt.ndjson');
  await Promise.all([
    writeFile(configFile, '', { mode: 0o600 }),
    writeFile(receiptFile, '', { mode: 0o600 }),
  ]);
  let running = false;
  let stopped = false;
  const service: OwnedPrivateService = {
    container: 'oracle-pwned-provider',
    project: 'owned-project',
    service: 'oracle-pwned-provider',
    image: id,
    configFile,
    receiptFile,
    control: {
      run: async (args) => {
        if (args[0] === 'inspect' && args[2] === '{{json .}}') {
          return JSON.stringify({
            Id: containerId,
            Name: '/oracle-pwned-provider',
            Image: id,
            Config: {
              Image: id,
              Labels: {
                'com.docker.compose.project': 'owned-project',
                'com.docker.compose.service': 'oracle-pwned-provider',
              },
            },
            State: { Status: 'created', Running: false },
          });
        }
        if (args[0] === 'start') {
          running = true;
          return '';
        }
        if (args[0] === 'inspect') {
          return JSON.stringify({
            Status: running ? 'running' : 'exited',
            Running: running,
            Health: { Status: running ? 'healthy' : 'none' },
          });
        }
        if (args[0] === 'stop') {
          running = false;
          stopped = true;
          return '';
        }
        throw new TypeError('unexpected control command');
      },
    },
  };
  try {
    await expect(
      createOwnedPasswordCompromiseFixture(
        {
          clear: service,
          compromised: service,
          unavailable: service,
        },
        'candidate'
      ).withAttempt({ password: 'private-password', outcome: 'compromised' }, async () => {
        throw new TypeError('body failed');
      })
    ).rejects.toThrow('body failed');
    expect(stopped).toBe(true);
    await expect(readFile(configFile, 'utf8')).resolves.toBe('');
    await expect(readFile(receiptFile, 'utf8')).resolves.toBe('');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('compensates a container that starts before its health inspection fails', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'owned-pwned-health-'));
  const configFile = path.join(directory, 'config.json');
  const receiptFile = path.join(directory, 'receipt.ndjson');
  await Promise.all([
    writeFile(configFile, '', { mode: 0o600 }),
    writeFile(receiptFile, '', { mode: 0o600 }),
  ]);
  let running = false;
  let stopped = false;
  const service: OwnedPrivateService = {
    container: 'candidate-pwned-provider',
    project: 'owned-project',
    service: 'candidate-pwned-provider',
    image: id,
    configFile,
    receiptFile,
    control: {
      run: async (args) => {
        if (args[0] === 'inspect' && args[2] === '{{json .}}') {
          return JSON.stringify({
            Id: containerId,
            Name: '/candidate-pwned-provider',
            Image: id,
            Config: {
              Image: id,
              Labels: {
                'com.docker.compose.project': 'owned-project',
                'com.docker.compose.service': 'candidate-pwned-provider',
              },
            },
            State: { Status: 'created', Running: false },
          });
        }
        if (args[0] === 'start') {
          running = true;
          return '';
        }
        if (args[0] === 'stop') {
          running = false;
          stopped = true;
          return '';
        }
        if (args[0] === 'inspect' && stopped) {
          return JSON.stringify({ Status: 'exited', Running: false });
        }
        if (args[0] === 'inspect' && running) {
          throw new TypeError('health inspection failed');
        }
        throw new TypeError('unexpected control command');
      },
    },
  };
  try {
    await expect(
      createOwnedPasswordCompromiseFixture(
        {
          clear: service,
          compromised: service,
          unavailable: service,
        },
        'candidate'
      ).withAttempt({ password: 'private-password', outcome: 'clear' }, async () => 'unused')
    ).rejects.toThrow('health inspection failed');
    expect(stopped).toBe(true);
    await expect(readFile(configFile, 'utf8')).resolves.toBe('');
    await expect(readFile(receiptFile, 'utf8')).resolves.toBe('');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
