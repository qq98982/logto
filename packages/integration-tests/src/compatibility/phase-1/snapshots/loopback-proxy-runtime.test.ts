import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:net';
import path from 'node:path';
import { promisify } from 'node:util';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const runnerPath = path.join(repositoryRoot, '.scripts/compatibility/run-phase1.sh');
const executeFile = promisify(execFile);
const temporaryRoots = new Set<string>();

const sourceSection = (source: string, startToken: string, endToken: string): string => {
  const start = source.indexOf(startToken);
  const end = source.indexOf(endToken, start + startToken.length);

  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
};

const listen = async (server: Server): Promise<number> => {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Expected an IPv4 loopback listener');
  }
  return address.port;
};

const close = async (server: Server): Promise<void> => {
  if (!server.listening) {
    return;
  }
  const closed = once(server, 'close');

  server.close();
  await closed;
};

const reservePort = async (): Promise<number> => {
  const server = createServer();
  const port = await listen(server);

  await close(server);
  return port;
};

const commonHarness = (source: string): string => {
  const portFunctions = sourceSection(
    source,
    'port_is_listening() {',
    '\n\ncapture_build_root_identity'
  );
  const startProxyFunction = sourceSection(
    source,
    'start_loopback_proxy() {',
    '\n\nowned_process_group_exists()'
  );
  const processGroupFunctions = sourceSection(
    source,
    'owned_process_group_exists() {',
    '\ncleanup() {'
  );

  return `PS_BIN=/usr/bin/ps
AWK_BIN=/usr/bin/awk
SS_BIN=/usr/bin/ss
ENV_BIN=/usr/bin/env
SETSID_BIN=/usr/bin/setsid
SOCAT_BIN=/usr/bin/socat
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_TOKENS=()
random_hex() { /usr/bin/printf '%064x' "$$"; }
fail() { exit 97; }
${portFunctions}
${startProxyFunction}
${processGroupFunctions}
`;
};

afterEach(async () => {
  await Promise.all(
    [...temporaryRoots].map(async (root) => rm(root, { recursive: true, force: true }))
  );
  temporaryRoots.clear();
});

describe('Phase 1 loopback proxy runtime', () => {
  it('forwards each binding to its selected sentinel after delayed setsid and cleans up', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const root = await mkdtemp('/var/tmp/henry-build/phase1-proxy-forward-test-');
    temporaryRoots.add(root);
    const scriptPath = path.join(root, 'verify-forwarding.sh');
    const delayedSetsidPath = path.join(root, 'delayed-setsid');
    const alphaServer = createServer((socket) => socket.end('alpha-sentinel\n'));
    const betaServer = createServer((socket) => socket.end('beta-sentinel\n'));
    const alphaTargetPort = await listen(alphaServer);
    const betaTargetPort = await listen(betaServer);
    const alphaHostPort = await reservePort();
    const betaHostPort = await reservePort();

    await writeFile(
      delayedSetsidPath,
      '#!/bin/sh\n/usr/bin/sleep 0.2\nexec /usr/bin/setsid "$@"\n',
      { mode: 0o700 }
    );
    await chmod(delayedSetsidPath, 0o700);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
${commonHarness(source)}
SETSID_BIN=${JSON.stringify(delayedSetsidPath)}
container_network_ipv4() {
  case "$1|$2" in
    alpha-core\\|alpha-network|beta-core\\|beta-network) printf '127.0.0.1' ;;
    *) exit 88 ;;
  esac
}
cleanup() {
  local index
  trap - EXIT
  for ((index=\${#PROXY_PGIDS[@]} - 1; index >= 0; index--)); do
    terminate_owned_process_group \
      "\${PROXY_PIDS[index]}" "\${PROXY_PGIDS[index]}" "\${PROXY_TOKENS[index]}" || true
  done
}
trap cleanup EXIT
start_loopback_proxy alpha-core alpha-network ${alphaHostPort} ${alphaTargetPort}
start_loopback_proxy beta-core beta-network ${betaHostPort} ${betaTargetPort}
read_proxy() {
  local port=$1 expected=$2 actual
  exec 9<>"/dev/tcp/127.0.0.1/\${port}"
  IFS= read -r -t 2 actual <&9
  exec 9>&-
  [[ "\${actual}" == "\${expected}" ]]
}
read_proxy ${alphaHostPort} alpha-sentinel
read_proxy ${betaHostPort} beta-sentinel
for ((index=\${#PROXY_PGIDS[@]} - 1; index >= 0; index--)); do
  terminate_owned_process_group \
    "\${PROXY_PIDS[index]}" "\${PROXY_PGIDS[index]}" "\${PROXY_TOKENS[index]}"
done
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_TOKENS=()
! port_is_listening ${alphaHostPort}
! port_is_listening ${betaHostPort}
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    try {
      await expect(
        executeFile('/bin/bash', [scriptPath], { timeout: 15_000 })
      ).resolves.toMatchObject({ stderr: '' });
    } finally {
      await Promise.all([close(alphaServer), close(betaServer)]);
    }
  });

  it('rejects an occupied port and terminates the still-live failed proxy', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const root = await mkdtemp('/var/tmp/henry-build/phase1-occupied-port-test-');
    temporaryRoots.add(root);
    const scriptPath = path.join(root, 'verify-occupied-port.sh');
    const socatWrapperPath = path.join(root, 'occupied-port-socat');
    const proxyIdentityPath = path.join(root, 'proxy-identity');
    const server = createServer();
    const occupiedPort = await listen(server);

    await writeFile(
      socatWrapperPath,
      `#!/bin/sh
/usr/bin/printf '%s %s\n' "$$" "$(/usr/bin/ps -o pgid= -p $$ | /usr/bin/tr -d '[:space:]')" > ${JSON.stringify(proxyIdentityPath)}
/usr/bin/socat "$@" || true
exec /usr/bin/sleep 300
`,
      { mode: 0o700 }
    );
    await chmod(socatWrapperPath, 0o700);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
${commonHarness(source)}
SOCAT_BIN=${JSON.stringify(socatWrapperPath)}
container_network_ipv4() { printf '127.0.0.1'; }
cleanup() {
  local index
  trap - EXIT
  for ((index=\${#PROXY_PGIDS[@]} - 1; index >= 0; index--)); do
    terminate_owned_process_group \
      "\${PROXY_PIDS[index]}" "\${PROXY_PGIDS[index]}" "\${PROXY_TOKENS[index]}" || true
  done
}
trap cleanup EXIT
start_loopback_proxy ignored ignored ${occupiedPort} 1
exit 41
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    try {
      await expect(
        executeFile('/bin/bash', [scriptPath], { timeout: 30_000 })
      ).rejects.toMatchObject({ code: 97 });
      expect(server.listening).toBe(true);
      const proxyIdentity = await readFile(proxyIdentityPath, 'utf8');
      const [proxyPid, proxyPgid] = proxyIdentity.trim().split(' ');

      await expect(executeFile('/bin/kill', ['-0', proxyPid ?? ''])).rejects.toMatchObject({
        code: 1,
      });
      await expect(
        executeFile('/bin/kill', ['-0', '--', `-${proxyPgid ?? ''}`])
      ).rejects.toMatchObject({ code: 1 });
    } finally {
      await close(server);
    }
  });

  it('does not signal a reused process group with a different ownership token', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const root = await mkdtemp('/var/tmp/henry-build/phase1-reused-group-test-');
    temporaryRoots.add(root);
    const scriptPath = path.join(root, 'verify-reused-group.sh');
    const processGroupFunctions = sourceSection(
      source,
      'owned_process_group_exists() {',
      '\ncleanup() {'
    );
    const staleToken = 'a'.repeat(64);
    const currentToken = 'b'.repeat(64);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
PS_BIN=/usr/bin/ps
AWK_BIN=/usr/bin/awk
${processGroupFunctions}
/usr/bin/setsid /usr/bin/env -i PATH=/usr/bin:/bin ASTER_PHASE1_PROCESS_TOKEN=${currentToken} /usr/bin/sleep 300 &
pid=$!
pgid="\${pid}"
for ((attempt=0; attempt<100; attempt++)); do
  observed="$(/usr/bin/ps -o pgid= -p "\${pid}" | /usr/bin/tr -d '[:space:]')"
  [[ "\${observed}" == "\${pgid}" ]] && break
  /usr/bin/sleep 0.01
done
if terminate_owned_process_group "\${pid}" "\${pgid}" ${staleToken}; then
  exit 31
fi
kill -0 "\${pid}"
terminate_owned_process_group "\${pid}" "\${pgid}" ${currentToken}
! kill -0 "\${pid}" 2>/dev/null
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    await expect(
      executeFile('/bin/bash', [scriptPath], { timeout: 10_000 })
    ).resolves.toMatchObject({ stderr: '' });
  });

  it('fails closed when process-group inspection is unavailable', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const root = await mkdtemp('/var/tmp/henry-build/phase1-ps-failure-test-');
    temporaryRoots.add(root);
    const scriptPath = path.join(root, 'verify-ps-failure.sh');
    const processGroupFunctions = sourceSection(
      source,
      'owned_process_group_exists() {',
      '\ncleanup() {'
    );
    const ownershipToken = 'e'.repeat(64);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
PS_BIN=/usr/bin/ps
AWK_BIN=/usr/bin/awk
${processGroupFunctions}
cleanup_group() {
  kill -KILL -- "-\${pgid}" 2>/dev/null || true
  wait "\${pid}" 2>/dev/null || true
}
/usr/bin/setsid /usr/bin/env -i PATH=/usr/bin:/bin ASTER_PHASE1_PROCESS_TOKEN=${ownershipToken} /usr/bin/sleep 300 &
pid=$!
pgid="\${pid}"
trap cleanup_group EXIT
for ((attempt=0; attempt<100; attempt++)); do
  observed="$(/usr/bin/ps -o pgid= -p "\${pid}" | /usr/bin/tr -d '[:space:]')"
  [[ "\${observed}" == "\${pgid}" ]] && break
  /usr/bin/sleep 0.01
done
PS_BIN=/bin/false
group_status=0
process_group_has_live_members "\${pgid}" || group_status=$?
[[ "\${group_status}" == 2 ]]
if terminate_owned_process_group "\${pid}" "\${pgid}" ${ownershipToken}; then
  exit 31
fi
kill -0 "\${pid}"
cleanup_group
trap - EXIT
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    await expect(
      executeFile('/bin/bash', [scriptPath], { timeout: 10_000 })
    ).resolves.toMatchObject({ stderr: '' });
  });

  it('cleans a trusted session when a child deliberately clears the ownership token', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const root = await mkdtemp('/var/tmp/henry-build/phase1-mixed-group-test-');
    temporaryRoots.add(root);
    const scriptPath = path.join(root, 'verify-mixed-group.sh');
    const identityPath = path.join(root, 'mixed-group-identity');
    const ignoreTermPath = path.join(root, 'ignore-term');
    const processGroupFunctions = sourceSection(
      source,
      'owned_process_group_exists() {',
      '\ncleanup() {'
    );
    const leaderToken = 'c'.repeat(64);
    const foreignToken = 'd'.repeat(64);

    await writeFile(ignoreTermPath, "#!/bin/sh\ntrap '' TERM\nexec /usr/bin/sleep 300\n", {
      mode: 0o700,
    });
    await chmod(ignoreTermPath, 0o700);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
PS_BIN=/usr/bin/ps
AWK_BIN=/usr/bin/awk
${processGroupFunctions}
cleanup_group() {
  kill -KILL -- "-\${pgid}" 2>/dev/null || true
  wait "\${launcher}" 2>/dev/null || true
}
/usr/bin/setsid /usr/bin/env -i PATH=/usr/bin:/bin ASTER_PHASE1_PROCESS_TOKEN=${leaderToken} /bin/sh -c '
  /usr/bin/env -i PATH=/usr/bin:/bin ASTER_PHASE1_PROCESS_TOKEN=${foreignToken} ${JSON.stringify(ignoreTermPath)} &
  child=$!
  /usr/bin/printf "%s %s %s\\n" "$$" "$(/usr/bin/ps -o pgid= -p $$ | /usr/bin/tr -d "[:space:]")" "$child" > ${JSON.stringify(identityPath)}
  exec /usr/bin/sleep 300
' &
launcher=$!
for ((attempt=0; attempt<200; attempt++)); do
  [[ -s ${JSON.stringify(identityPath)} ]] && break
  /usr/bin/sleep 0.01
done
read -r leader pgid foreign < ${JSON.stringify(identityPath)}
trap cleanup_group EXIT
kill -0 "\${leader}"
kill -0 "\${foreign}"
terminate_owned_process_group "\${leader}" "\${pgid}" ${leaderToken}
! process_group_has_live_members "\${pgid}"
trap - EXIT
`;
    await writeFile(scriptPath, harness, { mode: 0o700 });
    await chmod(scriptPath, 0o700);

    await expect(
      executeFile('/bin/bash', [scriptPath], { timeout: 10_000 })
    ).resolves.toMatchObject({ stderr: '' });
  });
});
