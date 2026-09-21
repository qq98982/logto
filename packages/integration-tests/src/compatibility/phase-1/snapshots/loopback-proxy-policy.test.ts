import { readFile } from 'node:fs/promises';
import path from 'node:path';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const composePath = path.join(repositoryRoot, 'docker-compose.phase1-compatibility.yml');
const runnerPath = path.join(repositoryRoot, '.scripts/compatibility/run-phase1.sh');

const isolatedNetworks =
  'oracle-primary oracle-foreign candidate-primary candidate-foreign oracle-phase0 candidate-phase0 candidate-connector-boundary candidate-saml-boundary candidate-script-boundary'.split(
    ' '
  );
const loopbackProxyBindings = [
  'oracle-primary-core|oracle-primary|3311|3001',
  'oracle-primary-core|oracle-primary|3411|3411',
  'oracle-foreign-core|oracle-foreign|3312|3001',
  'oracle-foreign-core|oracle-foreign|3412|3002',
  'candidate-primary-core|candidate-primary|3321|3001',
  'candidate-primary-core|candidate-primary|3421|3421',
  'candidate-foreign-core|candidate-foreign|3322|3001',
  'candidate-foreign-core|candidate-foreign|3422|3002',
  'oracle-phase0-core|oracle-phase0|3331|3001',
  'oracle-phase0-core|oracle-phase0|3431|3431',
  'candidate-phase0-core|candidate-phase0|3341|3001',
  'candidate-phase0-core|candidate-phase0|3441|3441',
] as const;

type ComposeDocument = {
  networks: Record<string, unknown>;
};

const shellVariable = (name: string) => ['$', `{${name}}`].join('');

const sourceSection = (source: string, startToken: string, endToken: string): string => {
  const start = source.indexOf(startToken);
  const end = source.indexOf(endToken, start + startToken.length);

  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
};

const expectedProxyCleanup = (): string => {
  const proxyCount = shellVariable('#PROXY_PGIDS[@]');
  const proxyPidAtIndex = shellVariable('PROXY_PIDS[index]');
  const proxyPgidAtIndex = shellVariable('PROXY_PGIDS[index]');
  const proxyTokenAtIndex = shellVariable('PROXY_TOKENS[index]');

  return [
    `  for ((index=${proxyCount} - 1; index >= 0; index--)); do`,
    '    terminate_owned_process_group \\',
    `      "${proxyPidAtIndex}" "${proxyPgidAtIndex}" "${proxyTokenAtIndex}" || cleanup_failed=1`,
    '  done',
    '  PROXY_PIDS=()',
    '  PROXY_PGIDS=()',
    '  PROXY_TOKENS=()',
  ].join('\n');
};

const assertInternalNetworkPolicy = (document: ComposeDocument): void => {
  expect(Object.keys(document.networks)).toEqual(isolatedNetworks);
  for (const network of isolatedNetworks) {
    expect(document.networks[network]).toEqual({ internal: true });
  }
};

const sourceProxyBindings = (source: string): readonly string[] => {
  const declaration = 'readonly LOOPBACK_PROXY_BINDINGS=(';
  const declarationBody = sourceSection(source, declaration, '\n)').slice(declaration.length);
  return Object.freeze(
    declarationBody
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const match = /^ {2}'([^']+)'$/u.exec(line);

        expect(match).not.toBeNull();
        return match?.[1] ?? '';
      })
  );
};

const assertLoopbackProxyRunnerPolicy = (source: string): void => {
  const actualBindings = sourceProxyBindings(source);

  expect(actualBindings).toEqual(loopbackProxyBindings);

  const proxyPid = shellVariable('proxy_pid');
  const proxyPgid = shellVariable('proxy_pgid');
  const hostPort = shellVariable('host_port');
  const service = shellVariable('service');
  const network = shellVariable('network');
  const targetIp = shellVariable('target_ip');
  const containerPort = shellVariable('container_port');
  const ownershipToken = shellVariable('ownership_token');
  const observedPgid = shellVariable('observed_pgid');
  const psBin = shellVariable('PS_BIN');
  const containerId = shellVariable('container_id');
  const projectName = shellVariable('project_name');
  const networkName = shellVariable('network_name');
  const networkLookupFunction = sourceSection(
    source,
    'container_network_ipv4() {',
    '\n}\n\nstart_loopback_proxy()'
  );
  const networkLookup = [
    `  container_id="$(compose ps -q "${service}" 2>/dev/null || true)"`,
    `  [[ "${containerId}" =~ ^[0-9a-f]{12,64}$ ]] || fail`,
    `  network_name="${projectName}_${network}"`,
    '  result="$(docker_cli inspect --format \\',
    `    "{{with index .NetworkSettings.Networks \\"${networkName}\\"}}{{.IPAddress}}{{end}}" \\`,
    `    "${containerId}" 2>/dev/null || true)"`,
  ].join('\n');
  const startFunction = sourceSection(
    source,
    'start_loopback_proxy() {',
    '\n}\n\nowned_process_group_exists()'
  );
  const registration = [
    '  proxy_pid=$!',
    `  proxy_pgid="${proxyPid}"`,
    `  PROXY_PIDS+=("${proxyPid}")`,
    `  PROXY_PGIDS+=("${proxyPgid}")`,
    `  PROXY_TOKENS+=("${ownershipToken}")`,
  ].join('\n');
  const observation = startFunction.indexOf('observed_pgid=');
  const failedProxyTermination = `terminate_owned_process_group "${proxyPid}" "${proxyPgid}" "${ownershipToken}"`;
  const socatLaunch = [
    `  target_ip="$(container_network_ipv4 "${service}" "${network}")"`,
    '  ownership_token="$(random_hex 32)"',
    `  ASTER_PHASE1_PROCESS_TOKEN="${ownershipToken}" \\`,
    `    "${shellVariable('ENV_BIN')}" -i PATH='/usr/bin:/bin' "ASTER_PHASE1_PROCESS_TOKEN=${ownershipToken}" \\`,
    `    "${shellVariable('SETSID_BIN')}" "${shellVariable('SOCAT_BIN')}" \\`,
    `    "TCP4-LISTEN:${hostPort},bind=127.0.0.1,reuseaddr,fork" \\`,
    `    "TCP4:${targetIp}:${containerPort}" </dev/null >/dev/null 2>&1 &`,
  ].join('\n');
  const readinessLoop = [
    '  for ((attempt=0; attempt<100; attempt++)); do',
    `    kill -0 "${proxyPid}" 2>/dev/null || break`,
    `    observed_pgid="$("${psBin}" -o pgid= -p "${proxyPid}" 2>/dev/null | /usr/bin/tr -d '[:space:]')"`,
    `    if [[ "${observedPgid}" == "${proxyPgid}" ]] && \\`,
    `      process_has_ownership_token "${proxyPid}" "${ownershipToken}" && \\`,
    `      port_is_listened_by_pid "${hostPort}" "${proxyPid}"; then`,
    '      return 0',
    '    fi',
    '    /usr/bin/sleep 0.05',
    '  done',
  ].join('\n');

  expect(source).toContain('SOCAT_BIN="$(trusted_system_binary /usr/bin/socat)"');
  expect(networkLookupFunction).toContain(networkLookup);
  expect(startFunction).toContain(socatLaunch);
  expect(startFunction).toContain(readinessLoop);
  expect(startFunction.match(/TCP4-LISTEN:/gu)).toHaveLength(1);
  expect(startFunction.match(/TCP4:\$\{target_ip\}:\$\{container_port\}/gu)).toHaveLength(1);
  expect(startFunction).toContain(registration);
  expect(observation).toBeGreaterThan(startFunction.indexOf(registration));
  expect(startFunction).toContain(`port_is_listened_by_pid "${hostPort}" "${proxyPid}"`);
  expect(startFunction).not.toContain(`port_is_listening "${hostPort}"`);
  expect(startFunction.indexOf(failedProxyTermination)).toBe(
    startFunction.lastIndexOf(failedProxyTermination)
  );
  expect(startFunction.indexOf(failedProxyTermination)).toBeGreaterThan(observation);
  expect(source).toContain('process_has_ownership_token() {');
  expect(source).toContain('process_group_has_trusted_leader() {');
  expect(source).toContain('process_group_is_owned() {');
  expect(source).toContain(
    `process_group_is_owned "${shellVariable('pgid')}" "${shellVariable('token')}" || return 1`
  );
  expect(source).toContain(`process_group_is_same_session "${shellVariable('pgid')}" || return 1`);

  const dockerBin = shellVariable('DOCKER_BIN');
  const envBin = shellVariable('ENV_BIN');
  const privateHome = shellVariable('PRIVATE_HOME');
  const dockerAuthorityLines = source.split('\n').filter((line) => /\bDOCKER_BIN\b/u.test(line));

  expect(dockerAuthorityLines).toEqual([
    'DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)"',
    'readonly DOCKER_BIN',
    `  "${envBin}" -i PATH='/usr/bin:/bin' HOME="${privateHome}" "${dockerBin}" "$@"`,
  ]);

  const bindingArray = shellVariable('LOOPBACK_PROXY_BINDINGS[@]');
  const binding = shellVariable('binding');
  const proxyService = shellVariable('proxy_service');
  const proxyNetwork = shellVariable('proxy_network');
  const proxyHostPort = shellVariable('proxy_host_port');
  const proxyContainerPort = shellVariable('proxy_container_port');
  const loopStart = `for binding in "${bindingArray}"; do`;
  const bindingLoop = sourceSection(source, loopStart, '\ndone');

  expect(bindingLoop).toBe(
    [
      loopStart,
      `  IFS='|' read -r proxy_service proxy_network proxy_host_port proxy_container_port <<<"${binding}"`,
      '  start_loopback_proxy \\',
      `    "${proxyService}" "${proxyNetwork}" "${proxyHostPort}" "${proxyContainerPort}"`,
    ].join('\n')
  );

  const cleanupFunction = sourceSection(source, 'cleanup() {', '\n}\ntrap cleanup EXIT');
  const proxyCleanup = expectedProxyCleanup();
  const projectStarted = shellVariable('project_started');

  expect(cleanupFunction.indexOf(proxyCleanup)).toBeGreaterThan(0);
  expect(cleanupFunction.indexOf(proxyCleanup)).toBeLessThan(
    cleanupFunction.indexOf(`if [[ "${projectStarted}" == 1 ]]`)
  );
};

describe('Phase 1 loopback proxy policy', () => {
  it('pins exact internal networks, proxy bindings, ownership, and reverse cleanup', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const document = JSON.parse(await readFile(composePath, 'utf8')) as ComposeDocument;

    assertInternalNetworkPolicy(document);
    assertLoopbackProxyRunnerPolicy(source);
  });

  it('rejects mutations that weaken isolation, mapping, ownership, or cleanup', async () => {
    const source = await readFile(runnerPath, 'utf8');
    const proxyPid = shellVariable('proxy_pid');
    const proxyPgid = shellVariable('proxy_pgid');
    const ownershipToken = shellVariable('ownership_token');
    const registration = [
      `  PROXY_PIDS+=("${proxyPid}")`,
      `  PROXY_PGIDS+=("${proxyPgid}")`,
      `  PROXY_TOKENS+=("${ownershipToken}")`,
    ].join('\n');
    const withoutRegistration = source.replace(`${registration}\n`, '');

    expect(withoutRegistration).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withoutRegistration);
    }).toThrow();

    const proxyService = shellVariable('proxy_service');
    const proxyNetwork = shellVariable('proxy_network');
    const proxyHostPort = shellVariable('proxy_host_port');
    const proxyContainerPort = shellVariable('proxy_container_port');
    const orderedArguments = `    "${proxyService}" "${proxyNetwork}" "${proxyHostPort}" "${proxyContainerPort}"`;
    const swappedArguments = `    "${proxyNetwork}" "${proxyService}" "${proxyContainerPort}" "${proxyHostPort}"`;
    const withSwappedArguments = source.replace(orderedArguments, swappedArguments);

    expect(withSwappedArguments).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withSwappedArguments);
    }).toThrow();

    const declarationStart = source.indexOf('readonly LOOPBACK_PROXY_BINDINGS=(');
    const declarationEnd = source.indexOf('\n)', declarationStart);
    const withBogusBinding = [
      source.slice(0, declarationEnd),
      "\n  'oracle-primary-core|oracle-primary|6553|3001'",
      source.slice(declarationEnd),
    ].join('');

    expect(() => {
      assertLoopbackProxyRunnerPolicy(withBogusBinding);
    }).toThrow();

    const hostPort = shellVariable('host_port');
    const ownershipCheck = `port_is_listened_by_pid "${hostPort}" "${proxyPid}"`;
    const withoutSocketOwnership = source.replace(
      ownershipCheck,
      `port_is_listening "${hostPort}"`
    );

    expect(withoutSocketOwnership).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withoutSocketOwnership);
    }).toThrow();

    const service = shellVariable('service');
    const network = shellVariable('network');
    const targetLookup = `target_ip="$(container_network_ipv4 "${service}" "${network}")"`;
    const withSwappedTargetLookup = source.replace(
      targetLookup,
      `target_ip="$(container_network_ipv4 "${network}" "${service}")"`
    );

    expect(withSwappedTargetLookup).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withSwappedTargetLookup);
    }).toThrow();

    const composeServiceLookup = `compose ps -q "${service}"`;
    const withHardcodedComposeService = source.replace(
      composeServiceLookup,
      'compose ps -q "oracle-primary-core"'
    );

    expect(withHardcodedComposeService).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withHardcodedComposeService);
    }).toThrow();

    const projectNetwork = `network_name="${shellVariable('project_name')}_${network}"`;
    const withHardcodedNetwork = source.replace(
      projectNetwork,
      `network_name="${shellVariable('project_name')}_oracle-primary"`
    );

    expect(withHardcodedNetwork).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withHardcodedNetwork);
    }).toThrow();

    const inspectedContainer = `    "${shellVariable('container_id')}" 2>/dev/null || true)"`;
    const withWrongInspectedContainer = source.replace(
      inspectedContainer,
      '    "hardcoded-container" 2>/dev/null || true)"'
    );

    expect(withWrongInspectedContainer).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withWrongInspectedContainer);
    }).toThrow();

    const targetIp = shellVariable('target_ip');
    const containerPort = shellVariable('container_port');
    const targetAddress = `"TCP4:${targetIp}:${containerPort}"`;
    const withWrongTarget = source.replace(targetAddress, `"TCP4:127.0.0.1:${proxyHostPort}"`);

    expect(withWrongTarget).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withWrongTarget);
    }).toThrow();

    const trustedSocat = 'SOCAT_BIN="$(trusted_system_binary /usr/bin/socat)"';
    const withUntrustedSocat = source.replace(trustedSocat, "SOCAT_BIN='/usr/bin/socat'");

    expect(withUntrustedSocat).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withUntrustedSocat);
    }).toThrow();

    const listenerAddress = `"TCP4-LISTEN:${hostPort},bind=127.0.0.1,reuseaddr,fork"`;
    const withWildcardListener = source.replace(
      listenerAddress,
      `${listenerAddress}\n    "TCP4-LISTEN:${hostPort},reuseaddr,fork"`
    );

    expect(withWildcardListener).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withWildcardListener);
    }).toThrow();

    const withoutPgidPolling = source.replace(
      'for ((attempt=0; attempt<100; attempt++)); do',
      'if true; then'
    );

    expect(withoutPgidPolling).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withoutPgidPolling);
    }).toThrow();

    const readinessTokenCheck = `process_has_ownership_token "${proxyPid}" "${ownershipToken}" && \\`;
    const withoutReadinessToken = source.replace(readinessTokenCheck, 'true && \\');

    expect(withoutReadinessToken).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withoutReadinessToken);
    }).toThrow();

    const dockerInspect = 'result="$(docker_cli inspect --format \\';
    const withAmbientDockerInspect = source.replace(
      dockerInspect,
      `result="$("${shellVariable('DOCKER_BIN')}" inspect --format \\`
    );

    expect(withAmbientDockerInspect).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(withAmbientDockerInspect);
    }).toThrow();

    const proxyCleanup = expectedProxyCleanup();
    const withoutProxyCleanup = source.replace(`${proxyCleanup}\n\n`, '');
    const composeEnvironmentRemoval = `  rm -f -- "${shellVariable('COMPOSE_ENV')}"`;
    const cleanupMovedAfterContainers = withoutProxyCleanup.replace(
      composeEnvironmentRemoval,
      `${proxyCleanup}\n\n${composeEnvironmentRemoval}`
    );

    expect(cleanupMovedAfterContainers).not.toBe(source);
    expect(() => {
      assertLoopbackProxyRunnerPolicy(cleanupMovedAfterContainers);
    }).toThrow();

    const document = JSON.parse(await readFile(composePath, 'utf8')) as ComposeDocument;
    const withPublicBoundary = {
      ...document,
      networks: {
        ...document.networks,
        'candidate-script-boundary': { internal: false },
      },
    };

    expect(() => {
      assertInternalNetworkPolicy(withPublicBoundary);
    }).toThrow();
  });
});
