import { isDeepStrictEqual } from 'node:util';
import path from 'node:path';

const host = 'dysmsapi.aliyuncs.com';
const trustPath = '/run/aster/fetch-observer-ca.pem';
const root = '/run/aster-sms-provider';
const keys = ['fixtureImage', 'runtimeUid', 'runtimeGid', 'providerScript', 'caFile',
  'certificateFile', 'privateKeyFile', 'oracleConfigurationFile', 'oracleReceiptFile',
  'oracleControlDirectory', 'candidateConfigurationFile', 'candidateReceiptFile',
  'candidateControlDirectory'];
const fail = () => { throw new TypeError('Invalid Phase 2 SMS provider topology'); };
const exactKeys = (value, names) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...names].toSorted().join('\0');
const optionsFor = (value) => {
  if (!exactKeys(value, keys) || !/^sha256:[a-f0-9]{64}$/u.test(value.fixtureImage) ||
      !Number.isSafeInteger(value.runtimeUid) || value.runtimeUid <= 0 ||
      !Number.isSafeInteger(value.runtimeGid) || value.runtimeGid <= 0) return fail();
  const paths = keys.slice(3).map((key) => value[key]);
  if (new Set(paths).size !== paths.length || paths.some((file) =>
    typeof file !== 'string' || !path.isAbsolute(file) || path.normalize(file) !== file ||
    /[: ,\u0000-\u001F\u007F]/u.test(file)) ||
    ['oracle', 'candidate'].some((role) =>
      Buffer.byteLength(`${value[`${role}ControlDirectory`]}/s.sock`) > 100)) return fail();
  return value;
};
const provider = (options, role) => ({
  image: options.fixtureImage,
  entrypoint: ['node'],
  command: [`${root}/provider.mjs`],
  environment: {
    ASTER_SMS_PROVIDER_CERTIFICATE_FILE: `${root}/tls/server.pem`,
    ASTER_SMS_PROVIDER_PRIVATE_KEY_FILE: `${root}/tls/server.key`,
    ASTER_SMS_PROVIDER_CONFIGURATION_FILE: `${root}/private/configuration.json`,
    ASTER_SMS_PROVIDER_RECEIPT_FILE: `${root}/receipts/observations.json`,
    ASTER_SMS_PROVIDER_CONTROL_SOCKET: `${root}/control/s.sock`,
    ASTER_SMS_PROVIDER_HOST: '0.0.0.0',
    ASTER_SMS_PROVIDER_PORT: '443',
  },
  healthcheck: {
    test: ['CMD', 'node', '-e',
      `const{readFileSync}=require('node:fs'),{get}=require('node:https'),r=get({hostname:'127.0.0.1',servername:'${host}',port:443,path:'/healthz',headers:{host:'${host}'},ca:readFileSync('${root}/tls/ca.pem')},x=>process.exit(x.statusCode===204?0:1));r.on('error',()=>process.exit(1));r.setTimeout(2000,()=>{r.destroy();process.exit(1)});`],
    interval: '1s', timeout: '3s', retries: 60,
  },
  networks: {
    [`${role}-primary`]: { ipv4_address: role === 'oracle' ? '172.30.231.54' : '172.30.241.54', aliases: [host] },
  },
  mac_address: role === 'oracle' ? '02:42:ac:1e:e7:36' : '02:42:ac:1e:f1:36',
  volumes: [
    `${options.providerScript}:${root}/provider.mjs:ro`,
    `${options.caFile}:${root}/tls/ca.pem:ro`,
    `${options.certificateFile}:${root}/tls/server.pem:ro`,
    `${options.privateKeyFile}:${root}/tls/server.key:ro`,
    `${options[`${role}ConfigurationFile`]}:${root}/private/configuration.json:ro`,
    `${options[`${role}ReceiptFile`]}:${root}/receipts/observations.json:rw`,
    `${options[`${role}ControlDirectory`]}:${root}/control:rw`,
  ],
  user: `${options.runtimeUid}:${options.runtimeGid}`,
  userns_mode: 'keep-id', pids_limit: 32, mem_limit: '192m', cpus: 0.25,
  cap_drop: ['ALL'], read_only: true, security_opt: ['no-new-privileges:true'],
  sysctls: { 'net.ipv4.ip_unprivileged_port_start': '443' }, restart: 'no',
});
const assertTarget = (document, role, options) => {
  const core = document?.services?.[`${role}-primary-core`];
  const address = role === 'oracle' ? '172.30.231.54' : '172.30.241.54';
  if (!exactKeys(document, ['services', 'networks', 'volumes']) ||
      document.networks?.[`${role}-primary`]?.internal !== true ||
      core?.environment?.[role === 'oracle' ? 'NODE_EXTRA_CA_CERTS' : 'SSL_CERT_FILE'] !== trustPath ||
      core?.volumes?.filter((value) => value === `${options.caFile}:${trustPath}:ro`).length !== 1 ||
      core?.extra_hosts?.filter((value) => value.startsWith(`${host}:`)).length !== 1 ||
      !core.extra_hosts.includes(`${host}:${address}`) ||
      !isDeepStrictEqual(document.services[`${role}-sms-provider`], provider(options, role))) return fail();
};
export const assertSmsProviderTopology = (oracle, candidate, input) => {
  const options = optionsFor(input);
  assertTarget(oracle, 'oracle', options);
  assertTarget(candidate, 'candidate', options);
};
export const bindSmsProviderTopology = (rawOracle, rawCandidate, input) => {
  const options = optionsFor(input);
  const oracle = structuredClone(rawOracle), candidate = structuredClone(rawCandidate);
  for (const [document, role, address] of [[oracle, 'oracle', '172.30.231.54'],
    [candidate, 'candidate', '172.30.241.54']]) {
    if (!exactKeys(document, ['services', 'networks', 'volumes']) ||
        document.services[`${role}-sms-provider`] !== undefined) return fail();
    const core = document.services[`${role}-primary-core`];
    const current = core?.extra_hosts ?? [];
    if (!core || !Array.isArray(current) || current.some((value) =>
      typeof value !== 'string' || value.startsWith(`${host}:`))) return fail();
    core.extra_hosts = [...current, `${host}:${address}`];
    document.services[`${role}-sms-provider`] = provider(options, role);
  }
  assertSmsProviderTopology(oracle, candidate, options);
  return Object.freeze({ oracle, candidate });
};
