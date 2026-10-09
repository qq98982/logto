import { isDeepStrictEqual } from 'node:util';
import path from 'node:path';

const failure = 'Invalid Phase 2 Google provider topology';
const imagePattern = /^sha256:[0-9a-f]{64}$/u;
const pathPattern = /^\/(?!.*(?:\/\.{1,2}(?:\/|$)))[^\u0000-\u001F\u007F]{1,4095}$/u;
const caContainerPath = '/run/aster/fetch-observer-ca.pem';
const scriptContainerPath = '/opt/aster-fixture/phase2-google-provider.mjs';
const providerCaPath = '/run/aster-google-provider/tls/ca.pem';
const providerCertificatePath = '/run/aster-google-provider/tls/server.pem';
const providerKeyPath = '/run/aster-google-provider/tls/server.key';
const providerConfigurationPath = '/run/aster-google-provider/private/configuration.json';
const providerReceiptPath = '/run/aster-google-provider/receipts/observations.json';
const tokenHost = 'oauth2.googleapis.com';
const userinfoHost = 'openidconnect.googleapis.com';

const fail = () => {
  throw new TypeError(failure);
};

const exactKeys = (value, keys) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');

const safePath = (value) =>
  typeof value === 'string' &&
  pathPattern.test(value) &&
  path.normalize(value) === value &&
  !/[:,]/u.test(value)
    ? value
    : fail();

const validateOptions = (options) => {
  if (
    !exactKeys(options, [
      'fixtureImage',
      'runtimeUid',
      'runtimeGid',
      'providerScript',
      'caFile',
      'certificateFile',
      'privateKeyFile',
      'oracleConfigurationFile',
      'oracleReceiptFile',
      'candidateConfigurationFile',
      'candidateReceiptFile',
    ]) ||
    !imagePattern.test(options.fixtureImage) ||
    !Number.isInteger(options.runtimeUid) ||
    options.runtimeUid <= 0 ||
    !Number.isInteger(options.runtimeGid) ||
    options.runtimeGid <= 0
  ) {
    return fail();
  }
  const paths = Object.fromEntries(
    [
      'providerScript',
      'caFile',
      'certificateFile',
      'privateKeyFile',
      'oracleConfigurationFile',
      'oracleReceiptFile',
      'candidateConfigurationFile',
      'candidateReceiptFile',
    ].map((key) => [key, safePath(options[key])])
  );
  if (
    paths.oracleConfigurationFile === paths.candidateConfigurationFile ||
    paths.oracleReceiptFile === paths.candidateReceiptFile ||
    new Set(Object.values(paths)).size !== Object.values(paths).length
  ) {
    return fail();
  }
  return Object.freeze({ ...options, ...paths });
};

const healthProgram =
  "const{readFileSync}=require('node:fs'),{get}=require('node:https'),r=get({hostname:'127.0.0.1',servername:'oauth2.googleapis.com',port:443,path:'/healthz',headers:{host:'oauth2.googleapis.com'},ca:readFileSync('/run/aster-google-provider/tls/ca.pem')},x=>process.exit(x.statusCode===204?0:1));r.on('error',()=>process.exit(1));r.setTimeout(2000,()=>{r.destroy();process.exit(1)});";

const expectedService = (options, role) => {
  const oracle = role === 'oracle';
  const configurationFile = oracle
    ? options.oracleConfigurationFile
    : options.candidateConfigurationFile;
  const receiptFile = oracle ? options.oracleReceiptFile : options.candidateReceiptFile;
  const network = oracle ? 'oracle-primary' : 'candidate-primary';
  const address = oracle ? '172.30.231.52' : '172.30.241.52';
  const macAddress = oracle ? '02:42:ac:1e:e7:34' : '02:42:ac:1e:f1:34';
  return {
    image: options.fixtureImage,
    entrypoint: ['node'],
    command: [scriptContainerPath],
    environment: {
      ASTER_GOOGLE_PROVIDER_CERTIFICATE_FILE: providerCertificatePath,
      ASTER_GOOGLE_PROVIDER_PRIVATE_KEY_FILE: providerKeyPath,
      ASTER_GOOGLE_PROVIDER_CONFIGURATION_FILE: providerConfigurationPath,
      ASTER_GOOGLE_PROVIDER_RECEIPT_FILE: providerReceiptPath,
      ASTER_GOOGLE_PROVIDER_HOST: '0.0.0.0',
      ASTER_GOOGLE_PROVIDER_PORT: '443',
    },
    healthcheck: {
      test: ['CMD', 'node', '-e', healthProgram],
      interval: '1s',
      timeout: '3s',
      retries: 60,
    },
    networks: {
      [network]: {
        ipv4_address: address,
        aliases: [tokenHost, userinfoHost],
      },
    },
    mac_address: macAddress,
    volumes: [
      `${options.providerScript}:${scriptContainerPath}:ro`,
      `${options.caFile}:${providerCaPath}:ro`,
      `${options.certificateFile}:${providerCertificatePath}:ro`,
      `${options.privateKeyFile}:${providerKeyPath}:ro`,
      `${configurationFile}:${providerConfigurationPath}:ro`,
      `${receiptFile}:${providerReceiptPath}:rw`,
    ],
    user: `${options.runtimeUid}:${options.runtimeGid}`,
    userns_mode: 'keep-id',
    pids_limit: 32,
    mem_limit: '192m',
    cpus: 0.25,
    cap_drop: ['ALL'],
    read_only: true,
    security_opt: ['no-new-privileges:true'],
    sysctls: { 'net.ipv4.ip_unprivileged_port_start': '443' },
    restart: 'no',
  };
};

export const assertGoogleProviderTopology = (oracle, candidate, rawOptions) => {
  const options = validateOptions(rawOptions);
  if (
    !exactKeys(oracle, ['services', 'networks', 'volumes']) ||
    !exactKeys(candidate, ['services', 'networks', 'volumes']) ||
    oracle.networks?.['oracle-primary']?.internal !== true ||
    candidate.networks?.['candidate-primary']?.internal !== true ||
    oracle.services?.['oracle-primary-core']?.environment?.NODE_EXTRA_CA_CERTS !==
      caContainerPath ||
    candidate.services?.['candidate-primary-core']?.environment?.SSL_CERT_FILE !==
      caContainerPath ||
    oracle.services?.['oracle-primary-core']?.volumes?.filter(
      (value) => value === `${options.caFile}:${caContainerPath}:ro`
    ).length !== 1 ||
    candidate.services?.['candidate-primary-core']?.volumes?.filter(
      (value) => value === `${options.caFile}:${caContainerPath}:ro`
    ).length !== 1 ||
    !isDeepStrictEqual(
      oracle.services?.['oracle-google-provider'],
      expectedService(options, 'oracle')
    ) ||
    !isDeepStrictEqual(
      candidate.services?.['candidate-google-provider'],
      expectedService(options, 'candidate')
    )
  ) {
    return fail();
  }
};

export const bindGoogleProviderTopology = (rawOracle, rawCandidate, rawOptions) => {
  const options = validateOptions(rawOptions);
  const oracle = structuredClone(rawOracle);
  const candidate = structuredClone(rawCandidate);
  if (
    !exactKeys(oracle, ['services', 'networks', 'volumes']) ||
    !exactKeys(candidate, ['services', 'networks', 'volumes']) ||
    oracle.services['oracle-google-provider'] !== undefined ||
    candidate.services['candidate-google-provider'] !== undefined
  ) {
    return fail();
  }
  oracle.services['oracle-google-provider'] = expectedService(options, 'oracle');
  candidate.services['candidate-google-provider'] = expectedService(options, 'candidate');
  assertGoogleProviderTopology(oracle, candidate, options);
  return Object.freeze({ oracle, candidate });
};
