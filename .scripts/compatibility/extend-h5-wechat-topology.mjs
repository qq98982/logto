import path from 'node:path';

const fail = () => {
  throw new TypeError('Invalid Common206 H5 WeChat topology');
};
const absolute = (value) =>
  typeof value === 'string' &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/[,:\u0000-\u001F\u007F]/u.test(value);
const exact = (value, keys) => {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).toSorted().join('\0') !== [...keys].toSorted().join('\0')
  ) {
    fail();
  }
  return value;
};
const image = /^sha256:[0-9a-f]{64}$/u;

export const extendH5WechatTopology = (raw, options) => {
  const keys = [
    'certificateFile',
    'descriptor',
    'privateKeyFile',
    'role',
    'script',
  ];
  exact(options, keys);
  if (
    !['oracle', 'candidate'].includes(options.role) ||
    !['certificateFile', 'privateKeyFile', 'script'].every((key) => absolute(options[key]))
  ) {
    fail();
  }
  const descriptor = exact(options.descriptor, [
    'container',
    'project',
    'service',
    'image',
    'configFile',
    'receiptFile',
    'healthDiagnosticFile',
    'dockerHome',
    'apiVersion',
  ]);
  if (
    descriptor.service !== `${options.role}-h5-wechat-provider` ||
    descriptor.container !== `${descriptor.project}-${descriptor.service}-1` ||
    !image.test(descriptor.image) ||
    !['configFile', 'receiptFile', 'healthDiagnosticFile'].every((key) => absolute(descriptor[key]))
  ) {
    fail();
  }
  const document = structuredClone(raw);
  const network = `${options.role}-primary`;
  const prefix = options.role === 'oracle' ? '172.30.231' : '172.30.241';
  if (document.networks?.[network]?.internal !== true) {
    fail();
  }
  document.services[descriptor.service] = {
    image: descriptor.image,
    entrypoint: ['node'],
    command: ['/opt/aster-fixture/phase2-wechat-provider.mjs'],
    environment: {
      ASTER_WECHAT_PROVIDER_CERTIFICATE_FILE: '/run/fixture/tls.pem',
      ASTER_WECHAT_PROVIDER_PRIVATE_KEY_FILE: '/run/fixture/tls.key',
      ASTER_WECHAT_PROVIDER_CONFIGURATION_FILE: '/run/fixture/configuration.json',
      ASTER_WECHAT_PROVIDER_RECEIPT_FILE: '/run/fixture/receipt.json',
      ASTER_WECHAT_PROVIDER_HOST: '0.0.0.0',
      ASTER_WECHAT_PROVIDER_PORT: '443',
    },
    healthcheck: {
      test: [
        'CMD',
        'node',
        '-e',
        "require('node:https').get({host:'127.0.0.1',port:443,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===204?0:1)).on('error',()=>process.exit(1))",
      ],
      interval: '1s',
      timeout: '3s',
      retries: 60,
    },
    networks: { [network]: { ipv4_address: `${prefix}.53` } },
    volumes: [
      `${options.script}:/opt/aster-fixture/phase2-wechat-provider.mjs:ro`,
      `${options.certificateFile}:/run/fixture/tls.pem:ro`,
      `${options.privateKeyFile}:/run/fixture/tls.key:ro`,
      `${descriptor.configFile}:/run/fixture/configuration.json:rw`,
      `${descriptor.receiptFile}:/run/fixture/receipt.json:rw`,
    ],
    mac_address: options.role === 'oracle' ? '02:42:ac:1e:e7:35' : '02:42:ac:1e:f1:35',
    user: `${process.getuid()}:${process.getgid()}`,
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
  return Object.freeze(document);
};
