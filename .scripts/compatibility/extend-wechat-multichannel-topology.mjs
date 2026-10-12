import path from 'node:path';
const fail=()=>{throw new TypeError('Invalid Common206 WeChat multichannel topology');};
const absolute=value=>typeof value==='string'&&value.startsWith('/')&&path.normalize(value)===value&&!/[,:\u0000-\u001f\u007f]/u.test(value);
const image=/^sha256:[0-9a-f]{64}$/u;
export const extendWechatMultichannelTopology=(raw,options)=>{
 const keys=['certificateFile','configurationFile','fixtureImage','privateKeyFile','receiptFile','role','script'];
 if(!options||Object.keys(options).toSorted().join()!==keys.toSorted().join()||!['oracle','candidate'].includes(options.role)||!image.test(options.fixtureImage)||!['certificateFile','configurationFile','privateKeyFile','receiptFile','script'].every(key=>absolute(options[key])))fail();
 const document=structuredClone(raw);const network=`${options.role}-primary`;const prefix=options.role==='oracle'?'172.30.231':'172.30.241';const core=document.services?.[`${options.role}-primary-core`];
 if(!core||document.networks?.[network]?.internal!==true)fail();
 const current=core.extra_hosts??[];if(!Array.isArray(current))fail();
 core.extra_hosts=[...current.filter(value=>!/^api\.weixin\.qq\.com:/u.test(value)),`api.weixin.qq.com:${prefix}.53`];
 document.services[`${options.role}-wechat-multichannel-provider`]={image:options.fixtureImage,entrypoint:['node'],command:['/opt/aster-fixture/wechat-multichannel-provider.mjs'],environment:{ASTER_WECHAT_MULTICHANNEL_CERTIFICATE_FILE:'/run/fixture/tls.pem',ASTER_WECHAT_MULTICHANNEL_PRIVATE_KEY_FILE:'/run/fixture/tls.key',ASTER_WECHAT_MULTICHANNEL_CONFIGURATION_FILE:'/run/fixture/configuration.json',ASTER_WECHAT_MULTICHANNEL_RECEIPT_FILE:'/run/fixture/receipt.ndjson'},healthcheck:{test:['CMD','node','-e',"require('node:https').get({host:'127.0.0.1',port:443,path:'/healthz',rejectUnauthorized:false},r=>process.exit(r.statusCode===204?0:1)).on('error',()=>process.exit(1))"],interval:'1s',timeout:'3s',retries:60},networks:{[network]:{ipv4_address:`${prefix}.53`}},volumes:[`${options.script}:/opt/aster-fixture/wechat-multichannel-provider.mjs:ro`,`${options.certificateFile}:/run/fixture/tls.pem:ro`,`${options.privateKeyFile}:/run/fixture/tls.key:ro`,`${options.configurationFile}:/run/fixture/configuration.json:ro`,`${options.receiptFile}:/run/fixture/receipt.ndjson:rw`],mac_address:options.role==='oracle'?'02:42:ac:1e:e7:3b':'02:42:ac:1e:f1:3b',user:`${process.getuid()}:${process.getgid()}`,userns_mode:'keep-id',pids_limit:32,mem_limit:'192m',cpus:.25,cap_drop:['ALL'],read_only:true,security_opt:['no-new-privileges:true'],sysctls:{'net.ipv4.ip_unprivileged_port_start':'443'},restart:'no'};
 return Object.freeze(document);
};
