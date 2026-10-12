import { randomBytes } from 'node:crypto';
import { chmod, mkdir, open, writeFile } from 'node:fs/promises';
import path from 'node:path';
const [root,image,oracleProject,candidateProject,oracleGoogle,candidateGoogle,oracleWeb,candidateWeb,smsRoot]=process.argv.slice(2);
if(!root||!path.isAbsolute(root)||path.normalize(root)!==root||!/^sha256:[0-9a-f]{64}$/u.test(image??'')||![oracleProject,candidateProject].every(value=>/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(value??''))||![oracleGoogle,candidateGoogle,oracleWeb,candidateWeb,smsRoot].every(value=>typeof value==='string'&&path.isAbsolute(value)&&path.normalize(value)===value))throw new TypeError('Invalid Common206 runtime descriptor input');
const runtime=`${root}/runtime-common`;
const dockerHome=`${runtime}/docker-home`;const apiVersion='4.9.4';
await mkdir(dockerHome,{recursive:true,mode:0o700});await chmod(dockerHome,0o700);
const token=()=>randomBytes(24).toString('base64url');
const exclusive=async(file,value)=>{await mkdir(path.dirname(file),{recursive:true,mode:0o700});const handle=await open(file,'wx',0o600);try{await handle.writeFile(`${JSON.stringify(value)}\n`);await handle.sync();}finally{await handle.close();}await chmod(file,0o600);};
const empty=async file=>{await mkdir(path.dirname(file),{recursive:true,mode:0o700});const handle=await open(file,'wx',0o600);await handle.close();};
for(const [role,ports] of Object.entries({oracle:{core:3311,h5:3351,admin:3411,prefix:'172.30.231'},candidate:{core:3321,h5:3352,admin:3421,prefix:'172.30.241'}})){
 const roleRoot=`${runtime}/${role}`;await mkdir(roleRoot,{recursive:true,mode:0o700});
 const project=role==='oracle'?oracleProject:candidateProject;const service=`${role}-wechat-multichannel-provider`;const container=`${project}-${service}-1`;
 const wechatConfig=`${roleRoot}/wechat/configuration.json`,wechatReceipt=`${roleRoot}/wechat/receipt.ndjson`,wechatHealth=`${roleRoot}/wechat/health.json`;
 const h5WechatRoot=`${roleRoot}/h5-wechat`,h5WechatConfig=`${h5WechatRoot}/configuration.json`,h5WechatReceipt=`${h5WechatRoot}/receipt.ndjson`,h5WechatHealth=`${h5WechatRoot}/health.json`;
 const clientId=`wechat-${role}-${token()}`,clientSecret=token(),unionId=`common206-${role}-${token()}`,collisionUnionId=`common206-collision-${role}-${token()}`;
 await empty(wechatConfig);await empty(wechatReceipt);await empty(wechatHealth);
 await empty(h5WechatConfig);await empty(h5WechatReceipt);await empty(h5WechatHealth);
 const serviceRow=async(kind,name,{config=true,socket=false}={})=>{const base=`${roleRoot}/${kind}/${name}`;const receiptFile=`${base}/receipt.ndjson`;await empty(receiptFile);let configFile; if(config){configFile=`${base}/configuration.json`;const body=kind==='pwned'?{prefix:'ABCDE',suffix:'0123456789ABCDEFFEDCBA9876543210ABC',responseMode:name==='clear'?'count-zero':name==='compromised'?'count-one':'status-503'}:{};await exclusive(configFile,body);}let socketFile;if(socket){const socketRoot=`${base}/socket`;await mkdir(socketRoot,{recursive:true,mode:0o700});socketFile=`${socketRoot}/consume.sock`;}const serviceName=`${role}-${kind}-${name}`;return {container:`${project}-${serviceName}-1`,project,service:serviceName,image,receiptFile,...(configFile&&{configFile}),...(socketFile&&{socketFile}),dockerHome,apiVersion};};
 const pwned={clear:await serviceRow('pwned','clear'),compromised:await serviceRow('pwned','compromised'),unavailable:await serviceRow('pwned','unavailable')};
 const backchannel={accepted:await serviceRow('backchannel','accepted',{config:false,socket:true}),rejected:await serviceRow('backchannel','rejected',{config:false,socket:true})};
 const smsShort=role==='oracle'?'o':'c';const smsConfiguration=JSON.parse(await (await import('node:fs/promises')).readFile(`${smsRoot}/${smsShort}/configuration.json`,'utf8'));
 const h5WechatService=`${role}-h5-wechat-provider`;
 const descriptor={schemaVersion:1,target:{label:role,coreUrl:`http://localhost:${ports.core}/`,adminUrl:`http://localhost:${ports.admin}/`},googleProviderInput:role==='oracle'?oracleGoogle:candidateGoogle,webProviderInput:role==='oracle'?oracleWeb:candidateWeb,h5:{listenUrl:`https://localhost:${ports.h5}`,caFile:`${root}/runtime-h5/h5-loopback-ca.pem`,spkiFile:`${root}/runtime-h5/h5-loopback-server.spki`},h5Wechat:{container:`${project}-${h5WechatService}-1`,project,service:h5WechatService,image,configFile:h5WechatConfig,receiptFile:h5WechatReceipt,healthDiagnosticFile:h5WechatHealth,dockerHome,apiVersion},wechat:{container,project,service,image,configFile:wechatConfig,receiptFile:wechatReceipt,healthDiagnosticFile:wechatHealth,dockerHome,apiVersion,clientId,clientSecret,unionId,collisionUnionId,ownerEmail:`owner-${role}@common206.invalid`,phone:role==='oracle'?'15555550101':'15555550102',smsAccessKeyId:smsConfiguration.accessKeyId,smsAccessSecret:smsConfiguration.accessKeySecret,smsSignName:smsConfiguration.signName,smsTemplateCode:smsConfiguration.templates.Register,smsCodeSocket:`${smsRoot}/${smsShort}/s.sock`,universalLink:`https://native-${role}.common206.aster.test/`},pwned,backchannel};
 await exclusive(`${runtime}/${role}-descriptor.json`,descriptor);
}
