import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import https from 'node:https';

const MAX = 65536;
const fail = () => { throw new Error('fixture configuration invalid'); };
const required = name => process.env[name] || fail();
const ownedFile = async (file, modes) => {
  if (file !== await realpath(file)) fail();
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.uid !== process.getuid() ||
      before.nlink !== 1 || !modes.includes(before.mode & 0o777) || before.size > MAX) fail();
  return before;
};
const configurationFile = required('ASTER_WECHAT_MULTICHANNEL_CONFIGURATION_FILE');
await ownedFile(configurationFile, [0o400, 0o600]);
const configuration = JSON.parse(await readFile(configurationFile, 'utf8'));
const codeNames = ['setup','browser','account','foreignAccount','miniSetup','miniPositive','miniCollision',
  'miniNoUnionId','miniInvalidCode','miniReplay','miniMalformedProvider','nativeSetup',
  'nativePositive','nativeNoUnionId','nativeInvalidCode','nativeReplay','nativeMalformedProvider'];
if (configuration.schemaVersion !== 1 || typeof configuration.appId !== 'string' ||
    typeof configuration.appSecret !== 'string' || typeof configuration.unionId !== 'string' ||
    typeof configuration.collisionUnionId !== 'string' || configuration.unionId === configuration.collisionUnionId ||
    !configuration.codes || codeNames.some(name => typeof configuration.codes[name] !== 'string') ||
    new Set(codeNames.map(name => configuration.codes[name])).size !== codeNames.length) fail();
const receiptFile = required('ASTER_WECHAT_MULTICHANNEL_RECEIPT_FILE');
const before = await ownedFile(receiptFile, [0o600]);
if (before.size !== 0) fail();
const receipt = await open(receiptFile, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
const certificate = await readFile(required('ASTER_WECHAT_MULTICHANNEL_CERTIFICATE_FILE'));
const privateKey = await readFile(required('ASTER_WECHAT_MULTICHANNEL_PRIVATE_KEY_FILE'));
const consumed = new Set();
let receipts = 0;
const record = async facts => {
  if (++receipts > 32) fail();
  await receipt.write(`${JSON.stringify(facts)}\n`); await receipt.sync();
};
const exactQuery = (url, keys) => {
  const actual = [...url.searchParams.keys()];
  return actual.length === keys.length && new Set(actual).size === keys.length &&
    actual.toSorted().join() === [...keys].toSorted().join();
};
const selected = code => {
  const name=codeNames.find(key=>configuration.codes[key]===code); if(!name)return undefined;
  if(name.startsWith('mini'))return {name,channel:'mini',kind:name.slice(4,5).toLowerCase()+name.slice(5)};
  if(name.startsWith('native'))return {name,channel:'native',kind:name.slice(6,7).toLowerCase()+name.slice(7)};
  return {name,channel:'web',kind:name};
};
const json = (response, status, body) => {
  const value = JSON.stringify(body); response.writeHead(status, {'content-type':'application/json','cache-control':'no-store','content-length':String(Buffer.byteLength(value))}); response.end(value);
};
const server = https.createServer({cert:certificate,key:privateKey}, (request,response) => void (async () => {
  const url = new URL(request.url ?? '/', 'https://api.weixin.qq.com');
  if (url.pathname === '/healthz' && request.method === 'GET') return response.writeHead(204).end();
  const mini = url.pathname === '/sns/jscode2session';
  const nativeToken = url.pathname === '/sns/oauth2/access_token';
  const nativeUser = url.pathname === '/sns/userinfo';
  if (!mini && !nativeToken && !nativeUser) return json(response,404,{error:'not_found'});
  if (nativeUser) {
    const token=url.searchParams.get('access_token'); const code=token?.startsWith('owned-')?token.slice(6):undefined;
    const choice=selected(code); const kind=choice?.kind; const exact=request.method==='GET'&&exactQuery(url,['access_token','openid'])&&url.searchParams.get('openid')==='owned-openid';
    const valid=exact&&choice&&choice.channel!=='mini'&&kind!=='invalidCode'&&!consumed.has(`userinfo:${code}`);
    if (!valid) return json(response,200,{errcode:40014,errmsg:'invalid token'});
    consumed.add(`userinfo:${code}`); const union=kind!=='noUnionId';
    await record({channel:choice.channel,step:'userinfo',kind,methodGet:true,exactQuery:true,unionIdPresent:union});
    if(kind==='malformedProvider'){response.writeHead(200,{'content-type':'application/json'});return response.end('{');}
    return json(response,200,{openid:'owned-openid',...(union&&{unionid:kind==='collision'?configuration.collisionUnionId:configuration.unionId})});
  }
  const code=url.searchParams.get('js_code')??url.searchParams.get('code'); const choice=selected(code); const kind=choice?.kind;
  const keys=mini?['appid','secret','js_code','grant_type']:['appid','secret','code','grant_type'];
  const exact=request.method==='GET'&&exactQuery(url,keys)&&url.searchParams.get('appid')===configuration.appId&&url.searchParams.get('secret')===configuration.appSecret&&url.searchParams.get('grant_type')==='authorization_code';
  const channelMatches=choice&&(mini?choice.channel==='mini':choice.channel!=='mini');
  const valid=exact&&channelMatches&&kind!=='invalidCode'&&!consumed.has(`code:${code}`);
  await record({channel:mini?'mini':choice?.channel??'unknown',step:mini?'session':'token',kind:kind??'unknown',methodGet:request.method==='GET',exactQuery:exact,accepted:Boolean(valid)});
  if (!valid) return json(response,200,{errcode:40029,errmsg:'invalid code'});
  consumed.add(`code:${code}`);
  if(kind==='malformedProvider'){response.writeHead(200,{'content-type':'application/json'});return response.end('{');}
  if (mini) return json(response,200,{openid:'owned-openid',session_key:'owned-session',...(kind!=='noUnionId'&&{unionid:kind==='collision'?configuration.collisionUnionId:configuration.unionId})});
  return json(response,200,{access_token:`owned-${code}`,openid:'owned-openid',expires_in:300});
})().catch(()=>{if(!response.headersSent)json(response,500,{error:'fixture_failure'});else response.destroy();}));
server.listen(443,'0.0.0.0');
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>server.close(()=>process.exit(0)));
