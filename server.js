'use strict';
// Strike the Stickman V13.3 account server. Node.js 20+, PostgreSQL for hosting.
// Host behind HTTPS for real internet use. Start locally with: node server.js
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {promisify} = require('node:util');
const scrypt = promisify(crypto.scrypt);

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const DATA_DIR = process.env.STICKMAN_DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'accounts.json');
const INDEX_FILE = path.join(ROOT, 'index.html');
const COOKIE = 'stickman_session';
const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map();
const limits = new Map();

// Cloud deployments must not silently fall back to an ephemeral file.
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL && (process.env.RENDER === 'true' || process.env.REQUIRE_DATABASE === '1')) {
  console.error('DATABASE_URL is required. Add the PostgreSQL connection string in Render Environment.');
  process.exit(1);
}
let pool=null;
let database={users:Object.create(null)};
let saveQueue=Promise.resolve();
function readLegacy(){
 if(!fs.existsSync(DB_FILE))return {};
 const loaded=JSON.parse(fs.readFileSync(DB_FILE,'utf8'));
 if(!loaded || !loaded.users || typeof loaded.users!=='object' || Array.isArray(loaded.users))throw Error('Invalid legacy accounts file');
 return loaded.users;
}
function persist(){
 const snapshot=JSON.stringify(database);
 saveQueue=saveQueue.catch(()=>{}).then(async()=>{
  const filename=DB_FILE+'.'+process.pid+'.tmp';
  await fs.promises.writeFile(filename,snapshot,{mode:0o600});
  await fs.promises.rename(filename,DB_FILE);
 });return saveQueue;
}
async function initializeStorage(){
 if(!DATABASE_URL){
  fs.mkdirSync(DATA_DIR,{recursive:true,mode:0o700});
  Object.assign(database.users,readLegacy());
  console.log('Local development storage (not suitable for ephemeral hosting).');return;
 }
 const {Pool}=require('pg');
 // Neon connection strings contain sslmode=require. Enforce certificate validation.
 const url=new URL(DATABASE_URL);
 if(!['postgres:', 'postgresql:'].includes(url.protocol))throw Error('DATABASE_URL must be a PostgreSQL URL');
 const sslmode=url.searchParams.get('sslmode');
 if(sslmode==='disable' && process.env.RENDER==='true')throw Error('TLS is required on Render');
 for(const k of ['sslmode','sslcert','sslkey','sslrootcert'])url.searchParams.delete(k);
 pool=new Pool({connectionString:url.toString(),ssl:sslmode==='disable'?false:{rejectUnauthorized:true},max:5,connectionTimeoutMillis:15000,idleTimeoutMillis:30000});
 pool.on('error',()=>console.error('Database idle connection interrupted.'));
 await pool.query(`CREATE TABLE IF NOT EXISTS stickman_accounts (
  account_key TEXT PRIMARY KEY, username TEXT NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL,
  progress JSONB NOT NULL, created_at BIGINT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
 )`);
 await pool.query(`CREATE TABLE IF NOT EXISTS stickman_sessions (
  token_hash TEXT PRIMARY KEY, account_key TEXT NOT NULL REFERENCES stickman_accounts(account_key) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
 )`);
 // Import an existing local data file when present, without overwriting cloud accounts.
 if(fs.existsSync(DB_FILE)){
  for(const [key,account] of Object.entries(readLegacy())){
   if(!/^[a-z0-9_]{3,20}$/.test(key)||!account||typeof account.username!=='string'||!(/^[a-f0-9]{32}$/i.test(account.salt||''))||!(/^[a-f0-9]{128}$/i.test(account.hash||'')))continue;
   await createAccount(key,{...account,progress:safeProgress(account.progress)});
  }
  console.log('Legacy account import checked (existing database rows kept).');
 }
 console.log('PostgreSQL connected; persistent accounts enabled.');
}
async function getAccount(key){
 if(!pool)return database.users[key]||null;
 const r=await pool.query('SELECT username,salt,hash,progress FROM stickman_accounts WHERE account_key=$1',[key]);return r.rows[0]||null;
}
async function createAccount(key,account){
 if(!pool){if(database.users[key])return false;database.users[key]=account;try{await persist();}catch(e){delete database.users[key];throw e;}return true;}
 const r=await pool.query(`INSERT INTO stickman_accounts(account_key,username,salt,hash,progress,created_at)
 VALUES($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT(account_key) DO NOTHING`,[key,account.username,account.salt,account.hash,JSON.stringify(account.progress),account.createdAt||Date.now()]);return r.rowCount===1;
}
function mergeProgress(previous,incoming){
 const old=safeProgress(previous), next=safeProgress(incoming);
 // These counters only increase in this version. Preserve discoveries across stale saves.
 for(const key of ['coins','resets','deaths','best','hits'])next[key]=Math.max(old[key],next[key]);
 next.unlockedItems=[...old.unlockedItems,...next.unlockedItems.filter(key=>!old.unlockedItems.includes(key))].slice(0,100);
 return next;
}
async function storeProgress(key,incoming){
 if(!pool){const user=database.users[key];if(!user)return null;const prior=user.progress;const next=mergeProgress(prior,incoming);user.progress=next;try{await persist();}catch(e){if(user.progress===next)user.progress=prior;throw e;}return next;}
 const client=await pool.connect();
 try{
  await client.query('BEGIN');
  const r=await client.query('SELECT progress FROM stickman_accounts WHERE account_key=$1 FOR UPDATE',[key]);
  if(!r.rowCount){await client.query('ROLLBACK');return null;}
  const next=mergeProgress(r.rows[0].progress,incoming);
  await client.query('UPDATE stickman_accounts SET progress=$2::jsonb,updated_at=NOW() WHERE account_key=$1',[key,JSON.stringify(next)]);
  await client.query('COMMIT');return next;
 }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}
function send(res,status,obj,headers={}) {
  const content=Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Length':content.length,...headers});res.end(content);
}
function refuse(res,status,msg){send(res,status,{error:msg});}
function cookieValue(req,name){
 const cookie=req.headers.cookie||'';
 for(const item of cookie.split(';')){const [k,...v]=item.trim().split('=');if(k===name)return v.join('=');}
 return '';
}
function sessionHash(sid){return crypto.createHash('sha256').update(sid).digest('hex');}
async function signedUser(req){
 const sid=cookieValue(req,COOKIE);if(!/^[A-Za-z0-9_-]{43}$/.test(sid))return null;
 if(pool){
  const r=await pool.query(`SELECT a.account_key AS key,a.username,a.progress FROM stickman_sessions s JOIN stickman_accounts a USING(account_key) WHERE s.token_hash=$1 AND s.expires_at>NOW()`,[sessionHash(sid)]);
  return r.rows[0]||null;
 }
 const entry=sessions.get(sid);if(!entry)return null;
 if(entry.until<Date.now()){sessions.delete(sid);return null;}
 const user=await getAccount(entry.key);return user?{...user,key:entry.key}:null;
}
async function issueSession(req,res,key){
 const sid=crypto.randomBytes(32).toString('base64url');
 if(pool){
  await pool.query('DELETE FROM stickman_sessions WHERE expires_at<=NOW()');
  await pool.query('INSERT INTO stickman_sessions(token_hash,account_key,expires_at) VALUES($1,$2,$3)',[sessionHash(sid),key,new Date(Date.now()+SESSION_TTL)]);
 }else sessions.set(sid,{key,until:Date.now()+SESSION_TTL});
 const secure=process.env.RENDER==='true'||!!req.socket.encrypted||req.headers['x-forwarded-proto']==='https';
 res.setHeader('Set-Cookie',`${COOKIE}=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL/1000)}${secure?'; Secure':''}`);
}
async function clearSession(req,res){
 const sid=cookieValue(req,COOKIE);
 if(pool){if(sid)await pool.query('DELETE FROM stickman_sessions WHERE token_hash=$1',[sessionHash(sid)]);}else sessions.delete(sid);
 const secure=process.env.RENDER==='true'||!!req.socket.encrypted||req.headers['x-forwarded-proto']==='https';
 res.setHeader('Set-Cookie',`${COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure?'; Secure':''}`);
}
function allowedMutation(req){
 if(req.headers['x-stickman-client']!=='1')return false;
 if(!String(req.headers['content-type']||'').startsWith('application/json'))return false;
 if(req.headers.origin){
  try{
   const parsed=new URL(req.headers.origin);
   if(parsed.host!==req.headers.host)return false;
  }catch{return false;}
 }
 return true;
}
function readBody(req){
 return new Promise((resolve,reject)=>{
  let size=0;const chunks=[];
  req.on('data',chunk=>{size+=chunk.length;if(size>40000){reject(new Error('Request too large'));req.destroy();return;}chunks.push(chunk);});
  req.on('end',()=>{try{const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!input||typeof input!=='object'||Array.isArray(input))throw Error('Invalid body');resolve(input)}catch(e){reject(new Error('Invalid JSON body'));}});
  req.on('error',reject);
 });
}
function validateCredentials(body){
 const username=typeof body.username==='string'?body.username.trim():'';
 const password=body.password;
 if(!/^[A-Za-z0-9_]{3,20}$/.test(username))throw new Error('Username must be 3–20 letters, numbers, or underscores.');
 if(typeof password!=='string'||password.length<8||password.length>128)throw new Error('Password must contain 8–128 characters.');
 return {username,password,key:username.toLowerCase()};
}
function safeProgress(input){
 const p=input&&typeof input==='object'&&!Array.isArray(input)?input:{};
 const n=v=>Number.isFinite(v)?Math.min(1e9,Math.max(0,Math.floor(v))):0;
 const validItems=Array.isArray(p.unlockedItems)?p.unlockedItems.filter(v=>typeof v==='string'&&/^[a-z0-9]{1,30}$/.test(v)).slice(0,100):[];
 return {
  coins:n(p.coins),resets:n(p.resets),deaths:n(p.deaths),best:n(p.best),hits:n(p.hits),combo:n(p.combo),
  sound:typeof p.sound==='boolean'?p.sound:true,dialogueMuted:!!p.dialogueMuted,
  stickName:typeof p.stickName==='string'?p.stickName.trim().slice(0,24):'STICKY THE STICKMAN',
  skin:typeof p.skin==='string'?p.skin.slice(0,30):'classic',
  map:typeof p.map==='string'?p.map.slice(0,30):'studio',
  unlockedItems:[...new Set(validItems)],
  avatar:typeof p.avatar==='string'&&p.avatar.length<=30000&&/^data:image\/jpeg;base64,\/9j\/[A-Za-z0-9+/]+={0,2}$/.test(p.avatar)?p.avatar:''
 };
}
function throttle(req){
 const ip=String(req.socket.remoteAddress||'unknown');
 const now=Date.now();const old=limits.get(ip);
 const rec=(!old||old.reset<now)?{count:0,reset:now+10*60*1000}:old;
 rec.count++;limits.set(ip,rec);
 if(limits.size>2000)for(const [k,v] of limits)if(v.reset<now)limits.delete(k);
 return rec.count<=45;
}
async function handler(req,res){
 const u=new URL(req.url,'http://localhost');
 if(req.method==='GET'&&(u.pathname==='/'||u.pathname==='/index.html')){
  fs.readFile(INDEX_FILE,(err,html)=>{
   if(err)return refuse(res,500,'Missing index.html');
   res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(html);
  });return;
 }
 if(req.method==='GET'&&u.pathname==='/api/session'){
  const user=await signedUser(req);
  return send(res,200,{service:'strike-stickman-accounts',storage:pool?'postgres':'local-file',username:user?.username||null,progress:user?.progress||null});
 }
 if(u.pathname==='/api/register'&&req.method==='POST'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  if(!throttle(req))return refuse(res,429,'Too many account attempts. Try again later.');
  let body,credentials;try{body=await readBody(req);credentials=validateCredentials(body)}catch(err){return refuse(res,400,err.message)}
  const {username,password,key}=credentials;
  if(await getAccount(key))return refuse(res,409,'That username is already taken.');
  const salt=crypto.randomBytes(16).toString('hex');
  const hash=(await scrypt(password,salt,64)).toString('hex');
  const progress=safeProgress(body.progress);
  if(!await createAccount(key,{username,salt,hash,progress,createdAt:Date.now()}))return refuse(res,409,'That username is already taken.');
  await issueSession(req,res,key);
  return send(res,201,{username,progress});
 }
 if(u.pathname==='/api/login'&&req.method==='POST'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  if(!throttle(req))return refuse(res,429,'Too many login attempts. Try again later.');
  let credentials;try{credentials=validateCredentials(await readBody(req))}catch(err){return refuse(res,400,err.message)}
  const account=await getAccount(credentials.key);
  if(!account)return refuse(res,401,'Invalid username or password.');
  const computed=await scrypt(credentials.password,account.salt,64);
  const expected=Buffer.from(account.hash,'hex');
  if(expected.length!==computed.length||!crypto.timingSafeEqual(expected,computed))return refuse(res,401,'Invalid username or password.');
  await issueSession(req,res,credentials.key);
  return send(res,200,{username:account.username,progress:account.progress});
 }
 if(u.pathname==='/api/logout'&&req.method==='POST'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  await clearSession(req,res);return send(res,200,{ok:true});
 }
 if(u.pathname==='/api/progress'&&req.method==='PUT'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  const user=await signedUser(req);if(!user)return refuse(res,401,'Please log in again.');
  let body;try{body=await readBody(req)}catch(err){return refuse(res,400,err.message)}
  const progress=await storeProgress(user.key,body.progress);
  if(!progress)return refuse(res,401,'Please log in again.');
  return send(res,200,{ok:true});
 }
 return refuse(res,404,'Not found');
}
initializeStorage().then(()=>{
 http.createServer((req,res)=>{
  handler(req,res).catch(err=>{console.error('Account request failed:',err.code||err.name);if(!res.headersSent)send(res,503,{service:'strike-stickman-accounts',error:'Account storage temporarily unavailable. Please try again.'});else res.end();});
 }).listen(PORT,HOST,()=>console.log(`Strike the Stickman game + accounts at http://localhost:${PORT}`));
}).catch(err=>{console.error('Account storage initialization failed:',err.code||err.message);process.exit(1);});
