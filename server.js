'use strict';
// Strike the Stickman V13.2 account server. Node.js 20+, no npm packages needed.
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

fs.mkdirSync(DATA_DIR, {recursive:true, mode:0o700});
let database = {users:{}};
if (fs.existsSync(DB_FILE)) {
  try {
    const loaded = JSON.parse(fs.readFileSync(DB_FILE,'utf8'));
    if (loaded && loaded.users && typeof loaded.users === 'object') database = loaded;
  } catch(err) { console.error('Cannot load account database:', err); process.exit(1); }
}
let saveQueue = Promise.resolve();
function persist() {
  saveQueue = saveQueue.catch(()=>{}).then(async()=>{
    const filename = DB_FILE+'.'+process.pid+'.tmp';
    await fs.promises.writeFile(filename, JSON.stringify(database), {mode:0o600});
    await fs.promises.rename(filename, DB_FILE);
  });
  return saveQueue;
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
function signedUser(req){
 const sid=cookieValue(req,COOKIE);const entry=sessions.get(sid);
 if(!entry)return null;
 if(entry.until<Date.now()){sessions.delete(sid);return null;}
 entry.until=Date.now()+SESSION_TTL;
 return database.users[entry.key] || null;
}
function issueSession(req,res,key){
 const sid=crypto.randomBytes(32).toString('base64url');
 sessions.set(sid,{key,until:Date.now()+SESSION_TTL});
 const secure=!!req.socket.encrypted||req.headers['x-forwarded-proto']==='https';
 res.setHeader('Set-Cookie',`${COOKIE}=${sid}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL/1000)}${secure?'; Secure':''}`);
}
function clearSession(req,res){
 sessions.delete(cookieValue(req,COOKIE));
 const secure=!!req.socket.encrypted||req.headers['x-forwarded-proto']==='https';
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
  const user=signedUser(req);
  return send(res,200,{service:'strike-stickman-accounts',username:user?.username||null,progress:user?.progress||null});
 }
 if(u.pathname==='/api/register'&&req.method==='POST'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  if(!throttle(req))return refuse(res,429,'Too many account attempts. Try again later.');
  let body,credentials;try{body=await readBody(req);credentials=validateCredentials(body)}catch(err){return refuse(res,400,err.message)}
  const {username,password,key}=credentials;
  if(database.users[key])return refuse(res,409,'That username is already taken.');
  const salt=crypto.randomBytes(16).toString('hex');
  const hash=(await scrypt(password,salt,64)).toString('hex');
  if(database.users[key])return refuse(res,409,'That username is already taken.');
  const progress=safeProgress(body.progress);
  database.users[key]={username,salt,hash,progress,createdAt:Date.now()};
  try{await persist()}catch(err){delete database.users[key];console.error(err);return refuse(res,500,'Could not save account. Try again.');}
  issueSession(req,res,key);
  return send(res,201,{username,progress});
 }
 if(u.pathname==='/api/login'&&req.method==='POST'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  if(!throttle(req))return refuse(res,429,'Too many login attempts. Try again later.');
  let credentials;try{credentials=validateCredentials(await readBody(req))}catch(err){return refuse(res,400,err.message)}
  const account=database.users[credentials.key];
  if(!account)return refuse(res,401,'Invalid username or password.');
  const computed=await scrypt(credentials.password,account.salt,64);
  const expected=Buffer.from(account.hash,'hex');
  if(expected.length!==computed.length||!crypto.timingSafeEqual(expected,computed))return refuse(res,401,'Invalid username or password.');
  issueSession(req,res,credentials.key);
  return send(res,200,{username:account.username,progress:account.progress});
 }
 if(u.pathname==='/api/logout'&&req.method==='POST'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  clearSession(req,res);return send(res,200,{ok:true});
 }
 if(u.pathname==='/api/progress'&&req.method==='PUT'){
  if(!allowedMutation(req))return refuse(res,403,'Invalid request');
  const user=signedUser(req);if(!user)return refuse(res,401,'Please log in again.');
  let body;try{body=await readBody(req)}catch(err){return refuse(res,400,err.message)}
  user.progress=safeProgress(body.progress);
  try{await persist()}catch(err){console.error(err);return refuse(res,500,'Progress save failed.');}
  return send(res,200,{ok:true});
 }
 return refuse(res,404,'Not found');
}
http.createServer((req,res)=>{
 handler(req,res).catch(err=>{console.error(err);if(!res.headersSent)refuse(res,500,'Server error');else res.end();});
}).listen(PORT,HOST,()=>console.log(`Strike the Stickman game + accounts at http://localhost:${PORT}`));
