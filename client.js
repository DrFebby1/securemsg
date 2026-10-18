#!/usr/bin/env node
// SecureMsg CLI client — Node.js >= 22.13, zero dependencies.
//   node client.js wss://securemsg.<you>.workers.dev
//
// Security model
//  - Password never leaves your machine. It only unlocks a local vault (scrypt + AES-256-GCM).
//  - Identity = Ed25519 keypair (login/signatures). Encryption = X25519 + HKDF + AES-256-GCM.
//  - Messages are end-to-end encrypted and signed; the server sees only ciphertext.
//  - Local database (SQLite) stores every message and contact encrypted with a random key held in the vault.
//  - First-seen keys of contacts are pinned (TOFU); key changes are blocked until you run `trust <user>`.

process.emitWarning = () => {};
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';

// ───────────────────────── helpers ─────────────────────────
const C = {
  b: (s) => `\x1b[1m${s}\x1b[0m`, d: (s) => `\x1b[2m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`,
  g: (s) => `\x1b[32m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m`, c: (s) => `\x1b[36m${s}\x1b[0m`,
};
const NAME = /^[a-z0-9_]{3,20}$/;
const b64 = (b) => Buffer.from(b).toString('base64');
const unb = (s) => Buffer.from(s, 'base64');
const clean = (s) => String(s).replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, ''); // blocks terminal-escape injection
const fmt = (t) => {
  const d = new Date(t), hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return d.toDateString() === new Date().toDateString() ? hm : `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${hm}`;
};
const die = (m) => { console.log(C.r('✗ ' + m)); process.exit(1); };

const SPKI = { ed: Buffer.from('302a300506032b6570032100', 'hex'), x: Buffer.from('302a300506032b656e032100', 'hex') };
const pubObj = (raw, t) => crypto.createPublicKey({ key: Buffer.concat([SPKI[t], raw]), format: 'der', type: 'spki' });
const rawPub = (k) => k.export({ format: 'der', type: 'spki' }).subarray(12);
const privObj = (b) => crypto.createPrivateKey({ key: b, format: 'der', type: 'pkcs8' });
const derPriv = (k) => k.export({ format: 'der', type: 'pkcs8' });

const kdf = (pw, salt) => crypto.scryptSync(pw, salt, 32, { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
function seal(key, data, aad = '') {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(data), c.final()]);
  return Buffer.concat([iv, ct, c.getAuthTag()]);
}
function unseal(key, blob, aad = '') {
  blob = Buffer.from(blob);
  const d = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(blob.subarray(-16));
  return Buffer.concat([d.update(blob.subarray(12, -16)), d.final()]);
}
const fingerprint = (sigPub, boxPub) =>
  crypto.createHash('sha256').update(unb(sigPub)).update(unb(boxPub)).digest('hex').slice(0, 40).match(/.{5}/g).join(' ');

// ───────────────────────── prompts ─────────────────────────
const ask = (q) => new Promise((res) => {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question(q, (a) => { rl.close(); res(a.trim()); });
});
const askHidden = (q) => new Promise((res) => {
  process.stdout.write(q);
  let s = '';
  const stdin = process.stdin;
  stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
  const on = (chunk) => {
    for (const ch of chunk) {
      if (ch === '\r' || ch === '\n') { stdin.setRawMode(false); stdin.off('data', on); stdin.pause(); process.stdout.write('\n'); return res(s); }
      if (ch === '\x03') process.exit(0);
      if (ch === '\x7f' || ch === '\b') s = s.slice(0, -1); else s += ch;
    }
  };
  stdin.on('data', on);
});

// ───────────────────────── state ─────────────────────────
let SERVER, USER, DIR, db, dbKey, sigPriv, sigPub, boxPriv, boxPub;
let ws = null, ready = false, closing = false, backoff = 1000, seq = 0;
const pending = new Map();
let rl = null, chatWith = null, lastList = [];

function say(s) {
  if (!rl) return console.log(s);
  readline.cursorTo(process.stdout, 0); readline.clearLine(process.stdout, 0);
  console.log(s); rl.prompt(true);
}
const setPrompt = () => rl.setPrompt(chatWith ? C.c(`${USER} → ${chatWith}`) + ' › ' : C.b(USER) + ' › ');

// ───────────────────────── local database ─────────────────────────
const pidx = (peer) => crypto.createHmac('sha256', dbKey).update('peer|' + peer).digest('hex');
function openDb(DatabaseSync) {
  db = new DatabaseSync(path.join(DIR, 'messages.db'));
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON;
    CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, mid TEXT UNIQUE, pidx TEXT, ts INTEGER, unread INTEGER, blob BLOB);
    CREATE INDEX IF NOT EXISTS ix_msg ON messages(pidx, ts);
    CREATE TABLE IF NOT EXISTS contacts(pidx TEXT PRIMARY KEY, blob BLOB);`);
}
function getContact(name) {
  const r = db.prepare('SELECT blob FROM contacts WHERE pidx=?').get(pidx(name));
  return r ? JSON.parse(unseal(dbKey, r.blob, 'c')) : null;
}
function putContact(name, o) {
  db.prepare('INSERT OR REPLACE INTO contacts(pidx,blob) VALUES(?,?)').run(pidx(name), seal(dbKey, Buffer.from(JSON.stringify({ name, ...o })), 'c'));
}
function addMsg(mid, peer, dir, ts, text, unread) {
  const r = db.prepare('INSERT OR IGNORE INTO messages(mid,pidx,ts,unread,blob) VALUES(?,?,?,?,?)')
    .run(mid, pidx(peer), ts, unread ? 1 : 0, seal(dbKey, Buffer.from(JSON.stringify({ peer, dir, text })), 'm'));
  return r.changes > 0;
}
const history = (peer, n = 25) =>
  db.prepare('SELECT ts, blob FROM messages WHERE pidx=? ORDER BY ts DESC LIMIT ?').all(pidx(peer), n).reverse()
    .map((r) => ({ ts: r.ts, ...JSON.parse(unseal(dbKey, r.blob, 'm')) }));
const markRead = (peer) => db.prepare('UPDATE messages SET unread=0 WHERE pidx=? AND unread=1').run(pidx(peer));
function inboxRows() {
  const rows = db.prepare('SELECT pidx, COALESCE(SUM(unread),0) u, MAX(ts) t FROM messages GROUP BY pidx ORDER BY t DESC').all();
  return rows.map((r) => {
    const c = db.prepare('SELECT blob FROM contacts WHERE pidx=?').get(r.pidx);
    return { name: c ? JSON.parse(unseal(dbKey, c.blob, 'c')).name : '?', u: r.u, t: r.t };
  });
}

// ───────────────────────── network ─────────────────────────
function connect(mode) {
  return new Promise((resolve, reject) => {
    const sock = new WebSocket(`${SERVER}/ws?u=${USER}`);
    let settled = false;
    sock.onmessage = (ev) => {
      let m; try { m = JSON.parse(ev.data); } catch { return; }
      if (m.t === 'chal') {
        if (mode === 'reg') {
          const sp = b64(rawPub(sigPub)), bp = b64(rawPub(boxPub));
          const sig = b64(crypto.sign(null, Buffer.from(`register|${USER}|${m.nonce}|${sp}|${bp}`), sigPriv));
          sock.send(JSON.stringify({ t: 'reg', sigPub: sp, boxPub: bp, sig }));
        } else {
          sock.send(JSON.stringify({ t: 'login', sig: b64(crypto.sign(null, Buffer.from(`login|${USER}|${m.nonce}`), sigPriv)) }));
        }
      } else if (m.t === 'ok') {
        ws = sock; ready = true; backoff = 1000; settled = true; mode = 'login'; resolve();
        if (rl) say(C.g('● connected'));
      } else if (m.t === 'err' && !settled) {
        settled = true; reject(new Error(m.code)); sock.close();
      } else onServer(m);
    };
    sock.onclose = () => {
      if (sock === ws) { ws = null; ready = false; for (const p of pending.values()) { clearTimeout(p.to); p.rej(new Error('offline')); } pending.clear(); if (rl) say(C.y('● disconnected — reconnecting…')); }
      if (!settled) { settled = true; reject(new Error('connection failed')); }
      else if (!closing) retry();
    };
    sock.onerror = () => {};
  });
}
function retry() {
  if (closing) return;
  setTimeout(() => connect('login').catch((e) => { if (e.message === 'auth') die('Server rejected this identity.'); retry(); }), backoff);
  backoff = Math.min(backoff * 2, 30000);
}
function request(m) {
  return new Promise((res, rej) => {
    if (!ready) return rej(new Error('You are offline.'));
    m.cid = ++seq;
    const to = setTimeout(() => { pending.delete(m.cid); rej(new Error('Server timeout.')); }, 10000);
    pending.set(m.cid, { res, rej, to });
    ws.send(JSON.stringify(m));
  });
}
function onServer(m) {
  if ((m.t === 'pub' || m.t === 'sent') && pending.has(m.cid)) {
    const p = pending.get(m.cid); clearTimeout(p.to); pending.delete(m.cid); p.res(m);
  } else if (m.t === 'msg') incoming(m).catch(() => {});
}

// ───────────────────────── contacts / keys (TOFU pinning) ─────────────────────────
async function resolve(name) {
  const r = await request({ t: 'lookup', u: name });
  if (!r.found) return { found: false };
  const c = getContact(name);
  if (!c) { putContact(name, { sigPub: r.sigPub, boxPub: r.boxPub }); return { found: true, c: { sigPub: r.sigPub, boxPub: r.boxPub } }; }
  if (c.sigPub !== r.sigPub || c.boxPub !== r.boxPub) return { found: true, changed: true, c, server: r };
  return { found: true, c };
}
const keyWarn = (n) => C.r(`⚠ The security keys of "${n}" CHANGED. This could be an attack or a new account.\n  Verify with them using "fp ${n}" then run "trust ${n}" to accept.`);

// ───────────────────────── send / receive ─────────────────────────
async function sendMsg(peer, text) {
  if (peer === USER) throw new Error('You cannot message yourself.');
  if (text.length > 4000) throw new Error('Message too long (max 4000 chars).');
  const r = await resolve(peer);
  if (!r.found) throw new Error(`User "${peer}" does not exist.`);
  if (r.changed) throw new Error(keyWarn(peer));

  const ts = Date.now(), mid = crypto.randomBytes(12).toString('hex');
  const eph = crypto.generateKeyPairSync('x25519');
  const ephRaw = rawPub(eph.publicKey);
  const sig = b64(crypto.sign(null, Buffer.from(`msg|${USER}|${peer}|${ts}|${mid}|${text}|${b64(ephRaw)}`), sigPriv));
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: pubObj(unb(r.c.boxPub), 'x') });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, ephRaw, 'securemsg-v1', 32));
  const iv = crypto.randomBytes(12), ci = crypto.createCipheriv('aes-256-gcm', key, iv);
  ci.setAAD(ephRaw);
  const ct = Buffer.concat([ci.update(JSON.stringify({ from: USER, to: peer, ts, m: mid, text, sig })), ci.final(), ci.getAuthTag()]);

  const res = await request({ t: 'send', to: peer, env: { e: b64(ephRaw), i: b64(iv), c: b64(ct) } });
  if (!res.ok) throw new Error(res.code === 'nouser' ? `User "${peer}" does not exist.` : res.code === 'full' ? 'Recipient mailbox is full.' : 'Send failed.');
  addMsg(mid, peer, 'out', ts, text, false);
  return ts;
}

async function incoming(m) {
  const ack = () => ready && ws.send(JSON.stringify({ t: 'ack', ids: [m.id] }));
  try {
    const eph = unb(m.env.e), iv = unb(m.env.i), ct = unb(m.env.c);
    const shared = crypto.diffieHellman({ privateKey: boxPriv, publicKey: pubObj(eph, 'x') });
    const key = Buffer.from(crypto.hkdfSync('sha256', shared, eph, 'securemsg-v1', 32));
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(eph); d.setAuthTag(ct.subarray(-16));
    const p = JSON.parse(Buffer.concat([d.update(ct.subarray(0, -16)), d.final()]));
    if (p.to !== USER || !NAME.test(p.from) || typeof p.text !== 'string' || p.text.length > 4000) return ack();

    const r = await resolve(p.from);
    if (!r.found) return ack();
    if (r.changed) { say(keyWarn(p.from) + C.d('\n  (a message from them was rejected)')); return ack(); }
    const okSig = crypto.verify(null, Buffer.from(`msg|${p.from}|${p.to}|${p.ts}|${p.m}|${p.text}|${b64(eph)}`), pubObj(unb(r.c.sigPub), 'ed'), unb(p.sig));
    if (!okSig) return ack();

    const live = chatWith === p.from;
    if (addMsg(p.m, p.from, 'in', p.ts, p.text, !live)) {
      if (live) say(line(p.from, 'in', p.ts, p.text));
      else say(C.y(`● New message from ${p.from}`));
    }
  } catch { /* undecryptable / forged: drop */ }
  ack();
}

// ───────────────────────── UI ─────────────────────────
const line = (peer, dir, ts, text) => `${C.d(fmt(ts))} ${dir === 'out' ? C.g('you') : C.c(peer)}: ${clean(text)}`;

function showInbox() {
  const rows = inboxRows(); lastList = rows.map((r) => r.name);
  console.log('\n' + C.c('═'.repeat(48)));
  console.log(` ${C.b('SecureMsg')} · ${C.b(USER)}   ${ready ? C.g('● online') : C.r('● offline')}`);
  console.log(C.c('═'.repeat(48)));
  if (!rows.length) console.log(C.d('  (inbox is empty)'));
  rows.forEach((r, i) => console.log(` ${String(i + 1).padStart(2)}. ${r.name.padEnd(20)} ${r.u ? C.y(`[${r.u} new]`.padEnd(10)) : ''.padEnd(10)} ${C.d(fmt(r.t))}`));
  console.log(C.d('\n msg <user> <text> · chat <user|#> · fp [user] · trust <user> · list · quit\n'));
}

async function enterChat(name) {
  const r = await resolve(name);
  if (!r.found) throw new Error(`User "${name}" does not exist.`);
  if (r.changed) console.log(keyWarn(name));
  chatWith = name; setPrompt();
  console.log('\n' + C.c(`── chat with ${name} ──`) + C.d('  (/back to leave, /fp for fingerprint)'));
  history(name).forEach((h) => console.log(line(name, h.dir, h.ts, h.text)));
  markRead(name);
}

async function showFp(name) {
  if (!name) return console.log(`Your fingerprint:\n  ${C.b(fingerprint(b64(rawPub(sigPub)), b64(rawPub(boxPub))))}`);
  const r = await resolve(name);
  if (!r.found) throw new Error(`User "${name}" does not exist.`);
  console.log(`Fingerprint of ${name} (compare over a trusted channel):\n  ${C.b(fingerprint(r.c.sigPub, r.c.boxPub))}`);
}

async function menu(input) {
  const parts = input.split(/\s+/), cmd = (parts[0] || '').toLowerCase();
  if (!cmd) return;
  if (cmd === 'list' || cmd === 'ls') return showInbox();
  if (cmd === 'help') return console.log(C.d(' msg <user> <text>  send one message\n chat <user|#>     open conversation\n fp [user]         show fingerprint\n trust <user>      accept a changed key\n quit'));
  if (cmd === 'quit' || cmd === 'exit') return quit();
  if (cmd === 'msg') {
    const mm = input.match(/^\S+\s+(\S+)\s+([\s\S]+)$/);
    if (!mm) return console.log('Usage: msg <user> <text>');
    await sendMsg(mm[1].toLowerCase(), mm[2]);
    return console.log(C.g(`✓ sent to ${mm[1].toLowerCase()} (encrypted)`));
  }
  if (cmd === 'chat' || /^\d+$/.test(cmd)) {
    const arg = cmd === 'chat' ? parts[1] : cmd;
    if (!arg) return console.log('Usage: chat <user|#>');
    return enterChat(/^\d+$/.test(arg) ? lastList[+arg - 1] || die('No such entry.') : arg.toLowerCase());
  }
  if (cmd === 'fp') return showFp(parts[1] && parts[1].toLowerCase());
  if (cmd === 'trust') {
    const n = (parts[1] || '').toLowerCase();
    const r = await resolve(n);
    if (!r.found) throw new Error('No such user.');
    if (r.changed) { putContact(n, { sigPub: r.server.sigPub, boxPub: r.server.boxPub }); return console.log(C.g('✓ new key trusted for ' + n)); }
    return console.log('Key unchanged.');
  }
  console.log('Unknown command. Type "help".');
}

function quit() { closing = true; try { ws && ws.close(); db && db.close(); } catch {} console.log('\nBye.'); process.exit(0); }

// ───────────────────────── main ─────────────────────────
(async () => {
  console.log(C.c('\n  ╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐╔╦╗┌─┐┌─┐\n  ╚═╗├┤ │  │ │├┬┘├┤ ║║║└─┐│ ┬\n  ╚═╝└─┘└─┘└─┘┴└─└─┘╩ ╩└─┘└─┘') + C.d('   end-to-end encrypted\n'));

  const HOME = path.join(os.homedir(), '.securemsg');
  fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
  const cfgFile = path.join(HOME, 'config.json');
  const cfg = fs.existsSync(cfgFile) ? JSON.parse(fs.readFileSync(cfgFile, 'utf8')) : {};
  let server = process.argv[2] || cfg.server || (await ask('Server URL (wss://….workers.dev): '));
  server = server.replace(/^http/, 'ws').replace(/\/+$/, '');
  if (!/^wss?:\/\/[^\s/]+$/.test(server)) die('Invalid server URL.');
  SERVER = server; cfg.server = server; fs.writeFileSync(cfgFile, JSON.stringify(cfg));

  const act = await ask('[1] Login   [2] Create account  › ');
  USER = (await ask('Username › ')).toLowerCase();
  if (!NAME.test(USER)) die('Username: 3-20 chars, a-z 0-9 _ only.');
  DIR = path.join(HOME, new URL(server.replace(/^ws/, 'http')).host.replace(':', '_'), USER);
  const vaultFile = path.join(DIR, 'vault.json');
  let mode, vault;

  if (act === '2') {
    if (fs.existsSync(vaultFile)) die('An account with this name already exists on this device.');
    const pw = await askHidden('Password (min 10 chars) › ');
    if (pw.length < 10) die('Password too short.');
    if (pw !== (await askHidden('Repeat password › '))) die('Passwords do not match.');
    console.log(C.d('Generating keys…'));
    const ed = crypto.generateKeyPairSync('ed25519'), x = crypto.generateKeyPairSync('x25519');
    vault = { sig: derPriv(ed.privateKey), box: derPriv(x.privateKey), db: crypto.randomBytes(32) };
    const salt = crypto.randomBytes(16);
    fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
    const blob = seal(kdf(pw, salt), Buffer.from(JSON.stringify({ sig: b64(vault.sig), box: b64(vault.box), db: b64(vault.db) })), 'vault');
    fs.writeFileSync(vaultFile, JSON.stringify({ v: 1, salt: b64(salt), blob: b64(blob) }), { mode: 0o600 });
    mode = 'reg';
  } else {
    if (!fs.existsSync(vaultFile)) die('No account with this name on this device. Create one first (option 2).');
    const pw = await askHidden('Password › ');
    const f = JSON.parse(fs.readFileSync(vaultFile, 'utf8'));
    try {
      const v = JSON.parse(unseal(kdf(pw, unb(f.salt)), unb(f.blob), 'vault'));
      vault = { sig: unb(v.sig), box: unb(v.box), db: unb(v.db) };
    } catch { die('Wrong password.'); }
    mode = 'login';
  }

  sigPriv = privObj(vault.sig); sigPub = crypto.createPublicKey(sigPriv);
  boxPriv = privObj(vault.box); boxPub = crypto.createPublicKey(boxPriv);
  dbKey = vault.db;

  console.log(C.d('Connecting…'));
  try { await connect(mode); }
  catch (e) {
    if (mode === 'reg') fs.rmSync(DIR, { recursive: true, force: true });
    die(e.message === 'taken' ? 'That username is already taken.' : e.message === 'auth' ? 'Authentication failed.' : 'Could not reach the server.');
  }
  if (mode === 'reg') console.log(C.g('✓ Account created.'));

  const { DatabaseSync } = await import('node:sqlite');
  openDb(DatabaseSync);

  rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.on('SIGINT', quit);
  rl.on('close', quit);
  setPrompt();
  showInbox();
  rl.prompt();

  rl.on('line', async (raw) => {
    const input = raw.trim();
    try {
      if (chatWith) {
        if (input === '/back' || input === '/exit') { chatWith = null; setPrompt(); showInbox(); }
        else if (input === '/fp') await showFp(chatWith);
        else if (input) {
          readline.moveCursor(process.stdout, 0, -1); readline.clearLine(process.stdout, 0);
          const ts = await sendMsg(chatWith, input);
          console.log(line(chatWith, 'out', ts, input) + C.d(' ✓'));
        }
      } else await menu(input);
    } catch (e) { console.log(e.message.startsWith('\x1b') ? e.message : C.r('✗ ' + e.message)); }
    rl.prompt();
  });
})();
