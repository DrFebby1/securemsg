// SecureMsg server — Cloudflare Worker + one Durable Object per user.
// The server only ever sees: usernames, PUBLIC keys, and opaque encrypted envelopes.
// No passwords, no plaintext, no private keys.

const NAME = /^[a-z0-9_]{3,20}$/;
const MAX_FRAME = 32 * 1024;        // max websocket frame
const MAX_QUEUE = 2000;             // max offline messages per user
const TTL = 30 * 24 * 3600 * 1000;  // offline messages expire after 30 days
const enc = new TextEncoder();

const unb = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const isKey32 = (s) => { try { return typeof s === 'string' && unb(s).length === 32; } catch { return false; } };

async function verify(pubB64, msg, sigB64) {
  try {
    const key = await crypto.subtle.importKey('raw', unb(pubB64), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, unb(sigB64), enc.encode(msg));
  } catch { return false; }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === '/ws') {
      if (req.headers.get('Upgrade') !== 'websocket') return new Response('Upgrade required', { status: 426 });
      const u = (url.searchParams.get('u') || '').toLowerCase();
      if (!NAME.test(u)) return new Response('bad username', { status: 400 });
      const stub = env.MAILBOX.get(env.MAILBOX.idFromName(u));
      return stub.fetch(new Request(`https://do/ws?u=${u}`, req));
    }
    return new Response('SecureMsg server', { status: 200 });
  },
};

export class Mailbox {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }

  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === '/ws') {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server);
      const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
      server.serializeAttachment({ name: url.searchParams.get('u'), nonce, auth: false, w: 0, c: 0 });
      server.send(JSON.stringify({ t: 'chal', nonce }));
      return new Response(null, { status: 101, webSocket: client });
    }

    // Internal calls (Durable Object -> Durable Object only; never routed from the internet)
    if (url.pathname === '/pub') {
      const u = await this.ctx.storage.get('user');
      return u ? Response.json({ sigPub: u.sigPub, boxPub: u.boxPub }) : new Response('no', { status: 404 });
    }

    if (url.pathname === '/deliver' && req.method === 'POST') {
      if (!(await this.ctx.storage.get('user'))) return new Response('no', { status: 404 });
      const { env: e } = await req.json();
      const n = (await this.ctx.storage.list({ prefix: 'q:', limit: MAX_QUEUE })).size;
      if (n >= MAX_QUEUE) return new Response('full', { status: 429 });
      const ts = Date.now();
      const id = String(ts).padStart(15, '0') + '-' + crypto.randomUUID().slice(0, 8);
      const rec = { id, ts, env: e };
      await this.ctx.storage.put('q:' + id, rec); // kept until the client ACKs it
      for (const s of this.ctx.getWebSockets()) {
        if (s.deserializeAttachment()?.auth) { try { s.send(JSON.stringify({ t: 'msg', ...rec })); } catch {} }
      }
      return new Response('ok');
    }
    return new Response('not found', { status: 404 });
  }

  async webSocketMessage(ws, data) {
    if (typeof data !== 'string' || data.length > MAX_FRAME) return ws.close(1009, 'too big');
    const att = ws.deserializeAttachment() || {};
    const now = Date.now();
    if (now - att.w > 10000) { att.w = now; att.c = 0; }
    if (++att.c > 60) return ws.close(1008, 'rate limit');
    ws.serializeAttachment(att);

    let m;
    try { m = JSON.parse(data); } catch { return; }
    const send = (o) => ws.send(JSON.stringify(o));

    // ---------- authentication ----------
    if (!att.auth) {
      if (m.t === 'reg') {
        if (!isKey32(m.sigPub) || !isKey32(m.boxPub)) return ws.close(1008, 'bad keys');
        const ok = await verify(m.sigPub, `register|${att.name}|${att.nonce}|${m.sigPub}|${m.boxPub}`, m.sig);
        if (!ok) { send({ t: 'err', code: 'auth' }); return ws.close(1008); }
        // get + put with only storage awaits in between => atomic (no race for the same name)
        if (await this.ctx.storage.get('user')) { send({ t: 'err', code: 'taken' }); return ws.close(1000); }
        await this.ctx.storage.put('user', { sigPub: m.sigPub, boxPub: m.boxPub, created: now });
      } else if (m.t === 'login') {
        const user = await this.ctx.storage.get('user');
        const ok = user && (await verify(user.sigPub, `login|${att.name}|${att.nonce}`, m.sig));
        if (!ok) { send({ t: 'err', code: 'auth' }); return ws.close(1008); }
      } else return;

      att.auth = true;
      ws.serializeAttachment(att);
      send({ t: 'ok' });
      // flush the mailbox
      const q = await this.ctx.storage.list({ prefix: 'q:' });
      const dead = [];
      for (const [k, v] of q) {
        if (now - v.ts > TTL) dead.push(k);
        else send({ t: 'msg', id: v.id, ts: v.ts, env: v.env });
      }
      if (dead.length) await this.ctx.storage.delete(dead.slice(0, 128));
      return;
    }

    // ---------- authenticated ----------
    if (m.t === 'lookup' && NAME.test(m.u || '')) {
      const r = await this.stub(m.u).fetch('https://do/pub');
      if (!r.ok) return send({ t: 'pub', cid: m.cid, u: m.u, found: false });
      const p = await r.json();
      return send({ t: 'pub', cid: m.cid, u: m.u, found: true, ...p });
    }

    if (m.t === 'send') {
      const e = m.env;
      if (!NAME.test(m.to || '') || m.to === att.name || !e || ![e.e, e.i, e.c].every((x) => typeof x === 'string')) {
        return send({ t: 'sent', cid: m.cid, ok: false, code: 'bad' });
      }
      const r = await this.stub(m.to).fetch('https://do/deliver', { method: 'POST', body: JSON.stringify({ env: { e: e.e, i: e.i, c: e.c } }) });
      const code = r.status === 404 ? 'nouser' : r.status === 429 ? 'full' : r.ok ? undefined : 'error';
      return send({ t: 'sent', cid: m.cid, ok: r.ok, code });
    }

    if (m.t === 'ack' && Array.isArray(m.ids)) {
      const keys = m.ids.slice(0, 100).filter((i) => typeof i === 'string' && i.length < 40).map((i) => 'q:' + i);
      if (keys.length) await this.ctx.storage.delete(keys);
    }
  }

  stub(name) { return this.env.MAILBOX.get(this.env.MAILBOX.idFromName(name)); }
  webSocketClose(ws) { try { ws.close(); } catch {} }
  webSocketError(ws) { try { ws.close(); } catch {} }
}
