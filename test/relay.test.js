import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import { startServer, oauthFlow, connectPhone, mcp, linkLegacy, postJson, PHONE, PHONE2, RELAY_TOKEN, RELAY_TOKEN2 } from './helpers.js';

test('/mcp requires a valid, unexpired access token; WWW-Authenticate is set', async () => {
  const s = await startServer();
  try {
    const none = await mcp(s, null);
    assert.equal(none.status, 401);
    assert.match(none.headers.get('www-authenticate'), /Bearer/);
    assert.equal((await mcp(s, 'nope')).status, 401);
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const f = await oauthFlow(s, PHONE);
    s.db.prepare('UPDATE access_tokens SET expires_at = ?').run(Date.now() - 1);
    assert.equal((await mcp(s, f.tokens.access_token)).status, 401);
  } finally { await s.close(); }
});

test('relay routes each Claude call to the right phone only', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    await linkLegacy(s, PHONE2, RELAY_TOKEN2);
    const a = await connectPhone(s, RELAY_TOKEN, (p) => ({ who: 'A', p }));
    const b = await connectPhone(s, RELAY_TOKEN2, (p) => ({ who: 'B', p }));
    const fa = await oauthFlow(s, PHONE);
    const fb = await oauthFlow(s, PHONE2);
    const ra = await (await mcp(s, fa.tokens.access_token, { id: 1, method: 'x' })).json();
    const rb = await (await mcp(s, fb.tokens.access_token, { id: 2, method: 'y' })).json();
    assert.equal(ra.who, 'A');
    assert.equal(rb.who, 'B');
    assert.equal(a.ws.received.length, 1);
    assert.equal(b.ws.received.length, 1);
  } finally { await s.close(); }
});

test('a phone cannot answer a request that was sent to a different phone', async () => {
  const s = await startServer({});
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    await linkLegacy(s, PHONE2, RELAY_TOKEN2);
    const victim = await connectPhone(s, RELAY_TOKEN, () => undefined); // never answers
    const evil = await connectPhone(s, RELAY_TOKEN2, () => undefined);
    const f = await oauthFlow(s, PHONE);
    const call = mcp(s, f.tokens.access_token, { id: 7 });
    await new Promise((r) => setTimeout(r, 100));
    const sentToVictim = victim.ws.received.length;
    assert.equal(sentToVictim, 1);
    // find the correlation id the server is waiting on and have the other phone forge a reply
    const [id] = [...s.pendingRelayCalls.keys()];
    evil.ws.send(JSON.stringify({ correlationId: id, payload: { forged: true } }));
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(s.pendingRelayCalls.size, 1, 'forged reply ignored');
    victim.ws.close();
    const res = await call;
    assert.equal(res.status, 503, 'pending call fails fast when the real phone disconnects');
  } finally { await s.close(); }
});

test('offline phone is 503; malformed frames do not crash the server', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const f = await oauthFlow(s, PHONE);
    assert.equal((await mcp(s, f.tokens.access_token)).status, 503);
    const c = await connectPhone(s, RELAY_TOKEN, () => undefined);
    for (const frame of ['null', '7', '"x"', '[]', '{bad', '{"correlationId":{"a":1}}']) c.ws.send(frame);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal((await fetch(`${s.base}/healthz`)).status, 200);
    assert.equal(c.ws.readyState, 1);
    assert.equal((await postJson(`${s.base}/mcp`, [1], { Authorization: `Bearer ${f.tokens.access_token}` })).status !== 500, true);
    const nonObject = await fetch(`${s.base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', Authorization: `Bearer ${f.tokens.access_token}` }, body: '5' });
    assert.ok([400].includes(nonObject.status));
  } finally { await s.close(); }
});

test('per-phone in-flight cap and relay timeout bound resource use', async () => {
  const s = await startServer({ env: { MAX_PENDING_RELAY_PER_PHONE: '2' } });
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    await connectPhone(s, RELAY_TOKEN, () => undefined);
    const f = await oauthFlow(s, PHONE);
    const p1 = mcp(s, f.tokens.access_token); const p2 = mcp(s, f.tokens.access_token);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal((await mcp(s, f.tokens.access_token)).status, 429);
    // clean up pending timers so the test exits promptly
    for (const p of s.pendingRelayCalls.values()) { clearTimeout(p.timeout); p.reject(new Error('relay_timeout')); }
    assert.equal((await p1).status, 504); assert.equal((await p2).status, 504);
  } finally { await s.close(); }
});

test('oversized /mcp body is rejected', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const f = await oauthFlow(s, PHONE);
    const r = await postJson(`${s.base}/mcp`, { pad: 'x'.repeat(300_000) }, { Authorization: `Bearer ${f.tokens.access_token}` });
    assert.equal(r.status, 413);
  } finally { await s.close(); }
});

test('message bodies pass through memory only: never in the database file, tables, or logs', async () => {
  const s = await startServer();
  try {
    await linkLegacy(s, PHONE, RELAY_TOKEN);
    const secretIn = 'MSG-BODY-SECRET-IN-7731';
    const secretOut = 'MSG-BODY-SECRET-OUT-9942';
    await connectPhone(s, RELAY_TOKEN, () => ({ result: { text: secretOut } }));
    const f = await oauthFlow(s, PHONE);
    const r = await mcp(s, f.tokens.access_token, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { text: secretIn } });
    assert.match(JSON.stringify(await r.json()), new RegExp(secretOut));
    s.db.pragma('wal_checkpoint(TRUNCATE)');
    for (const marker of [secretIn, secretOut]) {
      const dump = JSON.stringify(s.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().flatMap((t) => s.db.prepare(`SELECT * FROM ${t.name}`).all()));
      assert.ok(!dump.includes(marker), 'not in any table');
      for (const f2 of [s.dbPath, `${s.dbPath}-wal`]) if (fs.existsSync(f2)) assert.ok(!fs.readFileSync(f2).includes(marker), `not in ${f2}`);
      assert.ok(!s.logs.join('\n').includes(marker), 'not in logs');
    }
    assert.ok(!s.logs.join('\n').includes('4155550101'), 'phone numbers not logged');
  } finally { await s.close(); }
});
