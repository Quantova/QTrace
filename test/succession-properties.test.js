'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { mulberry32, iterations } = require('./fuzz');
const { world, iso, failing } = require('./honest');

const ROUNDS = iterations(40);
const image = Buffer.from('an image made by a model');

function failed(r, name, pattern) {
  return r.checks.some((c) => c.name === name && !c.ok && (!pattern || pattern.test(c.detail)));
}

function plan(rng, now) {
  const int = (k) => Math.floor(rng() * k);
  const n = 1 + int(3);
  const start = now - 80000;
  const end = now - 100;
  const step = (end - start) / (n + 1);
  const bounds = [start];
  for (let i = 1; i <= n; i += 1) bounds.push(Math.round(start + step * (i - 0.3 + 0.6 * rng())));
  bounds.push(end);
  const used = new Set(bounds);
  const slot = (lo, hi) => {
    for (;;) {
      const v = lo + int(hi - lo);
      if (!used.has(v)) {
        used.add(v);
        return v;
      }
    }
  };
  const records = [];
  for (let x = 0; x <= n; x += 1) {
    const count = 2 + int(2);
    for (let k = 0; k < count; k += 1) records.push({ x, s: int(n + 1) });
  }
  const own = int(n + 1);
  records.push({ x: own, s: own });
  for (const rec of records) {
    rec.time = slot(bounds[rec.s] + 2, bounds[rec.s + 1] - 60);
    if (int(5) < 2) rec.outputTime = slot(rec.time + 1, rec.time + 50);
    if (rec.s === rec.x && rec.x > 0 && int(2) === 0) {
      const e = int(rec.x);
      rec.earlyTime = slot(bounds[e] + 2, bounds[e + 1] - 60);
    }
    rec.lag = int(30);
  }
  return { n, bounds, records, int };
}

test('a record anchored before an owner key handover never verifies as the earlier owner\'s, while the successor\'s records after it do', async (t) => {
  const rng = mulberry32(0x5acc);
  const counts = { rounds: ROUNDS, handovers: 0, before: 0, during: 0, retired: 0, outputsBefore: 0, outputsDuring: 0, outputsRetired: 0, outputsBeforeHandoverOfModel: 0 };
  for (let round = 0; round < ROUNDS; round += 1) {
    const now = Math.floor(Date.now() / 1000);
    const p = plan(rng, now);
    const w = world(now - 86400);
    const keys = Array.from({ length: p.n + 1 }, () => q.generateKey());
    const producer = q.generateKey();
    const events = [];
    const changes = [];
    for (let i = 1; i <= p.n; i += 1) {
      const h = p.bounds[i];
      events.push({ time: h, make: () => q.rotateOwnerKey({ key: keys[i - 1], successor: q.describeKey(keys[i]), changedAt: iso(h - p.int(30)) }), done: (env) => changes.push(env) });
    }
    if (p.int(2) === 0) {
      const tm = p.bounds[1] - 30;
      events.push({ time: tm, make: () => q.revokeOwnerKey({ key: q.generateKey(), changedAt: iso(tm) }), done: (env) => changes.push(env) });
    }
    for (const rec of p.records) {
      const signed = q.registerModel({ key: keys[rec.x], name: 'Atlas Vision', version: String(rec.x), model: Buffer.from('weights ' + rec.x), producers: [q.describeKey(producer)], registeredAt: iso(Math.min(rec.time, rec.earlyTime || rec.time) - rec.lag) });
      events.push({ time: rec.time, make: () => signed, done: (env) => { rec.model = env; } });
      if (rec.outputTime !== undefined) {
        events.push({ time: rec.outputTime, make: () => q.attest({ key: producer, content: image, mediaType: 'image/png', model: signed, createdAt: iso(rec.outputTime) }), done: (env) => { rec.output = env; } });
      }
      if (rec.earlyTime !== undefined) {
        events.push({ time: rec.earlyTime, make: () => q.attest({ key: producer, content: image, mediaType: 'image/png', model: signed, createdAt: iso(rec.earlyTime) }), done: (env) => { rec.early = env; } });
      }
    }
    events.sort((a, b) => a.time - b.time);
    for (const e of events) e.done(await w.anchor(e.make(), e.time));
    w.chain.newBlock(now);
    for (let i = changes.length - 1; i > 0; i -= 1) {
      const j = p.int(i + 1);
      [changes[i], changes[j]] = [changes[j], changes[i]];
    }
    counts.handovers += p.n;
    const common = Object.assign({ ownerKeyChanges: changes, at: iso(now) }, w.ep);
    for (const rec of p.records) {
      const where = 'round ' + round + ', key ' + rec.x + ' of ' + p.n + ' handovers, anchored in segment ' + rec.s;
      const r = await q.verify(rec.model, Object.assign({ type: 'model', ownerKeyId: q.keyId(keys[0]) }, common));
      if (rec.s < rec.x) {
        assert.strictEqual(r.status, 'invalid', where + ' verified ' + r.status);
        assert.ok(failed(r, 'expected owner', /anchored before/), where + ' ' + failing(r).join('\n'));
        counts.before += 1;
      } else if (rec.s === rec.x) {
        assert.strictEqual(r.status, 'valid', where + ' ' + failing(r).join('\n'));
        counts.during += 1;
      } else {
        assert.strictEqual(r.status, 'invalid', where + ' verified ' + r.status);
        assert.ok(failed(r, 'owner key', /retired at/), where + ' ' + failing(r).join('\n'));
        counts.retired += 1;
      }
      const outputCheck = (env) => q.verify(env, Object.assign({ type: 'output', content: image, model: rec.model, modelOwnerKeyId: q.keyId(keys[0]), producerKeyId: q.keyId(producer), withdrawals: [] }, common));
      if (rec.early) {
        const e = await outputCheck(rec.early);
        assert.strictEqual(e.status, 'invalid', where + ' output anchored before the handover verified ' + e.status);
        assert.ok(failed(e, 'model owner handover', /anchored before/), where + ' ' + failing(e).join('\n'));
        assert.strictEqual(e.producerAuthorised, false, where + ' output anchored before the handover kept its producer authorised');
        counts.outputsBeforeHandoverOfModel += 1;
      }
      if (!rec.output) continue;
      const o = await outputCheck(rec.output);
      if (rec.s === rec.x) {
        assert.strictEqual(o.status, 'valid', where + ' output ' + failing(o).join('\n'));
        counts.outputsDuring += 1;
      } else {
        assert.strictEqual(o.status, 'invalid', where + ' output verified ' + o.status);
        assert.strictEqual(o.producerAuthorised === true, false, where + ' output kept its producer authorised');
        if (rec.s < rec.x) counts.outputsBefore += 1;
        else counts.outputsRetired += 1;
      }
    }
  }
  assert.ok(counts.before > 0 && counts.during > 0 && counts.retired > 0 && counts.outputsBeforeHandoverOfModel > 0, JSON.stringify(counts));
  t.diagnostic(JSON.stringify(counts));
});
