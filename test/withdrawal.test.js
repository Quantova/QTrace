// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { world, iso } = require('./honest');
const q = require('..');

async function leaked() {
  const now = Math.floor(Date.now() / 1000);
  const w = world(now - 86400);
  const owner = q.generateKey();
  const producer = q.generateKey();
  const stranger = q.generateKey();
  const weights = Buffer.from('weights');
  const image = Buffer.from('an image');
  const t0 = now - 7300;
  const v1 = await w.anchor(q.registerModel({ key: owner, name: 'Atlas', version: '1', model: weights, producers: [q.keyId(producer)], registeredAt: iso(t0) }), t0 + 5);
  const before = await w.anchor(q.attest({ key: producer, content: image, mediaType: 'image/png', sourceType: 'trainedAlgorithmicMedia', model: v1, createdAt: iso(t0 + 1000) }), t0 + 1005);
  const v2 = await w.anchor(q.registerModel({ key: owner, name: 'Atlas', version: '2', model: weights, producers: [], registeredAt: iso(t0 + 2000) }), t0 + 2005);
  const withdrawal = await w.anchor(q.withdrawProducer({ key: owner, model: v1, producer: q.keyId(producer), withdrawnAt: iso(t0 + 3000) }), t0 + 3005);
  const after = await w.anchor(q.attest({ key: producer, content: image, mediaType: 'image/png', sourceType: 'trainedAlgorithmicMedia', model: v1, createdAt: iso(t0 + 6000) }), t0 + 6005);
  const strangerModel = await w.anchor(q.registerModel({ key: stranger, name: 'Atlas', version: '1', model: weights, producers: [q.keyId(producer)], registeredAt: iso(t0 + 6100) }), t0 + 6105);
  const strangerWithdrawal = await w.anchor(q.withdrawProducer({ key: stranger, model: strangerModel, producer: q.keyId(producer), withdrawnAt: iso(t0 + 6200) }), t0 + 6205);
  w.chain.newBlock(now);
  const opts = Object.assign({ type: 'output', producerKeyId: q.keyId(producer), modelOwnerKeyId: q.keyId(owner), model: v1, content: image, ownerKeyChanges: [], at: iso(now) }, w.ep);
  return { v2, before, after, withdrawal, strangerWithdrawal, opts };
}

test('an output a withdrawn producer anchors after the withdrawal is invalid, an earlier one stays valid', async () => {
  const s = await leaked();
  const late = await q.verify(s.after, Object.assign({ withdrawals: [s.withdrawal] }, s.opts));
  assert.strictEqual(late.status, 'invalid');
  assert.notStrictEqual(late.producerAuthorised, true);
  const early = await q.verify(s.before, Object.assign({ withdrawals: [s.withdrawal] }, s.opts));
  assert.strictEqual(early.status, 'valid', JSON.stringify(early.checks.filter((c) => !c.ok)));
});

test('an output is never valid when the verifier states no withdrawal list', async () => {
  const s = await leaked();
  const r = await q.verify(s.after, s.opts);
  assert.strictEqual(r.valid, false);
  assert.ok(r.checks.some((c) => c.name === 'withdrawals' && !c.ok));
});

test('a withdrawal signed by anyone other than the model owner is ignored', async () => {
  const s = await leaked();
  const r = await q.verify(s.after, Object.assign({ withdrawals: [s.strangerWithdrawal] }, s.opts));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  const both = await q.verify(s.after, Object.assign({ withdrawals: [s.strangerWithdrawal, s.withdrawal] }, s.opts));
  assert.strictEqual(both.status, 'invalid');
});

test('an output never borrows a later registration of the model', async () => {
  const s = await leaked();
  const r = await q.verify(s.after, Object.assign({ withdrawals: [s.withdrawal] }, s.opts, { model: s.v2 }));
  assert.strictEqual(r.valid, false);
});

test('an output claimed more than a day before its anchor, or anchored after the time of verification, is not proven', async () => {
  const now = Math.floor(Date.now() / 1000);
  const w = world(now - 4 * 86400);
  const producer = q.generateKey();
  const image = Buffer.from('img');
  const make = (t) => q.attest({ key: producer, content: image, mediaType: 'image/png', sourceType: 'digitalCreation', createdAt: iso(t) });
  const old = await w.anchor(make(now - 3 * 86400 - 60), now - 60);
  const fresh = await w.anchor(make(now - 180), now - 60);
  w.chain.newBlock(now);
  const opts = Object.assign({ type: 'output', producerKeyId: q.keyId(producer), content: image, withdrawals: [], ownerKeyChanges: [] }, w.ep);
  const late = await q.verify(old, opts);
  assert.strictEqual(late.valid, false);
  assert.ok(late.checks.some((c) => !c.ok && /24 hours/.test(c.detail)));
  assert.strictEqual((await q.verify(old, Object.assign({ maxAnchorDelay: 4 * 86400 }, opts))).status, 'valid');
  assert.strictEqual((await q.verify(fresh, opts)).status, 'valid');
  const asOf = await q.verify(fresh, Object.assign({ at: iso(now - 1800) }, opts));
  assert.strictEqual(asOf.valid, false);
});
