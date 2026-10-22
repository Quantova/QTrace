// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const qt = require('..');
const { makeChain, client, SEED } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require('@quantovainc/qstamp');
const image = Buffer.from('an image made by a model');

function pinned(t) {
  const had = Object.prototype.hasOwnProperty.call(qstamp, 'isProven');
  const before = qstamp.isProven;
  qstamp.isProven = () => true;
  t.after(() => {
    if (had) qstamp.isProven = before;
    else delete qstamp.isProven;
  });
}

function world() {
  const chain = makeChain(ROOT);
  const ep = { network: 'testnet', trustCustomEndpoints: true, clients: [client(chain, 'a'), client(chain, 'b')] };
  const anchor = async (env) => (await qt.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  return { chain, ep, anchor, k1: qt.generateKey(), k2: qt.generateKey(), k3: qt.generateKey(), producer: qt.generateKey() };
}

function inLastBlock(chain) {
  const original = chain.submitCall;
  chain.submitCall = function (from, to, argsHex) {
    chain.submitCall = original;
    const prev = chain.height;
    const txId = original(from, to, argsHex);
    const tx = chain.txs.get(txId);
    const target = chain.blocks.get(prev);
    chain.events.get(prev).push(...chain.events.get(tx.height));
    chain.events.delete(tx.height);
    chain.blocks.delete(tx.height);
    chain.height = prev;
    chain.time = target.time;
    tx.height = prev;
    tx.block = target.block;
    return txId;
  };
}

function model(w, key, extra) {
  return qt.registerModel(Object.assign({ key, name: 'Atlas Vision', version: '3', model: Buffer.from('weights'), producers: [qt.describeKey(w.producer)] }, extra || {}));
}

const handover = (w, from, to) => w.anchor(qt.rotateOwnerKey({ key: from, successor: qt.describeKey(to) }));
const asOwner = (w, env, changes, extra) => qt.verify(env, Object.assign({ ownerKeyId: qt.keyId(w.k1), ownerKeyChanges: changes }, w.ep, extra || {}));
const outputCheck = (w, out, m, changes) => qt.verify(out, Object.assign({ content: image, model: m, modelOwnerKeyId: qt.keyId(w.k1), withdrawals: [], ownerKeyChanges: changes }, w.ep));
const failed = (r, name) => r.checks.find((c) => c.name === name && !c.ok);
const open = (r) => JSON.stringify(r.checks.filter((c) => !c.ok));

test('a model registered by the successor key before the handover is not the model of the expected owner', async (t) => {
  pinned(t);
  const w = world();
  const early = await w.anchor(model(w, w.k2));
  const rotation = await handover(w, w.k1, w.k2);
  const late = await w.anchor(model(w, w.k2));
  const before = await asOwner(w, early, [rotation]);
  assert.strictEqual(before.status, 'invalid');
  assert.match(failed(before, 'expected owner').detail, /anchored before .* handed over/);
  const after = await asOwner(w, late, [rotation]);
  assert.strictEqual(after.status, 'valid', open(after));
  assert.match(after.checks.find((c) => c.name === 'expected owner').detail, /after that rotation/);
  const earlyOut = await outputCheck(w, await w.anchor(qt.attest({ key: w.producer, content: image, mediaType: 'image/png', model: early })), early, [rotation]);
  assert.strictEqual(earlyOut.status, 'invalid');
  assert.ok(failed(earlyOut, 'model owner'));
  assert.strictEqual(earlyOut.model, null);
  const lateOut = await outputCheck(w, await w.anchor(qt.attest({ key: w.producer, content: image, mediaType: 'image/png', model: late })), late, [rotation]);
  assert.strictEqual(lateOut.status, 'valid', open(lateOut));
});

test('an output anchored before the handover does not speak for the expected owner even when its model was anchored after', async (t) => {
  pinned(t);
  const w = world();
  const signed = model(w, w.k2);
  const out = await w.anchor(qt.attest({ key: w.producer, content: image, mediaType: 'image/png', model: signed }));
  const rotation = await handover(w, w.k1, w.k2);
  const m = await w.anchor(signed);
  const reg = await asOwner(w, m, [rotation]);
  assert.strictEqual(reg.status, 'valid', open(reg));
  const r = await outputCheck(w, out, m, [rotation]);
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'model owner handover').detail, /anchored before/);
  assert.strictEqual(r.producerAuthorised, false);
});

test('a successor record whose order against the handover cannot be proven is indeterminate', async (t) => {
  pinned(t);
  const w = world();
  const rotation = await handover(w, w.k1, w.k2);
  const handedAt = rotation.anchor.anchor.time;
  const stated = (s) => new Date((handedAt + s) * 1000).toISOString();
  const laterClaim = await asOwner(w, model(w, w.k2, { registeredAt: stated(60) }), [rotation], { requireAnchor: false });
  assert.strictEqual(laterClaim.status, 'indeterminate', open(laterClaim));
  const c = failed(laterClaim, 'expected owner');
  assert.ok(c && c.indeterminate);
  assert.match(c.detail, /no proven anchor time/);
  const earlierClaim = await asOwner(w, model(w, w.k2, { registeredAt: stated(-3600) }), [rotation], { requireAnchor: false });
  assert.strictEqual(earlierClaim.status, 'invalid');
  assert.match(failed(earlierClaim, 'expected owner').detail, /states a time before/);
  inLastBlock(w.chain);
  const same = await w.anchor(model(w, w.k2));
  assert.strictEqual(same.anchor.anchor.height, rotation.anchor.anchor.height);
  const r = await asOwner(w, same, [rotation]);
  assert.strictEqual(r.status, 'indeterminate', open(r));
  assert.match(failed(r, 'expected owner').detail, /same block/);
});

test('every step of a chain of handovers is checked', async (t) => {
  pinned(t);
  const w = world();
  const first = await handover(w, w.k1, w.k2);
  const between = await w.anchor(model(w, w.k3));
  const second = await handover(w, w.k2, w.k3);
  const late = await w.anchor(model(w, w.k3));
  const ok = await asOwner(w, late, [first, second]);
  assert.strictEqual(ok.status, 'valid', open(ok));
  const mid = await asOwner(w, between, [first, second]);
  assert.strictEqual(mid.status, 'invalid');
  assert.match(failed(mid, 'expected owner').detail, /anchored before/);
  const v = world();
  const premature = await handover(v, v.k2, v.k3);
  const real = await handover(v, v.k1, v.k2);
  const m = await v.anchor(model(v, v.k3));
  const r = await asOwner(v, m, [premature, real]);
  assert.strictEqual(r.status, 'invalid');
  assert.match(failed(r, 'expected owner').detail, /different owner/);
  const direct = await asOwner(v, await v.anchor(model(v, v.k2)), [premature, real]);
  assert.strictEqual(direct.status, 'invalid');
  assert.match(failed(direct, 'owner key').detail, /retired/);
});
