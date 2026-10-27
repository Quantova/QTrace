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
  const owner = qt.generateKey();
  const producer = qt.generateKey();
  return { chain, ep, anchor, owner, producer };
}

async function modelOf(w, key) {
  return w.anchor(qt.registerModel({ key: key || w.owner, name: 'Atlas Vision', version: '2.1', model: Buffer.from('weights'), producers: [qt.describeKey(w.producer)] }));
}

async function outputOf(w, model) {
  return w.anchor(qt.attest({ key: w.producer, content: image, mediaType: 'image/png', model }));
}

function check(w, output, model, changes, owner) {
  return qt.verify(output, Object.assign({ content: image, model, modelOwnerKeyId: qt.keyId(owner || w.owner), withdrawals: [], ownerKeyChanges: changes }, w.ep));
}

const failed = (r, name) => r.checks.find((c) => c.name === name && !c.ok);

test('outputs anchored after the owner key was revoked verify invalid', async (t) => {
  pinned(t);
  const w = world();
  const model = await modelOf(w);
  const early = await outputOf(w, model);
  const revocation = await w.anchor(qt.revokeOwnerKey({ key: w.owner, note: 'key exposed' }));
  const late = await outputOf(w, model);
  const ok = await check(w, early, model, [revocation]);
  assert.strictEqual(ok.status, 'valid', JSON.stringify(ok.checks.filter((c) => !c.ok)));
  const bad = await check(w, late, model, [revocation]);
  assert.strictEqual(bad.status, 'invalid');
  assert.match(failed(bad, 'model owner key').detail, /before this output was anchored/);
  assert.strictEqual(bad.producerAuthorised, false);
  const after = await modelOf(w);
  const reg = await qt.verify(after, Object.assign({ ownerKeyId: qt.keyId(w.owner), ownerKeyChanges: [revocation] }, w.ep));
  assert.strictEqual(reg.status, 'invalid');
  assert.match(failed(reg, 'owner key').detail, /before this registration was anchored/);
});

test('a rotated owner key hands its models over to the successor key', async (t) => {
  pinned(t);
  const w = world();
  const successor = qt.generateKey();
  const model = await modelOf(w);
  const rotation = await w.anchor(qt.rotateOwnerKey({ key: w.owner, successor: qt.describeKey(successor) }));
  const stale = await outputOf(w, model);
  const staleResult = await check(w, stale, model, [rotation]);
  assert.strictEqual(staleResult.status, 'invalid');
  const renewed = await modelOf(w, successor);
  const fresh = await outputOf(w, renewed);
  const freshResult = await check(w, fresh, renewed, [rotation]);
  assert.strictEqual(freshResult.status, 'valid', JSON.stringify(freshResult.checks.filter((c) => !c.ok)));
  assert.match(freshResult.checks.find((c) => c.name === 'model owner').detail, /rotation/);
  const reg = await qt.verify(renewed, Object.assign({ ownerKeyId: qt.keyId(w.owner), ownerKeyChanges: [rotation] }, w.ep));
  assert.strictEqual(reg.status, 'valid', JSON.stringify(reg.checks.filter((c) => !c.ok)));
  const unrelated = await modelOf(w, qt.generateKey());
  const other = await qt.verify(unrelated, Object.assign({ ownerKeyId: qt.keyId(w.owner), ownerKeyChanges: [rotation] }, w.ep));
  assert.strictEqual(other.status, 'invalid');
});

test('owner key changes must be supplied and only the owner can make one', async (t) => {
  pinned(t);
  const w = world();
  const model = await modelOf(w);
  const output = await outputOf(w, model);
  const missing = await check(w, output, model, undefined);
  assert.strictEqual(missing.status, 'indeterminate');
  assert.ok(failed(missing, 'model owner key'));
  const forged = await w.anchor(qt.revokeOwnerKey({ key: qt.generateKey() }));
  const r = await check(w, output, model, [forged]);
  assert.strictEqual(r.status, 'valid');
  const own = await qt.verify(forged, Object.assign({ type: 'keychange', ownerKeyId: qt.keyId(w.owner) }, w.ep));
  assert.strictEqual(own.status, 'invalid');
});

test('verification never falls back to the local clock when the chain time fails', async () => {
  const owner = qt.generateKey();
  const model = qt.registerModel({ key: owner, name: 'Atlas Vision', model: Buffer.from('weights') });
  const down = { base: 'https://down.example', async nodeInfo() { throw new Error('refused by test'); }, async transaction() { return null; } };
  const down2 = Object.assign({}, down, { base: 'https://down2.example' });
  const r = await qt.verify(model, { network: 'custom', ownerKeyId: qt.keyId(owner), ownerKeyChanges: [], requireAnchor: false, trustCustomEndpoints: true, clients: [down, down2] });
  assert.strictEqual(r.status, 'indeterminate');
  const c = failed(r, 'chain time');
  assert.ok(c && c.transport);
  assert.match(c.detail, /local clock was not used/);
});

test('a fabricated receipt from endpoints that are not pinned operators never verifies valid', async () => {
  const w = world();
  const model = await modelOf(w);
  const output = await outputOf(w, model);
  const r = await check(w, output, model, []);
  assert.strictEqual(r.status, 'unproven');
  assert.strictEqual(r.anchoredAt, null);
  const single = await qt.verify(output, { content: image, model, modelOwnerKeyId: qt.keyId(w.owner), withdrawals: [], ownerKeyChanges: [], network: 'custom', trustCustomEndpoints: true, clients: [w.ep.clients[0]], trustSingleEndpoint: true });
  assert.notStrictEqual(single.status, 'valid');
  const elsewhere = makeChain(ROOT);
  const honest = await qt.verify(output, { content: image, model, modelOwnerKeyId: qt.keyId(w.owner), withdrawals: [], ownerKeyChanges: [], network: 'custom', trustCustomEndpoints: true, clients: [client(elsewhere, 'c'), client(elsewhere, 'd')] });
  assert.notStrictEqual(honest.status, 'valid');
});

test('endpoints chosen by the caller need trustCustomEndpoints, loopback needs allowLoopback and the anchor sender is checked', async (t) => {
  const w = world();
  const model = await modelOf(w);
  const output = await outputOf(w, model);
  const opts = { network: 'testnet', content: image, model, modelOwnerKeyId: qt.keyId(w.owner), withdrawals: [], ownerKeyChanges: [] };
  const untrusted = await qt.verify(output, Object.assign({ clients: w.ep.clients, at: new Date().toISOString() }, opts));
  assert.notStrictEqual(untrusted.status, 'valid');
  await assert.rejects(qt.verify(output, Object.assign({ clients: w.ep.clients, at: new Date().toISOString() }, opts, { network: 'custom' })), /trustCustomEndpoints/);
  const loop = await qt.verify(output, Object.assign({ trustCustomEndpoints: true, rpc: 'http://127.0.0.1:9', at: new Date().toISOString() }, opts));
  assert.notStrictEqual(loop.status, 'valid');
  const plainResult = await qt.verify(output, Object.assign({}, opts, w.ep));
  assert.strictEqual(plainResult.status, 'unproven');
  pinned(t);
  const wrong = await qt.verify(output, Object.assign({ expectedSender: w.chain.core.address(new Uint8Array(32).fill(9), 0) }, opts, w.ep));
  assert.strictEqual(wrong.status, 'invalid');
  const right = await qt.verify(output, Object.assign({ expectedSender: w.chain.core.address(SEED, 0) }, opts, w.ep));
  assert.strictEqual(right.status, 'valid', JSON.stringify(right.checks.filter((c) => !c.ok)));
  const custom = await qt.verify(output, Object.assign({ expectedSender: w.chain.core.address(SEED, 0) }, opts, w.ep, { network: 'custom' }));
  assert.strictEqual(custom.status, 'valid', JSON.stringify(custom.checks.filter((c) => !c.ok)));
});

test('an output with sources is indeterminate, never invalid, when only the chain time is unavailable', async (t) => {
  pinned(t);
  const w = world();
  const photo = Buffer.from('an original photograph');
  const edit = Buffer.from('an edited photograph');
  const src = await w.anchor(qt.attest({ key: w.producer, content: photo, mediaType: 'image/png', sourceType: 'digitalCreation' }));
  const out = await w.anchor(qt.attest({ key: w.producer, content: edit, mediaType: 'image/png', action: 'edited', sourceType: 'humanEdits', ingredients: [src] }));
  const opts = Object.assign({ producerKeyId: qt.keyId(w.producer), content: edit, ingredients: [src], withdrawals: [], ownerKeyChanges: [] }, w.ep);
  const good = await qt.verify(out, opts);
  assert.strictEqual(good.status, 'valid', JSON.stringify(good.checks.filter((c) => !c.ok)));
  const real = qstamp.chainTime;
  qstamp.chainTime = async () => {
    throw new Error('the endpoints did not answer in time');
  };
  let down;
  try {
    down = await qt.verify(out, opts);
  } finally {
    qstamp.chainTime = real;
  }
  assert.strictEqual(down.status, 'indeterminate', JSON.stringify(down.checks.filter((c) => !c.ok)));
  const ing = down.checks.find((c) => c.name === 'ingredients');
  assert.ok(ing && ing.ok, JSON.stringify(ing));
});

test('options are read only from the object given and never from Object.prototype', async () => {
  const w = world();
  const out = qt.attest({ key: w.producer, content: image, mediaType: 'image/png', sourceType: 'digitalCreation' });
  const opts = Object.assign({ producerKeyId: qt.keyId(w.producer), content: image }, w.ep);
  const before = await qt.verify(out, opts);
  assert.notStrictEqual(before.status, 'valid');
  const polluted = { requireAnchor: false, withdrawals: [], ownerKeyChanges: [], ingredients: [], strict: false, action: 'edited' };
  try {
    for (const [k, v] of Object.entries(polluted)) Object.prototype[k] = v;
    const after = await qt.verify(out, opts);
    assert.strictEqual(after.status, before.status, JSON.stringify(after.checks.filter((c) => !c.ok)));
    const again = qt.attest({ key: w.producer, content: image, mediaType: 'image/png', sourceType: 'digitalCreation' });
    assert.strictEqual(again.statement.action, 'created');
  } finally {
    for (const k of Object.keys(polluted)) delete Object.prototype[k];
  }
});

test('a key change signed by a key that was already rotated or revoked never verifies valid', async (t) => {
  pinned(t);
  const w = world();
  const successor = qt.generateKey();
  const rotation = await w.anchor(qt.rotateOwnerKey({ key: w.owner, successor: qt.describeKey(successor) }));
  w.chain.newBlock();
  const thief = await w.anchor(qt.rotateOwnerKey({ key: w.owner, successor: qt.describeKey(qt.generateKey()) }));
  const opts = (list) => Object.assign({ type: 'keychange', ownerKeyId: qt.keyId(w.owner), ownerKeyChanges: list }, w.ep);
  for (const list of [[rotation], [rotation, thief], [thief, rotation]]) {
    const r = await qt.verify(thief, opts(list));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(r.checks.filter((c) => !c.ok)));
    assert.ok(failed(r, 'earlier key change'));
  }
  const omitted = await qt.verify(thief, opts(undefined));
  assert.strictEqual(omitted.status, 'indeterminate');
  assert.ok(failed(omitted, 'earlier key change'));
  const first = await qt.verify(rotation, opts([rotation, thief]));
  assert.strictEqual(first.status, 'valid', JSON.stringify(first.checks.filter((c) => !c.ok)));
  w.chain.newBlock();
  const revoked = qt.generateKey();
  const revocation = await w.anchor(qt.revokeOwnerKey({ key: revoked }));
  w.chain.newBlock();
  const late = await w.anchor(qt.rotateOwnerKey({ key: revoked, successor: qt.describeKey(qt.generateKey()) }));
  const r = await qt.verify(late, Object.assign({ type: 'keychange', ownerKeyId: qt.keyId(revoked), ownerKeyChanges: [revocation] }, w.ep));
  assert.strictEqual(r.status, 'invalid');
});

test('the verify pass shares a time limit so no anchor is checked once it is reached', async () => {
  const origIsProven = qstamp.isProven;
  const origVerify = qstamp.verify;
  const origNow = performance.now.bind(performance);
  const { honest } = require('./honest');
  const h = await honest();
  let tick = 0;
  let count = 0;
  performance.now = () => { tick += 1; return tick; };
  qstamp.verify = async (...args) => { count += 1; return origVerify(...args); };
  try {
    await qt.verify(h.all.output, Object.assign({}, h.options.output, { deadlineMs: 1 }));
  } finally {
    qstamp.verify = origVerify;
    qstamp.isProven = origIsProven;
    performance.now = origNow;
  }
  assert.strictEqual(count, 0, 'no anchor was verified after the shared time limit, saw ' + count);
});
