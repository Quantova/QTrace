'use strict';

const path = require('path');
const q = require('..');
const { makeChain, client, SEED, qstampRoot } = require('./chain');

const ROOT = path.join(__dirname, '..');
const qstamp = require(qstampRoot(ROOT));

function confirmedByTestChain(r) {
  return !!r && r.status === 'unproven' && r.trust === 'custom-endpoints' && Array.isArray(r.checks) && r.checks.every((c) => c.ok || c.name === 'proof');
}

qstamp.isProven = confirmedByTestChain;

const iso = (s) => new Date(s * 1000).toISOString();
const failing = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name + ': ' + c.detail);

function world(startTime) {
  const chain = makeChain(ROOT, { time: startTime });
  const ep = { clients: [client(chain, 'a'), client(chain, 'b')], trustCustomEndpoints: true };
  const anchor = async (env, t) => {
    chain.nextBlockTime = t;
    return (await q.anchor(env, Object.assign({ seed: SEED, index: 0 }, ep)))[0];
  };
  return { chain, ep, anchor };
}

async function honest() {
  const now = Math.floor(Date.now() / 1000);
  const w = world(now - 86400);
  const K = { owner: q.generateKey(), producer: q.generateKey(), successor: q.generateKey() };
  const weights = Buffer.from('model weights');
  const image = Buffer.from('an image made by a model');
  const t0 = now - 80000;
  const model = await w.anchor(q.registerModel({ key: K.owner, name: 'Atlas Vision', version: '3', model: weights, producers: [q.describeKey(K.producer)], registeredAt: iso(t0) }), t0 + 5);
  const output = await w.anchor(q.attest({ key: K.producer, content: image, mediaType: 'image/png', model, createdAt: iso(t0 + 10) }), t0 + 15);
  const withdrawal = await w.anchor(q.withdrawProducer({ key: K.owner, model, producer: q.keyId(K.producer), withdrawnAt: iso(t0 + 20) }), t0 + 25);
  const keychange = await w.anchor(q.rotateOwnerKey({ key: K.owner, successor: q.describeKey(K.successor), changedAt: iso(t0 + 30) }), t0 + 35);
  w.chain.newBlock(now);
  const common = Object.assign({ at: iso(now) }, w.ep);
  const options = {
    model: Object.assign({ type: 'model', ownerKeyId: q.keyId(K.owner), ownerKeyChanges: [keychange], artefact: weights }, common),
    output: Object.assign({ type: 'output', content: image, model, producerKeyId: q.keyId(K.producer), modelOwnerKeyId: q.keyId(K.owner), withdrawals: [withdrawal], ownerKeyChanges: [keychange] }, common),
    keychange: Object.assign({ type: 'keychange', ownerKeyId: q.keyId(K.owner) }, common),
  };
  return { q, w, now, K, weights, image, options, all: { model, output, withdrawal, keychange } };
}

module.exports = { honest, world, iso, failing, ROOT };
