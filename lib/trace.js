// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  return Object.assign(Object.create(null), value);
}

const KIND = Object.freeze({ model: 'ai_model', output: 'ai_output', withdrawal: 'ai_model', keychange: 'ai_model' });
const IPTC = 'http://cv.iptc.org/newscodes/digitalsourcetype/';

function requireSeed(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  return key;
}

function generateKey() {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qtrace-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

function textOption(value, max, what, required) {
  const v = value === undefined ? '' : value;
  const p = F.textProblem(v, max, what, required);
  if (p) F.reject(p);
  return v;
}

function timeOption(value, what) {
  const v = value === undefined ? new Date().toISOString() : value;
  const p = F.timeProblem(v, what);
  if (p) F.reject(p);
  return v;
}

function digestOption(options, bytesKey, digestKey, what, required) {
  const given = [bytesKey, digestKey].filter((k) => options[k] !== undefined);
  if (given.length > 1) F.reject('give ' + bytesKey + ' or ' + digestKey + ', not both');
  if (given.length === 0) {
    if (required) F.reject(what + ' is required, give ' + bytesKey + ' or ' + digestKey);
    return { digest: '', size: null };
  }
  if (options[bytesKey] !== undefined) {
    if (!(options[bytesKey] instanceof Uint8Array)) F.reject(bytesKey + ' is a Uint8Array');
    return { digest: F.sha3(options[bytesKey]).toString('hex'), size: options[bytesKey].length };
  }
  const d = options[digestKey];
  if (typeof d !== 'string' || !/^[0-9a-f]{64}$/.test(d)) F.reject(digestKey + ' is 64 lowercase hex characters, the SHA3-256 of ' + what);
  return { digest: d, size: null };
}

function keyIdFrom(value, what) {
  if (typeof value === 'string') {
    if (!/^[0-9a-f]{64}$/.test(value)) F.reject(what + ' is a key id of 64 lowercase hex characters');
    return value;
  }
  if (value instanceof Uint8Array) return F.keyIdOf(value);
  if (value && typeof value === 'object' && value.format === 'qtrace-key/1' && typeof value.publicKey === 'string') {
    const raw = Buffer.from(value.publicKey, 'base64');
    if (raw.toString('base64') !== value.publicKey) F.reject(what + ' holds a public key that is not canonical base64');
    const id = F.keyIdOf(raw);
    if (value.id !== undefined && value.id !== id) F.reject(what + ' names an id that does not match its public key');
    return id;
  }
  F.reject(what + ' is a key id, a public key or a qtrace-key/1 description');
}

function sign(type, statement, key) {
  const pk = publicKey(key);
  const problem = F.statementProblem(type, statement);
  if (problem) F.reject(problem);
  const message = F.payload(type, statement);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') },
    statement,
    signature: Buffer.from(signature).toString('base64'),
  };
}

function signedEnvelope(envelope, type, what) {
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    F.reject(what + ' is not a valid envelope, ' + e.message);
  }
  if (p.type !== type) F.reject(what + ' must be a ' + type + ' envelope');
  if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== F.boundKey(p) || !native.verify(p.publicKey, F.payload(p.type, p.statement), p.signature)) {
    F.reject(what + ' is not validly signed by the key it names');
  }
  return p;
}

function registerModel(options) {
  if (!options || typeof options !== 'object') F.reject('registerModel needs options');
  options = own(options);
  requireSeed(options.key);
  const owner = keyId(options.key);
  const model = digestOption(options, 'model', 'modelDigest', 'the model artefact', true);
  const card = digestOption(options, 'card', 'cardDigest', 'the model card', false);
  const list = options.producers === undefined ? [] : options.producers;
  if (!Array.isArray(list) || list.length > F.PRODUCERS_MAX) F.reject('producers is a list of at most ' + F.PRODUCERS_MAX + ' keys');
  const producers = list.map((v, i) => keyIdFrom(v, 'producer ' + (i + 1)));
  if (new Set(producers).size !== producers.length) F.reject('producers must not repeat a key');
  return sign('model', {
    modelId: randomHex(16),
    ownerKeyId: owner,
    name: textOption(options.name, F.NAME_MAX, 'name', true),
    version: textOption(options.version, F.VERSION_MAX, 'version', false),
    modelDigest: model.digest,
    cardDigest: card.digest,
    producers,
    registeredAt: timeOption(options.registeredAt, 'registeredAt'),
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function withdrawProducer(options) {
  if (!options || typeof options !== 'object') F.reject('withdrawProducer needs options');
  options = own(options);
  requireSeed(options.key);
  const model = signedEnvelope(options.model, 'model', 'the model registration');
  const owner = keyId(options.key);
  if (owner !== model.statement.ownerKeyId) F.reject('only the owner of the model can withdraw a producer');
  const producer = keyIdFrom(options.producer, 'producer');
  if (producer === owner) F.reject('the owner key cannot be withdrawn as a producer');
  return sign('withdrawal', {
    withdrawalId: randomHex(16),
    ownerKeyId: owner,
    modelId: model.statement.modelId,
    producerKeyId: producer,
    withdrawnAt: timeOption(options.withdrawnAt, 'withdrawnAt'),
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function changeOwnerKey(options, successor) {
  requireSeed(options.key);
  const owner = keyId(options.key);
  if (successor === owner) F.reject('the successor must be a different key');
  return sign('keychange', {
    changeId: randomHex(16),
    ownerKeyId: owner,
    successorKeyId: successor,
    changedAt: timeOption(options.changedAt, 'changedAt'),
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function revokeOwnerKey(options) {
  if (!options || typeof options !== 'object') F.reject('revokeOwnerKey needs options');
  options = own(options);
  return changeOwnerKey(options, '');
}

function rotateOwnerKey(options) {
  if (!options || typeof options !== 'object') F.reject('rotateOwnerKey needs options');
  options = own(options);
  if (options.successor === undefined) F.reject('rotateOwnerKey needs the successor key');
  return changeOwnerKey(options, keyIdFrom(options.successor, 'successor'));
}

function commitInput(input) {
  if (!(input instanceof Uint8Array)) F.reject('the input is a Uint8Array');
  const salt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(salt);
  return { salt, digest: F.inputCommitment(salt, input) };
}

function attest(options) {
  if (!options || typeof options !== 'object') F.reject('attest needs options');
  options = own(options);
  requireSeed(options.key);
  const producer = keyId(options.key);
  const content = digestOption(options, 'content', 'contentDigest', 'the content', true);
  let size = content.size;
  if (size === null) {
    size = options.contentSize;
    if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) F.reject('contentSize, the length of the content in bytes, is required with contentDigest');
  } else if (options.contentSize !== undefined && options.contentSize !== size) {
    F.reject('contentSize does not match the content');
  }
  let modelRef = '';
  if (options.model !== undefined) {
    const m = signedEnvelope(options.model, 'model', 'model');
    const st = m.statement;
    if (producer !== st.ownerKeyId && !st.producers.includes(producer)) F.reject('this key is not authorised by the model owner to attest outputs of ' + st.name);
    modelRef = F.refOf(m);
  }
  let inputDigest = '';
  if (options.inputDigest !== undefined) {
    if (typeof options.inputDigest !== 'string' || !/^[0-9a-f]{64}$/.test(options.inputDigest)) F.reject('inputDigest is 64 lowercase hex characters, from commitInput');
    inputDigest = options.inputDigest;
  }
  const ing = options.ingredients === undefined ? [] : options.ingredients;
  if (!Array.isArray(ing) || ing.length > F.INGREDIENTS_MAX) F.reject('ingredients is a list of at most ' + F.INGREDIENTS_MAX + ' output envelopes');
  const ingredients = ing.map((e, i) => F.refOf(signedEnvelope(e, 'output', 'ingredient ' + (i + 1))));
  if (new Set(ingredients).size !== ingredients.length) F.reject('ingredients must not repeat an output');
  const c2pa = digestOption(options, 'c2pa', 'c2paDigest', 'the C2PA manifest store', false);
  return sign('output', {
    outputId: randomHex(16),
    producerKeyId: producer,
    modelRef,
    contentDigest: content.digest,
    contentSize: size,
    mediaType: options.mediaType,
    action: options.action === undefined ? 'created' : options.action,
    sourceType: options.sourceType === undefined ? 'trainedAlgorithmicMedia' : options.sourceType,
    inputDigest,
    ingredients,
    c2paDigest: c2pa.digest,
    createdAt: timeOption(options.createdAt, 'createdAt'),
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function batch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('at least one envelope is needed');
  const copies = list.map((e) => {
    try {
      return F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
  });
  const parsed = copies.map((e) => {
    const p = F.parse(e);
    if (p.signerId !== F.keyIdOf(p.publicKey) || p.signerId !== F.boundKey(p)) F.reject('an envelope is not signed by the key it names');
    if (!native.verify(p.publicKey, F.payload(p.type, p.statement), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  const types = new Set(parsed.map((p) => p.type));
  if (types.size !== 1) F.reject('models, outputs, withdrawals and owner key changes are anchored in separate batches');
  return { copies, parsed, type: parsed[0].type };
}

function attach(copies, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== copies.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return copies.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  const { copies, parsed, type } = batch(envelopes);
  if (parsed.some((p) => p.anchor !== undefined)) F.reject('an envelope is already anchored');
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  return attach(copies, await qstamp.stamp(Object.assign(own(options), { records, kind: KIND[type] })));
}

async function complete(envelopes, pending, options) {
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { copies, parsed, type } = batch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(qstamp.KINDS[KIND[type]])) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  return attach(copies, await qstamp.complete(p, own(options)));
}

function c2paActions(source, model) {
  if (!source || typeof source !== 'object') F.reject('c2paActions needs an output envelope or the action, sourceType and model of the output to come');
  let action;
  let sourceType;
  let when;
  let modelRef = null;
  if (source.format !== undefined) {
    const p = signedEnvelope(source, 'output', 'the output');
    action = p.statement.action;
    sourceType = p.statement.sourceType;
    when = p.statement.createdAt;
    modelRef = p.statement.modelRef;
  } else {
    for (const k of Object.keys(source)) if (!['action', 'sourceType', 'when'].includes(k)) F.reject('a planned output is described only by action, sourceType and when');
    action = source.action === undefined ? 'created' : source.action;
    sourceType = source.sourceType === undefined ? 'trainedAlgorithmicMedia' : source.sourceType;
    when = source.when === undefined ? new Date().toISOString() : source.when;
    if (!F.ACTIONS.includes(action)) F.reject('action is one of ' + F.ACTIONS.join(', '));
    if (!F.SOURCE_TYPES.includes(sourceType)) F.reject('sourceType is one of ' + F.SOURCE_TYPES.join(', '));
    const tp = F.timeProblem(when, 'when');
    if (tp) F.reject(tp);
  }
  const entry = { action: 'c2pa.' + action, digitalSourceType: IPTC + sourceType, when };
  if (model !== undefined) {
    const m = signedEnvelope(model, 'model', 'model');
    if (modelRef !== null && F.refOf(m) !== modelRef) F.reject('the model is not the one this output names');
    entry.softwareAgent = { name: m.statement.name, version: m.statement.version };
  } else if (F.MODEL_REQUIRED.includes(sourceType) && modelRef === null) {
    F.reject('content made by a trained model needs the model registration to name its software agent');
  }
  return { label: 'c2pa.actions.v2', data: { actions: [entry] } };
}

module.exports = {
  KIND, generateKey, publicKey, keyId, describeKey, registerModel, withdrawProducer, revokeOwnerKey, rotateOwnerKey, commitInput, attest, anchor, complete, c2paActions, signedEnvelope, keyIdFrom,
};
