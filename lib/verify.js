// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const T = require('./trace');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const INGREDIENTS_MAX = 64;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract'];
const CLAIMED = { model: 'registeredAt', output: 'createdAt', withdrawal: 'withdrawnAt' };

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  if (checks.some((c) => !c.ok && !c.transport && !c.indeterminate)) return 'invalid';
  if (checks.some((c) => !c.ok)) return 'indeterminate';
  return 'valid';
}

function recorder() {
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate });
  return { checks, add };
}

const NET = Symbol('endpoints');

function noteEndpoints(opts, result) {
  const net = opts[NET];
  if (!net || !(result.endpoints || []).length) return;
  for (const e of result.endpoints) net.endpoints.add(e);
  net.official = net.official !== false && result.officialEndpoints === true;
}

function finish(checks, extra, net) {
  const status = statusOf(checks);
  const seen = net ? { endpoints: [...net.endpoints], officialEndpoints: net.official } : { endpoints: [], officialEndpoints: null };
  return Object.assign({ valid: status === 'valid', status }, extra, seen, { checks: checks.map((c) => Object.assign({}, c)) });
}

function anchorOptions(opts) {
  const out = {};
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function iso(ms) {
  return new Date(ms).toISOString();
}

function signatureOk(p) {
  return p.signerId === F.keyIdOf(p.publicKey) && p.signerId === F.boundKey(p) && native.verify(p.publicKey, F.payload(p.type, p.statement), p.signature);
}

function expectedKey(opts, idName, pkName, what, required) {
  if (opts[idName] !== undefined && opts[pkName] !== undefined) F.reject('give ' + idName + ' or ' + pkName + ', not both');
  if (opts[idName] !== undefined) return T.keyIdFrom(opts[idName], idName);
  if (opts[pkName] !== undefined) {
    let pk = opts[pkName];
    if (typeof pk === 'string') {
      const raw = Buffer.from(pk, 'base64');
      if (raw.toString('base64') !== pk) F.reject(pkName + ' is canonical base64');
      pk = raw;
    }
    return T.keyIdFrom(pk, pkName);
  }
  if (required) F.reject('the expected ' + what + ' is required, give ' + idName + ' or ' + pkName + ' so an attacker cannot substitute a key of its own');
  return null;
}

function digestGiven(opts, bytesKey, digestKey) {
  const given = [bytesKey, digestKey].filter((k) => opts[k] !== undefined);
  if (given.length > 1) F.reject('give ' + bytesKey + ' or ' + digestKey + ', not both');
  if (given.length === 0) return null;
  if (opts[bytesKey] !== undefined) {
    if (!(opts[bytesKey] instanceof Uint8Array)) F.reject(bytesKey + ' is a Uint8Array');
    return { digest: F.sha3(opts[bytesKey]).toString('hex'), size: opts[bytesKey].length };
  }
  if (typeof opts[digestKey] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[digestKey])) F.reject(digestKey + ' is 64 lowercase hex characters');
  return { digest: opts[digestKey], size: null };
}

function atOf(opts) {
  if (opts.at === undefined) return Date.now();
  const tp = F.timeProblem(opts.at, 'at');
  if (tp) F.reject(tp);
  return Date.parse(opts.at);
}

async function checkAnchor(p, opts, add, label, requireAnchor) {
  const receipt = p.anchor;
  if (receipt === undefined) {
    if (requireAnchor) add(label, false, 'not anchored, so its time is only the claim of its signer', false, true);
    else add(label, true, 'not anchored, the time is the claim of the signer');
    return null;
  }
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
      add(label, false, 'the anchor is not a Qstamp receipt');
      return null;
    }
    if (receipt.kind !== String(qstamp.KINDS[T.KIND[p.type]])) {
      add(label, false, 'the anchor was not recorded under the record kind for an AI ' + (p.type === 'model' ? 'model' : 'output'));
      return null;
    }
    if (!receipt.record || receipt.record.alg !== 'sha3-256') {
      add(label, false, 'the anchor does not record a SHA3 digest');
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(p) }));
    noteEndpoints(opts, result);
    for (const c of result.checks) add(label + ' ' + c.name, c.ok, c.detail, c.transport);
    if (result.status !== 'valid') return null;
    const ms = receipt.anchor.time * 1000;
    if (Date.parse(p.statement[CLAIMED[p.type]]) > ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the claimed time is later than the anchor time ' + iso(ms));
      return null;
    }
    add(label + ' time', true, 'recorded by ' + iso(ms));
    return { ms, height: receipt.anchor.height, chain: receipt.chain.id + '/' + receipt.chain.genesis };
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

function futureCheck(p, atMs, add, label) {
  if (Date.parse(p.statement[CLAIMED[p.type]]) > atMs + CLOCK_SKEW_MS) {
    add(label, false, 'it is dated after the time of verification');
    return false;
  }
  return true;
}

async function verifyModel(m, opts, add) {
  const expected = expectedKey(opts, 'ownerKeyId', 'ownerPublicKey', 'model owner', true);
  const sigOk = signatureOk(m);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the model owner is valid' : 'the model registration is not validly signed by the owner it names');
  const trusted = expected === m.statement.ownerKeyId;
  add('expected owner', trusted, trusted ? 'registered by the expected owner' : 'registered by a different owner than expected');
  const requireAnchor = opts.requireAnchor !== false;
  let pos = null;
  if (sigOk) {
    futureCheck(m, atOf(opts), add, 'time');
    pos = await checkAnchor(m, opts, add, 'anchor', requireAnchor);
    const art = digestGiven(opts, 'artefact', 'artefactDigest');
    if (art) add('model artefact', art.digest === m.statement.modelDigest, art.digest === m.statement.modelDigest ? 'the model artefact matches the registered fingerprint' : 'the model artefact differs from the registered one');
  }
  const st = m.statement;
  return { type: 'model', modelId: st.modelId, modelRef: F.refOf(m), ownerKeyId: st.ownerKeyId, name: st.name, version: st.version, producers: st.producers.slice(), anchoredAt: pos ? iso(pos.ms) : null };
}

const OUTPUT_OPTS = ['producerKeyId', 'producerPublicKey', 'content', 'contentDigest', 'model', 'modelOwnerKeyId', 'modelOwnerPublicKey', 'input', 'inputSalt', 'c2pa', 'c2paDigest', 'ingredients', 'withdrawals', 'artefact', 'artefactDigest'];
const MODEL_OPTS = ['ownerKeyId', 'ownerPublicKey', 'artefact', 'artefactDigest'];

function expectedType(opts) {
  const out = OUTPUT_OPTS.filter((k) => opts[k] !== undefined && !MODEL_OPTS.includes(k));
  const mod = MODEL_OPTS.filter((k) => opts[k] !== undefined && !OUTPUT_OPTS.includes(k));
  if (out.length && mod.length) F.reject('options for a model registration and for an output manifest were mixed, ' + mod.join(', ') + ' apply only to a model and ' + out.join(', ') + ' only to an output');
  const inferred = mod.length ? 'model' : out.length ? 'output' : null;
  if (opts.type !== undefined) {
    if (opts.type !== 'model' && opts.type !== 'output') F.reject('type is model or output');
    if (inferred !== null && inferred !== opts.type) F.reject('type is ' + opts.type + ' but the options given apply to a' + (inferred === 'model' ? ' model registration' : 'n output manifest'));
    if (inferred === null) F.reject('the expected signer is required, give ownerKeyId for a model registration or producerKeyId or modelOwnerKeyId for an output manifest');
    return opts.type;
  }
  if (inferred === null) F.reject('the expected signer is required, give ownerKeyId for a model registration or producerKeyId or modelOwnerKeyId for an output manifest');
  return inferred;
}

function timeOrder(earlierIso, laterIso) {
  return Date.parse(earlierIso) <= Date.parse(laterIso) + CLOCK_SKEW_MS;
}

async function checkWithdrawals(ms, st, pos, opts, add) {
  if (opts.withdrawals === undefined) {
    add('withdrawals', false, 'no withdrawal list was given, so it is not known whether the model owner withdrew this producer, give withdrawals, an empty list when none is held', false, true);
    return false;
  }
  if (!Array.isArray(opts.withdrawals) || opts.withdrawals.length > F.WITHDRAWALS_MAX) F.reject('withdrawals is a list of at most ' + F.WITHDRAWALS_MAX + ' withdrawal envelopes');
  let withdrawn = false;
  const seen = new Set();
  for (const [i, env] of opts.withdrawals.entries()) {
    const name = 'withdrawal ' + (i + 1);
    let w;
    try {
      w = F.parse(env);
    } catch (e) {
      add(name, true, 'ignored, it is not a well formed envelope');
      continue;
    }
    const ws = w.statement;
    if (w.type !== 'withdrawal' || ws.ownerKeyId !== ms.ownerKeyId || ws.modelId !== ms.modelId || ws.producerKeyId !== st.producerKeyId) {
      add(name, true, 'ignored, it concerns another model, owner or producer');
      continue;
    }
    if (!signatureOk(w)) {
      add(name, true, 'ignored, it is not validly signed by the model owner');
      continue;
    }
    const ref = F.refOf(w);
    if (seen.has(ref)) {
      add(name, true, 'ignored, it repeats an earlier withdrawal');
      continue;
    }
    seen.add(ref);
    const sub = [];
    const wpos = await checkAnchor(w, opts, (n, ok, detail, transport) => sub.push({ n, ok, detail, transport }), name + ' anchor', true);
    for (const c of sub) if (!c.ok) add(c.n, false, c.detail, c.transport, true);
    if (wpos === null) {
      add(name, false, 'the model owner withdrew this producer but the withdrawal has no verified anchor time, so its order cannot be proven', false, true);
      continue;
    }
    const when = iso(wpos.ms);
    if (pos === null) {
      add(name, false, 'the model owner withdrew this producer at ' + when + ' and this output has no anchor proving it came first', false, true);
      continue;
    }
    const first = wpos.chain === pos.chain ? wpos.height <= pos.height : wpos.ms <= pos.ms;
    if (first) {
      withdrawn = true;
      add(name, false, 'the model owner withdrew this producer at ' + when + ', before this output was anchored');
    } else {
      add(name, true, 'the model owner withdrew this producer at ' + when + ', after this output was anchored');
    }
  }
  return withdrawn;
}

async function verifyOutput(o, opts, add) {
  const expected = expectedKey(opts, 'producerKeyId', 'producerPublicKey', 'producer', false);
  const ownerPin = expectedKey(opts, 'modelOwnerKeyId', 'modelOwnerPublicKey', 'model owner', false);
  if (expected === null && ownerPin === null) F.reject('the expected producer or model owner is required, give producerKeyId or modelOwnerKeyId so an attacker cannot substitute a key of its own');
  const st = o.statement;
  const sigOk = signatureOk(o);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the producer is valid' : 'the output manifest is not validly signed by the producer it names');
  if (expected !== null) {
    const trusted = expected === st.producerKeyId;
    add('expected producer', trusted, trusted ? 'attested by the expected producer' : 'attested by a different producer than expected');
  }
  const base = { type: 'output', outputId: st.outputId, outputRef: F.refOf(o), producerKeyId: st.producerKeyId, contentDigest: st.contentDigest, contentSize: st.contentSize, mediaType: st.mediaType, action: st.action, sourceType: st.sourceType, createdAt: st.createdAt };
  const empty = { model: null, producerAuthorised: null, contentChecked: false, contentMatched: false, inputChecked: false, inputMatched: false, ingredients: [], anchoredAt: null };
  if (!sigOk) return Object.assign(base, empty);
  const requireAnchor = opts.requireAnchor !== false;
  const atMs = atOf(opts);
  const result = Object.assign(base, empty);

  const content = digestGiven(opts, 'content', 'contentDigest');
  if (!content) {
    add('content', false, 'the content was not supplied, so it is unknown whether this manifest describes it', false, true);
  } else {
    result.contentChecked = true;
    result.contentMatched = content.digest === st.contentDigest && (content.size === null || content.size === st.contentSize);
    add('content', result.contentMatched, result.contentMatched ? 'the content matches the fingerprint the producer signed' : 'the content differs from the content the producer signed');
  }

  let withdrawFor = null;
  const modelExpected = opts.model !== undefined || ownerPin !== null || opts.artefact !== undefined || opts.artefactDigest !== undefined;
  if (st.modelRef === '') {
    if (modelExpected) add('model', false, 'a model was expected but the output names none');
    else add('model', true, 'the output names no model');
  } else if (opts.model === undefined) {
    add('model', false, 'the output names a model but its registration was not supplied', false, true);
  } else {
    let m = null;
    try {
      m = F.parse(opts.model);
    } catch (e) {
      add('model', false, 'the model registration is not valid, ' + e.message);
    }
    if (m) {
      if (m.type !== 'model' || F.refOf(m) !== st.modelRef) {
        add('model', false, 'the supplied model is not the registration this output names');
      } else if (!signatureOk(m)) {
        add('model', false, 'the model registration is not validly signed by its owner');
      } else {
        const ms = m.statement;
        let ownerOk = false;
        if (ownerPin === null) add('model owner', false, 'the expected model owner was not given, so anyone could have registered a model under this name', false, true);
        else if (ownerPin !== ms.ownerKeyId) add('model owner', false, 'the model was registered by a different owner than expected');
        else {
          ownerOk = true;
          add('model owner', true, 'the model ' + ms.name + ' was registered by the expected owner');
        }
        const authorised = st.producerKeyId === ms.ownerKeyId || ms.producers.includes(st.producerKeyId);
        if (ownerOk && st.producerKeyId !== ms.ownerKeyId) withdrawFor = ms;
        add('producer authorised', authorised, authorised ? 'the model owner authorised this producer to attest its outputs' : 'the model owner did not authorise this producer');
        const art = digestGiven(opts, 'artefact', 'artefactDigest');
        if (art) add('model artefact', art.digest === ms.modelDigest, art.digest === ms.modelDigest ? 'the model artefact matches the registered fingerprint' : 'the model artefact differs from the registered one');
        if (!timeOrder(ms.registeredAt, st.createdAt)) add('model time', false, 'the output claims a time before its model was registered');
        futureCheck(m, atMs, add, 'model time');
        const mpos = await checkAnchor(m, opts, add, 'model anchor', requireAnchor);
        if (ownerOk) {
          result.producerAuthorised = authorised;
          result.model = { modelId: ms.modelId, modelRef: st.modelRef, modelDigest: ms.modelDigest, name: ms.name, version: ms.version, ownerKeyId: ms.ownerKeyId, anchoredAt: mpos ? iso(mpos.ms) : null };
        }
      }
    }
  }

  if (opts.input !== undefined || opts.inputSalt !== undefined) {
    if (!(opts.input instanceof Uint8Array) || !(opts.inputSalt instanceof Uint8Array) || opts.inputSalt.length !== 32) F.reject('give input and its 32 byte inputSalt together, both as Uint8Array');
    result.inputChecked = true;
    result.inputMatched = st.inputDigest !== '' && F.inputCommitment(opts.inputSalt, opts.input) === st.inputDigest;
    add('input', result.inputMatched, result.inputMatched ? 'the input matches the private commitment the producer signed' : st.inputDigest === '' ? 'the output commits to no input' : 'the input or its salt differs from the commitment the producer signed');
  }

  const c2pa = digestGiven(opts, 'c2pa', 'c2paDigest');
  if (c2pa) {
    const same = st.c2paDigest !== '' && c2pa.digest === st.c2paDigest;
    add('c2pa', same, same ? 'the C2PA manifest store matches the one the producer bound' : st.c2paDigest === '' ? 'the output binds no C2PA manifest store' : 'the C2PA manifest store differs from the one the producer bound');
  }

  const list = opts.ingredients === undefined ? [] : opts.ingredients;
  if (!Array.isArray(list) || list.length > INGREDIENTS_MAX) F.reject('ingredients is a list of at most ' + INGREDIENTS_MAX + ' output envelopes');
  if (st.ingredients.length === 0) {
    if (list.length) add('ingredients', false, 'sources were expected but the output names none');
  } else {
    const byRef = new Map();
    for (const env of list) {
      try {
        const p = F.parse(env);
        if (p.type === 'output' && signatureOk(p)) byRef.set(F.refOf(p), p);
      } catch (e) {
        continue;
      }
    }
    let missing = 0;
    let disordered = 0;
    for (const [i, ref] of st.ingredients.entries()) {
      const p = byRef.get(ref);
      if (!p) {
        missing += 1;
        continue;
      }
      if (!timeOrder(p.statement.createdAt, st.createdAt) || Date.parse(p.statement.createdAt) > atMs + CLOCK_SKEW_MS) disordered += 1;
      const ipos = await checkAnchor(p, opts, add, 'source ' + (i + 1) + ' anchor', requireAnchor);
      result.ingredients.push({ outputRef: ref, outputId: p.statement.outputId, producerKeyId: p.statement.producerKeyId, contentDigest: p.statement.contentDigest, createdAt: p.statement.createdAt, anchoredAt: ipos ? iso(ipos.ms) : null });
    }
    if (disordered) add('ingredients', false, disordered + ' source is dated after the output that uses it or after the time of verification');
    else if (missing) add('ingredients', false, missing + ' of the ' + st.ingredients.length + ' sources this output names were not supplied with a valid signature', false, true);
    else add('ingredients', true, 'every source this output names is a validly signed output, which existed before this manifest was signed');
  }

  futureCheck(o, atMs, add, 'time');
  const pos = await checkAnchor(o, opts, add, 'anchor', requireAnchor);
  result.anchoredAt = pos ? iso(pos.ms) : null;
  if (withdrawFor) {
    const withdrawn = await checkWithdrawals(withdrawFor, st, pos, opts, add);
    if (withdrawn) result.producerAuthorised = false;
  }
  if (expected === null && result.producerAuthorised === false) add('producer', false, 'no expected producer was given and the producer is not authorised by the expected model owner');
  else if (expected === null && result.producerAuthorised === null) add('producer', false, 'no expected producer was given and the authorisation by the model owner could not be confirmed', false, true);
  return result;
}

async function verify(envelope, options) {
  if (options === null || typeof options !== 'object') F.reject('options is an object naming the expected signer');
  const want = expectedType(options);
  const opts = Object.assign({}, options);
  opts[NET] = { endpoints: new Set(), official: null };
  const { checks, add } = recorder();
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null }, opts[NET]);
  }
  if (p.type !== want) {
    add('format', false, 'a ' + (p.type === 'model' ? 'model registration' : p.type === 'withdrawal' ? 'producer withdrawal' : 'output manifest') + ' was given where a' + (want === 'model' ? ' model registration' : 'n output manifest') + ' was expected');
    return finish(checks, { type: p.type }, opts[NET]);
  }
  add('format', true, 'a well formed ' + (p.type === 'model' ? 'model registration' : 'output manifest'));
  const extra = p.type === 'model' ? await verifyModel(p, opts, add) : await verifyOutput(p, opts, add);
  return finish(checks, extra, opts[NET]);
}

module.exports = { verify, INGREDIENTS_MAX };
