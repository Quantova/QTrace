// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');
const T = require('./trace');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const INGREDIENTS_MAX = 64;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'expectedSender'];
const CLAIMED = { model: 'registeredAt', output: 'createdAt', withdrawal: 'withdrawnAt', keychange: 'changedAt' };
const KEY_CHANGES_MAX = 256;
const SUCCESSION_MAX = 16;

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  const open = checks.filter((c) => !c.ok);
  if (open.some((c) => !c.transport && !c.indeterminate && !c.unproven)) return 'invalid';
  if (open.some((c) => c.transport || c.indeterminate)) return 'indeterminate';
  if (open.length) return 'unproven';
  return 'valid';
}

function recorder() {
  const checks = [];
  const add = (name, ok, detail, transport, indeterminate, unproven) => checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate, unproven: !!unproven });
  return { checks, add };
}

function provenOf(result) {
  if (!result || (result.status !== 'valid' && result.status !== 'unproven')) return false;
  return typeof qstamp.isProven === 'function' && qstamp.isProven(result) === true;
}

const NET = Symbol('endpoints');
const CLOCK = Symbol('clock');
const CHANGES = Symbol('changes');
const NAME_ASSERTED = 'the model name and version are text chosen by the model owner, they are not verified, the identity that was checked is the owner key';

function noteEndpoints(opts, result) {
  const net = opts[NET];
  if (!net || !(result.endpoints || []).length) return;
  for (const e of result.endpoints) net.endpoints.add(e);
  net.official = net.official !== false && result.officialEndpoints === true;
}

function finish(checks, extra, net) {
  const status = statusOf(checks);
  const seen = net ? { endpoints: [...net.endpoints], officialEndpoints: net.official } : { endpoints: [], officialEndpoints: null };
  return Object.assign({ valid: status === 'valid', status }, extra, seen, { checks: checks.map((c) => Object.assign({}, c)) }, { valid: status === 'valid', status });
}

function anchorOptions(opts) {
  const out = Object.create(null);
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
    if (!((ArrayBuffer.isView(opts[bytesKey]) && opts[bytesKey] instanceof Uint8Array))) F.reject(bytesKey + ' is a Uint8Array');
    return { digest: F.sha3(opts[bytesKey]).toString('hex'), size: opts[bytesKey].length };
  }
  if (typeof opts[digestKey] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[digestKey])) F.reject(digestKey + ' is 64 lowercase hex characters');
  return { digest: opts[digestKey], size: null };
}

const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;

function networkProblem(opts) {
  if (opts.network === 'custom') return opts.trustCustomEndpoints === true ? null : 'network custom needs trustCustomEndpoints, it accepts anchors on any chain the endpoints name';
  if (typeof opts.network !== 'string' || !Object.prototype.hasOwnProperty.call(qstamp.NETWORKS, opts.network)) return 'network is required and names the network the records were anchored on, one of ' + Object.keys(qstamp.NETWORKS).concat(['custom']).join(', ');
  return null;
}

function onNetwork(receipt, opts) {
  if (opts.network === 'custom') return true;
  const net = qstamp.NETWORKS[opts.network];
  return !!receipt.chain && receipt.chain.id === net.chainId && receipt.chain.genesis === net.genesis;
}

function delayOf(opts) {
  if (opts.maxAnchorDelay === undefined) return DEFAULT_ANCHOR_DELAY_S * 1000;
  const v = opts.maxAnchorDelay;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
  return v * 1000;
}

function atGiven(opts) {
  const tp = F.timeProblem(opts.at, 'at');
  if (tp) F.reject(tp);
  return Date.parse(opts.at);
}

async function atOf(opts, add) {
  if (opts.at !== undefined) return atGiven(opts);
  if (opts[CLOCK] !== undefined) return opts[CLOCK];
  try {
    opts[CLOCK] = (await qstamp.chainTime(Object.assign(anchorOptions(opts), opts.network === 'custom' ? {} : { network: opts.network }))).early;
  } catch (e) {
    opts[CLOCK] = null;
    add('chain time', false, 'the time of the chain could not be established, so no date was checked against the present and the local clock was not used, ' + ((e && e.message) || 'unknown error'), true);
  }
  return opts[CLOCK];
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
      add(label, false, 'the anchor was not recorded under the record kind for an AI ' + (p.type === 'output' ? 'output' : 'model'));
      return null;
    }
    if (!receipt.record || receipt.record.alg !== 'sha3-256') {
      add(label, false, 'the anchor does not record a SHA3 digest');
      return null;
    }
    if (!onNetwork(receipt, opts)) {
      add(label, false, 'the anchor was recorded on another network than ' + opts.network);
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(opts), { digest: F.anchorDigest(p) }));
    noteEndpoints(opts, result);
    const confirmed = result.status === 'valid' || result.status === 'unproven';
    const proven = provenOf(result);
    for (const c of result.checks) {
      if (proven && !c.ok) continue;
      add(label + ' ' + c.name, c.ok, c.detail, confirmed ? false : c.transport, false, confirmed && !c.ok);
    }
    if (!confirmed) {
      if (result.status === 'invalid') {
        if (!result.checks.some((c) => !c.ok && !c.transport)) add(label, false, 'the anchor was refuted');
      } else {
        add(label + ' confirmed', false, 'the anchor was neither confirmed nor refuted, so it is treated as not anchored', true, true);
      }
      return null;
    }
    if (!proven) {
      if (!result.checks.some((c) => !c.ok)) add(label + ' proof', false, 'the anchor was confirmed only by endpoints that are not pinned independent operators of the network, so it is not proven and is treated as not anchored', false, false, true);
      return null;
    }
    const ms = receipt.anchor.time * 1000;
    if (Date.parse(p.statement[CLAIMED[p.type]]) > ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the claimed time is later than the anchor time ' + iso(ms));
      return null;
    }
    const position = { ms, height: receipt.anchor.height, chain: receipt.chain.id + '/' + receipt.chain.genesis };
    const delayMs = delayOf(opts);
    if (ms - Date.parse(p.statement[CLAIMED[p.type]]) > delayMs) {
      add(label + ' time', false, 'anchored at ' + iso(ms) + ', more than ' + Math.round(delayMs / 3600000) + ' hours after its stated time, so the stated time is not proven', false, true);
      return position;
    }
    if (opts.at !== undefined && ms > atGiven(opts)) {
      add(label + ' time', false, 'anchored at ' + iso(ms) + ', after the time given for verification, so it was not proven at that time', false, true);
      return position;
    }
    add(label + ' time', true, 'recorded by ' + iso(ms));
    return position;
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

function futureCheck(p, atMs, add, label) {
  if (atMs === null) return true;
  if (Date.parse(p.statement[CLAIMED[p.type]]) > atMs + CLOCK_SKEW_MS) {
    add(label, false, 'it is dated after the time of verification');
    return false;
  }
  return true;
}

function keyChangesOf(opts) {
  if (opts[CHANGES] !== undefined) return opts[CHANGES];
  if (opts.ownerKeyChanges === undefined) {
    opts[CHANGES] = null;
    return null;
  }
  if (!Array.isArray(opts.ownerKeyChanges) || opts.ownerKeyChanges.length > KEY_CHANGES_MAX) F.reject('ownerKeyChanges is a list of at most ' + KEY_CHANGES_MAX + ' owner key change envelopes');
  const byOwner = new Map();
  for (const env of opts.ownerKeyChanges) {
    let c;
    try {
      c = F.parse(env);
    } catch (e) {
      continue;
    }
    if (c.type !== 'keychange' || !signatureOk(c)) continue;
    const owner = c.statement.ownerKeyId;
    if (!byOwner.has(owner)) byOwner.set(owner, new Map());
    const refs = byOwner.get(owner);
    const ref = F.refOf(c);
    if (!refs.has(ref)) refs.set(ref, []);
    refs.get(ref).push(c);
  }
  opts[CHANGES] = { byOwner, retired: new Map() };
  return opts[CHANGES];
}

async function retirementOf(owner, opts) {
  const changes = keyChangesOf(opts);
  if (changes === null) return { known: false, pos: null, unproven: false, successor: '' };
  if (changes.retired.has(owner)) return changes.retired.get(owner);
  const out = { known: true, pos: null, unproven: false, successor: '', problems: [] };
  for (const copies of (changes.byOwner.get(owner) || new Map()).values()) {
    let best = null;
    const sub = [];
    const seen = new Set();
    for (const c of copies) {
      if (c.anchor === undefined) continue;
      const key = JSON.stringify(c.anchor);
      if (seen.has(key)) continue;
      seen.add(key);
      const p = await checkAnchor(c, opts, (n, ok, detail, transport, indeterminate, unproven) => sub.push({ n, ok, detail, transport, unproven }), 'owner key change anchor', true);
      if (p && (best === null || before(p, best))) best = p;
    }
    if (best === null) {
      out.unproven = true;
      out.problems.push(...sub.filter((c) => !c.ok));
      continue;
    }
    const successor = copies[0].statement.successorKeyId;
    if (out.pos === null || compare(best, out.pos) < 0) {
      out.pos = best;
      out.successor = successor;
    } else if (compare(best, out.pos) === 0 && successor !== out.successor) {
      if (successor !== '' && out.successor !== '') out.unproven = true;
      out.successor = '';
    }
  }
  changes.retired.set(owner, out);
  return out;
}

async function successorsOf(expected, opts) {
  let cur = { key: expected, since: [], uncertain: false };
  const chain = [cur];
  for (let i = 0; i < SUCCESSION_MAX; i += 1) {
    const r = await retirementOf(cur.key, opts);
    if (!r.pos || r.successor === '' || chain.some((s) => s.key === r.successor)) break;
    const order = Math.min(1, ...cur.since.map((h) => compare(r.pos, h.pos)));
    if (order < 0) break;
    cur = { key: r.successor, since: cur.since.concat([{ pos: r.pos, from: cur.key }]), uncertain: cur.uncertain || order === 0 || r.unproven };
    chain.push(cur);
  }
  return chain;
}

const NOT_HANDED_OVER = { ok: false, handedOver: false, since: [], uncertain: false };

async function ownerAccepted(expected, owner, opts) {
  if (expected === owner) return { ok: true, handedOver: false, since: [], uncertain: false };
  if (keyChangesOf(opts) === null) return NOT_HANDED_OVER;
  const step = (await successorsOf(expected, opts)).find((s) => s.key === owner);
  return step ? { ok: true, handedOver: true, since: step.since, uncertain: step.uncertain } : NOT_HANDED_OVER;
}

function handoverOrder(accepted, owner, pos, stated, subject) {
  let open = null;
  for (const h of accepted.since) {
    const c = pos ? compare(pos, h.pos) : (Date.parse(stated) + CLOCK_SKEW_MS < h.pos.ms ? -1 : 0);
    const when = iso(h.pos.ms);
    if (c < 0) {
      return {
        ok: false,
        detail: pos
          ? subject + ' was anchored before ' + when + ', when key ' + h.from + ' handed over to the next key, so it does not speak for the expected owner'
          : subject + ' states a time before ' + when + ', when key ' + h.from + ' handed over to the next key, so it does not speak for the expected owner',
      };
    }
    if (c === 0 && open === null) {
      open = pos
        ? subject + ' was anchored in the same block as the handover by key ' + h.from + ' at ' + when + ', so it cannot be proven that it came after the handover'
        : subject + ' has no proven anchor time, so it cannot be proven that it came after the handover by key ' + h.from + ' at ' + when;
    }
  }
  if (open === null && accepted.uncertain) open = 'the order of the handovers from the expected owner to key ' + owner + ' cannot be proven';
  if (open !== null) return { ok: null, detail: open };
  return { ok: true, detail: subject + ' was anchored after the expected owner handed over to key ' + owner + ' by an anchored rotation' };
}

async function retirementCheck(owner, pos, opts, add, label, what) {
  if (keyChangesOf(opts) === null) {
    add(label, false, 'no list of owner key changes was given, so it is not known whether the owner key was revoked or rotated, give ownerKeyChanges, an empty list when none is held', false, true);
    return null;
  }
  const r = await retirementOf(owner, opts);
  if (r.unproven && !r.reported) {
    r.reported = true;
    for (const c of r.problems) add(c.n, false, c.detail, c.transport, !c.unproven, c.unproven);
  }
  if (r.pos === null && r.unproven) {
    add(label, false, 'the owner key was revoked or rotated but no copy of that change has a proven anchor time, so its order cannot be proven', false, true);
    return null;
  }
  if (r.pos === null) {
    add(label, true, 'no revocation or rotation of the owner key was supplied');
    return true;
  }
  const when = iso(r.pos.ms) + (r.successor ? ', handed over to key ' + r.successor : '');
  if (pos === null) {
    add(label, false, 'the owner key was retired at ' + when + ' and this ' + what + ' has no proven anchor showing it came first', false, true);
    return null;
  }
  if (before(r.pos, pos)) {
    add(label, false, 'the owner key was retired at ' + when + ', before this ' + what + ' was anchored');
    return false;
  }
  if (r.unproven) {
    add(label, false, 'the owner key was retired at ' + when + ', after this ' + what + ' was anchored, but another change of the owner key has no proven time and may have come first', false, true);
    return null;
  }
  add(label, true, 'the owner key was retired at ' + when + ', after this ' + what + ' was anchored');
  return true;
}

function compare(a, b) {
  const x = a.chain === b.chain ? a.height : a.ms;
  const y = a.chain === b.chain ? b.height : b.ms;
  return x === y ? 0 : x > y ? 1 : -1;
}

function before(a, b) {
  return compare(a, b) <= 0;
}

async function verifyModel(m, opts, add) {
  const expected = expectedKey(opts, 'ownerKeyId', 'ownerPublicKey', 'model owner', true);
  const sigOk = signatureOk(m);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the model owner is valid' : 'the model registration is not validly signed by the owner it names');
  const accepted = sigOk ? await ownerAccepted(expected, m.statement.ownerKeyId, opts) : Object.assign({}, NOT_HANDED_OVER, { ok: expected === m.statement.ownerKeyId });
  const requireAnchor = opts.requireAnchor !== false;
  let pos = null;
  if (sigOk) {
    futureCheck(m, await atOf(opts, add), add, 'time');
    pos = await checkAnchor(m, opts, add, 'anchor', requireAnchor);
  }
  if (!accepted.ok) add('expected owner', false, 'registered by a different owner than expected');
  else if (!accepted.handedOver) add('expected owner', true, 'registered by the expected owner');
  else {
    const order = handoverOrder(accepted, m.statement.ownerKeyId, pos, m.statement.registeredAt, 'this registration by key ' + m.statement.ownerKeyId);
    add('expected owner', order.ok === true, order.ok === true ? 'registered by a key the expected owner handed over to by an anchored rotation, after that rotation' : order.detail, false, order.ok === null);
  }
  if (sigOk) {
    await retirementCheck(m.statement.ownerKeyId, pos, opts, add, 'owner key', 'registration');
    const art = digestGiven(opts, 'artefact', 'artefactDigest');
    if (art) add('model artefact', art.digest === m.statement.modelDigest, art.digest === m.statement.modelDigest ? 'the model artefact matches the registered fingerprint' : 'the model artefact differs from the registered one');
  }
  const st = m.statement;
  return { type: 'model', modelId: st.modelId, modelRef: F.refOf(m), ownerKeyId: st.ownerKeyId, name: st.name, version: st.version, producers: st.producers.slice(), anchoredAt: pos ? iso(pos.ms) : null, notes: [NAME_ASSERTED] };
}

async function earlierChangeCheck(c, pos, opts, add) {
  if (opts.ownerKeyChanges === undefined) {
    add('earlier key change', false, 'no list of owner key changes was given, so it is not known whether the key that signed this change had already been revoked or rotated, give ownerKeyChanges, an empty list when none is held', false, true);
    return;
  }
  const self = F.refOf(c);
  const others = Object.assign({}, opts, { ownerKeyChanges: opts.ownerKeyChanges.filter((env) => {
    try {
      return F.refOf(F.parse(env)) !== self;
    } catch (e) {
      return true;
    }
  }) });
  delete others[CHANGES];
  const r = await retirementOf(c.statement.ownerKeyId, others);
  if (r.pos === null && !r.unproven) {
    add('earlier key change', true, 'no other revocation or rotation of the key that signed this change was supplied');
    return;
  }
  if (r.pos !== null && pos !== null && compare(r.pos, pos) < 0) {
    add('earlier key change', false, 'the key that signed this change was already revoked or rotated at ' + iso(r.pos.ms) + (r.successor ? ', handed over to key ' + r.successor : '') + ', before this change was anchored, so this change is void');
    return;
  }
  if (r.pos !== null && pos !== null && compare(r.pos, pos) === 0) {
    add('earlier key change', false, 'another change of the key that signed this change was anchored in the same block, so which came first cannot be proven', false, true);
    return;
  }
  if (r.unproven || pos === null) {
    add('earlier key change', false, 'another change of the key that signed this change has no proven order against it, so it cannot be shown that this change came first', false, true);
    return;
  }
  add('earlier key change', true, 'the other changes of the key that signed this change were anchored after it');
}

async function verifyKeyChange(c, opts, add) {
  const expected = expectedKey(opts, 'ownerKeyId', 'ownerPublicKey', 'model owner', true);
  const sigOk = signatureOk(c);
  add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature of the owner key is valid' : 'the owner key change is not validly signed by the key it names');
  const trusted = expected === c.statement.ownerKeyId;
  add('expected owner', trusted, trusted ? 'made by the expected owner key' : 'made by a different key than expected');
  let pos = null;
  if (sigOk) {
    futureCheck(c, await atOf(opts, add), add, 'time');
    pos = await checkAnchor(c, opts, add, 'anchor', opts.requireAnchor !== false);
    await earlierChangeCheck(c, pos, opts, add);
  }
  const st = c.statement;
  return { type: 'keychange', changeId: st.changeId, ownerKeyId: st.ownerKeyId, successorKeyId: st.successorKeyId, changedAt: st.changedAt, anchoredAt: pos ? iso(pos.ms) : null };
}

const OUTPUT_OPTS = ['producerKeyId', 'producerPublicKey', 'content', 'contentDigest', 'model', 'modelOwnerKeyId', 'modelOwnerPublicKey', 'input', 'inputSalt', 'c2pa', 'c2paDigest', 'ingredients', 'withdrawals', 'artefact', 'artefactDigest'];
const MODEL_OPTS = ['ownerKeyId', 'ownerPublicKey', 'artefact', 'artefactDigest'];

function expectedType(opts) {
  const out = OUTPUT_OPTS.filter((k) => opts[k] !== undefined && !MODEL_OPTS.includes(k));
  const mod = MODEL_OPTS.filter((k) => opts[k] !== undefined && !OUTPUT_OPTS.includes(k));
  if (out.length && mod.length) F.reject('options for a model registration and for an output manifest were mixed, ' + mod.join(', ') + ' apply only to a model and ' + out.join(', ') + ' only to an output');
  const inferred = mod.length ? 'model' : out.length ? 'output' : null;
  if (opts.type === 'keychange') {
    if (out.length) F.reject('an owner key change is checked against ownerKeyId or ownerPublicKey only');
    if (opts.ownerKeyId === undefined && opts.ownerPublicKey === undefined) F.reject('the expected owner key is required, give ownerKeyId or ownerPublicKey');
    return 'keychange';
  }
  if (opts.type !== undefined) {
    if (opts.type !== 'model' && opts.type !== 'output') F.reject('type is model, output or keychange');
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
  const groups = new Map();
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
    if (!groups.has(ref)) groups.set(ref, []);
    else add(name, true, 'a further copy of an earlier withdrawal, its anchor is considered with the others');
    groups.get(ref).push({ w, name });
  }
  for (const copies of groups.values()) {
    const name = copies[0].name;
    const sub = [];
    let wpos = null;
    const seen = new Set();
    for (const c of copies) {
      if (c.w.anchor === undefined) continue;
      const key = JSON.stringify(c.w.anchor);
      if (seen.has(key)) continue;
      seen.add(key);
      const p = await checkAnchor(c.w, opts, (n, ok, detail, transport) => sub.push({ n, ok, detail, transport }), c.name + ' anchor', true);
      if (p && (wpos === null || before(p, wpos))) wpos = p;
    }
    if (wpos === null) {
      for (const c of sub) if (!c.ok) add(c.n, false, c.detail, c.transport, true);
      add(name, false, 'the model owner withdrew this producer but no copy of the withdrawal has a verified anchor time, so its order cannot be proven', false, true);
      continue;
    }
    const when = iso(wpos.ms);
    if (pos === null) {
      add(name, false, 'the model owner withdrew this producer at ' + when + ' and this output has no anchor proving it came first', false, true);
      continue;
    }
    if (before(wpos, pos)) {
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
  const atMs = await atOf(opts, add);
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
  let retireFor = null;
  let handedOver = null;
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
        const accepted = ownerPin === null ? null : await ownerAccepted(ownerPin, ms.ownerKeyId, opts);
        const mpos = await checkAnchor(m, opts, add, 'model anchor', requireAnchor);
        if (ownerPin === null) add('model owner', false, 'the expected model owner was not given, so anyone could have registered a model under this name', false, true);
        else if (!accepted.ok) add('model owner', false, 'the model was registered by a different owner than expected');
        else if (!accepted.handedOver) {
          ownerOk = true;
          add('model owner', true, 'the model ' + ms.name + ' was registered by the expected owner');
        } else {
          const order = handoverOrder(accepted, ms.ownerKeyId, mpos, ms.registeredAt, 'the registration of the model by key ' + ms.ownerKeyId);
          ownerOk = order.ok === true;
          add('model owner', ownerOk, ownerOk ? 'the model ' + ms.name + ' was registered by the expected owner through an anchored rotation of its key, after that rotation' : order.detail, false, order.ok === null);
          if (ownerOk) handedOver = { accepted, owner: ms.ownerKeyId };
        }
        const authorised = st.producerKeyId === ms.ownerKeyId || ms.producers.includes(st.producerKeyId);
        if (ownerOk && st.producerKeyId !== ms.ownerKeyId) withdrawFor = ms;
        add('producer authorised', authorised, authorised ? 'the model owner authorised this producer to attest its outputs' : 'the model owner did not authorise this producer');
        const art = digestGiven(opts, 'artefact', 'artefactDigest');
        if (art) add('model artefact', art.digest === ms.modelDigest, art.digest === ms.modelDigest ? 'the model artefact matches the registered fingerprint' : 'the model artefact differs from the registered one');
        if (!timeOrder(ms.registeredAt, st.createdAt)) add('model time', false, 'the output claims a time before its model was registered');
        futureCheck(m, atMs, add, 'model time');
        retireFor = { owner: ms.ownerKeyId, mpos };
        if (ownerOk) {
          result.producerAuthorised = authorised;
          result.model = { modelId: ms.modelId, modelRef: st.modelRef, modelDigest: ms.modelDigest, name: ms.name, version: ms.version, ownerKeyId: ms.ownerKeyId, anchoredAt: mpos ? iso(mpos.ms) : null };
        }
      }
    }
  }

  if (opts.input !== undefined || opts.inputSalt !== undefined) {
    if (!((ArrayBuffer.isView(opts.input) && opts.input instanceof Uint8Array)) || !((ArrayBuffer.isView(opts.inputSalt) && opts.inputSalt instanceof Uint8Array)) || opts.inputSalt.length !== 32) F.reject('give input and its 32 byte inputSalt together, both as Uint8Array');
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
      if (!timeOrder(p.statement.createdAt, st.createdAt) || (atMs !== null && Date.parse(p.statement.createdAt) > atMs + CLOCK_SKEW_MS)) disordered += 1;
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
  if (handedOver) {
    const order = handoverOrder(handedOver.accepted, handedOver.owner, pos, st.createdAt, 'this output under the model of key ' + handedOver.owner);
    add('model owner handover', order.ok === true, order.ok === true ? 'the output was anchored after the expected model owner handed over to the key that registered its model' : order.detail, false, order.ok === null);
    if (order.ok === false) result.producerAuthorised = false;
  }
  if (retireFor && keyChangesOf(opts) === null) {
    await retirementCheck(retireFor.owner, pos, opts, add, 'model owner key', 'output');
  } else if (retireFor) {
    const regOk = await retirementCheck(retireFor.owner, retireFor.mpos, opts, add, 'model owner key at registration', 'model registration');
    const outOk = await retirementCheck(retireFor.owner, pos, opts, add, 'model owner key', 'output');
    if ((regOk === false || outOk === false) && result.producerAuthorised !== null) result.producerAuthorised = false;
  }
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
  const opts = Object.assign(Object.create(null), options);
  const want = expectedType(opts);
  opts[NET] = { endpoints: new Set(), official: null };
  delayOf(opts);
  if (opts.at !== undefined) atGiven(opts);
  const np = networkProblem(opts);
  if (np) F.reject(np);
  const { checks, add } = recorder();
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    add('format', false, e.message);
    return finish(checks, { type: null }, opts[NET]);
  }
  const NAMES = { model: 'model registration', output: 'output manifest', withdrawal: 'producer withdrawal', keychange: 'owner key change' };
  if (p.type !== want) {
    add('format', false, 'a ' + NAMES[p.type] + ' was given where a' + (want === 'output' ? 'n ' : ' ') + NAMES[want] + ' was expected');
    return finish(checks, { type: p.type }, opts[NET]);
  }
  add('format', true, 'a well formed ' + NAMES[p.type]);
  const extra = p.type === 'model' ? await verifyModel(p, opts, add) : p.type === 'keychange' ? await verifyKeyChange(p, opts, add) : await verifyOutput(p, opts, add);
  return finish(checks, extra, opts[NET]);
}

module.exports = { verify, INGREDIENTS_MAX };
