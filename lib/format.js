// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qtrace/1';
const ALGORITHM = 'ML-DSA-65';
const TYPES = Object.freeze(['model', 'output']);
const KEY_DOMAIN = Buffer.from('quantova/qtrace/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qtrace/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qtrace/anchor/1', 'ascii');
const INPUT_DOMAIN = Buffer.from('quantova/qtrace/input/1', 'ascii');
const MAGIC = Buffer.from('QTRC', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const NAME_MAX = 200;
const VERSION_MAX = 100;
const NOTE_MAX = 1000;
const PRODUCERS_MAX = 32;
const INGREDIENTS_MAX = 32;
const ACTIONS = Object.freeze(['created', 'edited', 'converted', 'placed', 'translated', 'transcoded', 'published']);
const SOURCE_TYPES = Object.freeze([
  'trainedAlgorithmicMedia',
  'compositeWithTrainedAlgorithmicMedia',
  'algorithmicallyEnhanced',
  'algorithmicMedia',
  'compositeSynthetic',
  'dataDrivenMedia',
  'digitalCreation',
  'humanEdits',
]);
const MODEL_REQUIRED = Object.freeze(['trainedAlgorithmicMedia', 'compositeWithTrainedAlgorithmicMedia']);
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const MEDIA_TYPE = /^(?=.{3,127}$)[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;
const FIELDS = Object.freeze({
  model: Object.freeze(['modelId', 'ownerKeyId', 'name', 'version', 'modelDigest', 'cardDigest', 'producers', 'registeredAt', 'note']),
  output: Object.freeze(['outputId', 'producerKeyId', 'modelRef', 'contentDigest', 'contentSize', 'mediaType', 'action', 'sourceType', 'inputDigest', 'ingredients', 'c2paDigest', 'createdAt', 'note']),
});

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QTRACE_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QTRACE_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function inputCommitment(salt, input) {
  if (!(salt instanceof Uint8Array) || salt.length !== 32) reject('the input salt is 32 bytes');
  if (!(input instanceof Uint8Array)) reject('the input is a Uint8Array');
  return sha3(INPUT_DOMAIN, Buffer.from([0]), salt, input).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' must not be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function optionalDigest(value, what) {
  if (value === '') return null;
  return pattern(value, HEX32, what, 'empty or 64 lowercase hex characters');
}

function digestList(value, max, what) {
  if (!Array.isArray(value) || value.length > max) return what + ' must be a list of at most ' + max + ' digests';
  for (const d of value) if (typeof d !== 'string' || !HEX32.test(d)) return what + ' must hold 64 lowercase hex characters each';
  if (new Set(value).size !== value.length) return what + ' must not repeat an entry';
  return null;
}

function sameKeys(obj, fields) {
  return Object.keys(obj).sort().join(',') === fields.slice().sort().join(',');
}

function statementProblem(type, st) {
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (!sameKeys(st, FIELDS[type])) return 'a ' + type + ' statement holds exactly ' + FIELDS[type].join(', ');
  if (type === 'model') {
    return pattern(st.modelId, HEX16, 'modelId', '32 lowercase hex characters')
      || pattern(st.ownerKeyId, HEX32, 'ownerKeyId', '64 lowercase hex characters')
      || textProblem(st.name, NAME_MAX, 'name', true)
      || textProblem(st.version, VERSION_MAX, 'version', false)
      || pattern(st.modelDigest, HEX32, 'modelDigest', '64 lowercase hex characters, the SHA3-256 of the model artefact')
      || optionalDigest(st.cardDigest, 'cardDigest')
      || digestList(st.producers, PRODUCERS_MAX, 'producers')
      || timeProblem(st.registeredAt, 'registeredAt')
      || textProblem(st.note, NOTE_MAX, 'note', false);
  }
  const p = pattern(st.outputId, HEX16, 'outputId', '32 lowercase hex characters')
    || pattern(st.producerKeyId, HEX32, 'producerKeyId', '64 lowercase hex characters')
    || optionalDigest(st.modelRef, 'modelRef')
    || pattern(st.contentDigest, HEX32, 'contentDigest', '64 lowercase hex characters, the SHA3-256 of the content')
    || (typeof st.contentSize === 'number' && Number.isSafeInteger(st.contentSize) && st.contentSize >= 0 && !Object.is(st.contentSize, -0) ? null : 'contentSize must be a whole number of bytes from 0')
    || pattern(st.mediaType, MEDIA_TYPE, 'mediaType', 'a lowercase media type such as image/png')
    || (ACTIONS.includes(st.action) ? null : 'action must be one of ' + ACTIONS.join(', '))
    || (SOURCE_TYPES.includes(st.sourceType) ? null : 'sourceType must be one of ' + SOURCE_TYPES.join(', '))
    || optionalDigest(st.inputDigest, 'inputDigest')
    || digestList(st.ingredients, INGREDIENTS_MAX, 'ingredients')
    || optionalDigest(st.c2paDigest, 'c2paDigest')
    || timeProblem(st.createdAt, 'createdAt')
    || textProblem(st.note, NOTE_MAX, 'note', false);
  if (p) return p;
  if (MODEL_REQUIRED.includes(st.sourceType) && st.modelRef === '') return 'content made by a trained model must name the model it came from';
  return null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function count(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return field(b);
}

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type)];
  if (type === 'model') {
    parts.push(hex(st.modelId), hex(st.ownerKeyId), utf8(st.name), utf8(st.version), hex(st.modelDigest), hex(st.cardDigest), count(st.producers.length));
    for (const k of st.producers) parts.push(hex(k));
    parts.push(ascii(st.registeredAt));
  } else {
    parts.push(hex(st.outputId), hex(st.producerKeyId), hex(st.modelRef), hex(st.contentDigest), u64(st.contentSize), ascii(st.mediaType), ascii(st.action), ascii(st.sourceType), hex(st.inputDigest), count(st.ingredients.length));
    for (const r of st.ingredients) parts.push(hex(r));
    parts.push(hex(st.c2paDigest), ascii(st.createdAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parse(envelope) {
  let env;
  try {
    env = plainCopy(envelope);
  } catch (e) {
    fail('it is not plain data');
  }
  exactKeys(env, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (env.format !== FORMAT) fail('format must be ' + FORMAT);
  if (env.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(env.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(env.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof env.signer.id !== 'string' || !HEX32.test(env.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(env.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  const problem = statementProblem(env.type, env.statement);
  if (problem) fail(problem);
  const signature = decodeBase64(env.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(env, 'anchor') ? env.anchor : undefined;
  return { type: env.type, signerId: env.signer.id, publicKey, statement: env.statement, signature, anchor };
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature);
}

function boundKey(parsed) {
  return parsed.type === 'model' ? parsed.statement.ownerKeyId : parsed.statement.producerKeyId;
}

module.exports = {
  FORMAT, ALGORITHM, TYPES, FIELDS, ACTIONS, SOURCE_TYPES, MODEL_REQUIRED, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, NAME_MAX, VERSION_MAX, NOTE_MAX, PRODUCERS_MAX, INGREDIENTS_MAX,
  sha3, keyIdOf, inputCommitment, textProblem, timeProblem, statementProblem, payload, parse, refOf, anchorDigest, boundKey, reject, plainCopy,
};
