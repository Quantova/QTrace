#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qt = require('..');

const ENVELOPE_MAX = 1024 * 1024;
const KEY_JSON_MAX = 64 * 1024;
const FILE_MAX = 64 * 1024 * 1024 * 1024;

const HELP = `qtrace, post quantum content provenance for AI with Quantova time proofs

  qtrace keygen <keyfile>
  qtrace key <keyfile>
  qtrace register-model --key <owner keyfile> --name TEXT [--version TEXT] (--model-file FILE | --model-digest HEX)
                        [--card-file FILE | --card-digest HEX] [--producer KEY]... [--note TEXT] --out FILE
  qtrace withdraw --key <owner keyfile> --model FILE --producer KEY [--note TEXT] --out FILE
  qtrace revoke-owner-key --key <owner keyfile> [--note TEXT] --out FILE
  qtrace rotate-owner-key --key <owner keyfile> --successor KEY [--note TEXT] --out FILE
  qtrace attest --key <producer keyfile> (--content FILE | --content-digest HEX --content-size N) --media-type TYPE
                [--action ACTION] [--source-type TYPE] [--model FILE] [--input-file FILE --input-salt-out FILE]
                [--ingredient FILE]... [--c2pa-file FILE] [--note TEXT] --out FILE
  qtrace anchor <envelope>... --seed-file <file> [--index N] [--rpc URL]... [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--max-fee N]
  qtrace complete <envelope>... --pending FILE [--tx ID] [--rpc URL]... [--trust-single-endpoint] [--allow-endpoint HOST]...
                [--allow-loopback]
  qtrace verify <envelope> (--producer KEY | --owner KEY) [--content FILE | --content-digest HEX]
                [--model FILE --model-owner KEY] [--input-file FILE --input-salt-file FILE] [--c2pa-file FILE]
                [--ingredient FILE]... [--withdrawal FILE... | --no-withdrawals]
                [--owner-key-change FILE... | --no-owner-key-changes] [--artefact FILE] [--allow-unanchored]
                [--at TIME] [--max-anchor-delay SECONDS] [--expect-sender ADDRESS]... [--rpc URL]... [--trust-custom-endpoints]
                [--trust-single-endpoint] [--allow-endpoint HOST]... [--allow-loopback] [--json]
  qtrace c2pa (<output envelope> | --action ACTION --source-type TYPE [--when TIME]) [--model FILE]

A KEY is a 64 hex character key id or a qtrace-key/1 file written by the key command. Content and model files
are hashed with SHA3-256 as they are read and never leave this machine. Models and outputs are anchored in
separate batches, and a model owner withdraws a producer with a withdrawal anchored in its own batch. If an
anchor is interrupted after its transaction was sent, the pending stamp is kept beside the first envelope and
complete finishes it. A model owner revokes its key, or rotates it to a successor key, with an owner key change
anchored in its own batch. Registrations and outputs anchored after that change are refused. An anchor counts
only when it is proven by a finality certificate or by official endpoints of two different operators, any other
anchor is UNPROVEN and never VALID. Endpoints given with --rpc are consulted by verify only with --trust-custom-endpoints, loopback endpoints only
with --allow-loopback and private network endpoints only when named with --allow-endpoint. --expect-sender names
the account that must have signed each anchor.

Exit codes are 0 for valid, 1 for invalid or an error, 2 for indeterminate or unproven and 64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

function endpointOptions(flags) {
  const out = {};
  if (flags.rpc) out.clients = flags.rpc;
  if (flags['allow-endpoint']) out.endpointAllowList = flags['allow-endpoint'];
  if (flags['trust-single-endpoint']) out.trustSingleEndpoint = true;
  if (flags['trust-custom-endpoints']) out.trustCustomEndpoints = true;
  if (flags['allow-loopback']) out.allowLoopback = true;
  return out;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  'register-model': { flags: ['force'], values: ['key', 'name', 'version', 'model-file', 'model-digest', 'card-file', 'card-digest', 'note', 'out'], multi: ['producer'] },
  withdraw: { flags: ['force'], values: ['key', 'model', 'producer', 'note', 'out'] },
  'revoke-owner-key': { flags: ['force'], values: ['key', 'note', 'out'] },
  'rotate-owner-key': { flags: ['force'], values: ['key', 'successor', 'note', 'out'] },
  attest: { flags: ['force'], values: ['key', 'content', 'content-digest', 'content-size', 'media-type', 'action', 'source-type', 'model', 'input-file', 'input-salt-out', 'c2pa-file', 'note', 'out'], multi: ['ingredient'] },
  anchor: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['seed-file', 'index', 'max-fee'], multi: ['rpc', 'allow-endpoint'] },
  complete: { flags: ['trust-single-endpoint', 'allow-loopback'], values: ['pending', 'tx'], multi: ['rpc', 'allow-endpoint'] },
  verify: { flags: ['allow-unanchored', 'no-withdrawals', 'no-owner-key-changes', 'json', 'trust-single-endpoint', 'trust-custom-endpoints', 'allow-loopback'], values: ['producer', 'owner', 'content', 'content-digest', 'model', 'model-owner', 'input-file', 'input-salt-file', 'c2pa-file', 'artefact', 'at', 'max-anchor-delay'], multi: ['ingredient', 'withdrawal', 'owner-key-change', 'rpc', 'allow-endpoint', 'expect-sender'] },
  c2pa: { flags: [], values: ['model', 'action', 'source-type', 'when'] },
};

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + safe(a).slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(code);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function readJson(file, what, invalidExit, limit) {
  const max = limit || ENVELOPE_MAX;
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(max + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > max) throw bad('the ' + what + ' is larger than ' + max + ' bytes');
  try {
    return JSON.parse(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb\u00ad\u180e\ufe00-\ufe0f\u{e0000}-\u{e007f}]/gu, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = qt.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + qt.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => qt.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}

function need(flags, name) {
  if (flags[name] === undefined) throw usageError('--' + name + ' is required');
  return flags[name];
}

function readAll(fd, what, max) {
  const size = fs.fstatSync(fd).size;
  if (size > max) {
    const err = new Error('the ' + what + ' is larger than ' + max + ' bytes');
    err.invalid = true;
    throw err;
  }
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = fs.readSync(fd, buf, off, size - off, off);
    if (n === 0) break;
    off += n;
  }
  return buf.subarray(0, off);
}

function seqFlag(value, name) {
  if (!/^\d{1,9}$/.test(value)) throw usageError('--' + name + ' is a whole number');
  return Number(value);
}

function distinctFiles(files) {
  const seen = new Set();
  for (const f of files) {
    const st = statOf(f);
    if (!st || !st.isFile()) throw usageError('the envelope ' + safe(f) + ' is not a regular file');
    const id = st.dev + ':' + st.ino;
    if (seen.has(id)) throw usageError('the envelope ' + safe(f) + ' was given twice');
    seen.add(id);
    try {
      fs.accessSync(path.dirname(f), fs.constants.W_OK);
      fs.accessSync(f, fs.constants.W_OK);
    } catch (e) {
      throw usageError('the envelope ' + safe(f) + ' or its folder is not writable, so the anchor could not be saved');
    }
  }
}

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  let lost = false;
  anchored.forEach((env, i) => {
    try {
      atomicWrite(files[i], asciiJson(env) + '\n', true);
      console.log('anchored ' + safe(files[i]) + ' in transaction ' + safe(env.anchor.anchor.tx));
    } catch (e) {
      lost = true;
      console.error('the anchored envelope could not be written to ' + safe(files[i]) + ', it follows on standard output');
      process.stdout.write(asciiJson(env) + '\n');
    }
  });
  return lost ? 1 : 0;
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  if (positional.length > BATCH_MAX) throw usageError('at most ' + BATCH_MAX + ' envelopes can be anchored at once');
  for (const f of positional) if (Buffer.byteLength(path.basename(pendingPath(f))) > 200) throw usageError('the name of ' + safe(f) + ' is too long to keep a pending stamp beside it');
  distinctFiles(positional);
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'envelope', true, ENVELOPE_MAX));
  let index = 0;
  if (flags.index !== undefined) index = seqFlag(flags.index, 'index');
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    anchored = await qt.anchor(envs, { seed, index, network: 'testnet', ...endpointOptions(flags), maxFee: flags['max-fee'], onPending: keep });
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      let message = 'the anchoring transaction may already have been sent, ' + friendly(e);
      try {
        keep(e.pending);
        message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with qtrace complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        message += ', the pending stamp could not be saved and follows on standard error, keep it to finish the anchor';
        process.stderr.write(asciiJson(e.pending) + '\n');
      }
      throw new Error(message);
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  const code = saveAnchored(positional, anchored);
  if (code === 0 && saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return code;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the envelopes given to anchor, in the same order');
  if (positional.length > BATCH_MAX) throw usageError('at most ' + BATCH_MAX + ' envelopes can be completed at once');
  distinctFiles(positional);
  const pendingFile = need(flags, 'pending');
  const pending = readJson(pendingFile, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'envelope', true, ENVELOPE_MAX)).map((e) => {
    if (e && typeof e === 'object' && !Array.isArray(e)) delete e.anchor;
    return e;
  });
  const anchored = await qt.complete(envs, pending, endpointOptions(flags));
  const code = saveAnchored(positional, anchored);
  if (code === 0) {
    fs.rmSync(pendingFile, { force: true });
    for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  }
  return code;
}

const LIST_MAX = 32;
const BATCH_MAX = 1000;
const SALT_PREFIX = 'qtrace-salt/1 ';

async function hashFile(file, what) {
  let fh;
  try {
    fh = await fs.promises.open(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    throw usageError('the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  const h = crypto.createHash('sha3-256');
  const buf = Buffer.alloc(1024 * 1024);
  let size = 0;
  try {
    if (!(await fh.stat()).isFile()) throw usageError('the ' + what + ' must be a regular file');
    for (;;) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      if (size > FILE_MAX) throw usageError('the ' + what + ' is larger than ' + FILE_MAX + ' bytes');
      h.update(buf.subarray(0, bytesRead));
    }
  } finally {
    await fh.close();
  }
  return { digest: h.digest('hex'), size };
}

function openPublic(file, what) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    throw usageError('the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function readSmall(file, what, max) {
  const fd = openPublic(file, what);
  try {
    return readAll(fd, what, max);
  } finally {
    fs.closeSync(fd);
  }
}

function saltText(salt) {
  const digits = '0123456789abcdef';
  const out = Buffer.allocUnsafeSlow(SALT_PREFIX.length + 65);
  out.write(SALT_PREFIX, 0, 'ascii');
  for (let i = 0; i < 32; i += 1) {
    out[SALT_PREFIX.length + 2 * i] = digits.charCodeAt(salt[i] >> 4);
    out[SALT_PREFIX.length + 2 * i + 1] = digits.charCodeAt(salt[i] & 15);
  }
  out[out.length - 1] = 10;
  return out;
}

function readSalt(file) {
  const fd = openRegular(file, 'salt file');
  const raw = Buffer.allocUnsafeSlow(200);
  const salt = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the salt file ' + safe(file) + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the salt file ' + safe(file) + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13)) end -= 1;
    if (end !== SALT_PREFIX.length + 64 || raw.subarray(0, SALT_PREFIX.length).toString('ascii') !== SALT_PREFIX) throw usageError('the salt file must hold a qtrace-salt/1 line written by attest');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[SALT_PREFIX.length + 2 * i]);
      const lo = hexNibble(raw[SALT_PREFIX.length + 2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the salt file must hold a qtrace-salt/1 line written by attest');
      salt[i] = (hi << 4) | lo;
    }
    return salt;
  } catch (e) {
    salt.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function identityOf(file, follow) {
  let st = null;
  try {
    st = follow ? fs.statSync(file) : fs.lstatSync(file);
  } catch (e) {
    st = null;
  }
  let dir = path.dirname(path.resolve(file));
  try {
    dir = fs.realpathSync(dir);
  } catch (e) {
    dir = path.dirname(path.resolve(file));
  }
  return { path: path.join(dir, path.basename(file)).normalize('NFC').toLowerCase(), ino: st ? st.dev + ':' + st.ino : null, st };
}

function sameFile(a, b) {
  const x = statOf(a);
  const y = statOf(b);
  return !!(x && y && x.dev === y.dev && x.ino === y.ino);
}

function checkPaths(dests, sources) {
  const seen = [];
  const clash = (a, b) => a.path === b.path || (a.ino !== null && a.ino === b.ino);
  for (const [flag, f] of sources) if (f !== undefined) seen.push([flag, identityOf(f, true)]);
  for (const [flag, f, mayExist] of dests) {
    if (f === undefined) continue;
    const id = identityOf(f, false);
    if (id.st && id.st.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(f));
    if (id.st && !id.st.isFile()) throw usageError('something other than a file exists at ' + safe(f));
    if (id.st && !mayExist) throw usageError('a file already exists at ' + safe(f) + (flag === '--input-salt-out' ? ', a salt file is never replaced' : ', pass --force to replace it'));
    for (const [other, oid] of seen) if (clash(id, oid)) throw usageError(flag + ' must not be the same file as ' + other);
    seen.push([flag, id]);
  }
}

function hexFlag(value, name) {
  if (!/^[0-9a-f]{64}$/.test(value)) throw usageError('--' + name + ' is 64 lowercase hex characters');
  return value;
}

function capList(list, name, max) {
  const l = list || [];
  if (l.length > max) throw usageError('at most ' + max + ' values can be given for --' + name);
  return l;
}

function keyRef(value, name) {
  if (/^[0-9a-f]{64}$/.test(value)) return value;
  const desc = readJson(value, name + ' key', false, KEY_JSON_MAX);
  if (!desc || desc.format !== 'qtrace-key/1' || typeof desc.publicKey !== 'string') throw usageError('--' + name + ' is a key id or a qtrace-key/1 file');
  return desc;
}

function sizeFlag(value) {
  if (!/^\d{1,15}$/.test(value)) throw usageError('--content-size is a whole number of bytes');
  return Number(value);
}

function writeEnvelope(file, env, force) {
  atomicWrite(file, asciiJson(env) + '\n', force);
}

async function cmdRegisterModel(positional, flags) {
  if (positional.length) throw usageError('register-model takes options only');
  const out = need(flags, 'out');
  if ((flags['model-file'] === undefined) === (flags['model-digest'] === undefined)) throw usageError('give exactly one of --model-file or --model-digest');
  if (flags['card-file'] !== undefined && flags['card-digest'] !== undefined) throw usageError('give --card-file or --card-digest, not both');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--model-file', flags['model-file']], ['--card-file', flags['card-file']]]
    .concat(capList(flags.producer, 'producer', LIST_MAX).filter((v) => !/^[0-9a-f]{64}$/.test(v)).map((f) => ['--producer', f])));
  const opts = { name: need(flags, 'name'), version: flags.version, note: flags.note };
  opts.producers = capList(flags.producer, 'producer', LIST_MAX).map((p) => keyRef(p, 'producer'));
  opts.modelDigest = flags['model-digest'] !== undefined ? hexFlag(flags['model-digest'], 'model-digest') : (await hashFile(flags['model-file'], 'model file')).digest;
  if (flags['card-digest'] !== undefined) opts.cardDigest = hexFlag(flags['card-digest'], 'card-digest');
  if (flags['card-file'] !== undefined) opts.cardDigest = (await hashFile(flags['card-file'], 'model card')).digest;
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qt.registerModel(Object.assign({ key: seed }, opts)));
  writeEnvelope(out, env, flags.force);
  console.log('model ' + safe(env.statement.name) + ' registered as ' + qt.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdWithdraw(positional, flags) {
  if (positional.length) throw usageError('withdraw takes options only');
  const out = need(flags, 'out');
  const producer = need(flags, 'producer');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--model', flags.model]].concat(/^[0-9a-f]{64}$/.test(producer) ? [] : [['--producer', producer]]));
  const model = readJson(need(flags, 'model'), 'model', true);
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qt.withdrawProducer({ key: seed, model, producer: keyRef(producer, 'producer'), note: flags.note }));
  writeEnvelope(out, env, flags.force);
  console.log('producer ' + env.statement.producerKeyId + ' withdrawn from model ' + env.statement.modelId + ', written to ' + safe(out));
  return 0;
}

async function cmdOwnerKey(positional, flags, rotate) {
  if (positional.length) throw usageError((rotate ? 'rotate' : 'revoke') + '-owner-key takes options only');
  const out = need(flags, 'out');
  const successor = rotate ? need(flags, 'successor') : undefined;
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key]].concat(successor === undefined || /^[0-9a-f]{64}$/.test(successor) ? [] : [['--successor', successor]]));
  const env = withSeed(need(flags, 'key'), '--key', (seed) => (rotate
    ? qt.rotateOwnerKey({ key: seed, successor: keyRef(successor, 'successor'), note: flags.note })
    : qt.revokeOwnerKey({ key: seed, note: flags.note })));
  writeEnvelope(out, env, flags.force);
  console.log('owner key ' + env.statement.ownerKeyId + (rotate ? ' handed over to ' + env.statement.successorKeyId : ' revoked') + ', anchor it at once, written to ' + safe(out));
  return 0;
}

async function cmdAttest(positional, flags) {
  if (positional.length) throw usageError('attest takes options only');
  const out = need(flags, 'out');
  if ((flags['input-file'] === undefined) !== (flags['input-salt-out'] === undefined)) throw usageError('--input-file and --input-salt-out go together');
  if ((flags.content === undefined) === (flags['content-digest'] === undefined)) throw usageError('give exactly one of --content or --content-digest');
  const ing = capList(flags.ingredient, 'ingredient', LIST_MAX);
  checkPaths([['--input-salt-out', flags['input-salt-out'], false], ['--out', out, !!flags.force]],
    [['--key', flags.key], ['--content', flags.content], ['--model', flags.model], ['--input-file', flags['input-file']], ['--c2pa-file', flags['c2pa-file']]].concat(ing.map((f) => ['--ingredient', f])));
  const opts = { mediaType: need(flags, 'media-type'), note: flags.note };
  if (flags.action !== undefined) opts.action = flags.action;
  if (flags['source-type'] !== undefined) opts.sourceType = flags['source-type'];
  if (flags.content !== undefined) {
    if (flags['content-size'] !== undefined) throw usageError('--content-size goes with --content-digest only');
    const h = await hashFile(flags.content, 'content file');
    opts.contentDigest = h.digest;
    opts.contentSize = h.size;
  } else {
    opts.contentDigest = hexFlag(flags['content-digest'], 'content-digest');
    opts.contentSize = sizeFlag(need(flags, 'content-size'));
  }
  if (flags.model !== undefined) opts.model = readJson(flags.model, 'model', true);
  opts.ingredients = ing.map((f) => readJson(f, 'ingredient', true));
  if (flags['c2pa-file'] !== undefined) opts.c2paDigest = (await hashFile(flags['c2pa-file'], 'C2PA manifest')).digest;
  let salt = null;
  if (flags['input-file'] !== undefined) {
    const input = readSmall(flags['input-file'], 'input file', ENVELOPE_MAX * 16);
    try {
      const c = qt.commitInput(input);
      salt = c.salt;
      opts.inputDigest = c.digest;
    } finally {
      input.fill(0);
    }
  }
  try {
    const env = withSeed(need(flags, 'key'), '--key', (seed) => qt.attest(Object.assign({ key: seed }, opts)));
    if (salt) {
      const text = saltText(salt);
      try {
        atomicWrite(flags['input-salt-out'], text, false);
      } finally {
        text.fill(0);
      }
    }
    if (salt && sameFile(out, flags['input-salt-out'])) throw usageError('--out must not be the same file as --input-salt-out');
    writeEnvelope(out, env, flags.force);
    console.log('output ' + env.statement.outputId + ' attested as ' + qt.refOf(env) + ', written to ' + safe(out));
    return 0;
  } finally {
    if (salt) salt.fill(0);
  }
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one envelope');
  const env = readJson(positional[0], 'envelope', true);
  const opts = { requireAnchor: !flags['allow-unanchored'] };
  const type = env && typeof env === 'object' ? env.type : undefined;
  const OUTPUT_ONLY = ['producer', 'content', 'content-digest', 'model', 'model-owner', 'input-file', 'input-salt-file', 'c2pa-file', 'ingredient', 'withdrawal', 'no-withdrawals'];
  if (flags['no-owner-key-changes'] && flags['owner-key-change']) throw usageError('give --owner-key-change files or --no-owner-key-changes, not both');
  if (flags['owner-key-change']) opts.ownerKeyChanges = capList(flags['owner-key-change'], 'owner-key-change', 256).map((f) => readJson(f, 'owner key change', true));
  else if (flags['no-owner-key-changes']) opts.ownerKeyChanges = [];
  if (flags.artefact !== undefined) opts.artefactDigest = (await hashFile(flags.artefact, 'model artefact')).digest;
  if (type === 'keychange') {
    const stray = OUTPUT_ONLY.concat(['artefact']).filter((k) => flags[k] !== undefined);
    if (stray.length) throw usageError('an owner key change is checked against --owner only');
    opts.type = 'keychange';
    opts.ownerKeyId = keyRef(need(flags, 'owner'), 'owner');
  } else if (type === 'model') {
    const stray = OUTPUT_ONLY.filter((k) => flags[k] !== undefined);
    if (stray.length) throw usageError('a model registration is checked against --owner and --artefact only, --' + stray.join(', --') + ' apply to an output manifest');
    opts.ownerKeyId = keyRef(need(flags, 'owner'), 'owner');
  } else {
    if (flags.owner !== undefined) throw usageError('an output manifest is checked against --producer, and its model against --model-owner');
    if (flags.producer === undefined && flags['model-owner'] === undefined) throw usageError('give the expected --producer, or --model with its expected --model-owner');
    if (flags.producer !== undefined) opts.producerKeyId = keyRef(flags.producer, 'producer');
    if (flags.content !== undefined && flags['content-digest'] !== undefined) throw usageError('give --content or --content-digest, not both');
    if (flags.content !== undefined) opts.contentDigest = (await hashFile(flags.content, 'content file')).digest;
    if (flags['content-digest'] !== undefined) opts.contentDigest = hexFlag(flags['content-digest'], 'content-digest');
    if (flags.model !== undefined) opts.model = readJson(flags.model, 'model', true);
    if (flags['model-owner'] !== undefined) opts.modelOwnerKeyId = keyRef(flags['model-owner'], 'model-owner');
    if ((flags['input-file'] === undefined) !== (flags['input-salt-file'] === undefined)) throw usageError('--input-file and --input-salt-file go together');
    if (flags['input-file'] !== undefined) {
      opts.input = readSmall(flags['input-file'], 'input file', ENVELOPE_MAX * 16);
      opts.inputSalt = readSalt(flags['input-salt-file']);
    }
    if (flags['c2pa-file'] !== undefined) opts.c2paDigest = (await hashFile(flags['c2pa-file'], 'C2PA manifest')).digest;
    opts.ingredients = capList(flags.ingredient, 'ingredient', 64).map((f) => readJson(f, 'ingredient', true));
    if (flags['no-withdrawals'] && flags.withdrawal) throw usageError('give --withdrawal files or --no-withdrawals, not both');
    if (flags.withdrawal) opts.withdrawals = capList(flags.withdrawal, 'withdrawal', 256).map((f) => readJson(f, 'withdrawal', true));
    else if (flags['no-withdrawals']) opts.withdrawals = [];
  }
  if (flags.at !== undefined) opts.at = flags.at;
  if (flags['max-anchor-delay'] !== undefined) {
    if (!/^[1-9][0-9]{0,9}$/.test(flags['max-anchor-delay'])) throw usageError('--max-anchor-delay is a whole number of seconds');
    opts.maxAnchorDelay = Number(flags['max-anchor-delay']);
  }
  Object.assign(opts, endpointOptions(flags));
  if (flags['expect-sender']) opts.expectedSender = flags['expect-sender'];
  let res;
  try {
    res = await qt.verify(env, opts);
  } finally {
    if (opts.inputSalt) opts.inputSalt.fill(0);
    if (opts.input) opts.input.fill(0);
  }
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const c of res.checks) console.log((c.ok ? 'ok    ' : c.transport ? 'retry ' : c.indeterminate || c.unproven ? 'open  ' : 'FAIL  ') + safe(c.name) + '  ' + safe(c.detail));
    for (const n of res.notes || []) console.log('note  ' + safe(n));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  endpoints other than the official ones of this network were consulted, an anchor confirmed only by them is not proven');
    }
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' || res.status === 'unproven' ? 2 : 1;
}

async function cmdC2pa(positional, flags) {
  if (positional.length > 1) throw usageError('c2pa takes one output envelope, or --action and --source-type for an output still to be attested');
  const model = flags.model !== undefined ? readJson(flags.model, 'model', true) : undefined;
  let source;
  if (positional.length === 1) {
    if (flags.action !== undefined || flags['source-type'] !== undefined || flags.when !== undefined) throw usageError('--action, --source-type and --when describe an output still to be attested');
    source = readJson(positional[0], 'envelope', true);
  } else {
    source = { action: flags.action, sourceType: flags['source-type'], when: flags.when };
  }
  process.stdout.write(asciiJson(qt.c2paActions(source, model)) + '\n');
  return 0;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, 'register-model': cmdRegisterModel, withdraw: cmdWithdraw, 'revoke-owner-key': (p, f) => cmdOwnerKey(p, f, false), 'rotate-owner-key': (p, f) => cmdOwnerKey(p, f, true), attest: cmdAttest, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify, c2pa: cmdC2pa }[command];
  return run(positional, flags);
}

function friendly(e) {
  if (e && typeof e.syscall === 'string' && typeof e.code === 'string') return 'a file could not be ' + (e.syscall === 'open' || e.syscall === 'read' ? 'opened' : 'written') + ' (' + e.code + ')';
  return (e && e.message) || String(e);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(safe(friendly(e)).slice(0, 600));
    const evidence = /not a valid envelope|not validly signed|must be a (model|output) envelope|does not belong to these|not the one this output names|not authorised by the model owner|already anchored|signature that does not verify|not signed by the key it names/;
    process.exitCode = e && (e.usage || (e.code === 'QTRACE_INVALID_INPUT' && !evidence.test(e.message || ''))) ? 64 : 1;
  },
);
