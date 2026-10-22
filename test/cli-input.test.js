'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const { cliCampaign, runCli, tempDir, SAYS_VALID } = require('./fuzz');

const BIN = path.join(__dirname, '..', 'bin', 'qtrace.js');
const ENVELOPE_MAX = 1024 * 1024;
const image = Buffer.from('an image made by a model');

function records(dir) {
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const owner = q.generateKey();
  const producer = q.generateKey();
  const model = q.registerModel({ key: owner, name: 'Atlas Vision', version: '3', model: Buffer.from('weights'), producers: [q.describeKey(producer)], registeredAt: iso(now - 600000) });
  const output = q.attest({ key: producer, content: image, mediaType: 'image/png', model, createdAt: iso(now - 500000) });
  const keychange = q.rotateOwnerKey({ key: owner, successor: q.describeKey(q.generateKey()), changedAt: iso(now - 400000) });
  const files = {};
  for (const [name, env] of Object.entries({ model, output, keychange })) {
    files[name] = path.join(dir, name + '.json');
    fs.writeFileSync(files[name], JSON.stringify(env));
  }
  files.pending = path.join(dir, 'pending.json');
  fs.writeFileSync(files.pending, JSON.stringify({ records: [], kind: '0' }));
  const tail = ['--allow-unanchored', '--at', iso(now)];
  const ownerId = q.keyId(owner);
  return {
    text: { model: JSON.stringify(model), output: JSON.stringify(output), keychange: JSON.stringify(keychange) },
    files,
    verifyModel: (file) => ['verify', file, '--type', 'model', '--owner', ownerId, '--no-owner-key-changes'].concat(tail),
    verifyOutput: (file, modelFile) => ['verify', file, '--type', 'output', '--producer', q.keyId(producer), '--content-digest', F.sha3(image).toString('hex'), '--model', modelFile, '--model-owner', ownerId, '--no-withdrawals', '--no-owner-key-changes'].concat(tail),
    verifyChange: (file) => ['verify', file, '--type', 'keychange', '--owner', ownerId].concat(tail),
  };
}

async function valid(argv) {
  const r = await runCli(BIN, argv);
  assert.strictEqual(r.code, 0, r.out + r.err);
  assert.ok(SAYS_VALID.test(r.out), r.out);
}

async function campaignFor(t, text, commands) {
  const results = await cliCampaign({ bin: BIN, tag: 'qtrace-cli', cap: ENVELOPE_MAX, validText: text, commands });
  t.diagnostic(results.length + ' runs, slowest ' + Math.max(...results.map((r) => r.ms)) + ' ms');
}

let shared;
function setup() {
  if (!shared) {
    const dir = tempDir('qtrace-ok');
    shared = Object.assign(records(dir), { dir });
  }
  return shared;
}

test.after(() => {
  if (shared) fs.rmSync(shared.dir, { recursive: true, force: true });
});

test('hostile model registration files make verify and c2pa exit non zero quickly and never print VALID', async (t) => {
  const w = setup();
  await valid(w.verifyModel(w.files.model));
  await valid(w.verifyOutput(w.files.output, w.files.model));
  const c2pa = await runCli(BIN, ['c2pa', w.files.output, '--model', w.files.model]);
  assert.strictEqual(c2pa.code, 0, c2pa.out + c2pa.err);
  await campaignFor(t, w.text.model, [
    (file) => w.verifyModel(file),
    (file) => w.verifyModel(file).concat(['--json']),
    (file) => w.verifyOutput(w.files.output, file),
    (file) => ['c2pa', w.files.output, '--model', file],
  ]);
});

test('hostile output attestation files make verify, c2pa and complete exit non zero quickly and never print VALID', async (t) => {
  const w = setup();
  await valid(w.verifyOutput(w.files.output, w.files.model));
  await campaignFor(t, w.text.output, [
    (file) => w.verifyOutput(file, w.files.model),
    (file) => w.verifyOutput(file, w.files.model).concat(['--json']),
    (file) => ['c2pa', file, '--model', w.files.model],
    (file) => ['complete', file, '--pending', w.files.pending],
  ]);
});

test('hostile owner key change files make verify exit non zero quickly and never print VALID', async (t) => {
  const w = setup();
  await valid(w.verifyChange(w.files.keychange));
  await campaignFor(t, w.text.keychange, [
    (file) => w.verifyChange(file),
    (file) => w.verifyChange(file).concat(['--json']),
  ]);
});
