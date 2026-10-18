'use strict';

const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');
const { campaign, mutator, canon } = require('./fuzz');
const { honest, failing } = require('./honest');

const CODE = 'QTRACE_';
const NAMES = { model: 'model registration', output: 'output attestation', withdrawal: 'producer withdrawal', keychange: 'owner key change' };
const article = (word) => (/^[aeiou]/.test(word) ? 'an ' : 'a ') + word;
const valid = (r) => r.status === 'valid' || r.valid === true;
const takenAsWithdrawn = (r) => r.checks.some((c) => /^withdrawal \d+$/.test(c.name) && /withdrew this producer at \d{4}-/.test(c.detail));

function stringsOf(v, out) {
  if (typeof v === 'string' && v.length < 200) out.push(v);
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) stringsOf(v[k], out);
  return out;
}

let world;
async function setup() {
  if (!world) world = await honest();
  return world;
}

function target(w, type) {
  if (type === 'withdrawal') {
    return {
      check: (m) => w.q.verify(w.all.output, Object.assign({}, w.options.output, { withdrawals: [m] })),
      accepted: takenAsWithdrawn,
      baseline: (r) => r.status === 'valid' && takenAsWithdrawn(r),
    };
  }
  return { check: (m) => w.q.verify(m, w.options[type]), accepted: valid, baseline: (r) => r.status === 'valid' };
}

F.TYPES.forEach((type, n) => {
  const name = NAMES[type];
  const accepted = type === 'withdrawal' ? 'is never taken as a withdrawal of the producer' : 'never verifies valid';

  test('a changed ' + name + ' envelope ' + accepted + ', every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
    const w = await setup();
    const base = w.all[type];
    const tg = target(w, type);
    const honestResult = await tg.check(base);
    assert.ok(tg.baseline(honestResult), honestResult.status + ' ' + failing(honestResult).join('\n'));
    const stats = await campaign({
      name,
      seed: 0x7c30 + n,
      base,
      pool: stringsOf(w.all, []),
      code: CODE,
      check: tg.check,
      valid: tg.accepted,
    });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed Qstamp receipt on ' + article(name) + ' ' + accepted, async (t) => {
    const w = await setup();
    const base = w.all[type];
    const tg = target(w, type);
    const honestResult = await tg.check(base);
    assert.ok(tg.baseline(honestResult), honestResult.status + ' ' + failing(honestResult).join('\n'));
    const stats = await campaign({
      name: name + ' receipt',
      seed: 0x7cb0 + n,
      base: base.anchor,
      pool: stringsOf(Object.values(w.all).map((e) => e.anchor), []),
      code: CODE,
      check: (r) => tg.check(Object.assign({}, base, { anchor: r })),
      valid: tg.accepted,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});

test('the mutation stream is the same for the same seed', () => {
  const a = mutator(13);
  const b = mutator(13);
  const base = { format: 'qtrace/1', statement: { name: 'Atlas', producers: ['00ff'] }, signature: 'QUJDREVGR0hJSktMTU5PUA==' };
  for (let i = 0; i < 200; i += 1) assert.strictEqual(canon(a.mutate(base, i).value), canon(b.mutate(base, i).value));
});
