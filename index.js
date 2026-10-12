// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const T = require('./lib/trace');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: T.generateKey,
  publicKey: T.publicKey,
  keyId: T.keyId,
  describeKey: T.describeKey,
  registerModel: T.registerModel,
  commitInput: T.commitInput,
  attest: T.attest,
  anchor: T.anchor,
  complete: T.complete,
  c2paActions: T.c2paActions,
  verify,
  refOf: (envelope) => F.refOf(F.parse(envelope)),
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  TYPES: F.TYPES,
  ACTIONS: F.ACTIONS,
  SOURCE_TYPES: F.SOURCE_TYPES,
};
