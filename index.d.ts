// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type EnvelopeType = 'model' | 'output' | 'withdrawal';
export type Action = 'created' | 'edited' | 'converted' | 'placed' | 'translated' | 'transcoded' | 'published';
export type SourceType =
  | 'trainedAlgorithmicMedia'
  | 'compositeWithTrainedAlgorithmicMedia'
  | 'algorithmicallyEnhanced'
  | 'algorithmicMedia'
  | 'compositeSynthetic'
  | 'dataDrivenMedia'
  | 'digitalCreation'
  | 'humanEdits';

export interface Envelope {
  format: 'qtrace/1';
  type: EnvelopeType;
  algorithm: 'ML-DSA-65';
  signer: { id: string; publicKey: string };
  statement: Record<string, unknown>;
  signature: string;
  anchor?: unknown;
}

export interface KeyDescription {
  format: 'qtrace-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type KeyRef = string | Uint8Array | KeyDescription;

export interface WithdrawProducerOptions {
  key: Uint8Array;
  model: Envelope;
  producer: KeyRef;
  withdrawnAt?: string;
  note?: string;
}

export interface RegisterModelOptions {
  key: Uint8Array;
  name: string;
  version?: string;
  model?: Uint8Array;
  modelDigest?: string;
  card?: Uint8Array;
  cardDigest?: string;
  producers?: KeyRef[];
  registeredAt?: string;
  note?: string;
}

export interface AttestOptions {
  key: Uint8Array;
  content?: Uint8Array;
  contentDigest?: string;
  contentSize?: number;
  mediaType: string;
  action?: Action;
  sourceType?: SourceType;
  model?: Envelope;
  inputDigest?: string;
  ingredients?: Envelope[];
  c2pa?: Uint8Array;
  c2paDigest?: string;
  createdAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed: Uint8Array;
  index: number;
  network?: 'testnet';
  rpc?: string;
  client?: unknown;
  meter?: number;
  maxFee?: string | number;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void | Promise<void>;
}

export interface VerifyOptions {
  type?: 'model' | 'output';
  ownerKeyId?: KeyRef;
  ownerPublicKey?: Uint8Array | string;
  artefact?: Uint8Array;
  artefactDigest?: string;
  producerKeyId?: KeyRef;
  producerPublicKey?: Uint8Array | string;
  content?: Uint8Array;
  contentDigest?: string;
  model?: Envelope;
  modelOwnerKeyId?: KeyRef;
  modelOwnerPublicKey?: Uint8Array | string;
  input?: Uint8Array;
  inputSalt?: Uint8Array;
  c2pa?: Uint8Array;
  c2paDigest?: string;
  ingredients?: Envelope[];
  withdrawals?: Envelope[];
  requireAnchor?: boolean;
  at?: string;
  rpc?: string;
  client?: unknown;
  clients?: Array<string | unknown>;
  contract?: string;
  trustCustomContract?: boolean;
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'invalid' | 'indeterminate';
  type: EnvelopeType | null;
  checks: VerifyCheck[];
  [field: string]: unknown;
  endpoints: string[];
  officialEndpoints: boolean | null;
}

export interface C2paActions {
  label: 'c2pa.actions.v2';
  data: { actions: Array<{ action: string; digitalSourceType: string; when: string; softwareAgent?: { name: string; version: string } }> };
}

export interface PlannedOutput {
  action?: Action;
  sourceType?: SourceType;
  when?: string;
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function registerModel(options: RegisterModelOptions): Envelope;
export function withdrawProducer(options: WithdrawProducerOptions): Envelope;
export function commitInput(input: Uint8Array): { salt: Uint8Array; digest: string };
export function attest(options: AttestOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: { rpc?: string; client?: unknown; timeoutMs?: number }): Promise<Envelope[]>;
export function c2paActions(source: Envelope | PlannedOutput, model?: Envelope): C2paActions;
export function verify(envelope: unknown, options: VerifyOptions): Promise<VerifyResult>;
export function refOf(envelope: Envelope): string;
export function anchorDigest(envelope: Envelope): string;
export const FORMAT: 'qtrace/1';
export const ALGORITHM: 'ML-DSA-65';
export const TYPES: readonly EnvelopeType[];
export const ACTIONS: readonly Action[];
export const SOURCE_TYPES: readonly SourceType[];
