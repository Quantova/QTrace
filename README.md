# QTrace

QTrace is a post quantum provenance layer for content produced by AI. It lets a model owner register a model under its own key, lets the services that the owner authorises attest each document, image, audio file or answer the model produces, and lets anyone later prove which registered model and which producer stand behind a given piece of content, and when it was recorded. Every registration and every output manifest is signed with the Module Lattice Digital Signature Algorithm, parameter set 65, as standardised in FIPS 204, and each can carry a Qstamp time proof recorded on the Quantova network.

## What QTrace is

Generated text, images and audio now reach customers, newsrooms, courts and public bodies every day. When a piece of content is questioned, three facts matter. Which model produced it. Which organisation stands behind it. And whether the content in hand is exactly what was produced, or something altered since.

QTrace answers those questions with cryptographic evidence. A model owner signs a registration that names the model, its version, the SHA3 fingerprint of the model artefact and the keys of the services allowed to attest its outputs. Each authorised service signs an output manifest for every piece of content it releases, holding the fingerprint and size of the content, its media type, what was done to produce it, the registered model it came from, a private commitment to the prompt and any earlier outputs it was built from. A verifier, whether a platform, a newsroom, an auditor, a regulator or a court, can then confirm the chain from content to producer to model owner without trusting the producer, the platform that carried the content or Quantova Inc.

QTrace is standalone. It runs on the systems of the organisation, holds its keys locally and uses the Quantova network only as a neutral public ledger for time proofs.

## Why organisations need it

Article 50 of the European Union AI Act requires providers of AI systems that generate synthetic audio, image, video or text to mark the output in a machine readable format and make it detectable as artificially generated. Publishers, platforms and public bodies increasingly ask for content credentials before they accept or distribute material, and the industry has converged on the C2PA vocabulary for describing how content was made.

Existing content credentials are signed with classical algorithms that a quantum computer will be able to forge, and a credential that can be forged can also be moved onto content it never described. QTrace gives every output a post quantum signature, binds it to a registered model whose owner has authorised the producer, and fixes its time on a public ledger, so the provenance remains provable for as long as the content is kept.

## Who uses it

1. Model providers that want their outputs to be recognisable as theirs and to state which services may speak for their models.
2. Enterprises and public bodies that publish generated documents, images or answers and must show what was generated and by which system.
3. Newsrooms, platforms and marketplaces that need to check where a submitted image or text came from before they accept it.
4. Regulators and courts that need to establish whether a disputed piece of content was produced by a given model and organisation.

## How an organisation integrates QTrace

1. Register the model. The model owner creates an ML-DSA-65 key with the keygen command or the generateKey function and signs a registration naming the model, its version, the SHA3-256 fingerprint of the model artefact and, if it wishes, the fingerprint of its model card. The registration lists the keys of the serving systems the owner authorises. The owner anchors the registration as a Qstamp AI model record.

2. Give each serving system its own key. Every service that releases content holds its own producer key in the secrets manager or hardware protected store of the organisation, and its key identifier is listed in the model registration.

3. Attest every output. When the service releases a piece of content, it signs an output manifest with the content fingerprint and size, the media type, the action and the digital source type, the registered model, and optionally a commitment to the prompt, the outputs it was built from and the fingerprint of a C2PA manifest store. QTrace refuses to sign a manifest for a model whose owner has not authorised the producer.

4. Commit to the prompt privately. The commitInput function returns a random 32 byte salt and a commitment to the prompt. Only the commitment enters the manifest. The organisation keeps the prompt and the salt, and can later prove the prompt to a court or regulator without ever having published it.

5. Anchor on a schedule. A single service with a funded Quantova account anchors new manifests in batches as Qstamp AI output records. Each manifest receives its own receipt.

6. Carry the provenance with the content. Before attesting, the c2paActions function produces a C2PA actions assertion from the planned action, digital source type and model, so an existing C2PA tool can embed it in the file. The service then attests the final file, so the fingerprint covers the embedded assertion. A C2PA manifest store kept beside the file instead is bound by its own fingerprint. The QTrace manifest and its receipt travel alongside the file or are served on request.

7. Verify when it matters. A verifier receives the content, the output manifest, the model registration and any source outputs, and checks them against the producer key it expects, or against the model owner key alone, in which case the producer must be one the owner authorised. A verifier that relies on one specific model supplies its own trusted copy of that registration, or its artefact, rather than the one in the bundle. It can use the verify command, the library or the independent procedure below.

## What is published and what stays private

The content, the prompt, the model artefact, the manifests and the registrations stay with the organisation and the parties it chooses to share them with. Manifests hold only SHA3 fingerprints of the content, the model artefact and the C2PA manifest store, and a salted commitment to the prompt.

When an envelope is anchored, only a 32 byte Qstamp commitment reaches the chain. It is derived from a salted fingerprint of the signed envelope and cannot be reversed into the content, the prompt, the model or any other field.

## Cryptographic construction

1. Keys. Model owner and producer keys are 32 byte seeds from which ML-DSA-65 key pairs are derived by the key generation procedure of FIPS 204. A key identifier is the SHA3 hash with a 256 bit output of the ASCII label quantova/qtrace/key/1, the byte 0x00 and the 1952 byte public key.

2. Fingerprints. The content, the model artefact, the model card and the C2PA manifest store are each fingerprinted with plain SHA3-256 under FIPS 202, so any standard implementation reproduces the value. The prompt commitment is the SHA3-256 hash of the ASCII label quantova/qtrace/input/1, the byte 0x00, a random 32 byte salt and the prompt.

3. Statements. Each statement is a canonical binary encoding that begins with the ASCII bytes QTRC and the version byte 1, followed by the statement type and its fields in a fixed order. Every field is an unsigned 16 bit big endian length followed by its bytes, an optional digest is an empty field when absent, the content size is an unsigned 64 bit big endian integer, and lists are encoded as a count followed by their items, so every statement has exactly one encoding. A model registration encodes the model identifier, the owner key identifier, the name, the version, the model fingerprint, the card fingerprint, the authorised producer keys, the registration time and a note. An output manifest encodes the output identifier, the producer key identifier, the model reference, the content fingerprint and size, the media type, the action, the digital source type, the prompt commitment, the source references, the C2PA fingerprint, the creation time and a note. An owner key change encodes the change identifier, the owner key identifier, the successor key identifier, empty when the key is revoked without a successor, the time of the change and a note.

4. Signatures. Statements are signed with ML-DSA-65 in its hedged form under the FIPS 204 context string quantova/qtrace/1. This context separates QTrace signatures from QSign, QMandate and QLog signatures, from Quantova network transactions and from every other use of the algorithm.

5. References. An envelope is referenced by the SHA3 hash of the label quantova/qtrace/ref/1, the byte 0x00, the encoded statement and its signature. An output names its model and its sources by these references, so it relies on one exact signed registration and on exact signed sources, which therefore existed before the output was signed.

6. Anchor. To anchor an envelope, QTrace stamps the SHA3 hash of the label quantova/qtrace/anchor/1, the byte 0x00, the encoded statement and its signature, as a Qstamp AI model record for registrations, withdrawals and owner key changes, and as a Qstamp AI output record for manifests.

## Rules applied by verification

1. The envelope is well formed, it is the type of envelope the verifier expects, and its signer identifier matches its public key and the owner or producer it names.
2. A registration is signed by the expected model owner. A manifest is signed by the expected producer, or, when only the model owner is expected, by a producer that owner authorised.
3. When the content is supplied, its SHA3-256 fingerprint equals the one in the manifest.
4. When the manifest names a model, the supplied registration is exactly the one referenced, it is signed by the expected model owner, that owner authorised the producer, no withdrawal of that producer by the owner was anchored before the output, and the output is not dated before the registration. When the verifier expects a model, a manifest that names none is invalid. When the model artefact is supplied, its fingerprint equals the registered one.
5. When the prompt and its salt are supplied, they reproduce the committed value.
6. When a C2PA manifest store is supplied, its fingerprint equals the one in the manifest.
7. Every source the manifest names is supplied as a validly signed output with the referenced identity and is not dated after the output that uses it, and its anchor is verified when anchors are required. Sources supplied for a manifest that names none make the result invalid.
8. Each anchor is verified under the record kind for its envelope type, the model kind for a withdrawal or an owner key change, with a SHA3 digest, and the claimed time is not later than the anchor time, allowing five minutes for clock difference, and no more than 24 hours before it, a window the verifier may change. When a time of verification is given, an anchor made after it does not prove the time. No envelope may be dated after the time of verification, which is the time of the chain unless the verifier states another. When the time of the chain cannot be established the result is indeterminate and the local clock is never used in its place.
9. An anchor counts only when Qstamp reports it proven, which needs at least two pinned independent operators of the network or a light client proof. An anchor confirmed only by custom endpoints, or by a single endpoint under trustSingleEndpoint, is reported as unproven and treated as not anchored, so the result is never valid.
10. No revocation or rotation of the model owner key, signed by that key, was anchored at or before the registration or the output. The earliest proven change counts. A verifier that expects an owner key also accepts a registration by a successor key that the expected key named in a proven rotation, and by the successors that key named in turn.

A result is valid only when the expected producer or owner is given, the content is supplied, the named model and its expected owner are supplied, the withdrawals held for its producer are supplied, the owner key changes held for the model owner are supplied, every source is supplied and every envelope is anchored. When any of these is missing the result is indeterminate rather than valid, so a gap in the evidence can never be mistaken for proof. A verifier may accept unanchored envelopes explicitly when it needs to.

## Trust model of this release

This release anchors on the live Quantova network Q-test-net-1. The signing module is compiled from the Quantova Q-Crypto library, which follows FIPS 204 and FIPS 202 and has been tested against the NIST vectors and cross checked against an independent implementation. It has not been validated under FIPS 140-3. An anchor time is accepted only when Qstamp proves the anchor, either by a finality certificate checked against a pinned validator roster or by official endpoints of the network run by two different operators. An anchor confirmed by endpoints of one operator, or by endpoints chosen by the verifier, is reported as unproven and is never valid, whatever options are set. While the network has one official endpoint and no pinned roster every anchor is unproven, which is the honest result. Verification names the endpoints it consulted and says whether they are the official endpoints of the network.

An output manifest is the signed statement of its producer. QTrace proves who made that statement, that the model owner authorised the producer to make it, that the content matches and when the statement was recorded. It does not prove that the named model computed the content, because no signature can observe a computation, and it does not detect content that was never attested. Matching a key to an accountable organisation is a matter for that organisation, for example through a published key description. A model owner withdraws a producer with a withdrawal, a statement signed by the owner that names the model and the producer key and is anchored at once. An output anchored after the withdrawal is invalid, an output anchored before it stays valid, and a verifier must supply the withdrawals it holds, an empty list when it holds none.

A model owner whose key is exposed or retired signs an owner key change with that key and anchors it at once. A revocation ends the authority of the key. A rotation ends it in the same way and names a successor key, which registers the models again, with the same or new producers. Every registration, and every output under a model of that key, anchored at or after the change is invalid, and those anchored before it stay valid. A verifier must supply the owner key changes it holds, an empty list when it holds none. An owner key change can only be signed by the key it retires, so a key that is already lost cannot be retired this way, and a holder of a stolen key can retire it first and name its own successor. Verifiers that pin the owner key should therefore receive owner key changes through the same trusted channel as the key itself. The model name and version are text chosen by the owner and are not verified, the identity that is checked is the owner key. Text fields accept only visible characters in Unicode normal form C.

QTrace uses the action names of the C2PA specification and the digital source types of the IPTC vocabulary, and can export a C2PA actions assertion. It does not produce a signed C2PA manifest, because the C2PA specification currently lists only classical signature algorithms. It anchors the fingerprint of an existing C2PA manifest store instead, so a classical credential gains a post quantum time proof. The c2paActions function returns only the standard assertion, and it refuses an output envelope whose signature does not verify.

## Installation

```
npm install @quantovainc/qtrace
```

QTrace requires Node 20 or later.

## Command line use

```
qtrace keygen owner.key
qtrace keygen service.key
qtrace key owner.key > owner.pub.json
qtrace key service.key > service.pub.json

qtrace register-model --key owner.key --name "Atlas Vision" --version 2.1 --model-file weights.safetensors --producer service.pub.json --out model.json
qtrace anchor model.json --seed-file account.key

qtrace attest --key service.key --content image.png --media-type image/png --model model.json --input-file prompt.txt --input-salt-out prompt.salt --out image.qtrace.json
qtrace anchor image.qtrace.json --seed-file account.key

qtrace verify image.qtrace.json --producer service.pub.json --content image.png --model model.json --model-owner owner.pub.json --no-withdrawals --no-owner-key-changes
qtrace withdraw --key owner.key --model model.json --producer service.pub.json --out service.withdrawal.json
qtrace anchor service.withdrawal.json --seed-file account.key
qtrace c2pa --action created --source-type trainedAlgorithmicMedia --model model.json > c2pa-actions.json

qtrace rotate-owner-key --key owner.key --successor owner2.pub.json --out owner.rotation.json
qtrace anchor owner.rotation.json --seed-file account.key
qtrace verify image.qtrace.json --producer service.pub.json --content image.png --model model.json --model-owner owner.pub.json --no-withdrawals --owner-key-change owner.rotation.json
```

Content and model files are hashed as they are read, so files up to 64 GiB are supported and never leave the machine, and symbolic links such as model caches are followed for these public files. The prompt salt is written in its own qtrace-salt/1 format to a new file readable only by its owner and is never replaced, and no output may share a path with any input or with another output. Models, outputs and withdrawals are anchored in separate batches. If an anchor is interrupted after its transaction was sent, the pending stamp is saved beside the first envelope and the complete command finishes it without paying again. The command exits with status 0 when the result is valid, 1 when it is invalid, refused or the evidence is malformed, 2 when it cannot be decided or rests on an unproven anchor, and 64 for usage errors, including a path that cannot be opened. Key and salt files must be readable only by their owner and are never followed through symbolic links.

## Programmatic use

```js
const qtrace = require('@quantovainc/qtrace');

const model = qtrace.registerModel({ key: ownerKey, name: 'Atlas Vision', version: '2.1', model: weightBytes, producers: [serviceKeyDescription] });

const prompt = qtrace.commitInput(promptBytes);
const output = qtrace.attest({ key: serviceKey, content: imageBytes, mediaType: 'image/png', model, inputDigest: prompt.digest });

const [anchored] = await qtrace.anchor(output, { seed: accountSeed, index: 0, network: 'testnet' });

const result = await qtrace.verify(anchored, { producerKeyId, content: imageBytes, model: anchoredModel, modelOwnerKeyId, withdrawals: [], ownerKeyChanges: [] });

const revocation = qtrace.revokeOwnerKey({ key: ownerKey, note: 'key retired' });
```

## Independent verification procedure

1. Decode each public key and signature from base64 and confirm their lengths are 1952 and 3309 bytes.
2. Compute each key identifier from the label quantova/qtrace/key/1, the byte 0x00 and the public key, and compare it with the signer identifier and the owner or producer named in the statement.
3. Encode each statement as described above and verify its signature with ML-DSA-65 under the context string quantova/qtrace/1, following FIPS 204.
4. Compute the SHA3-256 fingerprint of the content and compare it with the manifest.
5. Compute the reference of the model registration and of each source, and confirm the manifest names them. Confirm the producer is the model owner or is listed among the authorised producers.
6. Compute the anchor value of each envelope and verify its receipt by the procedure published with Qstamp, then apply the rules of verification listed above.

## Network

The live Quantova network is named Q-test-net-1 with genesis hash ca91e093bb8de33e90db52d7c89876597d14760703793ea7211929e73e613062. Anchors are recorded by the official Qstamp contract on that network. The public endpoint is https://rpc-testnet.quantova.org. By default verification consults the official endpoints of the network. Endpoints chosen by the verifier are given with the rpc or clients option, or with --rpc once for each on the command line, and verification consults them only with trustCustomEndpoints, or --trust-custom-endpoints. An endpoint on a loopback address is refused unless allowLoopback, or --allow-loopback, is set, and an endpoint on a private network address unless it is named in endpointAllowList, or with --allow-endpoint. The option expectedSender, or --expect-sender, names the Quantova accounts entitled to anchor records, and an anchor signed by any other account is invalid. Anchoring accepts chain data only when at least two endpoints run by different operators agree, and the option trustSingleEndpoint, or --trust-single-endpoint, relies on one endpoint for anchoring and for the time of the chain.

## Licence

QTrace is created and owned by Quantova Inc. It is licensed under the Apache License 2.0 or the MIT licence, at your option. The full texts are in the files LICENSE-APACHE and LICENSE-MIT, and the notice is in NOTICE.
