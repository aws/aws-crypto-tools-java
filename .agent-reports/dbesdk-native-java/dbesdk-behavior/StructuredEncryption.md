# StructuredEncryption — Behavior Spec

**Module:** `StructuredEncryption` — the foundational structured / field-level encryption core of DB-ESDK.
**Source of truth:** the Dafny `.dfy` source under `aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/StructuredEncryption/` (NOT the `specification/` prose, NOT transpiled Java). Where the English spec and Dafny disagree, Dafny wins; §7 records the disagreements.
**Status:** draft, generated from the `structuredencryption-discovery.md` checklist in this same folder (Steps 0–6 verified against source + test vectors). No native Java has been written for this module yet.
**Reader contract:** a reviewer should be able to read this document and correctly predict what the native Java port must do, without opening the `.dfy` source. Byte layouts here are exact.

---

## 1. Public surface

`localService StructuredEncryption`, config `StructuredEncryptionConfig` (empty). Depends on `AwsCryptographicPrimitives` (crypto) and `AwsCryptographicMaterialProviders` (CMM/keyrings). Single error type `StructuredEncryptionException` (`@error("client")`, one `message: String` field).

Five operations (Dafny types, not Java types):

| Operation | Input | Output |
| --- | --- | --- |
| `EncryptStructure` | `tableName: String`, `plaintextStructure: StructuredDataMap`, `cryptoSchema: CryptoSchemaMap`, `cmm`, `algorithmSuiteId?`, `encryptionContext?` | `{encryptedStructure: StructuredDataMap, cryptoSchema: CryptoSchemaMap, parsedHeader: ParsedHeader}` |
| `DecryptStructure` | `tableName`, `encryptedStructure: StructuredDataMap`, `authenticateSchema: AuthenticateSchemaMap`, `cmm`, `encryptionContext?` | `{plaintextStructure: StructuredDataMap, cryptoSchema, parsedHeader}` |
| `EncryptPathStructure` | `tableName`, `plaintextStructure: CryptoList`, `cmm`, `algorithmSuiteId?`, `encryptionContext?` | `{encryptedStructure: CryptoList, parsedHeader}` |
| `DecryptPathStructure` | `tableName`, `encryptedStructure: AuthList`, `cmm`, `encryptionContext?` | `{plaintextStructure: CryptoList, parsedHeader}` |
| `ResolveAuthActions` | `tableName`, `authActions: AuthList`, `headerBytes: Blob` | `{cryptoActions: CryptoList}` |

**`EncryptStructure`/`DecryptStructure` are thin adapters over the Path variants.** `EncryptStructure` requires `plaintextStructure.Keys == cryptoSchema.Keys` (else error), merges the two maps into one `CryptoList` (`BuildCryptoMap`, keys sorted, no duplicates), calls `EncryptPathStructure`, then splits the result back into `{encryptedStructure, cryptoSchema}` (`UnBuildCryptoMap`). `DecryptStructure` mirrors this over `BuildAuthMap`/`DecryptPathStructure`. **The real behavior lives in the Path operations** — a native port should implement those and derive the Map variants from them, matching the Dafny structure.

**`ResolveAuthActions`** is header-legend-driven action resolution only — no CMM, no crypto. It partial-deserializes `headerBytes` for its legend and returns the per-field resolved `CryptoList` (see §4 legend resolution).

**Core types:**
- `StructuredDataTerminal { value: blob, typeId: 2-byte blob }`.
- `CryptoAction` enum: `ENCRYPT_AND_SIGN`, `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`, `SIGN_ONLY`, `DO_NOTHING`.
- `AuthenticateAction` enum: `SIGN`, `DO_NOT_SIGN`.
- `Path` = list of `PathSegment`; **only `StructureSegment{key:String}` (map member) is currently used** — list-index and attribute segments are commented out in the model.
- `CryptoItem{key:Path, data, action:CryptoAction}`, `AuthItem{key:Path, data, action:AuthenticateAction}`, and their list forms `CryptoList`/`AuthList`.
- `ParsedHeader{algorithmSuiteId, encryptedDataKeys, storedEncryptionContext, encryptionContext}`.

---

## 2. Preconditions / postconditions / invariants (behavioral contracts)

### EncryptPathStructure — preconditions (each violation → `StructuredEncryptionException`)
- If `encryptionContext` is present, no key may begin with the reserved prefix `aws-crypto-`.
- At least one field's action must be an auth attr (not `DO_NOTHING`) — i.e. at least one of ENCRYPT_AND_SIGN / SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT / SIGN_ONLY.
- No input path may be a reserved header/footer path (`aws_dbe_head` / `aws_dbe_foot`).
- Input paths must be unique.
- `tableName` must be a valid string (UTF-8-encodable, length fits uint64).

### EncryptPathStructure — postconditions (output shape)
- `|output| == |input| + 2`. Two reserved fields are appended: the **header** field (`aws_dbe_head`) is second-to-last, the **footer** field (`aws_dbe_foot`) is last.
- Every input path appears in the output with the same path; no other non-reserved paths appear.
- An `ENCRYPT_AND_SIGN` field's output terminal has `typeId = 0xFFFF` and value = the encrypted serialization (§4). Every other field keeps its original typeId and value.

### DecryptPathStructure — preconditions
- At least one `SIGN` action in the `authenticateSchema` (else error).
- No duplicate paths.
- Both header (`aws_dbe_head`) and footer (`aws_dbe_foot`) fields must be present, each binary (typeId `0xFFFF`) and marked `DO_NOT_SIGN`.

### DecryptPathStructure — postconditions
- Output strips the header/footer fields; every other input path appears in the output with the same path, and vice-versa (no adds/drops besides header+footer).
- An `ENCRYPT_AND_SIGN` field (as resolved from the header legend, §4) has output typeId = the first 2 bytes of the input encrypted value, and value = the AES-GCM decryption. Every other field passes through unchanged.

### Materials contract (both directions)
- **Encrypt:** `cmm.GetEncryptionMaterials` is called with commitment policy `DBE(REQUIRE_ENCRYPT_REQUIRE_DECRYPT)` and `maxPlaintextLength = encryptedTerminalDataNum*2 + totalEncryptedTerminalValuesSize`. Default suite when `algorithmSuiteId` is absent: `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384`.
- **Decrypt:** `cmm.DecryptMaterials` is called with `algorithmSuiteId` from the parsed header, EDKs from the header, and `reproducedEncryptionContext = the input encryptionContext`; encryption context passed = the EC parsed from the header.
- **In both cases the algorithm suite that governs all crypto is the suite on the returned materials, which MAY differ from the input/header suite.** It must satisfy `ValidSuite` (`alg.id.DBE?` and a DBE algorithm suite) else error.

---

## 3. Error / exception behavior

Every failure path produces the module's single client error `StructuredEncryptionException` (built by a helper `E(msg)`). Exact, wire-visible messages confirmed from source/tests:
- `"Crypto Keys don't match."` — `EncryptStructure` when `plaintextStructure.Keys != cryptoSchema.Keys`.
- `"Invalid Algorithm Suite"` — returned materials' suite is not a valid DBE suite.
- `"Context keys out of order."` — header EC deserialization sees non-strictly-increasing or duplicate keys.
- `"Key commitment mismatch."` — header commitment verification fails (constant-time compare).
- `"Signature is N bytes, should have been 103 bytes"` — footer signature length wrong on serialize.
- `"Schema changed : something that was signed is now unsigned."` / `"...unsigned is now signed."` — legend length ≠ number of signed fields during decrypt legend resolution.
- `"Encryption Context Mismatch"` (per-key, via `DetectMismatch`) — reproduced EC disagrees with stored/used EC.
- Reserved-prefix, reserved-path, duplicate-path, non-auth-attr, and invalid-string precondition violations each raise `E(...)` with a descriptive message.

**No `History` call-log behavior is externally observable here** — the Dafny `History` fields on the service trait are verification scaffolding (per `dbesdk-java-translation-guidelines` §1.2); nothing outside the verifier reads them, so they are **not ported**.

---

## 4. Non-obvious behavioral detail (the part a signature does not tell you)

### 4.1 Canonical path (the AES-GCM AAD **and** the sort key)
`CanonPath(table, path)` =
```
UTF8(table) ++ uint64_be(depth = |path|) ++ MakeCanonicalPath(path)
```
`MakeCanonicalPath` concatenates one `CanonicalPart` per segment. For a **Map** segment (the only kind used):
```
CanonicalPart(key) = 0x24 ('$') ++ uint64_be(len(UTF8(key))) ++ UTF8(key)
```
(`0x23` '#' is reserved for list segments, not used.) So for a top-level attribute `attr` in table `table` (flat-map case), the AAD is exactly:
```
UTF8(table) ++ uint64_be(1) ++ 0x24 ++ uint64_be(len(UTF8(attr))) ++ UTF8(attr)
```
**Confirmed byte-for-byte by `test/Paths.dfy`.** A port that computes the AAD any other way cannot decrypt Dafny-written data even if every other step is correct.

### 4.2 Field ordering is load-bearing in three places, and it is length-major
Canonicalized fields are sorted **ascending, unsigned byte-lexicographic over the full canonical-path bytes** (`SortCanon.Below`). That single ordering fixes: (1) the per-field AES-CTR key offset, (2) the footer canonical-content order, (3) the legend↔field correspondence on decrypt. Encrypt and decrypt sort identically (`AuthSortIsCryptoSort`), so offsets line up.

**Because each canonical part encodes an 8-byte big-endian key length before the key bytes, the ordering is length-major:** a shorter UTF-8 key always sorts before a longer one; only equal-length keys are ordered by content. Confirmed by `test/Header.dfy` `TestSchemaOrderLength` (`aa, zz, aaa, zzz, aaaa, zzzz`). **The comparator must run on the canonical-path bytes, NOT on the raw attribute name** — sorting by name (plain lexicographic) would be wrong.

### 4.3 Field key derivation (must match exactly — golden vectors exist)
- `FieldRootKey = HKDF(hmac=alg.kdf, salt=none, ikm=plaintextDataKey, info="AWS_DBE_DERIVE_KEY"(18) ++ msgID(32), len=alg encrypt-key length)`.
- `FieldKey(offset) = first 44 bytes of AES-CTR-stream(key=FieldRootKey, nonce=FieldKeyNonce(offset*3))`.
- `FieldKeyNonce(n) = "AwsDbeField"(11 ascii) ++ 0x2c (=44) ++ uint32_be(n)` (16 bytes total).
- `Cipherkey = FieldKey[0..32]`, `Nonce = FieldKey[32..44]` (12 bytes).
- **`offset` = the field's index among ENCRYPT_AND_SIGN fields only, in canonical-sorted order** (increments per encrypted field). The nonce uses `offset*3` (each field consumes 3 AES-CTR blocks).
- **`test/Crypt.dfy` provides concrete `(32-byte rootKey, offset) → 44-byte FieldKey` vectors — these are must-pass conformance vectors for the port.**

### 4.4 Terminal encrypt / decrypt
- **Encrypt:** AES-GCM(key=Cipherkey, iv=Nonce, aad=canonical path, plaintext=terminal value). Output terminal: `typeId = 0xFFFF`, value = `originalTypeId(2) ++ ciphertext ++ authTag(16)`.
- **Decrypt:** parse value as `typeId(2) ++ ciphertext ++ authTag(last 16)` (requires `|value| >= 18`); AES-GCM decrypt with the same key/nonce/aad; output typeId = the parsed 2 bytes, value = plaintext.
- Only ENCRYPT_AND_SIGN fields are encrypted; all others pass through unchanged.

### 4.5 Header wire format
Full header = **Partial Header** ++ **32-byte commitment**. Partial Header, in order:
1. `version` — 1 byte, `0x02` iff any action is SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, else `0x01`.
2. `flavor` — 1 byte = `algorithmSuite.binaryId[1]` (binaryId = `[0x67, flavor]`). `0x00` = …SYMSIG_HMAC_SHA384 (no ECDSA); `0x01` = …ECDSA_P384_SYMSIG_HMAC_SHA384.
3. `msgID` — 32 bytes, freshly random per record.
4. **Encrypt Legend** — `uint16_be(len)` ++ legend bytes; one byte per **signed** field in canonical order, none for unsigned: `0x65`='e' ENCRYPT_AND_SIGN, `0x63`='c' SIGN_AND_INCLUDE, `0x73`='s' SIGN_ONLY.
5. **Encryption Context** — `uint16_be(count)` ++ per KV `uint16_be(keyLen) ++ key ++ uint16_be(valLen) ++ value` (UTF-8), sorted ascending by key, no duplicates. Stored EC = materials EC **minus** `requiredEncryptionContextKeys`.
6. **Encrypted Data Keys** — **1-byte** count (>0, ≤255) ++ per EDK `uint16_be(idLen) ++ id ++ uint16_be(infoLen) ++ info ++ uint16_be(ctLen) ++ ciphertext`.

**Commitment** = first 32 bytes of `HMAC(key=CommitKey, msg=PartialHeader)`, where the HMAC digest is the suite's commitment HMAC (`alg.commitment.HKDF.hmac`) — **SHA-512** for both currently-supported DBE suites (the suite's `commitment` is `HKDF_SHA_512(Bits256)`; verified 2026-09-28 from `AlgorithmSuites.dfy` and confirmed by cross-decrypt parity — an earlier draft wrongly said SHA-384). `CommitKey = HKDF(hmac=alg.commitment.HKDF.hmac (SHA-512), salt=none, ikm=plaintextDataKey, info="AWS_DBE_COMMIT_KEY"(18) ++ msgID(32), len=32)`. Verification recomputes over everything but the trailing 32 bytes and compares **constant-time**.

### 4.6 Footer wire format
Footer terminal (typeId `0xFFFF`) value = **Recipient Tags** (48 bytes each, one per EDK, in the materials' symmetric-signing-key order) ++ **Signature** (0 bytes if the suite has no ECDSA; **103 bytes** if it does — see §7).
- `RecipientTag[i] = HMAC(digest=alg.symmetricSignature, key=symmetricSigningKeys[i], msg=canonicalHash)` (len 48).
- `Signature = ECDSA(curve=alg.signature.ECDSA.curve, key=signingKey, msg=canonicalHash)` (len 103, DER-encoded).
- `canonicalHash = SHA-384(canonicalRecord)`.
- **canonicalRecord** = `fullHeader ++ uint64_be(aadLen) ++ AAD ++ fieldData`, where `AAD = SerializeContext(materials.encryptionContext)` and **fieldData** = for each **signed** field (all non-DO_NOTHING), in canonical-path order, the canonical field:
  - Encrypted: `canonPath ++ uint64_be(valueLen-2) ++ "ENCRYPTED"(9) ++ value` (value = 2-byte typeId + ciphertext+tag; the `-2` recovers the original plaintext length).
  - Plaintext: `canonPath ++ uint64_be(valueLen) ++ "PLAINTEXT"(9) ++ typeId(2) ++ value`.
- **Decrypt verification:** #tags must == #EDKs; recompute canonicalHash; require at least one recipient tag matches (constant-time) the HMAC under the provided symmetricSigningKey; then if the suite is ECDSA, ECDSA-verify the signature; `sig.Some?` must equal `alg.signature.ECDSA?`.

### 4.7 Decrypt re-derives per-field action from the header legend
On decrypt the caller's `authenticateSchema` only says SIGN vs DO_NOT_SIGN. The **actual** per-field crypto action is reconstructed from the stored header Encrypt Legend, applied to the signed fields in canonical-sorted order (`DoResolveLegend`): a DO_NOT_SIGN field → DO_NOTHING (consumes no legend byte); a SIGN field consumes the next legend byte → `0x65`→ENCRYPT_AND_SIGN, `0x63`→SIGN_AND_INCLUDE, `0x73`→SIGN_ONLY. A field the caller marked SIGN that the legend says was ENCRYPT_AND_SIGN **will be decrypted**. Legend length ≠ signed-field count is a hard error.

### 4.8 Two distinct legends — do not conflate
- The **header Encrypt Legend** (§4.5) — `e`/`c`/`s` bytes, one per signed field.
- The **V2 encryption-context legend** `aws-crypto-legend` — one char per SIGN_AND_INCLUDE field, sorted by UTF-8: `S`=String, `N`=Number, `L`=Null or Boolean, `B`=otherwise. The type→char dispatch is `Operations.dfy` (`typeId == NULL`→`L`, `STRING`→`S`, `NUMBER`→`N`, `BOOLEAN`→`L`, else→`B`). Built only when a SIGN_AND_INCLUDE action exists; EC keys are `aws-crypto-attr.` + dotted path; a duplicate produced key is an error; then a **Required Encryption Context CMM** wraps the input CMM with those keys required. A port must implement both legends separately.

### 4.9 Constants (confirmed from `Util.dfy`)
`HeaderField="aws_dbe_head"`, `FooterField="aws_dbe_foot"`, `ReservedPrefix="aws_dbe_"`, `ReservedCryptoContextPrefix="aws-crypto-"`, `ATTR_PREFIX="aws-crypto-attr."`, `LEGEND="aws-crypto-legend"`. `KeySize=32`, `NonceSize=12`, `AuthTagSize=16`, `MSGID_LEN=32`, `TYPEID_LEN=2`, `BYTES_TYPE_ID=[0xFF,0xFF]`, `DbeAlgorithmFamily=0x67`. Type IDs: Null `0x0000`, String `0x0001`, Number `0x0002`, Boolean `0x0004`, Binary `0xFFFF`, StringSet `0x0101`, NumberSet `0x0102`, BinarySet `0x01FF`, Map `0x0200`, List `0x0300`. `ConstantTimeEquals` = XOR-accumulate byte pairs, result must be 0.

---

## 5. Explicit non-goals

- **Nested structures are not supported today.** Only flat maps: `PathSegment` has only the Map/`StructureSegment` variant active (list-index / attribute variants commented out). A port must not implement nested-path canonicalization unless/until the Dafny source enables it.
- **Do not port the `History` call-log fields** — verification scaffolding, no external observer (§3).
- **Do not port `OptimizedMergeSort`** — it is a Dafny-target-compiler performance workaround (avoids transpiled `seq`-slice copies); its only portable contract is "stable ascending sort by the byte-lexicographic canonical-key comparator," which Java's `List.sort` + `Arrays.compareUnsigned` over canonical-path bytes satisfies. The load-bearing artifact is the **comparator**, not the algorithm.
- **The module does not define its own algorithm suites or keyrings** — those are the MPL's responsibility, reached through the CMM interface. The suite that governs crypto is whatever the returned materials carry.
- **`Result`-wrapper threading is a Dafny idiom, not a required output shape** — the port should use idiomatic Java exceptions mapping to `StructuredEncryptionException` (per translation guidelines §2.1), preserving the exact messages in §3 where they are wire/test-visible.

---

## 6. Source pointers

Generated from (all under `aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/StructuredEncryption/`):
- `Model/StructuredEncryption.smithy`, `Model/AwsCryptographyDbEncryptionSdkStructuredEncryptionTypes.dfy` — §1 public surface, types.
- `src/AwsCryptographyDbEncryptionSdkStructuredEncryptionOperations.dfy` — §1–3 operation orchestration, materials, V2 EC/legend, errors.
- `src/Header.dfy` — §4.5 header wire format + commitment.
- `src/Footer.dfy` — §4.6 footer wire format + canonical record; `SignatureSize=103` (§7).
- `src/Crypt.dfy` — §4.3–4.4 field-key derivation + AES-GCM.
- `src/Paths.dfy` — §4.1 canonical path (AAD).
- `src/Canonize.dfy` — §4.2/4.7 canonicalization + legend resolution.
- `src/SortCanon.dfy` — §4.2 byte-lexicographic sort comparator.
- `src/Util.dfy` — §4.9 constants + `ConstantTimeEquals`.
- `src/OptimizedMergeSort.dfy`, `src/Index.dfy` — §5 non-goals (sort scaffolding; wiring).
- `test/Paths.dfy`, `test/Header.dfy`, `test/Crypt.dfy`, `test/HappyCaseTests.dfy`, `test/StructuredDataTestFixtures.dfy` — concrete vectors confirming §4 (canonical path, EC serialization, commitment tamper, FieldKey golden vectors, end-to-end round-trip).
- `specification/structured-encryption/{header,footer,encrypt-path-structure,decrypt-path-structure,structures}.md` — supplementary; §7 disagreements.

---

## 7. Dafny-vs-spec disagreements (Dafny wins)

1. **Footer signature size — SIGNIFICANT.** `footer.md` says the signature is `0 or 96` bytes; `Footer.dfy` fixes it at **103** (DER-encoded ECDSA P-384; 96 is the raw r‖s form). `DeserializeFooter` splits the last **103** bytes as the signature and `CreateFooter` errors otherwise. **A port MUST use 103** — trusting the spec's 96 misparses every signed footer.
2. **Footer "Signed Fields" prose — MINOR/stale.** `footer.md` says signed = ENCRYPT_AND_SIGN or SIGN_ONLY; `Footer.dfy` signs **all non-DO_NOTHING** fields, i.e. also SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT (a v2 action the prose predates). Signed = {ENCRYPT_AND_SIGN, SIGN_ONLY, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}.
