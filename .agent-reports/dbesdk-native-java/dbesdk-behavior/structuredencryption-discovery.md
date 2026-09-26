# StructuredEncryption — Dafny behavior-discovery checklist

**Module:** `StructuredEncryption` — foundational structured / field-level encryption core.
**Source of truth:** the Dafny `.dfy` source in `aws-database-encryption-sdk-dynamodb` (NOT the `specification/` prose, NOT transpiled Java).
**Why this module first:** CDD fewest-correct-answers-first; it is the base the item encryptor and transforms build on, and it backs the test server's simplest declared feature (`raw-aes` item encrypt/decrypt). Confirmed foundational — its `src/` does not reference `DynamoDbItemEncryptor`, `DynamoDbEncryptionTransforms`, or `DynamoDbEncryption`.
**Started:** 2026-09-25. Draft behavior spec is kept in this `.agent-reports` tree (constraint 10 — not written into the guidance package's `dbesdk-behavior-specs/`).

## Checklist

- [x] **1. Locate the module's Dafny source tree.**
  Path: `aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/StructuredEncryption/` → `Model/`, `src/`, `test/`.
  `src/` (5,789 LoC, 10 files): `Index.dfy` 53, `Paths.dfy` 345, `SortCanon.dfy` 365, `OptimizedMergeSort.dfy` 431, `Util.dfy` 440, `Footer.dfy` 468, `Crypt.dfy` 576, `Canonize.dfy` 850, `Header.dfy` 957, `AwsCryptographyDbEncryptionSdkStructuredEncryptionOperations.dfy` 1304.
  `test/` (734 LoC): `Paths.dfy`, `HappyCaseTests.dfy`, `Header.dfy`, `Crypt.dfy`, `StructuredDataTestFixtures.dfy`.
  `Model/`: `StructuredEncryption.smithy`, `AwsCryptographyDbEncryptionSdkStructuredEncryptionTypes.dfy`.
- [x] **2. Read the module's Smithy model (public surface).** Done — see Findings §Public surface.
- [x] **3. Read every `.dfy` file under `src/` in full.** ALL 10 read: Index, Operations, Header, Footer, Crypt, Paths, Canonize, SortCanon, Util, OptimizedMergeSort.
- [~] **4. Extract `requires`/`ensures`/`invariant` per public method.** Load-bearing behavioral contracts captured in the findings (wire format, crypto derivation, canonicalization, ordering, errors, constants). Verifier-internal invariants (proof scaffolding, not portable behavior) not transcribed.
- [ ] **4. Extract every `requires`/`ensures`/`invariant` clause per public method.**
- [x] **5. Read `test/` for concrete input/output pairs; reconcile against contracts.**
- [x] **6. Cross-check `specification/` prose — record any disagreement (Dafny wins).**
- [x] **7. Identify non-obvious behavior (ordering, mutation vs. immutability, edge cases, canonicalization).**
- [x] **8. Identify explicit non-goals.**
- [x] **9. Write the behavior-spec draft (in this `.agent-reports` tree; template from `dbesdk-behavior-specs/_INDEX.md`).**
- [x] **10. Record exact source-file pointers.**

## Findings log (evidence next to each step as completed)

### Step 1 — done
See paths/sizes above. Foundational confirmed via `grep -rEl 'DynamoDbItemEncryptor|DynamoDbEncryptionTransforms|module DynamoDbEncryption\b' src` → no matches.

### Step 2 — Public surface (from `Model/StructuredEncryption.smithy`)

`localService StructuredEncryption`, 5 operations, error `StructuredEncryptionException` (`@error("client")`, `message: String`). Config `StructuredEncryptionConfig` is empty; the client depends on `AwsCryptographicPrimitives` + `AwsCryptographicMaterialProviders`.

Operations:
- `EncryptStructure(tableName, plaintextStructure: StructuredDataMap, cryptoSchema: CryptoSchemaMap, cmm, algorithmSuiteId?, encryptionContext?) -> {encryptedStructure: StructuredDataMap, cryptoSchema, parsedHeader}`
- `DecryptStructure(tableName, encryptedStructure: StructuredDataMap, authenticateSchema: AuthenticateSchemaMap, cmm, encryptionContext?) -> {plaintextStructure, cryptoSchema, parsedHeader}`
- `EncryptPathStructure(tableName, plaintextStructure: CryptoList, cmm, algorithmSuiteId?, encryptionContext?) -> {encryptedStructure: CryptoList, parsedHeader}`
- `DecryptPathStructure(tableName, encryptedStructure: AuthList, cmm, encryptionContext?) -> {plaintextStructure: CryptoList, parsedHeader}`
- `ResolveAuthActions(tableName, authActions: AuthList, headerBytes: Blob) -> {cryptoActions: CryptoList}`

Core types: `StructuredDataTerminal{value: TerminalValue(blob), typeId: TerminalTypeId(exactly 2 bytes)}`; `CryptoAction` enum {ENCRYPT_AND_SIGN, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, SIGN_ONLY, DO_NOTHING}; `AuthenticateAction` enum {SIGN, DO_NOT_SIGN}; `Path` = list of `PathSegment` (currently only `StructureSegment{key:String}` — list/attribute segments are commented out); `CryptoItem{key:Path, data, action:CryptoAction}`, `AuthItem{key:Path, data, action:AuthenticateAction}`; `ParsedHeader{algorithmSuiteId, encryptedDataKeys, storedEncryptionContext, encryptionContext}`.

### Step 3 (partial) — Operation behavior from `Operations.dfy` (VERIFIED by reading source; supporting-file internals still pending)

- **EncryptStructure is a thin adapter over EncryptPathStructure:** requires `plaintextStructure.Keys == cryptoSchema.Keys` (else `E("Crypto Keys don't match.")`); combines the two maps into one `CryptoList` via `BuildCryptoMap` (keys sorted by `CharLess`, no duplicates), calls `EncryptPathStructure`, then splits the result back into `{encryptedStructure, cryptoSchema}` via `UnBuildCryptoMap`. DecryptStructure mirrors this over `BuildAuthMap`/`DecryptPathStructure`.
- **EncryptPathStructure preconditions (each yields a `StructuredEncryptionException`):**
  - encryptionContext, if present, MUST NOT contain any key whose value starts with the reserved `aws-crypto-` prefix.
  - at least one field action MUST be an auth attr (not `DO_NOTHING`) — i.e. ENCRYPT_AND_SIGN / SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT / SIGN_ONLY.
  - no input path may be a reserved header/footer path (`aws_dbe_head` / `aws_dbe_foot`, via `HeaderPaths`).
  - input paths MUST be unique (`CryptoListHasNoDuplicatesFromSet`); `tableName` MUST be a valid string.
- **Output shape:** `|finalData| == |origData| + 2`; the header field (`HeaderPath`) is second-to-last and the footer field (`FooterPath`) is last. Encrypted terminals get `typeId = 0xFFFF` (`BYTES_TYPE_ID`) and value = ciphertext; non-encrypted terminals keep original typeId+value.
- **Materials:** `GetStructuredEncryptionMaterials` calls `cmm.GetEncryptionMaterials` with commitmentPolicy `DBE(REQUIRE_ENCRYPT_REQUIRE_DECRYPT)`, `maxPlaintextLength = encryptedTerminalDataNum*2 + totalEncryptedTerminalValuesSize` (via `Add3`), and requires the returned suite satisfy `ValidSuite` else `E("Invalid Algorithm Suite")`. Default suite when none given: `ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384` (`GetAlgorithmSuiteId`).
- **V2 encryption context / legend (SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT):** builds EC entries keyed `aws-crypto-attr.` + dotted path; duplicate produced keys are an error; a `aws-crypto-legend` string is appended, one char per attr sorted by UTF8 (`ByteLess`): `S`=String, `N`=Number, `L`=Null or Boolean, `B`=otherwise. When any such attr exists, a **Required Encryption Context CMM** is created wrapping the input CMM with those keys required; else the input CMM/EC are used unchanged.
- **Header/commitment:** a fresh 256-bit random MessageID is generated per record (`Random.GenerateBytes(MSGID_LEN64)`); commit key derived from plaintext data key + msgID (`Crypt.GetCommitKey`); header serialized with commitment.
- **DecryptPathStructure:** requires ≥1 `SIGN` action, no duplicate paths, header+footer fields present (both binary, `DO_NOT_SIGN`, typeId 0xFFFF via `GetBinary`). Deserializes header (`Header.PartialDeserialize`); if header `version == 2`, reconstructs the V2 EC + Required-EC-CMM the same way as encrypt (must match). Calls `cmm.DecryptMaterials` (algorithmSuiteId from header, `reproducedEncryptionContext = input EC`); the suite from the returned materials (which MAY differ from input) governs the rest and must be `ValidSuite`. Verifies header commitment, deserializes+validates footer (signature), then `Crypt.Decrypt`. Output strips header/footer (`RemoveHeaders`). `DetectMismatch` produces a per-key "Encryption Context Mismatch" error.
- **ResolveAuthActions:** requires no duplicate paths, header+footer present; partial-deserializes the header for its `legend`, canonicalizes for decrypt, returns `cryptoActions` (the resolved CryptoList). No CMM/crypto — header-legend-driven action resolution only.
- **Errors:** all failures are `Error` → surfaced as `StructuredEncryptionException` (the module's single client error). Helper `E(msg)` builds these.

### Step 7 (partial) — non-obvious behavior noted so far
- EncryptStructure/DecryptStructure only support **flat maps** right now (source comments: "For now we only support encrypting flat maps"; `PathSegment` union has list/attribute variants commented out). Treat nested paths as an explicit non-goal until proven otherwise in `Paths.dfy`.
- Header is second-to-last, footer is last, in the path-structure output; both use reserved paths `aws_dbe_head`/`aws_dbe_foot` and typeId `0xFFFF`.
- Decrypt uses the algorithm suite from the **returned decryption materials**, not the header's indicated suite, for all crypto after the CMM call (they may differ).
- Field ordering for EC/legend and for map→list conversion is deterministic via `SortedSets.ComputeSetToOrderedSequence2` with `CharLess`/`ByteLess` — canonical ordering matters and lives in `SortCanon.dfy`/`Canonize.dfy` (pending read).

### Pending (next session)
Steps 3 (8 files) → 4 → 5 (tests: Header/Crypt/HappyCase/Paths + fixtures) → 6 (specification/structured-encryption/*.md cross-check) → 7/8 (complete) → 9 (write `StructuredEncryption.md` behavior-spec draft here in `.agent-reports`, per constraint 10) → 10. The wire-format byte layout (Header/Footer) and the AES-GCM/HKDF crypto details are the highest-value remaining unknowns and MUST come from `Header.dfy`/`Footer.dfy`/`Crypt.dfy` directly.

### Step 3/4 — Header wire format (`Header.dfy`, VERIFIED)

Full serialized header = **Partial Header** ++ **32-byte Header Commitment**.

Partial Header (in order):
1. `version` — 1 byte, `0x01` or `0x02`. Version is `0x02` iff any field action is `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`, else `0x01` (`VersionFromSchema`).
2. `flavor` — 1 byte, `0x00` or `0x01`; equals `algorithmSuite.binaryId[1]`. binaryId is 2 bytes `[DbeAlgorithmFamily(0x67), flavor]`. flavor 0x00 → ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_SYMSIG_HMAC_SHA384; 0x01 → …ECDSA_P384_SYMSIG_HMAC_SHA384.
3. `msgID` — 32 bytes (`MSGID_LEN`).
4. **Encrypt Legend** — 2-byte big-endian length ++ legend bytes. One legend byte per **authenticated** field (in canonical order), no byte for unsigned fields: `0x65`='e' ENCRYPT_AND_SIGN, `0x63`='c' SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, `0x73`='s' SIGN_ONLY. (This is a different legend from the V2-EC `aws-crypto-legend` S/N/L/B legend in Operations — do not conflate.)
5. **Encryption Context** — 2-byte BE count ++ KV entries. Each entry: 2-byte BE keyLen ++ key ++ 2-byte BE valueLen ++ value; key+value UTF8. Entries sorted ascending by key (UTF8 `ByteLess`); no duplicates; deserialize enforces strictly-increasing keys ("Context keys out of order."). The stored EC = materials EC **minus** `requiredEncryptionContextKeys`.
6. **Encrypted Data Keys** — **1-byte** count (1..255; >0 required) ++ entries. Each entry: 2-byte BE keyProviderIdLen ++ id(UTF8) ++ 2-byte BE keyProviderInfoLen ++ info ++ 2-byte BE ciphertextLen ++ ciphertext.

Commitment = **first 32 bytes of HMAC-SHA384**(key=`commitKey`, msg=Partial Header bytes) — `alg.commitment.HKDF.hmac`. `verifyCommitment` recomputes over `data[..|data|-32]` and compares the trailing 32 bytes **constant-time** ("Key commitment mismatch."). `PartialDeserialize` requires exactly 32 trailing bytes after the EDKs (commitment) — errors on too-short/extra bytes.

### Step 3/4 — Footer format + canonicalization (`Footer.dfy`, VERIFIED)

Footer terminal (typeId `0xFFFF`) value = **Recipient Tags** (48 bytes each, one per EDK, same order as the materials' symmetric signing keys) ++ **Signature** (0 bytes if no ECDSA; 103 bytes if ECDSA present).
- **Recipient Tag[i]** = HMAC(digest=`alg.symmetricSignature.HMAC`, key=`symmetricSigningKeys[i]`, msg=canonicalHash); length asserted == 48.
- **Signature** = ECDSA(curve=`alg.signature.ECDSA.curve`, key=signingKey, msg=canonicalHash); length must == 103.
- **canonicalHash** = SHA-384 of the **canonical record**.
- **Canonical record** = `header` (full serialized header w/ commitment) ++ AAD-length (8-byte BE uint64) ++ AAD (`SerializeContext(materials.encryptionContext)`) ++ field data.
- **Field data** = for each **signed** field (DO_NOTHING excluded), in lexicographic canonical-path order, the canonical field:
  - Encrypted (ENCRYPT_AND_SIGN): `canonPath ++ (valueLen-2 as 8-byte BE) ++ "ENCRYPTED"(9 ascii) ++ value` (value = 2-byte typeId + ciphertext+tag).
  - Plaintext (SIGN_ONLY / SIGN_AND_INCLUDE…): `canonPath ++ (valueLen as 8-byte BE) ++ "PLAINTEXT"(9 ascii) ++ typeId(2) ++ value`.
- **Decrypt validation:** #tags must == #EDKs; recompute canonicalHash; require at least one recipient tag matches (constant-time) the HMAC under the (single) `symmetricSigningKey`; then if suite is ECDSA, ECDSA-verify the signature over canonicalHash; `sig.Some?` must match `alg.signature.ECDSA?`. `DeserializeFooter(data, hasSig)`: if hasSig, last 103 bytes = signature and the rest must be a multiple of 48 (tags); else whole thing multiple of 48.

### Step 3/4 — Field key derivation + AES-GCM (`Crypt.dfy`, VERIFIED — the core port must match exactly)

- **FieldRootKey** = HKDF(digest=`alg.kdf.HKDF.hmac`, salt=None, ikm=plaintextDataKey, info=`"AWS_DBE_DERIVE_KEY"`(18 bytes) ++ msgID(32), expectedLength=alg encrypt-key length).
- **CommitKey** (`GetCommitKey`, used for header commitment) = HKDF(digest=`alg.commitment.HKDF.hmac`, salt=None, ikm=plaintextDataKey, info=`"AWS_DBE_COMMIT_KEY"`(18) ++ msgID(32), expectedLength=commit output length).
- **FieldKey(offset)** = first **44 bytes** (32 key + 12 nonce) of an AES-CTR keystream (`AesKdfCtr.Stream`) with input key=FieldRootKey and 16-byte nonce `FieldKeyNonce(offset*3)`.
- **FieldKeyNonce(offset)** (16 bytes) = `"AwsDbeField"`(11 ascii) ++ `0x2c`(=44, the FieldKey length) ++ offset (4-byte BE uint32).
- **Cipherkey** = FieldKey[0..32]; **Nonce** = FieldKey[32..44] (12 bytes).
- **offset** = index among ENCRYPT_AND_SIGN fields only (increments per encrypted field; the `*3` on the nonce means each field consumes 3 AES-CTR blocks of keystream). Fields are processed in canonical **sorted** order (`IsCryptoSorted`).
- **EncryptTerminal:** AES-GCM (`alg.encrypt.AES_GCM`), key=Cipherkey, iv=Nonce, **aad = canonical path**, plaintext = terminal value. Output terminal: typeId=`0xFFFF`, value = `original typeId(2) ++ ciphertext ++ authTag(16)`.
- **DecryptTerminal:** value parsed as typeId(2) ++ ciphertext ++ authTag(last 16). AES-GCM decrypt with same key/nonce/aad; output typeId = the deserialized 2 bytes, value = plaintext. Requires `|value| >= 18`.
- Only ENCRYPT_AND_SIGN fields are encrypted; all others pass through unchanged.

### Step 7 — additional non-obvious behavior (updated)
- **Two distinct legends exist:** the header Encrypt Legend (e/c/s bytes, one per signed field) vs. the V2 encryption-context `aws-crypto-legend` (S/N/L/B, one per SIGN_AND_INCLUDE field). A port must implement both, separately.
- **Per-field AES-CTR offset uses `offset*3`** for the KDF-CTR nonce; offset counts only encrypted fields, in canonical-sorted order — getting the offset or ordering wrong silently produces wrong keys.
- **AAD for each field's AES-GCM is that field's canonical path** (from `Canonize`/`Paths` — pending read for the exact canonical-path bytes).
- **Header commitment and recipient-tag comparisons are constant-time** (security requirement, not just correctness).
- Encrypted value carries the **original** 2-byte typeId as a plaintext prefix before the ciphertext; the outer terminal typeId becomes 0xFFFF.
- EDK count is a single byte (max 255); header EC count and all length fields are 2-byte BE; footer canonical-record lengths are 8-byte BE.

### Highest-value remaining unknown
The exact **canonical path** byte encoding (used as AES-GCM AAD and for footer field ordering) is defined in `Paths.dfy` + `Canonize.dfy` — MUST be read next, since a native port that computes the AAD differently will fail to decrypt Dafny-written data even with everything else correct.

### Step 3/4 — Canonical path = AES-GCM AAD (`Paths.dfy`, VERIFIED)

`CanonPath(table, path)` (the per-field AAD, and the footer canonical-path) =
`UTF8(table)` ++ `UInt64ToSeq(depth = |path|)` (8-byte BE) ++ `MakeCanonicalPath(path)`.

`MakeCanonicalPath` = concatenation of `CanonicalPart(segment)` per segment.
`CanonicalPart` for a **Map** segment (the only kind currently used) = `0x24` ('$', `MAP_TAG`) ++ `UInt64ToSeq(|key|)` (8-byte BE) ++ `UTF8(key)`.
(`ARRAY_TAG = 0x23` '#' is defined but list segments are not used.)

So for a **top-level attribute** `attr` in table `table` (the flat-map case): AAD =
`UTF8(table)` ++ `uint64_be(1)` ++ `0x24` ++ `uint64_be(len(UTF8(attr)))` ++ `UTF8(attr)`.
A native port MUST produce these exact bytes or AES-GCM decrypt of Dafny-written data fails. Canonical paths are proven unique per distinct path.

### Step 3/4 — Canonicalization + legend resolution pipeline (`Canonize.dfy`, VERIFIED)

- `CanonCryptoItem = {key: CanonicalPath, origKey: Path, data, action}`.
- **ForEncrypt(tableName, data: CryptoList):** validate paths → map each item to a `CanonCryptoItem` (compute canonical `key` via `CanonPath`) → **sort by canonical key** (`CryptoSort`→`SortCanon.CryptoSort`). Output is a sorted `CanonCryptoList`. This sort order is what fixes the per-field AES-CTR **offset** (Crypt) and the footer canonical-content order (Footer) — encrypt and decrypt sort identically so offsets line up.
- **ForDecrypt(tableName, data: AuthList, legend):** validate → `AuthToCanonAuth` (canonicalize) → `AuthSort` (sort by canonical key) → **`DoResolveLegend`**: walk the sorted fields and assign each field's `CryptoAction` from the stored header legend:
  - a `DO_NOT_SIGN` field → `DO_NOTHING` (consumes **no** legend byte);
  - a `SIGN` field → consume the next legend byte, mapped by `LegendToAction`: `0x65`→ENCRYPT_AND_SIGN, `0x63`→SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, `0x73`→SIGN_ONLY.
  - Errors if legend length ≠ number of signed fields ("Schema changed : something that was signed is now unsigned." / "...unsigned is now signed.").
  **Key point:** on decrypt, the caller's `authenticateSchema` only says SIGN vs DO_NOT_SIGN per field; the *actual* per-field crypto action (and thus what gets decrypted) is reconstructed from the header's Encrypt Legend applied in canonical-sorted order. The legend order therefore corresponds 1:1 to the signed fields in canonical-sorted order.
- `UnCanon`/`UnCanonEncrypt`/`UnCanonDecrypt`: map `CanonCryptoList` back to `CryptoList` using `origKey`.
- `AddHeaders`: appends header + footer as two `DO_NOTHING` `CryptoItem`s at the end (→ +2, header then footer). `RemoveHeaders`/`RemoveHeaderPaths`: strips the `aws_dbe_head`/`aws_dbe_foot` paths on decrypt.
- The `Updated`/`Updated2..5` ghost predicates formalize the per-item transform (encrypted iff data changed; encrypted output typeId=0xFFFF; decrypted typeId = first 2 bytes of the encrypted value) — these are the verifier's contract, not runtime behavior, but they confirm the encrypt/decrypt shape captured from `Crypt.dfy`.

### Step 7 — additional non-obvious behavior (updated)
- **AAD is the full canonical path including the 8-byte depth and per-segment `0x24`+8-byte-len framing**, not just the raw attribute name. Easy to get subtly wrong in a port.
- **Decrypt does not trust the input action beyond SIGN/DO_NOT_SIGN** — it re-derives ENCRYPT_AND_SIGN / SIGN_ONLY / SIGN_AND_INCLUDE from the stored legend, in canonical-sorted order. A field the caller marks SIGN that the legend says was ENCRYPT_AND_SIGN will be decrypted; a mismatch in signed-count is a hard error.
- **Sort order is load-bearing three times:** field-encryption offset assignment, footer canonical-content ordering, and legend↔field correspondence. All use the same `SortCanon` comparator over the canonical key.

### Highest-value remaining unknown (narrowed)
`SortCanon.dfy`'s `CryptoBelow`/`AuthBelow` comparator — almost certainly byte-lexicographic over the canonical `key`, but MUST be confirmed (and whether the sort is stable / how ties are handled), since it fixes the offset/footer/legend ordering above. Then `Util.dfy` for the exact constant values (`MSGID_LEN`=32 expected, KeySize=32, NonceSize=12, AuthTagSize=16, TYPEID_LEN=2, `BYTES_TYPE_ID`=0xFFFF, `HeaderPath`/`FooterPath` = `aws_dbe_head`/`aws_dbe_foot`, `ATTR_PREFIX`=`aws-crypto-attr.`) — several are inferred from usage above and need direct confirmation.

### Step 3/4 — Sort order (`SortCanon.dfy`, VERIFIED)

- `CryptoBelow(x,y)` / `AuthBelow(x,y)` = `Below(x.key, y.key)` — compare on the **canonical key** (`CanonicalPath` bytes).
- `Below(x,y)` is **ascending byte-lexicographic**: empty ≤ anything; otherwise `x[0] <= y[0]`, and on `x[0]==y[0]` recurse on the tails. Proven a total ordering. So canonical items are sorted **ascending by the raw bytes of the canonical path**.
- `AuthSort`/`CryptoSort` sort by that comparator; `AuthSortIsCryptoSort` proves the auth-sort order equals the crypto-sort order for identical keys — so encrypt and decrypt order fields identically, and the per-field AES-CTR offset lines up on both sides. Canonical keys are unique (no dups), so the sort is deterministic regardless of stability.
- **Port rule:** sort the canonicalized fields ascending by `memcmp` of the canonical-path bytes. That single ordering drives field offsets, footer canonical-content order, and legend↔field correspondence.

### Step 3/4 — Constants + primitives (`Util.dfy`, CONFIRMED — previously inferred values now verified)

- Reserved paths: `ReservedPrefix = "aws_dbe_"`; **`HeaderField = "aws_dbe_head"`, `FooterField = "aws_dbe_foot"`** (proven by `CheckNames`).
- Encryption-context reserved: `ReservedCryptoContextPrefixString = "aws-crypto-"`; **`ATTR_PREFIX = "aws-crypto-attr."`**; `LEGEND = "aws-crypto-legend"`.
- V2-EC value legend chars: `S`=String, `N`=Number, `L`=Literal (Null/Boolean), `B`=Binary. Literals: `"null"`, `"true"`, `"false"` (UTF8). (Distinct from the header e/c/s legend — as flagged.)
- Terminal type ids: `TYPEID_LEN = 2`; **`BYTES_TYPE_ID = [0xFF,0xFF]`**. Full table: Null `0x0000`, String `0x0001`, Number `0x0002`, Binary `0xFFFF`, Boolean `0x0004`, StringSet `0x0101`, NumberSet `0x0102`, BinarySet `0x01FF`, Map `0x0200`, List `0x0300`.
- Crypto sizes (CONFIRMED): **`KeySize = 32`, `NonceSize = 12`, `AuthTagSize = 16`, `MSGID_LEN = 32`**; `DbeAlgorithmFamily = 0x67`. `ValidSuiteSizes` proves the suite's AES-GCM keyLength=32, tagLength=16, ivLength=12.
- `ValidSuite(alg)` = `alg.id.DBE?` and `AlgorithmSuites.DBEAlgorithmSuite?(alg)`.
- `ConstantTimeEquals` = XOR-accumulate all byte pairs, result must be 0 (the constant-time primitive used for header-commitment and recipient-tag comparison).
- `IsAuthAttr(x) = !x.DO_NOTHING?` (ENCRYPT_AND_SIGN, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, SIGN_ONLY are "authenticated"/signed).
- `EncodeTerminal` (for V2-EC binary values) = `UTF8(Base64(typeId ++ value))`.
- `ValidString` = UTF8-encodable and length fits uint64.

### Step 3 — OptimizedMergeSort (`OptimizedMergeSort.dfy`, VERIFIED)
A performance-optimized, array-based merge sort, proven equal to the standard library `MergeSortBy`. No behavior to port beyond "stable ascending sort by the given total-order comparator." For a native port, any correct sort by the byte-lexicographic canonical-key comparator suffices; the optimization (2-array ping-pong, bounded-int indices) is a Dafny-target performance concern, not observable behavior. `TotalOrderingImpliesSortingIsUnique` proves the sorted result is unique given the total order, so the output is deterministic.

### Step 3 status: COMPLETE
All src behavior for a native port is now captured: public surface, the 5 operations, header/footer wire format, AES-GCM/HKDF field crypto + key derivation, canonical-path (AAD) bytes, canonicalization + legend resolution, byte-lexicographic sort order, and all constants. Remaining discovery steps: **5** (read `test/` vectors to confirm the above against concrete input/output — HappyCaseTests, Header, Crypt, Paths, StructuredDataTestFixtures), **6** (cross-check `specification/structured-encryption/*.md`, record any Dafny-vs-spec disagreement), **7/8** (finalize non-obvious + non-goals), **9** (write the `StructuredEncryption.md` behavior-spec draft here in `.agent-reports`, per constraint 10), **10** (source pointers). No native Java should be written for this module until 5/6/9 are done.

### Translation decision — sorting (derived from Step 3: `SortCanon.dfy` + `OptimizedMergeSort.dfy`)

**(a) Can Java's standard library reproduce the exact canonical-path ordering? YES.**
The sort orders solely by `Below(x.key, y.key)` = ascending **byte-lexicographic, unsigned** comparison of the canonical-path bytes; there is no secondary sort key. Java `list.sort(cmp)` / `Collections.sort` with a comparator built on `java.util.Arrays.compareUnsigned(byte[], byte[])` (JDK 9+; this module targets JDK 21) reproduces it byte-for-byte, including the prefix rule (a shorter array that is a prefix of a longer one sorts first — matches `Below`'s empty-≤-anything).
- **The one trap:** Java `byte` is signed (−128..127). A naive `b1 - b2` / `Byte.compare` sorts any byte ≥ `0x80` *before* `0x00`, the opposite of Dafny's unsigned order — and canonical paths routinely contain bytes > 0x7F (UTF-8, length bytes). The comparator MUST compare unsigned (`Arrays.compareUnsigned`, or `(a & 0xFF) - (b & 0xFF)` per byte on older JDKs).
- **Stability is irrelevant:** canonical keys are distinct (duplicate paths rejected upstream by `ConfigValidator`/`CryptoListHasNoDuplicates`; `Paths.CanonPathUnique` proves distinct paths → distinct canonical paths). `TotalOrderingImpliesSortingIsUnique` proves the sorted output is unique given the total order. Java's `List.sort`/`Collections.sort` are stable TimSort anyway.
- **Assumption:** the sort input always has distinct canonical keys (guaranteed as above). Under that guarantee the ordering is fully determined by the comparator.

**(b) Does the custom `OptimizedMergeSort` offer a real efficiency advantage over Java's built-in sort? NO.**
Its own header comment states it exists to work around Dafny's transpiled `seq`-slicing copies (`s[1..]`) and `nat`/bignum index math — Dafny target-compiler artifacts that do not exist in hand-written Java. Comparison:
- Both are O(n log n) time, O(n) aux space. Java's TimSort is **adaptive** (O(n) on sorted/nearly-sorted input, fewer comparisons on partially-ordered data); the custom merge sort is not. The custom sort pre-allocates **two full size-n arrays**; TimSort's temp buffer is typically smaller.
- The sorted data is a **per-item field list** (small n — item attributes), where per-field AES-GCM + HKDF-CTR crypto dominates cost by orders of magnitude; the sort is not on the critical path.
- The comparator cost (reading the precomputed canonical-path bytes; `Arrays.compareUnsigned` is a JVM intrinsic) is identical regardless of sort algorithm.
- **Recommendation:** use `list.sort(comparator)` / `Collections.sort` with the unsigned byte-lexicographic canonical-path comparator; do **NOT** port `OptimizedMergeSort`. This is a textbook translation-guidelines case (don't port Dafny scaffolding that exists only for the verifier/target compiler).
- **Caveat:** no measured benchmark exists yet (Phase 4 territory) — this is complexity/allocation reasoning, not a measured claim; it is robust across n because both are O(n log n) and TimSort strictly dominates on adaptivity and allocation.

**Porting rule for the implementing session:** the single load-bearing requirement is the *comparator* (unsigned, byte-lexicographic, over the full canonical-path bytes) — not the sort algorithm. `OptimizedMergeSort` and the Dafny sort machinery are NOT to be ported.

### Step 5 — test-vector confirmation (VERIFIED against `test/`)

Every contract above is confirmed on concrete data:
- **Canonical path (`test/Paths.dfy` TestSpecExamples):** `CanonPath("example_table", ["name"])` == `UTF8("example_table") ++ [0,0,0,0,0,0,0,1] ++ 0x24 ++ [0,0,0,0,0,0,0,4] ++ UTF8("name")` — byte-for-byte match of the recorded layout (8-byte BE depth, `0x24` map tag, 8-byte BE key length, key bytes).
- **Header EC serialization (`test/Header.dfy` TestDuplicateContext/TestOutOfOrderContext):** `SerializeContext(map[abc:=def, cba:=fed])` == `[0,2, 0,3,'a','b','c', 0,3,'d','e','f', 0,3,'c','b','a', 0,3,'f','e','d']` — 2-byte count, per-KV 2-byte len+bytes, ascending by key. Out-of-order or duplicate keys on deserialize → `Failure(E("Context keys out of order."))`.
- **Header round-trip + commitment (`TestRoundTrip`/`TestRoundTripWithCommit`):** serialize→PartialDeserialize is identity; flipping the last byte of the serialized header → `verifyCommitment` returns `Failure(E("Key commitment mismatch."))`.
- **FieldKey golden vectors (`test/Crypt.dfy` TestFieldKey):** concrete `(32-byte rootKey, offset) → 44-byte hex FieldKey` vectors (e.g. all-zero key, offset 0 → `4d17ac4f…`). The embedded JS reference confirms nonce = `"AwsDbeField"(11) ++ 0x2c ++ offset_be32` and `FieldKey = AES-256-CTR(len=44, key=rootKey, nonce=FieldKeyNonce(offset*3))`. **These are must-pass conformance vectors for a native port** (source: `DynamoDbEncryption/dafny/StructuredEncryption/test/Crypt.dfy`).
- **End-to-end (`HappyCaseTests` TestRoundTrip):** encrypt→decrypt round-trips; `foo`(ENCRYPT_AND_SIGN) value changes, `bar`(SIGN_ONLY)/`fizzbuzz`(DO_NOTHING) unchanged; encrypted keys = input keys `+ {aws_dbe_head, aws_dbe_foot}`; decrypt restores the original exactly; `parsedHeader.cryptoSchema` == the auth-only schema (DO_NOTHING dropped); 1 EDK.

### IMPORTANT refinement to the sort-ordering decision (from TestSchemaOrder*)

`test/Header.dfy` `TestSchemaOrderLength`/`Length2` prove the sort is ordered by the **canonical path**, whose per-segment form is `0x24 ++ uint64_be(keyLen) ++ keyBytes`. Because the **8-byte big-endian key length precedes the key bytes**, byte-lexicographic comparison of canonical paths is **length-major**: a shorter UTF-8 key always sorts before a longer one, and only equal-length keys are ordered by content. Test evidence: keys `aa, zz, aaa, zzz, aaaa, zzzz` → signed legend `[E&S, SIGN_ONLY, E&S, SIGN_ONLY]` (i.e. sorted `aa,zz | aaa,zzz | aaaa,zzzz`), independent of input order.

**Consequence for the Java port:** the comparator MUST sort on the **canonical-path bytes** (which include the length prefix), NOT on the raw attribute-name string. `Arrays.compareUnsigned` over the canonical-path bytes yields the correct length-major order; sorting by attribute name directly (plain lexicographic) would be WRONG. This does not change the earlier conclusion (use `list.sort` + unsigned comparator over canonical-path bytes, no custom mergesort) — it sharpens *what bytes* the comparator must run on.

### Step 6 — specification cross-check (Dafny is source of truth; disagreements recorded)

Cross-checked `specification/structured-encryption/{header,footer,encrypt-path-structure,decrypt-path-structure,structures}.md` against the recorded Dafny behavior.

**DISAGREEMENT 1 (SIGNIFICANT) — footer signature size: spec says 96, Dafny uses 103.**
`footer.md` Footer Format table: "Signature | **0 or 96** | Signature, if signatures are enabled". But `Footer.dfy` defines `const SignatureSize := 103` and `type Signature = x | |x| == 103`; `CreateFooter` errors unless `|sig| == 103` ("Signature is N bytes, should have been 103 bytes"), and `DeserializeFooter` splits off the last **103** bytes as the signature. **Dafny wins → the ECDSA P-384 signature is 103 bytes (DER-encoded), not 96 (96 = raw r‖s).** A native port MUST use 103, or footer serialize/deserialize will be off by 7 bytes and every signed decrypt will fail. (The spec's 96 appears to describe the raw signature; the implementation uses the MPL's DER-encoded ECDSA output.)

**DISAGREEMENT 2 (MINOR / stale prose) — footer "Signed Fields" omits SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT.**
`footer.md` §Signed Fields: "When encrypting, `signed fields` refers to all fields for which the Crypto Schema indicates `ENCRYPT_AND_SIGN` or `SIGN_ONLY`." But `Footer.dfy` `CanonContent` includes **every non-DO_NOTHING** field in the signed canonical record — i.e. also `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` (a v2 action, `IsAuthAttr = !DO_NOTHING`). The footer prose predates v2 and is incomplete. **Dafny wins → signed = all of {ENCRYPT_AND_SIGN, SIGN_ONLY, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT}.** (Consistent with the header Encrypt Legend, which assigns a byte — `e`/`s`/`c` — to each of these three.)

**Positively confirmed by the spec (no disagreement) — worth noting because they pin behavior the signature alone doesn't:**
- `encrypt-path-structure.md` states the FieldKey **offset** = "the zero-based position of the field in the ascending-sorted list of the ENCRYPT_AND_SIGN fields' canonical paths" — confirms offset counts only ENCRYPT_AND_SIGN fields, in canonical-sorted order (matches `Crypt.dfy`/`CryptList`).
- `decrypt-path-structure.md` gives the exact Authentication-Schema + Encrypt-Legend → Crypto-Action table (DO_NOT_SIGN→DO_NOTHING; SIGN+`0x73`→SIGN_ONLY; SIGN+`0x63`→SIGN_AND_INCLUDE; SIGN+`0x65`→ENCRYPT_AND_SIGN) — matches `Canonize.ResolveLegend`/`LegendToAction`.
- `header.md` byte layout, flavor↔suite (family `0x67`, flavor `0x00`/`0x01`), commitment (HKDF `AWS_DBE_COMMIT_KEY`+msgID, HmacSha384 first 32 bytes, constant-time) — all match.
- `structures.md` Terminal Type ID 0xFFFF for raw bytes; path segment is a map-member string ("might also refer to an index into a list" in future) — matches the flat-map-only scope.

**Net:** the recorded behavior stands; the one load-bearing correction from the spec cross-check is **signature size = 103, not 96** — carry this into the behavior spec (§Explicit non-goals / wire constants) so a port doesn't trust the spec's 96.
