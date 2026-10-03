# DynamoDbItemEncryptor — Behavior Spec

Ground truth: the Dafny source (below), not the spec prose. The item encryptor is
a **thin orchestration layer**: it converts a DynamoDB item to/from a
StructuredEncryption structured map, builds the encryption context, wraps the
configured CMM in a Required-Encryption-Context CMM, routes on plaintext/legacy
policy, and delegates all cryptography to the (already-native) StructuredEncryption
`EncryptStructure`/`DecryptStructure`. It performs no cryptography itself.

Source pointers (§10) are exact; re-run discovery if they change.

## 1. Public surface (from `Model/DynamoDbItemEncryptor.smithy`)

- **EncryptItem**(`plaintextItem: AttributeMap`) → (`encryptedItem: AttributeMap`, `parsedHeader: ParsedHeader?`).
- **DecryptItem**(`encryptedItem: AttributeMap`) → (`plaintextItem: AttributeMap`, `parsedHeader: ParsedHeader?`).
  - `parsedHeader` is `None` on a plaintext/legacy passthrough; `Some` on a real encrypt/decrypt.
- **Config** (`DynamoDbItemEncryptorConfig`): REQUIRED `logicalTableName`, `partitionKeyName`,
  `attributeActionsOnEncrypt` (map attr → CryptoAction). OPTIONAL `sortKeyName`,
  `allowedUnsignedAttributes`, `allowedUnsignedAttributePrefix`, `algorithmSuiteId`
  (`DBEAlgorithmSuiteId`), `keyring` XOR `cmm`, `legacyOverride`, `plaintextOverride`.
- **ParsedHeader**: `attributeActionsOnEncrypt` (only non-DO_NOTHING auth attrs),
  `algorithmSuiteId`, `encryptedDataKeys`, `storedEncryptionContext`, `encryptionContext`,
  `selectorContext`.
- **Error**: `DynamoDbItemEncryptorException(message)`.
- **CryptoAction** (from StructuredEncryption types): `DO_NOTHING`, `SIGN_ONLY`,
  `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`, `ENCRYPT_AND_SIGN`.

## 2. Configuration validity (`Index.dfy` constructor + `Operations.ValidInternalConfig?`)

Constructing the client validates, in order:
1. `keyring` and `cmm` are mutually exclusive; exactly one MUST be supplied
   ("Cannot provide both a keyring and a CMM" / "Must provide either a keyring or a CMM").
2. **Configuration version** = `VersionFromActions(actions)`: **2** if ANY action is
   `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`, else **1**.
3. **Key action** = `KeyActionFromVersion(version)`: v2 → `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT`,
   v1 → `SIGN_ONLY`. The `partitionKeyName` (and `sortKeyName` if present) MUST be in
   `attributeActionsOnEncrypt` with exactly this action, else
   "Partition key attribute action MUST be `<keyActionStr>`" / "Sort key attribute action MUST be `<keyActionStr>`".
4. For every configured attribute: `ForwardCompatibleAttributeAction` MUST hold
   (else `ExplainNotForwardCompatible(...)`), and the name MUST NOT begin with a reserved
   prefix (`aws_dbe_` or the SE reserved crypto-context prefix), else
   "Attribute: `<name>` is reserved, and may not be configured."
5. A `legacyOverride` and a `plaintextOverride` on the same config is invalid:
   "Cannot configure both a plaintext policy and a legacy config."
6. If no `plaintextOverride`, it defaults to `FORBID_PLAINTEXT_WRITE_FORBID_PLAINTEXT_READ`.
7. If a `keyring` (not `cmm`) is supplied, the configured CMM is a **default CMM** built from that keyring.

`ForwardCompatibleAttributeAction(attr, action, ...)`: if `action == DO_NOTHING` then `attr`
MUST be *allowed-unsigned*; otherwise `attr` MUST NOT be *allowed-unsigned*.

*Allowed-unsigned* (`AllowedUnsigned`): `attr` is in `allowedUnsignedAttributes`, OR begins with
`allowedUnsignedAttributePrefix`, OR begins with the reserved prefix `aws_dbe_`.

## 3. EncryptItem behavior (`Operations.EncryptItem`)

1. Require `partitionKeyName` in item and (`sortKeyName` absent or in item), else `KeyMissingMsg`.
2. Require every `SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` attribute is present in the item
   (`ContextAttrsExist`), else `ContextMissingMsg`.
3. **Legacy**: if `legacyOverride` policy is `FORCE_LEGACY_ENCRYPT_ALLOW_LEGACY_DECRYPT`,
   delegate to the legacy encryptor and return its output (extern; see §7).
4. **Plaintext passthrough**: if `plaintextOverride == FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ`,
   return the input item unchanged with `parsedHeader = None`.
5. `plaintextStructure = ItemToStructured2(item, actions)` — drop every `DO_NOTHING` attribute
   (kept only if reserved-prefix); each remaining attribute becomes a terminal
   (`AttrToStructured` = the terminal-level DynamoToStruct, §DynamoToStruct.md).
6. `context = MakeEncryptionContextForEncrypt(config, plaintextStructure)` — V1 vs V2 by config version (§5).
7. `cryptoSchema = ConfigToCryptoSchema(config, plaintextStructure)` — each structured key mapped to
   its crypto action (`GetCryptoSchemaAction`); attributes out of signature scope map to `DO_NOTHING`.
8. Build a **Required-Encryption-Context CMM**: underlying = configured CMM, required keys =
   the base-context keys (sorted by raw-byte order, ordering not observable).
9. Delegate to `structuredEncryption.EncryptStructure(tableName = logicalTableName,
   plaintextStructure, cryptoSchema, cmm = reqCMM, algorithmSuiteId = config.algorithmSuiteId,
   encryptionContext = Some(context))`.
10. `encryptedItem = StructuredToItemEncrypt(encryptedStructure, plaintextItem, actions)` (§6).
11. Build `ParsedHeader` from the EncryptStructure output; return with `parsedHeader = Some(...)`.

## 4. DecryptItem behavior (`Operations.DecryptItem`)

1. Require partition (and sort) key in item, else `KeyMissingMsg`.
2. **Legacy**: if `legacyOverride.Some && IsLegacyInput(input)`, delegate to legacy decrypt and return.
3. **Plaintext passthrough**: if `plaintextOverride` allows plaintext read
   (`FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ` or `FORBID_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ`)
   AND the item `IsPlaintextItem`, return it unchanged with `parsedHeader = None`.
4. Require NOT a plaintext item, else "Encrypted item missing expected header and footer attributes".
5. `encryptedStructure = ItemToStructured2(encryptedItem, actions)` (keeps the reserved
   `aws_dbe_head`/`aws_dbe_foot` because they are reserved-prefix).
6. Require `aws_dbe_head` present, of type `B`, non-empty.
7. `context = MakeEncryptionContextForDecrypt(config, header.B, encryptedStructure)` — version read
   from `header.B[0]` (must be 1 or 2, else "Header attribute has unexpected version number").
8. `authenticateSchema = ConfigToAuthenticateSchema(config, encryptedStructure)` — `SIGN` if in
   signature scope, else `DO_NOT_SIGN`.
9. Required-Encryption-Context CMM (as encrypt).
10. Delegate to `structuredEncryption.DecryptStructure(tableName, encryptedStructure,
    authenticateSchema, cmm = reqCMM, encryptionContext = Some(context))`.
11. `plaintextItem = StructuredToItemDecrypt(plaintextStructure, encryptedItem, cryptoSchema)` (§6).
12. Build `ParsedHeader`; return with `parsedHeader = Some(...)`.

## 5. Encryption-context construction (`MakeEncryptionContextV1` / `V2`)

Key constants (`Util.dfy`): `TABLE_NAME` = "aws-crypto-table-name", `PARTITION_NAME` =
"aws-crypto-partition-name", `SORT_NAME` = "aws-crypto-sort-name". Per-attribute EC keys use
`SE.ATTR_PREFIX` ("aws-crypto-attr."); values are UTF8 of `logicalTableName`/key names, and
`SE.EncodeTerminal(...)` for key values.

- **V1** base context: `TABLE_NAME → logicalTableName`, `PARTITION_NAME → partitionKeyName`,
  `EncodeName(partitionKeyName) → EncodeTerminal(partition value)`; if a sort key exists, also
  `SORT_NAME → sortKeyName` and `EncodeName(sortKeyName) → EncodeTerminal(sort value)`.
  **V1 includes the partition/sort key VALUES.**
- **V2** base context: `TABLE_NAME`, `PARTITION_NAME`, and (if sort key) `SORT_NAME` only.
  **V2 does NOT include key values.**
- No sort key ⇒ `SORT_NAME` MUST be absent (both versions).
- Missing partition/sort attribute in the structured item ⇒ error.

## 6. Item ↔ structured-map conversion (DynamoToStruct item layer — dependency)

These are `DynamoToStruct` functions the item encryptor calls (they are NOT part of the
already-implemented terminal layer — see the critical note in §7):
- `ItemToStructured2(item, actions)`: terminal map of the item, **excluding** attributes whose
  action is `DO_NOTHING` (unless reserved-prefix). DO_NOTHING attributes never reach SE.
- `StructuredToItemEncrypt(s, orig, actions)`: for each `orig` key (skipping reserved-prefix),
  if it is in `s` AND its action is `ENCRYPT_AND_SIGN` → `StructuredToAttr(s[k])` (the encrypted
  bytes re-wrapped as a `B` attribute); otherwise pass `orig[k]` through unchanged. **Additionally**,
  every key in `s` not in `orig` (the SE-added `aws_dbe_head`/`aws_dbe_foot`) is added via
  `StructuredToAttr`. Result = passthrough/encrypted ∪ added-reserved.
- `StructuredToItemDecrypt(s, orig, actions)`: for each `orig` key that is NOT reserved-prefix,
  if in `s` AND `ENCRYPT_AND_SIGN` → `StructuredToAttr(s[k])`; else `orig[k]`. Keys in `s` not in
  `orig` are ignored, and reserved-prefix keys are skipped — so `aws_dbe_head`/`foot` are dropped
  from the decrypted output.

Consequence: only `ENCRYPT_AND_SIGN` attributes change representation. `SIGN_ONLY` and
`SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT` attributes are signed but pass through as their original
DDB value.

## 7. Explicit non-goals / boundaries

- **Legacy override is an extern** (`InternalLegacyOverride`: `Build`, `EncryptItem`, `DecryptItem`,
  `IsLegacyInput`, `policy` are all `{:extern}`) — it bridges to the old DDBEC client. The native
  core cannot port it; native legacy support is a separate extension seam (the Implementation Plan
  flags "legacy-format read compatibility" as an open scope item). A first native cut MAY omit legacy
  override entirely, provided config rejects a legacy override rather than silently ignoring it.
- The item encryptor performs **no cryptography** — it delegates to StructuredEncryption. Its
  correctness boundary is: correct item↔structured conversion, correct EC construction (V1/V2),
  correct Required-EC-CMM wrapping, correct policy routing, correct ParsedHeader assembly.
- Attribute-name ordering in error messages / key sequences is explicitly "MUST NOT be relied upon."

## 8. DynamoToStruct native component — item layer status

The native `DynamoToStruct` (`dbesdk/`) now covers BOTH layers:
- **Terminal layer**: `attrToStructured`/`structuredToAttr` (= `AttrToStructured`/`StructuredToAttr`)
  plus `NumberNormalizer`.
- **Item layer** (added, this module needs it): `itemToStructured` (= `ItemToStructured2`),
  `structuredToItemEncrypt`, `structuredToItemDecrypt` (§6). See `DynamoToStruct.md` §1a.

So the DynamoToStruct dependency is complete for building DynamoDbItemEncryptor. The plain
`ItemToStructured`/`StructuredToItem` variants (keep-everything) are NOT yet ported — the item
encryptor does not call them; port them only if a later module needs them.

## 9. Disagreements with spec prose

None found. The Dafny source carries inline `//= type=implication` annotations quoting
`encrypt-item.md`, `decrypt-item.md`, `ddb-table-encryption-config.md`, and `ddb-item-conversion.md`
verbatim; these are verifier-proven, so Dafny and the quoted prose agree on every annotated point.
Cross-check basis: the embedded annotations were read against the code, not the standalone
`specification/*.md` files end to end — if a future discrepancy is suspected, read those files directly.

## 10. Source pointers

- `DynamoDbItemEncryptor/src/AwsCryptographyDbEncryptionSdkDynamoDbItemEncryptorOperations.dfy` (1143)
- `DynamoDbItemEncryptor/src/Index.dfy` (249) — config validation + client construction
- `DynamoDbItemEncryptor/src/Util.dfy` (250) — EC key constants, selector-context reconstruction
- `DynamoDbItemEncryptor/src/InternalLegacyOverride.dfy` (64) — extern legacy bridge
- `DynamoDbItemEncryptor/Model/DynamoDbItemEncryptor.smithy` (233) — public surface
- `DynamoDbItemEncryptor/test/DynamoDBItemEncryptorTest.dfy` (651) — round-trip + config-error tests
- `DynamoDbEncryption/src/DynamoToStruct.dfy` (1556) — item-layer conversions (§6), lines 27–230
All paths under `~/github/dbesdk/aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/`.

## 11. Native implementation status

Implemented in module `dbesdk/` (package `...dynamodbitemencryptor`),
the **MPL-free core**:
- `ItemEncryptorConfig` (+ validating builder): version derivation, key-action check,
  forward-compatibility, reserved-namespace check (`aws_dbe_` and `aws-crypto-`), signature scope.
- `ItemEncryptorOperations`: `makeEncryptionContextForEncrypt/Decrypt` (V1/V2, §5),
  `configToCryptoSchema`, `configToAuthenticateSchema`, `isPlaintextItem`, `encodeTerminal`
  (= `SE.EncodeTerminal` = UTF8(Base64(typeId ++ value))).
- `PlaintextOverride`, `DynamoDbItemEncryptorException`.
- 11 tests, 0 failures (byte-exact V1/V2 EC vectors with hand-computed base64, version derivation,
  all config-validation error paths, schema mapping, decrypt-version selection, plaintext detection).
- A test caught the Dafny validation ordering: a reserved attribute configured non-DO_NOTHING
  fails the forward-compat check first; the "reserved, and may not be configured" error only fires
  for a reserved attribute configured DO_NOTHING (forward-compat passes, reserved check then fails).

NOW DONE — the **seam** (`NativeItemEncryptorClient` in the test-server registry): the CMM-facing
`EncryptItem`/`DecryptItem` end-to-end. It composes the core (config, EC construction, schemas,
plaintext routing) with `DynamoToStruct.itemToStructured`/`structuredToItem*`, the shared
`NativeMaterialResolver` (CMM → materials, now generalized to merge an item base context with the
StructuredEncryption V2 contribution and mark the union required), and the StructuredEncryption
core. `ItemEncryptorFactory` builds it (keyring → default CMM, as Dafny does); `RealItemEncryptorClient`
(Dafny-backed) was deleted. Feature `plaintext-override` moved to supportedFeatures (union still == the
13-feature catalog). Proven by 5 seam tests cross-decrypting native↔published-Dafny offline (Raw AES),
including a V2 SIGN_AND_INCLUDE case and a FORCE_PLAINTEXT passthrough; the 3 refactored SE seam tests
still pass. `make orchestrate` (needs AWS creds + peer servers) not runnable on this host.

STILL NOT DONE: legacy override (extern, rejected not supported), the keyring/cmm-XOR and
legacy/plaintext-conflict config checks (the test-server's `ConfigValidator` already enforces XOR
upstream), and `algorithmSuiteId` is now threaded into `GetEncryptionMaterials` at the seam.
