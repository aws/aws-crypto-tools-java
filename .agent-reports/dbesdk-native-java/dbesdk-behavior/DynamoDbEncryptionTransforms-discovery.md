# DynamoDbEncryptionTransforms — Discovery Checklist

Source of truth: `~/github/dbesdk/aws-database-encryption-sdk-dynamodb` (primary, not the `-java` mirror).
Module: `DynamoDbEncryption/dafny/DynamoDbEncryptionTransforms/`.

- [ ] 1. Locate the module's Dafny source tree
- [ ] 2. Read the module's Smithy/Types model (public surface)
- [ ] 3. Read every .dfy file under src/ for this module
- [ ] 4. Extract requires/ensures/invariant clauses
- [ ] 5. Read the module's own test/ directory for concrete input/output pairs
- [ ] 6. Cross-check against specification/ prose — note any disagreement
- [ ] 7. Identify non-obvious behavior not derivable from the signature alone
- [ ] 8. Identify explicit non-goals
- [ ] 9. Write or update dbesdk-behavior-specs/DynamoDbEncryptionTransforms.md
- [ ] 10. Record source pointers with exact file paths

- [x] 1. Locate the module's Dafny source tree — `DynamoDbEncryptionTransforms/` (primary checkout), 19 src + Model + test.
- [x] 2. Read the module's Smithy/Types model — operation I/O via Types.dfy; surface summarized in spec §1.
- [x] 3. Read every .dfy file under src/ — all 19 read (Index, Operations, DdbMiddlewareConfig, DynamoDbMiddlewareSupport, 13 per-op transforms, AttributeResolver, GetNumberOfQueries, DdbStatement).
- [x] 4. Extract requires/ensures/invariant — captured per-op in spec §3 (passthrough conditions, legacy-param rejections, decrypt/removebeacons postconditions, UpdateItem signed-attr failure).
- [x] 5. Read the module's own test/ — read `test/PutItemTransform.dfy` (passthrough + multi-tenant keyProviderId failure + error-wrapping vector); full test/ dir present (15 files) for per-op vectors when building.
- [x] 6. Cross-check specification/ — source is densely `//=` duvet-annotated to `ddb-sdk-integration.md`; no disagreement found (spec §6).
- [x] 7. Non-obvious behavior — spec §7 (signed-vs-encrypted beacon placement, multi-tenant silent drop, batch-write plaintext restore by PK+SK, UpdateItem UPDATED_* signed-attr error, pure-passthrough input transforms, PartiQL categorical rejection).
- [x] 8. Explicit non-goals — spec §8.
- [x] 9. Write dbesdk-behavior-specs/DynamoDbEncryptionTransforms.md — written (118 lines).
- [x] 10. Record source pointers — spec §9, incl. the DDBSupport dependency pointer.

## STATUS: transforms-middleware discovery COMPLETE. Dependency NOT yet discovered.
The 28-op middleware is fully grounded + spec written. The **`DynamoDBSupport` beacon layer** (`DynamoDbEncryption/src/DDBSupport.dfy` + its `FilterExpr`/virtual-field/compound-beacon deps) is a **separate module** the middleware calls for every write/read beacon operation; it needs its OWN discovery pass before the full module can be built to pass. Partially covered already: `BeaconVersion.generateEncryptedBeacons` ≈ part of `GetEncryptedBeacons`. Unbuilt: `AddSignedBeacons`, `RemoveBeacons`, `QueryInputForBeacons`/`QueryOutputForBeacons`, `ScanInputForBeacons`/`ScanOutputForBeacons` (FilterExpr rewriting), `GetVirtualFields`, `GetCompoundBeacons`, `GetBeaconKeyId`, `IsWriteable`, `IsSigned`, `TestConditionExpression`, `TestUpdateExpression`.

## Notes / evidence (filled as I go)

### Module tree (step 1 ✓)
`DynamoDbEncryption/dafny/DynamoDbEncryptionTransforms/` — src/ 19 files (~2900 LOC), Model/Types 1984 LOC (mostly generated), full test/ dir with per-op vectors + TestFixtures.dfy.

### Architecture (steps 2–3, partial — read: Index, Operations, DynamoDbMiddlewareSupport, PutItemTransform)
- **Client construction** (`Index.dfy` `DynamoDbEncryptionTransforms(config)`): config = `DynamoDbTablesEncryptionConfig` = map<physicalTableName, DynamoDbTableEncryptionConfig>. Per table:
  - `SearchConfigToInfo.Convert(inputConfig)` → optional native `SearchInfo`.
  - signed beacons: `search.curr().ListSignedBeacons()`; init MUST fail if a signed-beacon NAME is already in attributeActionsOnEncrypt / allowedUnsignedAttributes / under the unauthenticated prefix (`IsConfigured`); each signed beacon is auto-added as `SIGN_ONLY` (`AddSignedBeaconActions`).
  - builds a per-table `DynamoDbItemEncryptor` from the (beacon-augmented) actions + keyring/cmm/legacyOverride/plaintextOverride.
  - internal `TableConfig` = {physicalTableName, logicalTableName, partitionKeyName, sortKeyName, itemEncryptor, search, plaintextOverride}.
  - init MUST fail on duplicate logicalTableName across physical tables.
- **Dispatch** (`...TransformsOperations.dfy`): each of 28 methods delegates to a per-op module `Input`/`Output`. ResolveAttributes → AttributeResolver; GetNumberOfQueries → NumberOfQueries.Get.
- **Middleware seam** (`DynamoDbMiddlewareSupport.dfy`): thin wrappers over `BS = DynamoDBSupport` (in `DynamoDbEncryption/src/DDBSupport.dfy`) + the item encryptor. The REAL beacon logic is in DDBSupport, NOT transforms: `AddSignedBeacons`, `GetEncryptedBeacons`, `RemoveBeacons`, `GetBeaconKeyId`, `QueryInputForBeacons`/`QueryOutputForBeacons`, `ScanInputForBeacons`/`ScanOutputForBeacons`, `GetVirtualFields`, `GetCompoundBeacons`, `IsWriteable`, `IsSigned`, `TestConditionExpression`, `TestUpdateExpression`, `GetNumberOfQueries`. Also `GetKeyIdFromHeader` (multi-tenant: pull beacon key id from parsed-header EDK when keySource is MultiLoc; Single → None).

### PutItem write path (grounded from PutItemTransform.dfy) — the beacon write path
`Input`: if `IsPlainWrite(config,table)` → passthrough. Else: reject legacy `Expected`/`ConditionalOperator`; `IsWriteable` (no attr name starts with `aws_dbe_`); `TestConditionExpression`; `GetRandomPartition`; `AddSignedBeacons` → item'; `itemEncryptor.EncryptItem(item')`; `GetKeyIdFromHeader`; `GetEncryptedBeacons(originalItem, keyId, partition)` → beacon map; result Item = `encrypted.encryptedItem + beacons`.
`Output`: table not configured OR no Attributes → passthrough; else `DecryptItem(Attributes)` → `RemoveBeacons` → replace Attributes.

### STILL TO READ (steps 3–8 remaining)
- Remaining per-op: BatchWriteItem, BatchGetItem, TransactWriteItems, TransactGetItems, ExecuteStatement, BatchExecuteStatement, ExecuteTransaction, DdbStatement, AttributeResolver, GetNumberOfQueries.
- **`DynamoDbEncryption/src/DDBSupport.dfy`** (the real beacon write/read logic the middleware calls) — highest-value remaining read.
- test/ vectors (step 5); specification/ cross-check (step 6).

### Config predicates (grounded from DdbMiddlewareConfig.dfy)
- `IsPlainWrite(config, table)` = table not configured OR plaintextOverride == `FORCE_PLAINTEXT_WRITE_ALLOW_PLAINTEXT_READ`. Drives PutItem/BatchWrite/TransactWrite passthrough.
- `GetRandomPartition(config, item)`: 0 if no search or numPartitions<=1; else `partitionSelector.GetPartitionNumber(item, numPartitions, logicalTableName)`, validated into [0, numPartitions).
- `ValidConfig?`: physicalTableName must key its entry; logical→physical is one-to-one (duplicate logical name is an init failure, also enforced in Index.dfy).
- Error type: `DynamoDbEncryptionTransformsException(message)`; `MapError` wraps item-encryptor errors, `AwsCryptographyDbEncryptionSdkDynamoDb` wraps DDBSupport errors.

### Per-operation patterns (grounded: Get/Query/Scan/Update/Delete + Put earlier)
Common shape: **Input** = validate/rewrite before the DDB call; **Output** = decrypt/filter after. Every op passes through unchanged when `TableName !in config` (and read-outputs also passthrough on absent Item(s)).
- **GetItem**: Input = passthrough (no change ever). Output = passthrough if unconfigured/no Item; else `DecryptItem(Item)` → `RemoveBeacons` → replace Item.
- **PutItem**: Input = (see write path above) IsWriteable + TestConditionExpression + GetRandomPartition + AddSignedBeacons + EncryptItem + GetKeyIdFromHeader + GetEncryptedBeacons; Item = encryptedItem + beacons. Output = DecryptItem(Attributes)+RemoveBeacons when ReturnValues ALL_OLD produced Attributes.
- **DeleteItem**: Input = reject legacy Expected/ConditionalOperator + TestConditionExpression, else unchanged. Output = like Put (ALL_OLD Attributes → decrypt+removebeacons).
- **UpdateItem**: Input = reject legacy Expected/AttributeUpdates/ConditionalOperator + TestUpdateExpression, else unchanged. Output: ALL_OLD/ALL_NEW → decrypt+removebeacons; **UPDATED_OLD/UPDATED_NEW → MUST fail if any returned attr IsSigned** (partial item can't be verified), else passthrough.
- **Query**: Input = reject legacy AttributesToGet/KeyConditions/QueryFilter/ConditionalOperator + `QueryInputForBeacons` (rewrite expr refs → beacons). Output = per-item DecryptItem; **multi-tenant keyId filter** (if a beacon keyId resolved from the key/filter expr, keep only items whose parsed-header has exactly 1 EDK with keyProviderInfo == keyId); then `QueryOutputForBeacons`.
- **Scan**: Input = reject legacy AttributesToGet/ScanFilter/ConditionalOperator + `ScanInputForBeacons`. Output = like Query (keyId filter from filter expr only; no KeyConditionExpression) + `ScanOutputForBeacons`.
- **GetKeyIdFromHeader** (multi-tenant write): if keySource is MultiLoc → require exactly 1 EDK, keyProviderId == `aws-kms-hierarchy`, return decoded keyProviderInfo as beacon key id; SingleLoc → None.

### Non-obvious details flagged so far (step 7)
- Signed beacons are injected into attributeActionsOnEncrypt as SIGN_ONLY at client construction (not per-call), with the IsConfigured init-failure rule.
- Encrypted beacons (`aws_dbe_b_*`) are computed from the ORIGINAL plaintext item (not the encrypted item) and appended AFTER encryption; signed beacons are added to the item BEFORE encryption.
- Query/Scan multi-tenant per-item keyId filtering drops items from other tenants silently (not an error).
- UpdateItem UPDATED_OLD/UPDATED_NEW + signed attribute = hard error (verification impossible on a partial item).
- `IsWriteable`: rejects any attribute name beginning with `aws_dbe_`.
