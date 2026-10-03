# DynamoDbItemEncryptor — behavior discovery checklist

Module chosen as CDD-next after StructuredEncryption: it depends directly on
StructuredEncryption (30 source refs) and minimally on DynamoDbEncryption (1),
fewer new dependencies than DynamoDbEncryption (SearchableEncryption) or
DynamoDbEncryptionTransforms. Derived from live Dafny source (the overarching
implementation plan is not on this branch; dependency order re-derived directly).

Source root: `~/github/dbesdk/aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/DynamoDbItemEncryptor/`

- [x] 1. Locate the module's Dafny source tree
      src/: AwsCryptographyDbEncryptionSdkDynamoDbItemEncryptorOperations.dfy (1143),
      Index.dfy (249), Util.dfy (250), InternalLegacyOverride.dfy (64).
      Model/: DynamoDbItemEncryptor.smithy (233) + generated Types.dfy.
      test/: DynamoDBItemEncryptorTest.dfy.
- [x] 2. Read the module's Smithy model (public surface) — DONE, read in full.
      Operations: EncryptItem(plaintextItem: AttributeMap) -> (encryptedItem, parsedHeader?),
        DecryptItem(encryptedItem) -> (plaintextItem, parsedHeader?). parsedHeader MAY be
        absent in plaintext/legacy mode.
      Config (DynamoDbItemEncryptorConfig): REQUIRED logicalTableName, partitionKeyName,
        attributeActionsOnEncrypt (map attr->CryptoAction); OPTIONAL sortKeyName,
        allowedUnsignedAttributes, allowedUnsignedAttributePrefix, algorithmSuiteId
        (DBEAlgorithmSuiteId), keyring XOR cmm, legacyOverride, plaintextOverride.
      ParsedHeader: attributeActionsOnEncrypt (non-DO_NOTHING), algorithmSuiteId,
        encryptedDataKeys, storedEncryptionContext, encryptionContext, selectorContext (Key).
      Error: DynamoDbItemEncryptorException("client").
- [~] 3. Read every .dfy under src/ — IN PROGRESS.
      DONE: Util.dfy (full). Findings:
        - Reserved prefixes: ReservedPrefix "aws_dbe_", BeaconPrefix "aws_dbe_b_",
          VersionPrefix "aws_dbe_v_".
        - EC key constants: TABLE_NAME "aws-crypto-table-name", PARTITION_NAME
          "aws-crypto-partition-name", SORT_NAME "aws-crypto-sort-name"; per-attribute
          values under SE.EC_ATTR_PREFIX ("aws-crypto-attr.").
        - Selector-context (branch-key supplier) reconstruction from EC: ConvertContextForSelector,
          GetV2AttrMap/GetAttrValue (legend S/N/L/B -> DDB AttributeValue), GetLiteralValue
          (true/false/null), AddAttributeToMap. Uses SE.DecodeTerminal + DynamoToStruct.BytesToAttr.
      Operations.dfy method map (not yet read in full):
        AllowedUnsigned, ForwardCompatibleAttributeAction, UnknownAttribute, InSignatureScope,
        MakeEncryptionContextForEncrypt/Decrypt, MakeEncryptionContextV1/V2, IsVersion2Schema,
        VersionFromActions, KeyActionFromVersion, ValidInternalConfig?, GetCryptoSchemaAction,
        GetAuthenticateSchemaAction, ConfigToCryptoSchema, ConfigToAuthenticateSchema,
        IsPlaintextItem, ConvertCryptoSchemaToAttributeActions, KeyMissingMsg, ContextAttrsExist,
        EncryptItem (body TBD), DecryptItem (body TBD).
      PENDING for step 3: EncryptItem + DecryptItem bodies in full; Index.dfy (config +
        ValidConfig); InternalLegacyOverride.dfy.
      KEY EXTERNAL DEPENDENCY found: `DynamoToStruct` (AttrToBytes / BytesToAttr) — the DDB
        AttributeValue<->bytes+typeId serialization (S/N/B/BOOL/NULL/L/M/SS/NS/BS). Imported,
        not in this module's src; likely under the DynamoDbEncryption module. MUST locate and
        assess: it is load-bearing byte-level behavior the item encryptor relies on, and is a
        candidate component of its own.
- [x] 3. Read every .dfy under src/ — DONE.
      Util.dfy (full, prior), Index.dfy (full: config validation + client construction),
      InternalLegacyOverride.dfy (full: all-extern legacy bridge), Operations.dfy (full 1143:
      helpers, ValidInternalConfig?, MakeEncryptionContextV1/V2, ConfigToCryptoSchema,
      ConfigToAuthenticateSchema, IsPlaintextItem, EncryptItem + DecryptItem bodies).
      Item-layer DynamoToStruct functions read: DynamoToStruct.dfy lines 27-230
      (ItemToStructured2, StructuredToItemEncrypt/Decrypt, ItemToStructured, StructuredToItem).
- [x] 4. Extract requires/ensures/invariant clauses — DONE (captured as spec §2-§6).
      EncryptItem/DecryptItem key/context requires; V1/V2 EC ensures (V1 includes key VALUES,
      V2 does not); ConfigToCryptoSchema (item.Keys == schema.Keys, matches actions);
      ConfigToAuthenticateSchema (SIGN vs DO_NOT_SIGN by scope); ValidInternalConfig? predicate.
- [x] 5. Read test/DynamoDBItemEncryptorTest.dfy — surveyed (651): TestRoundTrip, TestV2RoundTrip(+Complex,
      +ComplexSwitch, +Special), TestMissingSortKey, TestUnexpectedField, TestMissingContext,
      TestLargeRoundTrip. Round-trip + config-error tests; use KMS keyrings so they need real
      crypto — the cross-language test-server suite is the operative oracle, not these unit tests.
- [x] 6. Cross-check against specification/ prose — DONE via the inline //= type=implication
      annotations (verifier-proven) quoting encrypt-item.md/decrypt-item.md/
      ddb-table-encryption-config.md/ddb-item-conversion.md. No disagreement found; basis + caveat
      recorded in spec §9.
- [x] 7. Non-obvious behavior — DONE (spec §6): only ENCRYPT_AND_SIGN attrs change representation;
      DO_NOTHING attrs excluded from structured map; reserved aws_dbe_head/foot added on encrypt &
      dropped on decrypt; version 1 vs 2 EC differences; forward-compat / signature-scope rules;
      Required-EC-CMM wrapping so base-context keys are reconstructed on decrypt, not stored.
- [x] 8. Explicit non-goals — DONE (spec §7): legacy override is all-extern (native core cannot port
      it; first cut may omit but must reject, not ignore); item encryptor does no crypto itself;
      key/attr ordering not to be relied upon.
- [x] 9. Wrote dbesdk-behavior/DynamoDbItemEncryptor.md (per template).
- [x] 10. Source pointers recorded (spec §10, exact paths + line counts).

## Continuation notes (resolved + new)
- RESOLVED: DynamoToStruct specced + implemented as its own component (dbesdk/).
- NEW CRITICAL FINDING (spec §8): the native DynamoToStruct done so far is the TERMINAL layer only
  (attrToStructured/structuredToAttr + NumberNormalizer). The item encryptor also needs the ITEM
  layer — ItemToStructured2, StructuredToItemEncrypt, StructuredToItemDecrypt (spec §6). These must
  be added to the DynamoToStruct native component, and DynamoToStruct.md extended to cover them,
  BEFORE implementing DynamoDbItemEncryptor. This is the immediate next build step.
