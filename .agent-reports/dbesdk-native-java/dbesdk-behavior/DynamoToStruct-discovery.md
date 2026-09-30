# DynamoToStruct — behavior discovery checklist  [COMPLETE]

The DDB attribute serialization (AttributeValue <-> bytes + 2-byte typeId), the
byte-level foundation the DynamoDbItemEncryptor relies on. CDD-earlier than the
item encryptor. Lives in the DynamoDbEncryption module.

Source: `~/github/dbesdk/aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/DynamoDbEncryption/src/DynamoToStruct.dfy` (1556)
        + `NormalizeNumber.dfy`, `Util.dfy` (MAX_STRUCTURE_DEPTH=32); type ids in StructuredEncryption/src/Util.dfy
Tests:  `.../DynamoDbEncryption/test/DynamoToStruct.dfy`
Spec:   `specification/dynamodb-encryption-client/ddb-attribute-serialization.md` (inlined as //= in source)

- [x] 1. Located source tree (DynamoToStruct.dfy + NormalizeNumber.dfy + Util.dfy + test + spec).
- [x] 2. Public surface: AttrToStructured/StructuredToAttr, AttrToBytes/BytesToAttr, AttrToTypeId.
- [x] 3. Read DynamoToStruct.dfy in full (AttrToBytes 311-540; set/list/map serializers 542-1010;
      BytesToAttr 1374-1496 + Deserialize* helpers) and NormalizeNumber.dfy in full.
- [x] 4. Extracted requires/ensures — the AttrToBytes ensures ARE the byte-format spec (per-type,
      prefix layout, big-endian counts, no-dup sets, depth<=32). Recorded in spec §3.
- [x] 5. Read test/DynamoToStruct.dfy — concrete golden vectors for every type + normalization;
      confirmed exact type ids (S=0001,N=0002,B=FFFF,BOOL=0004,NULL=0000,SS=0101,NS=0102,BS=01FF,
      MAP=0200,LIST=0300) and byte layouts. Recorded in spec §8.
- [x] 6. Cross-checked spec prose — it is inlined as //= annotations in source and matches; no
      disagreement (spec §9).
- [x] 7. Non-obvious behavior captured (spec §6): UTF-16 ordering for S/N sets + map keys vs
      byte-order for B sets; lossy number normalization; NULL(false)->NULL(true) round-trip;
      top-level vs prefixed; set/map reordering determinism.
- [x] 8. Non-goals captured (spec §7): no input-order preservation; no NULL(false); depth>32,
      >38 sig digits, magnitude range, duplicate set entries, map key byte-length bounds rejected.
- [x] 9. Wrote dbesdk-behavior/DynamoToStruct.md (per template).
- [x] 10. Source pointers recorded (spec header + §-level cites).

## Follow-on for the port (not part of discovery)
DynamoToStruct is pure + golden-vector-testable — a natural standalone native component to build
before DynamoDbItemEncryptor. Then resume the DynamoDbItemEncryptor discovery
(DynamoDbItemEncryptor-discovery.md), whose remaining step 3 items (EncryptItem/DecryptItem bodies,
Index.dfy config validity, InternalLegacyOverride) still need reading.
