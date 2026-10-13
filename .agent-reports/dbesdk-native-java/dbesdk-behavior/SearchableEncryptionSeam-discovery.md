# SearchableEncryptionSeam — discovery checklist

Slice: the searchable-encryption seam — `GenerateEncryptedBeacons` orchestration
+ beacon-key retrieval (where native code meets the MPL key-store boundary).
Goal: light up the `searchable-encryption` test-server feature end-to-end over
the already-native beacon layer (primitive, key derivation, value location/set).

- [x] 1. Dafny source tree — DynamoDbEncryption/dafny/DynamoDbEncryption/src/ (SearchInfo.dfy, ConfigToInfo.dfy, DDBSupport.dfy)
- [x] 2. Smithy/public surface — commons test-server model + search tests: SearchConfig/BeaconVersion/StandardBeacon/BeaconKeyStore/BeaconKeySource/SingleKeyStore
- [x] 3. Read src .dfy — SearchInfo.dfy (KeySource 148–480, BeaconVersion 755–916), ConfigToInfo.dfy AddStandardBeacons 629–740
- [x] 4. requires/ensures — AddStandardBeacons init-failure ensures (dup name, non-E&S field, unencrypted loc, dup location); getKeysCache cache/TTL/GetBeaconKey contract
- [x] 5. test vectors — SearchMetadataStyleSemanticsTests (shared/partOnly/asSet/sharedSet) use live KeyStoreDdbTable + KMS 370957321024 + branch key 040a32a8-…; beacon value math pinned by committed Beacon golden vectors
- [x] 6. spec cross-check — no disagreement; inline //= implication/test annotations match
- [x] 7. non-obvious — loc defaults to name; SharedSet=Shared+AsSet; PartOnly not stored; shared computes under other's key; live-only key path (§7 of spec)
- [x] 8. non-goals — compound/virtual/query-rewrite/beacon-partitions/read-path (§8)
- [x] 9. behavior spec written — SearchableEncryptionSeam.md
- [x] 10. source pointers — recorded in spec §9

## Resolved open questions
- Orchestration entry: `BeaconVersion.GenerateEncryptedBeacons` → `GenerateBeacons2`
  (SearchInfo.dfy 851–916); DDBSupport.GetEncryptedBeacons is the DDB-level caller.
- Native/MPL boundary: `store.GetBeaconKey(GetBeaconKeyInput(branchKeyIdentifier))`
  (SearchInfo.dfy 411) + MP cache. Wrap the Dafny-compiled MPL KeyStore (dependency
  `aws-cryptographic-material-providers` already present); do NOT reimplement.
- Beacon key supply in tests: `SingleKeyStore` → `SingleLoc` → **live** DynamoDB
  branch-key store + KMS. `LiteralLoc` (static, offline) exists in Dafny but is
  NOT used by the searchable-encryption tests.
- Already covered by committed specs: value math (Beacon.md), HKDF derivation
  (BeaconKeyMaterials.md), value location/set (BeaconValueLocation.md). NEW here:
  config→beacons, key-store retrieval + cache, name→value map assembly, styles.

## Scoping reality (surfaced to user, not decided here)
- End-to-end `searchable-encryption` conformance needs the LIVE MPL branch-key
  store: DynamoDB KeyStoreDdbTable + KMS key in account 370957321024 + branch key
  040a32a8-… . Earlier creds seen were account 123367104812 (different account).
  Cannot be verified offline on this host without those resources/creds.
- The feature is broad: its tests also exercise shared/partOnly/asSet/sharedSet
  styles — flipping it to supported commits to that whole matrix.
- Offline-buildable now (unit-testable with an injected raw beacon key, anchored
  to Beacon.md golden vectors): config→beacons (standard), GenerateBeacons2
  assembly. Live-only: store.GetBeaconKey retrieval + end-to-end feature pass.
