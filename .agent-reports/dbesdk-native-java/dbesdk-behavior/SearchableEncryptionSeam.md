# SearchableEncryptionSeam — behavior spec

The write-path seam that turns a configured searchable-encryption `SearchConfig`
into the `aws_dbe_b_NAME` beacon attributes added to an item on `EncryptItem`.
Covers config→beacons, beacon-key retrieval (the MPL key-store boundary), and
the `GenerateEncryptedBeacons` orchestration. Scope here is the **standard
beacon**; compound/virtual/query-rewrite are non-goals (§8).

Source of truth (read directly, not spec prose):
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/SearchInfo.dfy`
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/ConfigToInfo.dfy`
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/DDBSupport.dfy`
- commons `dbesdk/test-server/.../search/SearchMetadataStyleSemanticsTests.java`

## 1. Public surface (test-server model)

`SearchConfig { writeVersion, versions: [BeaconVersion] }`
`BeaconVersion { version, standardBeacons:[StandardBeacon], keyStore:BeaconKeyStore, keySource:BeaconKeySource }`
`StandardBeacon { name, length, loc?, style?, numberOfPartitions? }`
`BeaconStyle = partOnly | shared{other} | asSet | sharedSet{other}`
`BeaconKeyStore { ddbTableName, logicalKeyStoreName, kmsKeyArn }`
`BeaconKeySource = single(SingleKeyStore{keyId, cacheTtlSeconds}) | multi(...)`

## 2. Config → beacons (ConfigToInfo.AddStandardBeacons, lines 629–716)

Per configured `StandardBeacon`, build an internal beacon:
- **loc defaults to name** (`GetLocStr`, lines 727–740): `loc` absent ⇒ terminal
  location string = `name`; else = `loc.value`. Parsed via `MakeTermLoc` (the
  already-native `TermLoc.make`).
- **style match** (lines 672–689): `partOnly`→isPartOnly; `shared{other}`→share=other;
  `asSet`→isAsSet; `sharedSet{other}`→share=other **and** isAsSet (SharedSet =
  Shared + AsSet).
- `MakeStandardBeacon(name, length, locString, isPartOnly, isAsSet, share, partitionCount)`.

Initialization MUST fail (all `Need`/`Failure`):
- duplicate standard-beacon **name** (`beacons[0].name in converted`).
- name matches a configured field whose action ≠ `ENCRYPT_AND_SIGN`
  (`BeaconNameAllowed`).
- terminal location is **not encrypted** (`IsEncryptedV` → "not defined on an
  encrypted field").
- two beacons on the **same location**; or a beacon location colliding with a
  single-location virtual field.

## 3. Beacon-key retrieval — the MPL key-store boundary (SearchInfo.dfy KeySource, lines 148–480)

`KeyLocation = LiteralLoc(keys) | SingleLoc(keyId) | MultiLoc(keyName,deleteKey)`.
The test-server `SingleKeyStore` ⇒ **`SingleLoc`** (live store); `LiteralLoc`
(static hmac keys, no AWS) is **not** exercised by the searchable-encryption tests.

`getKeyMap(stdNames, keyId)` → `getKeysCache` (lines 260–468):
1. Build cache id, `cache.GetCacheEntry` (MP cache = MPL).
2. On miss/expired (`cacheEntryWithinLimits`, TTL = `cacheTtlSeconds`):
   **`store.GetBeaconKey(GetBeaconKeyInput(branchKeyIdentifier := keyId))`** —
   this is the MPL branch-key store (DynamoDB `ddbTableName` + KMS `kmsKeyArn`).
3. `rawBeaconKeyMaterials.beaconKeyMaterials.beaconKey` (raw branch beacon key);
   `Need(key.Some?, "beacon key unexpectedly empty")`.
4. `getAllKeys(stdNames, key.value)` = **already-native** `BeaconKeyDerivation.deriveHmacKeys`
   (HKDF-SHA512 per name).
5. `cache.PutCacheEntry` with expiry `now + cacheTTL`; return the `HmacKeyMap`.

The native seam wraps the Dafny-compiled MPL KeyStore + MP cache (dependency
`aws-cryptographic-material-providers` already present); it does **not**
reimplement the key store (MPL boundary is fixed).

## 4. Orchestration (SearchInfo.BeaconVersion.GenerateEncryptedBeacons 851–886; GenerateBeacons2 894–916; DDBSupport.GetEncryptedBeacons)

1. `hmacKeys :- getKeyMap(keyId)` (§3).
2. `GenerateBeacons2(beaconNames, item, hmacKeys, EncryptedBeacon, partition)`:
   for each beacon name, if it is an `EncryptedBeacon` type **and not PartOnly**
   (PartOnly MUST NOT be stored), compute `attrHash(item, virtualFields, keys,
   partition)` = the already-native `StandardBeacon.getHash`. If `Some`, add
   `beacon.getBeaconName()` (= `aws_dbe_b_` + name) → value to the accumulator;
   if `None` (field absent), skip.
3. Result MUST NOT contain any plaintext keys from the item; it is the beacon
   attributes only, merged into the encrypt output.

Beacon value = the committed primitive: `HMAC-SHA384(hmacKey, locatedValueBytes
++ partitionBytes)[..8]` → lowercase-hex rightmost-`length`-bits. All of §4's
value math is already native + golden-pinned; what is new here is config→beacons,
key retrieval, and the name→value map assembly.

## 5. Error behavior
Config errors (§2) surface as init failure. Missing/empty beacon key →
"beacon key unexpectedly empty". KeyStore/cache failures propagate as the MPL
error class. Field absent in item ⇒ beacon simply not written (not an error).

## 6. Spec cross-check
No disagreement found: SearchInfo/ConfigToInfo carry inline `//= type=implication`
annotations matching their `ensures`; the test-server `//= type=test` lines cite
the same beacons.md sections. Recorded as grounded, not inferred.

## 7. Non-obvious / load-bearing
- loc defaults to name; a `.`/`[` in loc makes it a nested path (TermLoc), already handled.
- SharedSet = Shared + AsSet (two flags from one style).
- PartOnly beacons are configured but **MUST NOT** be written to the item.
- Shared beacon computes under the **other** beacon's key/loc — so two names can
  share one beacon value (the test's core assertion).
- The searchable-encryption test matrix uses the **live** branch-key store only;
  there is no offline key path in those tests.

## 8. Explicit non-goals (this slice)
Compound beacons (`CompoundBeacon.dfy`), virtual fields (`Virtual.dfy`), query/
filter rewrite (`FilterExpr.dfy`/`UpdateExpr.dfy`), `beacon-partitions` (separate
feature), and the read/decrypt beacon path. The `searchable-encryption` feature's
own tests additionally exercise shared/partOnly/asSet/sharedSet **styles** — those
are in scope for lighting up the feature but build on the standard-beacon core.

## 9. Source pointers
SearchInfo.dfy 42–137 (key derivation, already native), 148–480 (KeySource/cache/
MPL store.GetBeaconKey), 755–916 (BeaconVersion orchestration). ConfigToInfo.dfy
629–740 (AddStandardBeacons/GetLocStr). DDBSupport.dfy (GetEncryptedBeacons entry).
