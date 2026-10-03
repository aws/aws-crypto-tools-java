# BeaconKeyMaterials (HKDF-SHA512 beacon key derivation) — Behavior Spec

Scope: the per-beacon **HMAC key derivation** of the Dafny `DynamoDbEncryption` module
(`src/SearchInfo.dfy`, module `SearchableEncryptionInfo`): `GetBeaconKey`, `GetHmacKeys`,
`GetAllKeys`. Given a single "beacon key" (the branch/beacon key retrieved from the key
store), this derives one HMAC key per standard beacon, keyed by beacon name. This is the
layer that produces the key passed to the `StandardBeacon` primitive (`Beacon.md` §6).

Retrieving the beacon key itself from the key store (branch-key materials, the
`getKeysCache`/`getKeyMap`/`CreateCryptographicMaterialsCache` paths in `SearchInfo.dfy`)
is the **MPL/key-store boundary** — not part of this native-core slice (§7). This slice
takes the beacon key as an input and is pure crypto (HKDF-SHA512).

## 1. Public surface

- `GetBeaconKey(client, key, name) -> Bytes` (`SearchInfo.dfy:89`): derive the HMAC key
  for one beacon named `name` from beacon key `key`.
- `GetHmacKeys(client, allKeys, keysLeft, key, acc) -> HmacKeyMap`
  (`SearchInfo.dfy:53`): tail-recursive map builder, one `GetBeaconKey` per name.
- `GetAllKeys(client, stdNames, key) -> HmacKeyMap` (`SearchInfo.dfy:42`): entry point;
  `GetHmacKeys(client, stdNames, stdNames, key)`. `HmacKeyMap = map<string, Bytes>`
  (beacon name → derived 64-byte key).

## 2. The derivation: `GetBeaconKey`

Grounded from the `ensures` contract (`SearchInfo.dfy:95-122`) and body (`:124-130`):

```
info        = UTF8("AWS_DBE_SCAN_BEACON" + name)
derivedKey  = HKDF( digestAlgorithm = SHA_512,
                    salt            = None,
                    ikm             = key,          // the beacon key
                    info            = info,
                    expectedLength  = 64 )          // 64-byte output
```

- **HKDF-SHA512**, i.e. RFC 5869 extract-then-expand with HMAC-SHA512. `salt = None`
  means a salt of HashLen (64) zero bytes (RFC 5869 §2.2), matching the existing native
  `Hkdf` (structured-encryption `crypto/Hkdf.java`).
- `info` is the literal ASCII prefix `"AWS_DBE_SCAN_BEACON"` concatenated with the beacon
  name, UTF-8 encoded.
- Output length is **exactly 64 bytes**.
- Note the hash split: this *derivation* uses **SHA-512**, while the `StandardBeacon`
  `basicHash` that consumes the derived key uses **SHA-384** (`Beacon.md` §2). Two
  distinct hashes.

## 3. The key map: `GetAllKeys` / `GetHmacKeys`

`GetAllKeys` builds `{ name -> GetBeaconKey(key, name) : name in stdNames }`. `GetHmacKeys`
is the tail-recursive accumulator doing one derivation per remaining name. Preconditions
require `stdNames` has **no duplicates** (`Seq.HasNoDuplicates`); the names come from a
deduplicated set of beacon names upstream (`BeaconTestFixtures.dfy:388`,
`set b <- version.standardBeacons :: b.name`). Postcondition: every input name appears in
the output map.

## 4. Error / exception behavior

- `GetBeaconKey` fails if `UTF8.Encode("AWS_DBE_SCAN_BEACON" + name)` fails (invalid
  UTF-16 in `name`) or if the underlying `client.Hkdf` fails. In practice beacon names are
  validated attribute names, so the UTF-8 encode does not fail for real configs.
- `GetAllKeys`/`GetHmacKeys` propagate any `GetBeaconKey` failure.

## 5. Non-obvious behavior

- **Two different hash functions** in the beacon pipeline: HKDF uses SHA-512 (this layer),
  the HMAC in `basicHash` uses SHA-384 (`StandardBeacon`). Using one hash for both would
  reproduce neither golden vector.
- **`salt = None` ≠ empty salt in HKDF-extract**: it is HashLen zero bytes. The native
  `Hkdf` already encodes this (`saltOrZeros`).
- The derived key is **64 bytes** regardless of beacon length; the beacon length only
  truncates the *HMAC output*, not this key.
- `info` uses the raw beacon `name` (e.g. `"std2"`, `"Name"`), **not** the written
  attribute name `aws_dbe_b_<name>` and **not** the shared-beacon `keyName()` selection
  (shared beacons select *which* name's key to use at `hash` time, via
  `StandardBeacon.keyName()`; the derivation itself always keys on the beacon's own name).

## 6. Cross-check against spec prose

No disagreement. `specification/searchable-encryption/search-config.md#hmac-key-generation`
is inlined in `SearchInfo.dfy:108-122` as `//= type=implication` and matches the body:
HKDF-SHA512, no salt, ikm = beacon key, info = UTF8("AWS_DBE_SCAN_BEACON" + name),
expectedLength = 64.

## 7. Explicit non-goals (separate slices)

- Retrieving the beacon key from the key store / branch-key materials: the
  `getKeysCache`, `getKeyMap`, `getKeysLiteral`, `CreateCryptographicMaterialsCache`, and
  single-vs-multi key-source paths (`SearchInfo.dfy:149-470`). This is the MPL/key-store
  boundary and belongs at the searchable-encryption seam, not native core.
- Beacon-key caching / TTL (`PosLongAdd`/`PosLongSub`, cache get/put).
- `keyName()` shared-beacon key selection at query/write time (lives in the beacon layer
  that consumes this map, `SearchInfo.dfy:575-579`).
- `MakeSearchInfo`/`BeaconVersion` config assembly and `GenerateEncryptedBeacons`
  orchestration.

## 8. Golden vectors (from `test/Beacon.dfy` `TestOneBeaconValue`, base key `[1,2,3,4,5]`)

These compose this layer with the already-native `DynamoToStruct` (value bytes) and
`StandardBeacon` (`basicHash`): `deriveBeaconKey([1,2,3,4,5], name)` →
`StandardBeacon.create(name, length, name, false, 0).hash(serialize(value), derivedKey, 0)`:

| name | value | length (bits) | expected hex |
|---|---|---|---|
| std2 | `N("1.23")` | 24 | `"ac6f5d"` |
| Name | `S("MyName")` | 32 | `"7d9bfa40"` |
| Title | `S("MyTitle")` | 32 | `"e4feb833"` |
| std4 | `S("abc")` | 24 | `"0e9064"` |
| std6 | `S("666")` | 26 | `"2d99222"` |
| NameTitleField | `S("MyName__mytitle")` | 28 | `"4c577d7"` |
| Name | `S("")` (empty) | 32 | `"e0e88994"` |
| Title | `S("")` (empty) | 32 | `"af34f26f"` |

(`BeaconTestFixtures.dfy:96-103` define the constants; `test/Beacon.dfy:88-105` assert the
`GetBeaconValue` composition equals them.)

## 9. Disagreements with spec prose

None found (§6).

## 10. Source pointers

- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/SearchInfo.dfy:42-130` (`GetAllKeys`,
  `GetHmacKeys`, `GetBeaconKey`); `:149-470` (key-store/cache layer — non-goal §7).
- `DynamoDbEncryption/dafny/DynamoDbEncryption/test/Beacon.dfy:88-105` (`TestOneBeaconValue`,
  `GetBeaconValue` helper :380-402); `test/BeaconTestFixtures.dfy:96-103` (golden strings),
  `:388-391` (`GetHmacKeys` call over the deduplicated beacon-name set).
- `specification/searchable-encryption/search-config.md#hmac-key-generation`.
- Reused native primitive: `dbesdk` `crypto/Hkdf.java` (RFC 5869
  extract-then-expand, caller-selected Mac, salt=None → HashLen zeros).
