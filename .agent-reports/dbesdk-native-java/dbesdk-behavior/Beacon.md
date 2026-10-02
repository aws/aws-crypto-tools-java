# Beacon (standard beacon) — Behavior Spec

Scope: the **standard beacon** primitive of the Dafny `DynamoDbEncryption` module
(`src/Beacon.dfy`, Dafny module `BaseBeacon`). This is the searchable-encryption
feature's foundational, byte-testable crypto primitive: it maps a plaintext terminal
value to a truncated keyed hash ("beacon value") that can be equality-queried without
decrypting. Compound beacons, virtual fields, shared beacons, beacon-partitions
(`numberOfPartitions > 0`), the beacon-key-materials/HKDF layer, and query/filter
rewriting are separate slices (§7).

The value-serialization dependency (`DynamoToStruct.TopLevelAttributeToBytes` +
`NumberNormalizer`) is already implemented natively this session; this primitive builds
on it.

## 1. Public surface

A `StandardBeacon` is configured by `name`, `length : BeaconBitLength`, a value location
`loc`, a `style` (partOnly / asSet / shared / sharedSet), and `numberOfPartitions`. Its
core operation, given an already-derived per-beacon HMAC key, a record (DDB item), and a
partition number, produces an optional `AttributeValue`:

- **non-set beacon** → a `"S"` (String) attribute holding the beacon hex value, or no
  value if the located field is absent from the item.
- **asSet beacon** → an `"SS"` (StringSet) attribute holding the deduplicated beacon
  value of each element of the source Set.

The written beacon attribute name is `BeaconPrefix + name` where
`BeaconPrefix = "aws_dbe_b_"` (`src/Util.dfy:15`).

## 2. The beacon value: `basicHash`

`basicHash(value, key, length, partitionBytes)` (Dafny `BeaconBase.hash`), the whole
primitive, is:

```
hmac8 = HMAC_SHA384(key, value ++ partitionBytes)[0 .. 8]     // first 8 bytes
beaconHex = BytesToHex(hmac8, length)                          // §3
```

- `getHmac` uses **HMAC-SHA384** and keeps the **first 8 bytes** of the 48-byte MAC.
- `key` is the per-beacon HMAC key, supplied by the beacon-key-materials layer (§6),
  not derived here.
- `value` is the byte serialization of the terminal (§5).
- `partitionBytes` is appended to `value` **before** HMAC (§4).
- Output is a non-empty **lowercase** hex string of exactly `ceil(length/4)` chars.

## 3. `BytesToHex` — bit truncation (highest-value gotcha)

`BeaconBitLength`/`BeaconLength` is an integer **1..63 bits** (`src/Beacon.dfy:32`). The
beacon keeps the **rightmost `length` bits** of the 8-byte HMAC, rendered lowercase hex:

- `numBytes = ceil(length/8)` — bytes of the MAC used (the rightmost `numBytes`).
- `numChars = ceil(length/4)` — output hex length.
- `topBits = length mod 4`, or `4` if that is `0` — bits kept in the top hex nibble.
- The **top** nibble of the used region is truncated to its low `topBits` bits
  (`TruncateNibble(n, b) = n mod 2^b`); all remaining nibbles are full.
- `HexChar` emits `0-9a-f` (**lowercase** — MPL `StandardLibrary/src/HexStrings.dfy:12`).

So byte-aligned lengths (8,16,24,32,…) render the rightmost `length/8` bytes as full hex;
non-byte-aligned lengths additionally truncate the leading nibble.

## 4. Partition encoding

`partitionBytes = PartitionNumberToBytes(constrained_partition(partition))`
(`src/Util.dfy:97`, `src/Beacon.dfy:constrained_partition`):

- **Base searchable-encryption case** (`numberOfPartitions == 0` or `partition == 0`):
  `constrained_partition` returns the partition unchanged; `PartitionNumberToBytes(0) = []`
  → **nothing is appended**, so `basicHash` hashes `value` alone.
- **beacon-partitions case** (`numberOfPartitions > 0`, `partition > 0`): partition is
  `partition mod numberOfPartitions`; a partition `N ∈ 1..255` appends the **single byte
  `[N]`** to `value`. (`MAX_PARTITION_COUNT = 255`.) This is the separate
  `beacon-partitions` feature — not part of this slice's scope beyond documenting it.

## 5. Value serialization and location

- The source bytes come from `VirtToBytes(loc, item, vf)` (`src/Virtual.dfy:376`). For a
  **plain, non-virtual** beacon (the base case) this reduces to `TermLoc.TermToBytes`,
  i.e. locate the named attribute in the item and serialize its value with
  `DynamoToStruct.TopLevelAttributeToBytes` (already native this session). Virtual fields
  are a separate slice.
- **Set beacon** (`asSet`): each element is serialized via `TopLevelAttributeToBytes`
  (`S`/`N`/`B` element), hashed with `basicHash`, and collected into an `SS` with
  **duplicates dropped** (`HasNoDuplicates`). A non-Set source value for an `asSet` beacon
  is an error.
- Number values are normalized by `DynamoToStruct` before hashing, so `N("1.23")` and
  `N("000001.23000000")` produce the **same** beacon (confirmed by `TestNumbersNormalize`).

## 6. Beacon HMAC key derivation (dependency, not this primitive)

The per-beacon HMAC key passed to `basicHash` is derived in the beacon-key-materials layer
(`src/SearchInfo.dfy:~124`): **HKDF-SHA512**, `salt = None`, `ikm =` the beacon key,
`info = UTF8("AWS_DBE_SCAN_BEACON" + name)`, `expectedLength = 64`. `keyName()` selects
which beacon's key to use: `share.value` for a shared beacon, else `name`. This layer is
the immediate next dependency for an end-to-end searchable-encryption feature, analogous
to how the DynamoToStruct item layer was the dependency for the item encryptor.

## 7. Explicit non-goals (separate slices)

- Compound beacons (`src/CompoundBeacon.dfy`), constructors, prefixes, split-char checks.
- Virtual fields (`src/Virtual.dfy`) and multi-segment / nested term locations beyond a
  plain top-level attribute.
- Shared / sharedSet beacons beyond recording `keyName()` selection.
- beacon-partitions (`numberOfPartitions > 0`) beyond the encoding documented in §4.
- The beacon-key-materials/HKDF derivation itself (§6) and beacon-version/config assembly
  (`SearchInfo.dfy`, `ConfigToInfo.dfy`).
- Query/filter/scan rewriting (`FilterExpr.dfy`, `UpdateExpr.dfy`) and `GetBeaconValue`'s
  query-side `forContains` set handling.

## 8. Golden vectors (from `test/Beacon.dfy` — must-pass)

Direct-key primitive vectors (`key = [1,2]`, `length = 8`), which pin HMAC-SHA384-first-8
+ `BytesToHex` + partition encoding + lowercase without needing the HKDF layer:

| Input value | partition | `getHmac(value++part)` (8 bytes) | `basicHash` |
|---|---|---|---|
| `[1,2,3]` | 0 | `27 93 93 8b 26 e9 52 7e` | `"7e"` |
| `[1,2,3]` | 1 | `2a 64 f2 14 bc 00 21 1d` (of `[1,2,3,1]`) | `"1d"` |
| `[1,2,3]` | 2 | `35 97 90 22 31 13 a9 ef` (of `[1,2,3,2]`) | `"ef"` |
| `[]` (empty) | 0 | `…80` (byte 7 = `0x80`) | `"80"` |
| `x123`=`[0x31,0x32,0x33]` | 0 | `…61` (byte 7 = `0x61`) | — |

End-to-end vectors (base key `[1,2,3,4,5]` → per-beacon HKDF key §6, value serialized §5),
which additionally pin the **non-byte-aligned truncation** at lengths 24/26/28/32:

| beacon | value | length (bits) | expected hex |
|---|---|---|---|
| std2 | `N("1.23")` | 24 | `"ac6f5d"` |
| Name | `S("MyName")` | 32 | `"7d9bfa40"` |
| Title | `S("MyTitle")` | 32 | `"e4feb833"` |
| std4 | `S("abc")` | 24 | `"0e9064"` |
| **std6** | `S("666")` | **26** | `"2d99222"` (7 chars; top char `'2'`=2, fits in 2 bits = `26 mod 4`) |
| Name | `S("")` (empty) | 32 | `"e0e88994"` |
| Title | `S("")` (empty) | 32 | `"af34f26f"` |

## 9. Disagreements with spec prose

None found. The `specification/searchable-encryption/beacons.md` requirements are inlined
throughout `src/Beacon.dfy` as `//= type=implication` annotations and match the
implementation's `ensures` clauses (basicHash = HMAC-SHA384 first 8 bytes → rightmost
`length` bits as `ceil(length/4)` hex chars; partition-0 appends nothing).

## 10. Source pointers

- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/Beacon.dfy` (module `BaseBeacon`;
  `getHmac`, `hash`/`basicHash`, `BytesToHex`, `TruncateNibble`, `constrained_partition`,
  `getHash`/`getHashSet`/`getHashNonSet`, `Beaconize*Set`, `MakeStandardBeacon`).
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/Util.dfy:15` (`BeaconPrefix`),
  `:86-106` (`PartitionBytes`, `PartitionNumberToBytes`).
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/Virtual.dfy:376` (`VirtToBytes`),
  `src/TermLoc.dfy` (`TermToBytes`/`TermToAttr`).
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/SearchInfo.dfy:~124` (beacon HMAC key
  HKDF-SHA512 derivation).
- MPL `StandardLibrary/src/HexStrings.dfy:12` (`HexChar`, lowercase).
- Model: `DynamoDbEncryption/dafny/DynamoDbEncryption/Model/DynamoDbEncryption.smithy`
  (`StandardBeacon` ~L707, `BeaconBitLength` L324, `BeaconStyle` ~L621).
- Tests: `test/Beacon.dfy` (`TestBeacon`, `TestOneBeaconValue`, `TestNumbersNormalize`),
  `test/BeaconTestFixtures.dfy:96-103` (golden strings).

## 11. Native implementation status

Landed in module `dbesdk/dynamodb-encryption`, package
`software.amazon.cryptography.dbesdk.dynamodbencryption`:

- `StandardBeacon` — the `basicHash`/`BytesToHex`/partition-encoding primitive (§2–§4)
  plus the item-level value production (§5–§6, see `BeaconValueLocation.md`).
  `StandardBeacon.create(name, lengthBits, loc, asSet, numberOfPartitions)` validates
  length ∈ 1..63 and partition count ∈ 0..255 and parses `loc`; `hash(value, key,
  partition)` applies `constrainedPartition` then `basicHash` (HMAC-SHA384 first 8 bytes →
  `bytesToHex`). `getHmac`, `basicHash`, `bytesToHex`, `partitionNumberToBytes`,
  `constrainedPartition` are package-private for direct testing.
- `BeaconException` — module error type for invalid length/partition/HMAC failure.

Verified (10 tests, `StandardBeaconTest`): `getHmac` against the Dafny byte vectors
(`[1,2,3]`/`[1,2,3,1]`/`[1,2,3,2]` under key `[1,2]`); `basicHash` `"7e"/"1d"/"ef"/"80"`;
`bytesToHex` byte-aligned (8/16/24/32) and the **non-byte-aligned truncation** (26 → `"2e9527e"`,
28 → `"6e9527e"`, derived from the real MAC bytes — the 28-bit case distinguishes a
high-vs-low leading-nibble bug); the partition-mod branch (`7 % 5 → "ef"`, `5 % 5 → "7e"`)
and the unconstrained path (`numberOfPartitions == 0`); and the three range-rejection paths.

Deliberately **not** in this slice (recorded §5–§7, in dependency order for an end-to-end
`searchable-encryption` feature): the beacon-key-materials/HKDF-SHA512 layer (§6) that
derives the per-beacon key passed to `hash`; value location (`TermLoc`/`Virtual`,
`VirtToBytes`) and the `AttributeValue`→bytes composition via `DynamoToStruct`; set
beaconization (`asSet` → `"SS"` dedup) and the `"S"`/`"SS"` attribute wrapping; compound
beacons; beacon-version/config assembly; and query/filter rewriting. The end-to-end §8
vectors (std2/std4/std6/Name/Title) require the HKDF layer and so are not yet exercised;
the direct-key primitive vectors above pin the same `basicHash`/`bytesToHex` code paths
without it.
