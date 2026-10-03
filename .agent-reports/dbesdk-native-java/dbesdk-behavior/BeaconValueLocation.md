# BeaconValueLocation (TermLoc + set beaconization) — Behavior Spec

Scope: the two layers that sit **between** a DynamoDB item and the `StandardBeacon`
primitive (`Beacon.md`) — (a) locating and serializing a beacon's source value from an
item via a `TermLoc` (`src/TermLoc.dfy`), and (b) the set-beaconization dispatch that
turns a Set-valued attribute into an `SS` of per-element beacon values
(`src/Beacon.dfy` `getHash`/`getHashSet`/`getHashNonSet`/`ValueToSet`/`Beaconize*Set`).

Together with the already-native `DynamoToStruct` (value→bytes), `BeaconKeyDerivation`
(HKDF-SHA512 key), and `StandardBeacon` (basicHash), this layer completes the write-time
"beacon value for an item" computation for a **plain, non-virtual** beacon. Virtual fields
(`src/Virtual.dfy` `GetVirtField`) and compound beacons remain separate slices (§7).

## 1. Public surface

- `TermLoc` = a non-empty list of `Selector`, where `Selector = Map(key:string) |
  List(pos:uint64)` and the **first selector must be a `Map`** (`ValidTermLoc`,
  `TermLoc.dfy:45-51`). It is the parsed form of a terminal-location string.
- `MakeTermLoc(s) -> TermLoc` (`TermLoc.dfy:265`): parse a location string.
- `TermToAttr(t, item, names) -> Option<AttributeValue>` (`:75`): the located attribute,
  or `None` if absent.
- `TermToBytes(t, item) -> Option<Bytes>` (`:101`): the located attribute serialized via
  `DynamoToStruct.TopLevelAttributeToBytes`, or `None` if absent.
- `StandardBeacon.getHash(item, vf, key, partition) -> Option<AttributeValue>`
  (`Beacon.dfy:234`): the beacon value for an item — dispatches to `getHashSet` (asSet) or
  `getHashNonSet`.

## 2. Location string grammar (`MakeTermLoc` / `GetSelector` / `GetSelectors`)

A location is a field name optionally followed by segments:
- The **first segment** is a bare field name up to the first `.` or `[` (so a top-level
  attribute `"foo"` parses to `[Map("foo")]`; `TermLocMap(attr)` is the shortcut).
- `.name` → `Map("name")` — a lookup into a Structured Data **Map**.
- `[n]` → `List(n)` — an index into a Structured Data **List**; `n` is an unsigned decimal
  parsed by `GetNumber`, which **fails if it exceeds ~2^60** (`0xfff_ffff_ffff_ffff`) or
  contains a non-digit, and a `[` segment must end with `]` (`GetSelector`).
- `FindStartOfNext` splits on the first `.` or `[`. An empty location string fails
  (`"Path specification must not be empty."`).

## 3. Navigation (`GetTerminal` / `TermToAttr`)

`TermToAttr` starts at `item[firstKey]` (or `None` if that key is absent) and walks the
remaining selectors with `GetTerminal` (`TermLoc.dfy:113`):
- At a `List` value, a `List(pos)` selector indexes it; **out-of-range → failure**
  ("Tried to access beyond the end of the list"); a `Map` selector on a list → failure
  ("Tried to access list with key").
- At a `Map` value, a `Map(key)` selector looks it up; **missing key → failure** ("Tried
  to access `<key>` which is not in the map") unless an expression-attribute-name alias in
  `names` resolves it; a `List` selector on a map → failure ("Tried to access map with
  index").
- Any **scalar/set** value with selectors still left → failure ("Found `<type>` with parts
  left over.").
- When selectors are exhausted, the current value is the result.

**Key non-obvious point:** `TermToAttr` turns an internal `GetTerminal` *failure* (bad
path shape, out-of-range index, missing nested key) into `None` (absent), **not** an
error — the only inputs that reach the caller as "absent" are both "top-level key missing"
and "nested navigation failed." `TermToBytes` serializes the located attribute via
`TopLevelAttributeToBytes` (so numbers are normalized, §`DynamoToStruct.md`).

## 4. `VirtToBytes` reduces to `TermToBytes` for a plain beacon

`VirtToBytes(loc, item, vf)` (`Virtual.dfy:376`) returns `TermToBytes(loc, item)` **unless**
`loc` is a single segment whose key is in the virtual-field map `vf` — in which case it
builds the value from the virtual field (the non-goal §7). For a plain beacon with an
empty `vf`, `getHashNonSet`'s `VirtToBytes` is exactly `TermToBytes`.

## 5. Non-set value (`getHashNonSet`)

`getHashNonSet(item, vf, key, partition)`:
- `bytes = VirtToBytes(loc, item, vf)`; if `None` (field absent) → return `None` (no beacon
  written).
- else → `Some(S(hash(bytes, key, partition)))`, i.e. the `StandardBeacon` primitive's
  lowercase-hex value wrapped as a DynamoDB **String** attribute.

## 6. Set value (`getHashSet` / `ValueToSet` / `Beaconize*Set`)

For an `asSet` beacon (`getHashSet`, `Beacon.dfy:249`):
- `value = TermToAttr(loc, item, None)`; if `None` → return `None`.
- else `ValueToSet(value, key, partition)` → `Some(SS(...))`.
- `ValueToSet` (`:215`) dispatches by the located value's type and **fails if it is not
  `SS`/`NS`/`BS`** ("Beacon `<name>` has style AsSet, but attribute has type `<type>`.") —
  i.e. configuring a beacon `asSet` and writing a non-Set value is an error.
- `BeaconizeStringSet`/`NumberSet`/`BinarySet` (`:325-376`): for each element **in input
  order**, serialize the single element as `S`/`N`/`B` via `TopLevelAttributeToBytes`,
  compute `hash(bytes, key, partition)`, and append the hex **only if not already present**
  — dedup is on the **beacon value**, keeping first-encounter order. The result is always
  wrapped as an `SS` (even for a number or binary source set).

## 7. Explicit non-goals (separate slices)

- Virtual fields (`Virtual.dfy` `GetVirtField`, concat/segment transforms) — `VirtToBytes`'s
  virtual branch. This slice implements only `VirtToBytes == TermToBytes` (empty `vf`).
- Compound beacons (`CompoundBeacon.dfy`), `partOnly`, shared-beacon `keyName()`.
- Expression-attribute-name alias resolution (`names` arg) is a query-rewrite concern;
  write-time `getHash*` passes `None`, so document it but it is exercised only on the
  query path (`FilterExpr.dfy`, out of scope here).
- `GetBeaconValue`'s `forContains` query-side set handling, and `getNaked`/`TermToString`.
- `GenerateEncryptedBeacons` orchestration (which beacons run, assembling the item) — the
  searchable-encryption seam, where the beacon key also comes from the key store.

## 8. Golden / concrete vectors

The module has **no dedicated `test/TermLoc.dfy`** with isolated path vectors; TermLoc and
set beaconization are exercised through the integration path (`GenerateEncryptedBeacons`,
`test/Beacon.dfy` `TestNumbersNormalize`/`TestCompoundQueries`) rather than unit vectors.
Implementation tests should therefore be built by composition: construct an item, locate +
serialize + beacon it with the already-native primitive, and assert against the §`Beacon.md`
§8 end-to-end values for the top-level case, plus hand-constructed nested-path and
set-dedup cases grounded in §3/§6 behavior (e.g. a 2-element string set whose elements
beacon to distinct values → 2 entries; a set with a colliding pair → 1 entry).

## 9. Disagreements with spec prose

None found. The `specification/searchable-encryption/virtual.md` (terminal location,
segments) and `beacons.md` (value-for-a-(set-)standard-beacon, asSet-initialization)
requirements are inlined as `//= type=implication` in `TermLoc.dfy`/`Beacon.dfy` and match
the bodies.

## 10. Source pointers

- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/TermLoc.dfy` (whole file, 285 lines):
  `Selector`/`TermLoc`/`ValidTermLoc` (:35-51), `TermToAttr` (:75), `TermToBytes` (:101),
  `GetTerminal` (:113), `FindStartOfNext` (:180), `GetNumber` (:206), `GetSelector` (:224),
  `GetSelectors` (:250), `MakeTermLoc` (:265), `TermLocMap` (:281).
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/Beacon.dfy:215-310` (`ValueToSet`,
  `getHash`, `getHashSet`, `getHashNonSet`), `:325-376` (`Beaconize*Set`).
- `DynamoDbEncryption/dafny/DynamoDbEncryption/src/Virtual.dfy:376` (`VirtToBytes`).
- `specification/searchable-encryption/virtual.md`, `beacons.md`
  (#value-for-a-standard-beacon, #value-for-a-set-standard-beacon, #asset-initialization).

## 11. Native implementation status

Landed in module `dbesdk`, package
`software.amazon.cryptography.dbesdk.dynamodbencryption`:

- `TermLoc` — `make(loc)` parse (§2), `termToAttr(item)` navigation (§3, every miss →
  empty), `termToBytes(item)` (serialize via `DynamoToStruct`). `Selector`/`MapKey`/
  `ListIndex` are package-private records; list-index parsing compares unsigned to mirror
  Dafny's uint64 bound (a signed `long` would wrap before the bound check).
- `StandardBeacon` extended with `loc`/`asSet`/`name` and the item-level
  `getHash(item, key, partition)` dispatch (§5–§6): `getHashNonSet` (plain, `VirtToBytes`
  == `termToBytes` for empty `vf`), `getHashSet`/`valueToSet`/`beaconizeSet` (SS/NS/BS →
  deduped `SS`, non-Set → `BeaconException`). The primitive-only `of(...)` factory was
  replaced by the complete `create(name, lengthBits, loc, asSet, numberOfPartitions)` so a
  beacon is never half-initialized.

Not ported (recorded non-goals §7, future slices): virtual fields (`VirtToBytes` virtual
branch), compound beacons, `partOnly`/shared beacons, query-side alias resolution and
`forContains`, and `GenerateEncryptedBeacons` orchestration (the searchable-encryption
seam, where the beacon key also comes from the key store).

Tests (module total 54, 0 failures): `TermLocTest` (16 — parse incl. too-large index,
navigation incl. every absent/wrong-shape case, `termToBytes`); `StandardBeaconTest` (+7
item-level — top-level golden anchor `std4`→`0e9064`, nested-path locate, set content+order
and length-1 dedup, non-Set `asSet` rejection, absent fields). No isolated Dafny vectors
exist for this layer (§8), so item-level tests compose the already-verified primitive and
anchor the top-level case to the `Beacon.md` §8 golden.
