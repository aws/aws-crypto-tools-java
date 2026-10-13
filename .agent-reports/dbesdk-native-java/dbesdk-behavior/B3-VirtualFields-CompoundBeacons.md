# Behavior Spec: B3 — Virtual fields + Compound beacons

Source of truth: `DynamoDbEncryption/src/Virtual.dfy` + `CompoundBeacon.dfy`.

## Part 1 — Virtual fields (BUILT + offline-tested)
A virtual field is a value computed by concatenating, in configured order, the
transformed string value at each part's location.
- **Part** = a `TermLoc` location + an ordered list of transforms.
- **Evaluation** (`GetVirtField`): for each part, read its location as a plain
  string; apply the part's transforms in order; concatenate. The whole field is
  **absent** if any part's location is missing or is not a plain string (`S`).
- **Transforms** (`DoTransform`), ported faithfully (`VirtualTransform`):
  - `Upper`/`Lower` — ASCII-only case fold.
  - `Insert(literal)` — append literal.
  - `Prefix(n)`/`Suffix(n)` — first/last `n` chars; negative `n` drops the last/
    first `-n` (clamped to "" / whole string).
  - `Substring(low, high)` / `Segment(split, index)` / `Segments(split, low, high)`
    — positional indexing via `GetPos` (non-negative clamps to `limit-1`; negative
    is one-based from the end, clamped to 0) and a split that keeps empty segments
    (N delimiters → N+1 pieces).
- Native: `VirtualField` + `VirtualTransform` (sealed interface, 8 records) in the
  `dynamodbencryption` package; 7 tests (transform edge cases + concat + absent +
  non-string). Reuses the native `TermLoc`.

## Part 2 — Compound beacons (DISCOVERED; build is a separate slice)
A compound beacon assembles a value from ordered **parts**, each contributing
`prefix + partValue`, joined on a `split` character, chosen by the first matching
**constructor**.

### Structure
- `BeaconPart` = `Encrypted(prefix, StandardBeacon)` | `Signed(prefix, name, loc)`.
  Each has a non-empty `prefix` and a located string value (`getString` via
  `VirtToString`, so parts may reference virtual fields).
- `ConstructorPart` = {part, required}; `Constructor` = non-empty part list;
  a compound beacon has an ordered `ConstructorList`, `split` char, `parts`
  (signed parts first, then encrypted — `OrderedParts`), and `numSigned`.
- **Init failure** (`ValidPrefixSet`): no part's prefix may be a prefix of
  another's (so a value's prefix maps to exactly one part).

### Write value (`hash` → `TryConstructors` → `TryConstructor`)
- Try each constructor in order; use the first that succeeds.
- A constructor succeeds iff, for every part: locate its string value; if present,
  append `partValue` joined on `split`; if absent + required → constructor fails;
  if absent + optional → skip. A located value MUST NOT contain the split char.
- `partValue`: keyless/naked (`DontUseKeys`) → `prefix + plaintext`; else
  `PartValueCalc` — an Encrypted part contributes `prefix + beaconHash(value)`
  (the StandardBeacon hash), a Signed part contributes `prefix + plaintext`.
- No constructor succeeds → no beacon written (absent).
- `getNaked` = `TryConstructors` with `DontUseKeys` (plaintext part values) — the
  form used for client-side output filtering (ties into B2 §4).

### Read / query (`getPart`/`findPart`/`calcPart`/`calcParts`)
- Split a compound query value on `split`; for each piece `findPart` (its prefix
  matches exactly one part), `calcPart` = `PartValueCalc`, rejoin on `split`.
- `GetBeaconValue` produces the query beacon form (equality/contains); `KeyIdFromPart`
  extracts a multi-tenant beacon key id from a Signed part (feeds B2 §3).
- `GetFields` returns the underlying field names (for key derivation + config checks).

### Build scope (NOT yet built — deliberately deferred)
Compound beacons are ~657 lines of parity-critical assembly + prefix-matching +
constructor selection + part-value calculation + query parsing. This is its own
focused build slice (reusing the native `StandardBeacon` for Encrypted parts,
`VirtualField`/`TermLoc` for part locations, `BeaconKeyDerivation` for keys). It
was not rushed at the tail of the virtual-field turn; port it with dedicated
budget, anchored to compound-beacon test vectors.

### Non-goals (this slice)
`getNumQueries` partition-count/`lcm` fan-out (beacon-partitions feature).

## Source pointers
Virtual.dfy (full). CompoundBeacon.dfy: datatypes 27–118, MakeCompoundBeacon/
OrderedParts 89–118, ValidPrefixSet/OkPrefix 150–260, TryConstructor/TryConstructors
366–430, hash/getNaked 431–452, findPart/getPart/calcPart/calcParts 453–540,
GetBeaconValue 324–342, KeyIdFromPart (DDBSupport read earlier).
