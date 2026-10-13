# Behavior Spec: B2 — Query/Scan beaconization (read path)

The searchable-encryption read path: rewrite a Query/Scan's key/filter expression
so DynamoDB matches on beacon attributes, then re-filter the decrypted results.
A faithful-port target of Dafny `DynamoDBFilterExpr` + `DDBSupport` Query/Scan
ForBeacons. Source of truth:
- `DynamoDbEncryption/src/FilterExpr.dfy` (Beaconize/DoBeaconize/BeaconizeParsedExpr/BeaconForValue/FilterResults)
- `DynamoDbEncryption/src/DDBSupport.dfy` (QueryInputForBeacons/QueryOutputForBeacons/ScanInput/Output/GetBeaconKeyId)

Reuses the already-ported `ConditionExpressionParser` tokenizer (Layer A): the
same `Token`/`ParseExpr`/`FindIndexToken`. B2 adds the *rewrite* over those tokens.

## 1. Where it plugs in (transforms seams, Layer A)
- `QueryInput`/`ScanInput`: after rejecting legacy params, call `QueryInputForBeacons`.
- `QueryOutput`/`ScanOutput`: after per-item decrypt + the multi-tenant keyId filter,
  call `QueryOutputForBeacons`. No search config ⇒ input unchanged, output just
  strips `aws_dbe_*` (already the Layer A no-op + removeBeacons).

## 2. Input rewrite — `QueryInputForBeacons` → `Beaconize` → `BeaconizeParsedExpr` (grounded)
Rewrites both `KeyConditionExpression` and `FilterExpression` (each independently),
plus `ExpressionAttributeNames`/`ExpressionAttributeValues`. Per parsed token:
- **Attr token**: resolve `#name` via names map (fail if `#name` absent). If
  `b.IsBeacon(name)`:
  - **Not beaconized** when the attr is the operand of `attribute_exists` /
    `attribute_not_exists` (`OpNeedsBeacon` false) — keep the original attr.
  - **Hard error** when used with `size()` or `attribute_type()` (`IsAllowedOnBeacon`
    → "Function X cannot be used on encrypted fields").
  - Otherwise rewrite to `aws_dbe_b_<name>` (`beacons[name].getBeaconName()`):
    a direct attr becomes a new `Attr(aws_dbe_b_name)` token; an indirect `#name`
    keeps the token but remaps `names[#name] := aws_dbe_b_name`.
  - Non-beacon attrs pass through unchanged.
- **Value token**: look up the value in `ExpressionAttributeValues` (fail if absent).
  `BeaconForValue` decides which beacon (if any) this value is compared against by
  the surrounding tokens — the recognized shapes are exactly:
  `value <cmp> ATTR`, `ATTR <cmp> value`, `contains/begins_with(ATTR, value)`,
  `contains/begins_with(value, ATTR)`, `ATTR BETWEEN value AND *`,
  `ATTR BETWEEN * AND value`, and `ATTR IN value, value, …` — where `<cmp>` is
  `= <> < > <= >=`. If a beacon applies, replace the value with
  `beacon.GetBeaconValue(oldValue, keys, forEquality, forContains, partition)`;
  else keep it. The new value is stored under the **same** value name.
  **Hard error** if one value name resolves to two different beacon values across
  the expression (`:foo` used as both `this = :foo` and `that = :foo`): "used in
  two different contexts".
- All other tokens pass through. Reassembled via `ParsedExprToString` (tokens
  joined with single spaces).
- The HMAC keys come from `b.getKeyMap(keyId)` (the key-store retrieval — B4);
  `naked`/`DontUseKeys` mode skips key lookup (used by the output filter, §4).

## 3. Beacon key id for multi-tenant — `GetBeaconKeyId` (grounded)
`search.None?` ⇒ `DontUseKeyId`. Else `Filter.GetBeaconKeyId` extracts the beacon
key id from a **compound-beacon signed part** named by the key field in the
key/filter expression (`KeyIdFromPart`: split the compound value on its separator,
find the single part whose prefix matches, return the suffix). Feeds the
transforms multi-tenant per-item keyId filter (Layer A) + the key map used in §2.

## 4. Output filter — `QueryOutputForBeacons`/`ScanOutputForBeacons` → `FilterResults` (BUILT — evaluator fully grounded)
A beacon query returns a **superset**: beacons are truncated HMACs, so distinct
plaintext values can share a beacon value (false positives). The output transform
re-filters the decrypted items against the original key+filter expressions, then
strips `aws_dbe_*` (`DoRemoveBeacons`) from survivors; `search.None?` ⇒ just strip.

`FilterResults` (FilterExpr.dfy 1552): for key then filter expression —
`ParseExpr` → `BeaconizeParsedExpr(..., DontUseKeys, ...)` → `ConvertToPrefix` →
`ConvertToRpn` → `FilterItems(rpn, items, ...)` keeping matches.

**Resolved mechanism** (read `FilterItems` + `GeneratePlainBeacons` + `EvalExpr`):
`FilterItems` evaluates, per item: `newAttrs = b.GeneratePlainBeacons(item, partition)`
(= `GenerateBeacons2(allNames, item, DontUseKeys, AnyBeacon, partition)` — recompute
every beacon from the DECRYPTED plaintext item with **no secret key**), then
`EvalExpr(rewrittenExpr, item + newAttrs, names, values)` and keep the item iff
true. The rewrite (BeaconizeParsedExpr under `DontUseKeys`) maps a beacon attr to
`aws_dbe_b_<name>` AND maps each compared value through the SAME keyless
`GetBeaconValue`. So both sides of a comparison are the identical keyless "plain"
beacon transform: the RPN evaluator reads `aws_dbe_b_A` from `newAttrs`
(= plainBeacon(item's plaintext A)) and compares it to plainBeacon(query value) —
reproducing beacon equality/membership exactly on decrypted data, which removes
the DB superset's false positives. `EvalExpr` is a standard stack RPN evaluator
(`InnerEvalExpr`): Value→from values map, Attr→`StackValueFromAttr` (via TermLoc,
honoring `#name`), unary/binary/function ops pop+push, final single Bool is the
match. `ConvertToPrefix`/`ConvertToRpn` are the shunting-yard conversion using the
`Precedence` table.

**Smaller detail resolved at implementation:** `DontUseKeys` does NOT hash — per
Util.dfy it means "leave values plaintext" (`// DontUseKeys means to not hash the
values into beacons, but to leave them plaintext, which is necessary for the
post-query filtering"). So `GetBeaconValue(DontUseKeys)` returns the query value
unchanged, and `GeneratePlainBeacons` = `GenerateBeacons2(.., DontUseKeys, AnyBeacon)`
produces the NAKED (plaintext) beacon values (standard = located value, compound =
`prefix + plaintext` per part, encrypted parts included but NOT hashed). Both sides of
every comparison are therefore the same plaintext, so the re-filter reproduces the
original plaintext predicate on the decrypted item.

**DAFNY QUIRK — grouping parentheses do NOT override operator precedence (ported
exactly, not a bug to fix).** `ConvertToRpn_inner` (FilterExpr.dfy 967–1013,
byte-verified) never pushes an open paren (`case Open => rec(stack, pos+1)`) and a close
paren pops exactly ONE operator before advancing (`case Close => … [stack.top] +
rec(stack.pop, pos+1)`); the operator-precedence case re-processes the same token with
`pos` unchanged. Net effect: a grouping paren is dropped and the RPN falls back to pure
operator precedence (`And`=4 binds tighter than `Or`=3), so `(a = :x OR b = :y) AND
c = :z` evaluates as `a = :x OR (b = :y AND c = :z)`. Function-call parens still work
(the function is on the stack; `Comma` is dropped while the top is a function; `Close`
pops the function). Key-condition expressions disallow `OR`, so only parenthesized mixed
`AND`/`OR` **filter** expressions are affected. The native port replicates this exactly
for cross-language parity (every language server shares the same Dafny-derived semantics);
`ExpressionEvaluatorTest.groupingParensDoNotOverridePrecedence` pins it. Per constraint 1
(Dafny is ground truth), this disagreement with ordinary infix grouping is recorded, not
silently "corrected".

## 5. beacon-partitions fan-out — `DoBeaconize` (separate feature)
When `numPartitions > 1` and fewer queries than partitions, `DoBeaconize` runs
`Beaconize` once per partition and OR-combines the filter expressions, renaming
colliding value keys (`AddContext`/`MakeNewName`: append `AA`..`ZZ`). This is the
`beacon-partitions` feature (declared separately); the base searchable-encryption
case has `numPartitions == queries` (or 1) ⇒ a single `Beaconize`.

## 6. Non-obvious / load-bearing
- `attribute_exists`/`attribute_not_exists` do NOT beaconize their operand.
- `size()`/`attribute_type()` over a beacon is a hard error.
- A value name reused in two beacon contexts is a hard error.
- The query is lossy (superset) by design; the output re-filter on decrypted
  items is what makes the result exact — so B2 input and output must ship together
  to be correct (an input-only beaconization would return false positives).
- Indirect `#name` beacons are remapped in the names map, not the token.

## 7. Explicit non-goals (this slice)
`beacon-partitions` fan-out (§5), compound/virtual beacons feeding the rewrite
(B3), and the live key-store `getKeyMap` (B4). Standard-beacon equality/range/
contains/begins_with/in over single beacons is the B2 core.

## 8. Source pointers
FilterExpr.dfy: BeaconForValue 394–440, OpNeedsBeacon/IsAllowedOnBeacon 470–520,
BeaconizeParsedExpr 536–610, Beaconize 1938–2010, DoBeaconize 1873–1936,
FilterResults 1552–1610, ParseExpr/FindIndexToken (shared with Layer A).
DDBSupport.dfy: QueryInputForBeacons/QueryOutputForBeacons 369–420,
ScanInput/Output 443+, GetBeaconKeyId 424–441.
