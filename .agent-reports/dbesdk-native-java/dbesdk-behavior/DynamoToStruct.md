# DynamoToStruct — Behavior Spec

DynamoDB attribute serialization: convert a DynamoDB `AttributeValue` to/from a
StructuredEncryption terminal (`value` bytes + a 2-byte `typeId`). This is the
byte-level bridge the DynamoDbItemEncryptor uses to turn a DynamoDB item into
structured terminals that StructuredEncryption can encrypt/sign, and back.

Source: `~/github/dbesdk/aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/DynamoDbEncryption/src/`
- `DynamoToStruct.dfy` (1556) — serialize/deserialize
- `NormalizeNumber.dfy` — DynamoDB number normalization
- `Util.dfy` — `MAX_STRUCTURE_DEPTH := 32`
Type-id constants: `StructuredEncryption/src/Util.dfy` (imported as `SE`).
Tests: `DynamoDbEncryption/test/DynamoToStruct.dfy`. Spec prose:
`specification/dynamodb-encryption-client/ddb-attribute-serialization.md` (inlined as `//=` in source).

## 1. Public surface
- `AttrToStructured(AttributeValue) -> StructuredDataTerminal{value: bytes, typeId: 2 bytes}`.
  `value` is the top-level (un-prefixed) encoding; `typeId` is `AttrToTypeId(a)`.
- `StructuredToAttr(StructuredDataTerminal) -> AttributeValue` — the inverse. Requires `|typeId|==2`;
  fails "Mismatch between length of encoded data and length of data" if the parsed length does not
  consume exactly `|value|` (no trailing bytes allowed at top level).
- Internally: `AttrToBytes(a, prefix, depth)` and `BytesToAttr(value, typeId, totalBytes, depth, pos)`.
  `TopLevelAttributeToBytes(a) = AttrToBytes(a, prefix=false)`.

### 1a. Item layer (map ↔ terminal-map, used directly by DynamoDbItemEncryptor)
Same Dafny module; operates on whole items. `ReservedPrefix = "aws_dbe_"`.
- `ItemToStructured2(item, actions) -> TerminalDataMap`: each attribute → `AttrToStructured`, EXCLUDING
  any attribute whose action is `DO_NOTHING` and which is not reserved-prefix (they neither sign nor
  encrypt). Attributes absent from `actions`, non-DO_NOTHING attributes, and reserved-prefix attributes
  are all kept. (`ItemToStructured` is the plain variant that keeps everything.)
- `StructuredToItemEncrypt(s, orig, actions) -> AttributeMap`: for each non-reserved key in `orig`,
  emit `StructuredToAttr(s[k])` when it is `ENCRYPT_AND_SIGN` and present in `s`, else the original
  value; THEN add every key in `s` not in `orig` (the header/footer the SE client added) via
  `StructuredToAttr`. Reserved-prefix keys in `orig` are skipped.
- `StructuredToItemDecrypt(s, orig, actions) -> AttributeMap`: identical to the first loop above (per
  non-reserved `orig` key: decrypted `ENCRYPT_AND_SIGN` value, else passthrough), with NO second loop —
  so keys in `s` not in `orig` are ignored and reserved header/footer are dropped from the output.
- Ground truth for these three is the Dafny `by method` block (the compiled path), not the functional
  body it is bridged to by `assume {:axiom}`; the by-method skips reserved-prefix keys explicitly.
- Native status: implemented (`DynamoToStruct.itemToStructured`, `structuredToItemEncrypt`,
  `structuredToItemDecrypt`; the shared per-original-attribute loop is one private helper).

## 2. Type IDs (2 bytes; confirmed by test golden vectors)
| Type | typeId | | Type | typeId |
|---|---|---|---|---|
| String (S) | `00 01` | | String Set (SS) | `01 01` |
| Number (N) | `00 02` | | Number Set (NS) | `01 02` |
| Binary (B) | `FF FF` | | Binary Set (BS) | `01 FF` |
| Boolean (BOOL) | `00 04` | | Map (M) | `02 00` |
| Null (NULL) | `00 00` | | List (L) | `03 00` |

First byte: `00` scalar, `01` set, `02` map, `03` list, `FF` binary. Second byte: element/scalar
kind (`01` string, `02` number, `04` boolean, `00` null, `FF` binary).

## 3. Serialization format (`AttrToBytes`)
Two modes. **Top level** (`prefix=false`, used by `AttrToStructured`): output is just the base
bytes; the typeId travels separately on the terminal. **Prefixed** (`prefix=true`, used for every
nested element inside a set/list/map): output is `typeId(2) ++ bigEndianU32 length(4) ++ base`
(`PREFIX_LEN=6`). All counts/lengths are big-endian unsigned 32-bit (`U32ToBigEndian`; e.g.
`3 -> 00 00 00 03`); a length/count > 0xFFFFFFFF fails.

Base bytes per type:
- **BOOL**: 1 byte — `01` true, `00` false.
- **Binary (B)**: the bytes unchanged (identity).
- **NULL**: zero-length.
- **String (S)**: UTF-8 bytes of the string.
- **Number (N)**: `NormalizeNumber(n)` (§4) then UTF-8 bytes.
- **Set (SS/NS/BS)**: `count(4) ++ entries`. A set MUST NOT contain duplicates (fails
  "... had duplicate values"; NS also checked for duplicates *after* normalization). `count` MAY be 0
  (then no entries). Entry encoding:
  - SS/NS entry (`EncodeString`): `entryLen(4) ++ utf8Bytes`. NS entries are normalized first.
  - BS entry (`SerializeBinaryValue`): `entryLen(4) ++ rawBytes`.
  - **Ordering:** SS and NS entries are sorted ascending **UTF-16 binary order** (Dafny `CharLess`
    over UTF-16 code units) — for NS, *after* normalization. BS entries are sorted ascending by their
    **raw bytes** (`ByteLess`).
- **List (L)**: `count(4) ++ entries`, entries in **original list order** (not sorted). Each entry is
  a *prefixed* value: `typeId(2) ++ len(4) ++ value`. May mix types.
- **Map (M)**: `count(4) ++ entries`, entries ordered by **key** ascending UTF-16 binary order.
  Each entry (`SerializeMapItem`): `KeyType(2)=00 01 ++ KeyLen(4) ++ keyUtf8 ++ ValueType(2) ++
  ValueLen(4) ++ valueBytes`. The key is always a String type id; key length must be 1..65535 UTF-8
  bytes (`MAX_ATTR_NAME_LEN64`, byte length not char count). Values may mix types.
- **Depth**: nesting beyond `MAX_STRUCTURE_DEPTH = 32` fails on both encode and decode.

## 4. Number normalization (`NormalizeNumber`, DynamoDB style)
Applied to `N` values and each `NS` entry before serialization (the stored bytes are the normalized
decimal string). Rules:
- Optional leading `+`/`-`; parse `AAA.BBBeCCC` (integer/fraction/exponent forms).
- Fold the exponent into the decimal point, strip insignificant leading and trailing zeros, drop a
  trailing `.`; zero normalizes to `"0"` (and `-0 -> "0"`, sign dropped only for zero).
- At most **38 significant digits** (else fail); magnitude range roughly `10^-130 .. 10^125`
  (fails "smaller/larger than supported range"). Examples (from tests): `"000123.000" -> "123"`,
  `"001.00" -> "1"`.
Decode does **not** re-normalize — the stored normalized string is returned as the `N` value as-is.

## 5. Deserialization + validation (`BytesToAttr`) and errors
- Reads `count`/`length` big-endian; recurses into set/list/map entries by their per-entry
  `len`/`typeId`. Depth > 32 fails.
- NULL: length must be 0 (else "NULL type did not have length zero").
- BOOL: length must be 1 and byte in {0x00,0x01} (else "Boolean ... had inappropriate value" /
  "... more than one byte").
- Map key type id must be String (else "Key of Map is not String").
- Insufficient bytes -> "Structured Data has too few bytes" (and per-type "... less than 4 bytes"
  for a missing set/list/map count).
- Unknown type id -> "Unsupported TerminalTypeId".
- Top-level `StructuredToAttr` requires the decode to consume exactly `|value|` bytes (no trailing).

## 6. Non-obvious behavior (highest-value for the port)
- **UTF-16 ordering for S/N sets and map keys** (not UTF-8 byte order, not Java `String` natural
  ordering by code point) — the same `/unicodeChar:false` code-unit subtlety that bit CanonicalPath.
  Native Java: compare by `char`/`String` UTF-16 units. **Binary** sets sort by raw bytes instead.
- **Number normalization is lossy and canonicalizing**: `000123.000`, `1.23e2`, `123` all serialize
  identically to `123`. A set's no-duplicate rule is enforced both before and after normalization.
- **NULL round-trip is not identity**: `NULL(false)` decodes back as `NULL(true)` (the code picks
  `true` because the DynamoDB server rejects `NULL(false)`).
- **Top-level vs prefixed**: the top-level value omits the 6-byte typeId/length prefix (the typeId is
  carried on the terminal); every nested element includes it. A native impl must not double-prefix
  the top level or forget to prefix nested elements.
- **Set/map determinism**: output is fully determined (sorted) regardless of input order, so a
  round-trip may reorder set/map entries relative to the input sequence — expected, not a bug.

## 7. Explicit non-goals
- Does not preserve input set/map ordering (canonicalized on encode).
- Does not preserve `NULL(false)` (see §6).
- Does not support structures nested deeper than 32, numbers beyond 38 significant digits or the
  supported magnitude range, sets with duplicates, or map keys outside 1..65535 UTF-8 bytes.

## 8. Golden vectors (from test/DynamoToStruct.dfy — must-pass)
- `S("abc")` -> value `61 62 63`, typeId `00 01`.
- `N("123")` -> `31 32 33`, `00 02`; `N("000123.000")` -> `31 32 33` (normalized).
- `NS(["123","45"])` -> `00000002 00000003 313233 00000002 3435`, `01 02`.
- `SS(["abc","de"])` -> `00000002 00000003 616263 00000002 6465`, `01 01`.
- `BS([[1,2,3],[4,5]])` -> `00000002 00000003 010203 00000002 0405`, `01 FF`.
- `B([1,2,3,4,5])` -> `01 02 03 04 05`, `FF FF`.
- `NULL(true)` -> `` (empty), `00 00`.  `BOOL(false)` -> `00`, `00 04`.
- `L([B([1..5]), NULL, BOOL(false)])` -> `00000003  FFFF 00000005 0102030405  0000 00000000  0004 00000001 00`, `03 00`.
- `M({keyA:B, keyB:NULL, keyC:BOOL(false), keyD:L(...)})` -> count 4, each entry
  `0001 <keyLen> <key> <valueTypeId> <valueLen> <value>`, keys in order A,B,C,D; nested list value
  length 28. typeId `02 00`.
- `NS(["001.00"])` -> `00000001 00000001 31` (normalized to "1"), `01 02`.

## 9. Disagreements with spec prose
None found. `ddb-attribute-serialization.md` is inlined as `//=` implication/test annotations
throughout the source and matches the implementation.
