# Layer B (searchable encryption / beacons) — Discovery & Slice Plan

Builds on `SearchableEncryptionSeam.md` (write-path: config→beacons, MPL key
retrieval, GenerateEncryptedBeacons — already discovered; value math already
native + golden-pinned). This doc scopes the *remaining* Layer B work and tracks
its discovery. Source of truth: `~/github/dbesdk/aws-database-encryption-sdk-dynamodb`.

## Where Layer B plugs in (resolved)
The transforms client (`DynamoDbEncryptionTransforms`) has beacon seams that are
no-ops in Layer A: `addSignedBeacons`, `encryptedBeacons`, `removeBeacons`
(removeBeacons is already real — strips `aws_dbe_`), plus the Query/Scan
input/output paths and `GetBeaconKeyId`. Layer B replaces the no-op seams with
the real beacon layer, gated on a per-table `SearchInfo` (absent ⇒ seams stay
no-op, exactly as today).

## Sub-slices (fewest-correct-answers-first)
- [x] **B1 — write path** (library-level, built + offline-tested): `SearchInfo`
  (version tag `aws_dbe_v_1` + `encryptedBeacons` via native `BeaconVersion`) +
  optional `SearchInfo` on `TableConfig` + the transforms `addSignedBeacons`/
  `encryptedBeacons` seams delegate to it. 3 tests (beacon value == direct
  BeaconVersion output; PartOnly skipped; version tag written; read-path strip).
  Keys injected (B4 replaces with key-store-derived). **B1→B4 integration TODO:**
  the test-server factory must build `SearchInfo` from the wire `SearchConfig`
  (ConfigToInfo), and — grounded TODO — the real item encryptor's
  `attributeActionsOnEncrypt` must carry the version tag + any signed beacons as
  SIGN_ONLY (Index.dfy `AddSignedBeaconActions`) so EncryptItem signs them; not
  yet done (fake cryptor sidesteps it offline).
- [x] **B2 — read path** (discovered → `B2-QueryBeaconization.md`): input rewrite
  (`QueryInputForBeacons`/`Beaconize`/`BeaconizeParsedExpr`/`BeaconForValue`) fully
  grounded — reuses the Layer A tokenizer; attr→`aws_dbe_b_*`, value→beacon value by
  comparison context, attribute_exists/size/attribute_type + reused-value rules.
  `GetBeaconKeyId` grounded. Output filter (`QueryOutputForBeacons`/`FilterResults`)
  shape grounded (superset → re-filter decrypted items → strip). **One flagged gap
  before implementing the output filter:** the `FilterItems` RPN evaluator
  (`ConvertToPrefix`/`ConvertToRpn`/`FilterItems` + `GetBeaconValue` under
  `DontUseKeys`) is NOT yet read — its compare-plaintext-vs-beacon semantics are
  non-obvious and must not be implemented from assumption.
- [x] **B3 — virtual fields + compound beacons** (→ `B3-VirtualFields-CompoundBeacons.md`):
  **virtual fields BUILT + tested** (7). **Compound beacons BUILT + tested** — write-value
  core (`BeaconPart`, `CompoundBeacon` prefix-validation + constructor assembly +
  `PartValueCalc`) AND read-path query core (`findPart`, `getBeaconValue` with
  constructor-order validation + begins_with bare-prefix handling; query-equality
  beacon == write beacon property pinned). 12 compound + 7 virtual tests. `getFields`
  (underlying field names, virtual-field-expanding) and `keyIdFromValue`
  (FilterExpr.dfy `KeyIdFromPart`: single signed key-id part → stripped query piece)
  BUILT + tested. `getNaked` is covered by `getValue(..., null keys)`. Only remaining
  compound-adjacent bit is partition-count fan-out, which belongs to the separate
  `beacon-partitions` feature, not core compound beacons.
- [~] **B4 — live key-store retrieval + feature flip**: Option A BUILT at library level
  (→ `B4-KeyStoreRetrieval.md`). Native seam `BeaconKeySource` (`LiteralBeaconKeySource` +
  `KeyStoreBeaconKeySource` with cache-id/TTL/retrieve/derive/cache), tri-states
  `MaybeKeyId`/`MaybeKeyMap`, narrow seams `BeaconKeyRetriever`/`BeaconKeyCache`; 6
  `BeaconKeySourceTest` (incl. cache-id SHA-384 byte-layout pin). `SearchInfo` now consumes
  a `BeaconKeySource` (injected `Map` → `LiteralBeaconKeySource`). MPL retriever adapter
  (`MplBeaconKeyRetriever`) + `InMemoryBeaconKeyCache` + `SearchInfoFactory` WIRED into the
  test-server transforms factory (standard beacons over the single key store; compound/
  virtual/multi-version/shared-set fail loud). Library (175) + server (compileJava+test)
  build green; server resolves the lib via `includeBuild` so it compiles against the live
  seam. **Remaining (CI-only):** flip `searchable-encryption` in feature-config + verify on
  the KMS-credentialed orchestrator (live branch-key store, account 370957321024).
- [x] **B5 — compound + virtual beacons into the write path** (library + test-server factory,
  built + offline-tested). Native unified `Beacon` (sealed `Standard`|`Compound`) mirroring
  Dafny `SearchInfo.dfy datatype Beacon`; `BeaconVersion` now holds the unified ordered
  beacon list + virtual fields and emits two passes via one `GenerateBeacons2`:
  `generateSignedBeacons` (DontUseKeys, non-encrypted beacons → attr `<name>`, pre-encrypt)
  and `generateEncryptedBeacons` (keyed, encrypted beacons → `aws_dbe_b_<name>`, post-encrypt).
  `CompoundBeacon.isEncrypted()` = any encrypted part (Dafny `numSigned < |parts|`), driving
  the prefix/no-prefix name (ConfigToInfo:1191) and the signed/encrypted split. `StandardBeacon`
  gained vf-aware `getHash`/`getNaked` (VirtToBytes = UTF-8 of the virtual-field value, NOT
  DynamoToStruct bytes; VirtToAttr = S(value); set beacons never read a vf). `SearchInfo.addSignedBeacons`
  now adds signed compound beacons (+ the DDBSupport consistency check) alongside the version tag.
  `SearchInfoFactory` translates virtual fields, compound beacons, local+global parts, and
  constructors (global part pulled in only when a constructor references it), removing the old
  `rejectUnsupported` gate. 3 new `BeaconVersionTest` cases pin: encrypted compound →
  `aws_dbe_b_comp` = `S_<signed>.E_<hash>` with PartOnly standard excluded; fully-signed compound
  → attr `<name>` pre-encrypt and excluded from the encrypted pass; standard beacon over a virtual
  field hashes the field's UTF-8 value. Library 178 tests + server build green.
  **Remaining (CI-only):** attribute-action-dependent
  init validations (signed part SIGN_ONLY, encrypted field ENCRYPT_AND_SIGN, name collisions,
  AsSet-in-compound) not re-checked in the factory (do not affect beacon values); shared-set
  style + multi key source still fail loud.
- [x] **B6 — item-encryptor SIGN_ONLY actions for signed beacons** (library + test-server, built
  + offline-tested). Grounded in transforms `Index.dfy AddSignedBeaconActions`: only the
  signed-beacon names (`ListSignedBeacons` = fully-signed compound beacons) get an explicit
  SIGN_ONLY action; the version tag `aws_dbe_v_1` gets **none** — it carries the reserved
  `aws_dbe_` prefix the item encryptor already authenticates without an action (`AllowedUnsigned`
  includes `ReservedPrefix <= attr`; verified in both the Dafny item-encryptor ops and the native
  `ItemEncryptorConfig`). (Corrects B5's earlier TODO, which wrongly said the version tag needed a
  SIGN_ONLY action.) Native: `BeaconVersion.listSignedBeacons()` + `SearchInfo.signedBeaconNames()`.
  Test-server: `ItemEncryptorFactory.augmentedActions(config, signedBeaconNames)` validates a
  signed-beacon name is not already configured (Dafny `IsConfigured`: action / unauthenticated /
  under the unauthenticated prefix → `IllegalArgumentException`) and adds `name → SIGN_ONLY`;
  `create(config, signedBeaconNames)` builds the item encryptor with it, and `TransformsClientFactory`
  feeds the same augmented actions to both the item encryptor and the native `TableConfig`
  (mirroring Dafny's single augmented map). Library 179 tests (+1 `listSignedBeacons`); server build
  green (+2 `ItemEncryptorFactoryTest`: SIGN_ONLY added for a signed beacon, version tag absent,
  already-configured name rejected). **Remaining (CI-only):** end-to-end round-trip that EncryptItem
  actually signs the beacon attribute needs MPL + the orchestrator (same KMS/SSH wall).
- [~] **B2-impl — read path, built in 3 verified sub-slices** (the discovered design is in
  `B2-QueryBeaconization.md`). The two halves must ship together before `searchable-encryption` is
  honestly flippable: an input-only rewrite returns a superset (false positives), per §6.
  - [x] **B2.1 — expression token model + ParseExpr** (library, built + offline-tested). New
    `ExpressionTokenizer` (sealed `Token` = `Attr(s,loc)` | `Value(s)` | `Symbol` enum) + `parse`
    (`ParseExpr`/`FindIndexToken`) + `toExpression` (`ParsedExprToString`), faithful to
    `DynamoDBFilterExpr`, including the no-word-boundary `PrefixLower` quirk and `MakeAttr`'s
    TermLoc/`TermLocMap` fallback (added `TermLoc.ofKey`). `ConditionExpressionParser.extractAttributes`
    reimplemented on top (Dafny `ExtractAttributes2`/`IsSpecial`), Layer A behavior unchanged.
    5 `ExpressionTokenizerTest` + the 25-test transforms suite (incl. Layer A extraction probes) green.
  - [x] **B2.2 — input rewrite** (library + test-server wiring, built + offline-tested). Faithful port
    of `DynamoDBFilterExpr` `Beaconize`/`BeaconizeParsedExpr`/`BeaconForValue` + helpers (`GetBeacon`/
    `GetBeacon2`/`GetBetweenBeacon`/`HasBeacon`/`GetInPos`/`CanBeacon`/`CanStandardBeacon`/
    `CanCompoundBeacon`/`CanBetween`/`GetStringFromValue`/`OpNeedsBeacon`/`IsAllowedOnBeacon`,
    `IsEquality`/`IsInequality`/`RealName`) in new `QueryBeaconizer` + `ExprContext` (transforms pkg).
    Native beacon query-value methods added: `StandardBeacon.getBeaconValue(value,key,forContains,part)`
    (asSet/forContains->ValueToSet else hash of `attrToStructured(value).value()` — same serialization
    as the write path, so query==write), `Beacon.getBeaconValue` dispatch (DontUseKeys->value;
    Standard->key lookup by keyName; Compound->native getBeaconValue), `CompoundBeacon.isLessThanComparable`/
    `isBetweenComparable` (SkipSignedPieces + RemoveCommonPrefix, split char encapsulated).
    `BeaconVersion` gained `isBeacon`/`getBeacon`/`encryptedFields` (+3-arg `create` carrying the
    ENCRYPT_AND_SIGN non-beacon field set; 2-arg delegates with empty set). `SearchInfo.beaconizeQuery`
    resolves keys via the key source (base case keyId=DontUse) and delegates; `DynamoDbEncryptionTransforms`
    `queryInputTransform`/`scanInputTransform` build an `ExprContext` from the request and apply the rewrite
    when the table is search-configured. 9 `QueryBeaconizerTest` (equality rewrite + value pinned to the
    direct `getBeaconValue`; attribute_exists operand not beaconized; non-beacon attr passthrough; indirect
    `#name` remapped in the names map; size() over a beacon rejected; standard beacon rejects `<`;
    value reused in two beacon contexts rejected; encrypted non-beacon field query rejected; compound
    equality rewrite == direct compound `getBeaconValue`). Library 193 tests + server build green.
    **Honest remaining:** (1) B2.3 output filter must land before a flip — input-only returns a superset.
    (2) Multi-partition `DoBeaconize` OR fan-out = separate `beacon-partitions` feature. (3) Multi-tenant
    key-id extraction from the query (`GetBeaconKeyId` MultiLoc) not wired — base case uses DontUseKeyId.
    (4) The no-search `TestBeaconize` rejection (query references an ENCRYPT_AND_SIGN field on a table with
    no search config) needs the table's actions on `TableConfig`; the search path already rejects via
    `encryptedFields`, so this is a no-search-only validation gap, flagged not built.
  - [x] **B2.3 — output filter** (library + test-server wiring, built + offline-tested). New
    `ExpressionEvaluator` (transforms): `convertToPrefix` (A IN/BETWEEN -> prefix form),
    `convertToRpn` (shunting-yard + `Precedence`), `evalExpr`/`innerEvalExpr` (StackValue
    Bool|Str|Absent; apply unary/binary/function; `AttributeEQ/NE/LE/LT/GT/GE`; numeric via
    `NumberNormalizer.normalizeNumber` + new native `FloatCompare` port; strings surrogate-aware
    `unicodeLess`; binary unsigned-lexicographic; `is_between`/`is_in`/`beginsWith`/`doesContain`/
    `getSize`/`attrTypeToStr`). New `ResultFilter` (transforms): `filterResults`/`filterItems` —
    key then filter indep, reuses `QueryBeaconizer.beaconizeParsedExpr` under `DontUseKeys`
    (made package-visible, as is `ParsedContext`) -> `convertToPrefix` -> `convertToRpn` ->
    per item `BeaconVersion.generatePlainBeacons` overlaid on the item, keep iff `evalExpr` true.
    New `BeaconVersion.generatePlainBeacons` (GenerateBeacons2 DontUseKeys/AnyBeacon; `generate`
    boolean refactored to a `Kind{SIGNED,ENCRYPTED,ANY}` selector mirroring Dafny IsBeaconOfType).
    `NumberNormalizer`/`FloatCompare` made public for cross-package use. `SearchInfo.filterResults`
    + `DynamoDbEncryptionTransforms` query/scanOutputTransform wired: when search-configured,
    decrypt (keep beacons) -> `filterResults` on the ORIGINAL (pre-rewrite) expressions ->
    strip survivors -> update Count; no-search path unchanged. Grounded: `DontUseKeys` = leave
    PLAINTEXT (not hash) per Util.dfy; decrypt-then-filter order + original-expr use per
    QueryTransform.dfy `Output`; base case `DontUseKeyId` keeps all items (per-item keyId drop is
    the multi-tenant feature, not wired). **DAFNY QUIRK ported exactly** (recorded in B2 spec §4):
    `ConvertToRpn` drops grouping parens + pops one operator per close, so grouping does not
    override precedence (`(a=:x OR b=:y) AND c=:z` == `a=:x OR (b=:y AND c=:z)`); function-call
    parens still work. Library 214 tests (+21: ExpressionEvaluator 13, ResultFilter 3, FloatCompare
    4, BeaconVersion generatePlainBeacons 1) + server build green. Mutation-probed: always-keep
    filter -> removesFalsePositives fails; lexical numeric compare -> numeric/between tests fail.
    **Honest remaining:** multi-partition `DoBeaconize` OR fan-out (`beacon-partitions`); multi-tenant
    `GetBeaconKeyId` MultiLoc per-item keyId filter; the `searchable-encryption` flip + orchestrator
    (KMS creds + peer SSH, host-blocked). Read path (input rewrite B2.2 + output filter B2.3) is now
    complete and exact.

## Discovery checklist (per dafny-behavior-discovery)
- [ ] 1. Source tree located (DynamoDbEncryption/src: SearchInfo, ConfigToInfo, DDBSupport, FilterExpr, UpdateExpr, Virtual, CompoundBeacon, Beacon)
- [ ] 2. Model surface (SearchConfig/BeaconVersion/StandardBeacon/CompoundBeacon/VirtualField) — mostly in SearchableEncryptionSeam.md §1
- [ ] 3. Read read-path .dfy (FilterExpr Beaconize + DDBSupport Query/Scan ForBeacons)
- [ ] 4. Extract requires/ensures for the read path
- [ ] 5. Read read-path tests (FilterExpr test vectors)
- [ ] 6. Spec cross-check (ddb-support.md / beacons.md)
- [ ] 7. Non-obvious read-path behavior
- [ ] 8. Explicit non-goals
- [ ] 9. Write Layer B read-path behavior spec
- [ ] 10. Source pointers

## Notes / evidence (filled as I go)
- B1 write path: already discovered in `SearchableEncryptionSeam.md` (ConfigToInfo.AddStandardBeacons, GetLocStr, SearchInfo key retrieval, GenerateEncryptedBeacons). Value math native + golden-pinned (`BeaconVersion.generateEncryptedBeacons`, `StandardBeacon.getHash`, `BeaconKeyDerivation`). **Not yet discovered: `GenerateSignedBeacons`** (signed/compound write) + the `aws_dbe_v_1` version-tag detail (seen in DDBSupport.AddSignedBeacons).
- B2 read path located (FilterExpr.dfy): `ExprContext` (1789), `DoBeaconize` (1873), `Beaconize` (1938), `BeaconForValue` (394), `BeaconizeParsedExpr` (536); DDBSupport `QueryInputForBeacons`/`QueryOutputForBeacons`/`ScanInputForBeacons`/`ScanOutputForBeacons` delegate here. **Not yet read in full** — this is the main undiscovered gap and is parity-critical (it rewrites customer query expressions into beacon form), so it needs a dedicated careful discovery pass, not a rushed one.
- B3 virtual/compound: `Virtual.dfy`, `CompoundBeacon.dfy` — not yet read.
- B4 live key store: wraps MPL `KeyStore.GetBeaconKey` + MP cache; conformance needs account 370957321024 + orchestrator SSH → **CI-only, unverifiable on this host** (confirmed by the orchestrate SSH-clone + KMS-creds blockers hit while flipping ddb-transforms).

### Build-vs-blocked assessment
Offline-buildable + unit-testable here (value math golden-pinned; rewrites are pure given a SearchInfo): B1 (with an injected HMAC key map), B2, B3.
Blocked locally (needs live AWS + orchestrator): B4 end-to-end + the `searchable-encryption` cross-language conformance run and feature flip.
Recommended first build slice: **B1** (write path), offline-tested with an injected key map, since it is mostly discovered and the value math is already proven.
