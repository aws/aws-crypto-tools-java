# StructuredEncryption — Native Java Implementation Plan

**Scope:** the first native (non-Dafny) port target, `StructuredEncryption`, per the behavior spec
`.agent-reports/dbesdk-native-java/dbesdk-behavior/StructuredEncryption.md` (verified against source; the
authoritative correctness boundary — every byte layout / constant / ordering claim below traces to a spec
section cited inline). This plan is the implementation prompt: it fixes module layout, dependencies, the
internal type model, per-component class/method signatures, porting approach, tests, and the swap sequence
**before** any implementation code is written.

**Grounding rule for this plan:** anything not traceable to a spec section or a file I have read this session
is marked **[ASSUMPTION]** or **[OPEN — verify before coding the component]**. Those are decisions to confirm,
not facts.

---

## 0. Decisions and assumptions (confirm before/at first code)

| # | Decision | Choice | Basis / status |
|---|---|---|---|
| D1 | Where the native code lives | A **new Gradle library module** in `aws-crypto-tools-java`, sibling to `dbesdk/test-server/`. Proposed path `dbesdk/structured-encryption/`. | **[ASSUMPTION]** — repo currently has only `dbesdk/test-server/`, no library module, no top-level settings.gradle. Overview doc: native impl is NOT the test-server scaffold. Module/package naming is a flagged OPEN item in the planning caveat. |
| D2 | Package namespace | `software.amazon.cryptography.dbesdk.structuredencryption` (+ `.internal`, `.wire`, `.crypto` subpackages). | **[ASSUMPTION]** — MUST differ from the published `software.amazon.cryptography.dbencryptionsdk.structuredencryption`, which the test server still imports (verified: seam files import that namespace). `dbesdk` vs `dbencryptionsdk` is the deliberate distinguisher. |
| D3 | Public API surface now | **None.** Build the crypto core against hand-written internal types; author the from-scratch Smithy model in **Phase 3**, not now. | CDD: Phase 1 = behavioral conformance, Phase 3 = idiomatic API/Smithy reshape. Authoring the model now is premature (overview phase mapping). |
| D4 | Materials / CMM source | Consume the **published MPL** (`software.amazon.cryptography:aws-cryptographic-material-providers`) for `ICryptographicMaterialsManager`, materials I/O types, and algorithm-suite metadata. Do **not** reimplement MPL. | ESDK/MPL boundary is fixed (esdk-overview). Dafny calls the same CMM. The native work owns crypto + wire format, not keyrings/CMMs/suites. |
| D5 | Crypto primitives provider | JCE (`javax.crypto.*`, `java.security.*`) via the JVM default provider; HKDF (RFC 5869) implemented over `javax.crypto.Mac` since JCE has no built-in HKDF. | **[ASSUMPTION]** — standard algorithms produce byte-identical output to Dafny's `AwsCryptographicPrimitives`, so provider choice does not affect parity. Alternative: call MPL `AtomicPrimitives`. Recommend JCE+small-HKDF to avoid coupling crypto to MPL's primitive surface. Confirm whether ACCP is a required provider. |
| D6 | Seam type strategy | `NativeStructuredClient implements StructuredClient` (test-server interface). It **adapts** the published model types (`StructuredDataTerminal`, `CryptoItem`, `AuthItem`, `CryptoAction`, `AuthenticateAction`) at the boundary to the native internal types, calls the native core, and adapts back. | Verified: `StructuredClient` signatures use published types; the seam cannot change without touching the test server. Adaptation is the only non-invasive swap. |
| D7 | When the seam swaps | `StructuredClientFactory.create()` keeps returning `RealStructuredClient` (published-Dafny delegation) until the native core passes its own golden-vector + round-trip tests AND cross-decrypts with Dafny. Only then flip the factory to `NativeStructuredClient`. | Overview "green delegation baseline": the branch must never sit broken; the same shared tests validate the native code after the flip. |

**[RESOLVED 2026-09-28 — verified from MPL `Signature/{SignatureAlgorithm,ECDSA,SignUtils}.java`]** ECDSA P-384
signature is a **fixed 103 bytes** (spec §4.6/§7). Findings: (1) the MPL uses `NONEwithECDSA` over a separately
computed SHA-384 of the message; since the footer's message IS the canonical hash and the MPL pre-hashes it with
SHA-384, this is **exactly `SHA384withECDSA` applied to the canonical hash** — the native port uses
`Signature.getInstance("SHA384withECDSA")` over the 48-byte canonical hash for both sign and verify. (2) The fixed
103 is achieved by a retry loop: the reference negates `s` (`s → order − s`, still valid) via BouncyCastle ASN.1;
the native port instead **re-signs until the DER encoding is 103 bytes** — observably equivalent (ECDSA signing is
randomized and non-byte-reproducible; any valid 103-byte signature verifies). No BouncyCastle dependency. Implemented
in `wire/Footer.java`; verified by `FooterTest.signProduces103ByteSignatureThatVerifies`.

**[OPEN — verify at Operations §component 9]** The exact interleaving of (commitment verify) / (footer verify) /
(field decrypt) on the decrypt path is pinned by `Operations.dfy`. The discovery doc records the high-level order;
keep `Operations.dfy` open and match statement order rather than coding from this plan's summary.

---

## 1. Module & package layout

```
aws-crypto-tools-java/
  settings.gradle.kts                      # [NEW] include ":dbesdk:structured-encryption"; keep test-server include
  dbesdk/
    test-server/                           # unchanged (published-Dafny delegation baseline)
    structured-encryption/                 # [NEW] native library module (D1)
      build.gradle.kts                     # java-library; deps = MPL (D4); test = junit5 + jqwik
      src/main/java/software/amazon/cryptography/dbesdk/structuredencryption/
        StructuredEncryptionClient.java    # native core entry (internal-typed) — component 9
        internal/                          # internal type model — component 0/§3
          Terminal.java  CryptoAction.java  AuthenticateAction.java
          Path.java  CryptoItem.java  AuthItem.java  ParsedHeader.java
        crypto/
          Constants.java                   # component 1
          CanonicalPath.java               # component 2
          CanonicalPathComparator.java     # component 3
          FieldKeyDerivation.java          # component 4
          TerminalCryptor.java             # component 5
          Hkdf.java                        # RFC 5869 over Mac (D5)
          ConstantTime.java                # §4.9 ConstantTimeEquals
        wire/
          Header.java                      # component 6 (serialize/deserialize/commitment)
          Footer.java                      # component 7 (serialize/deserialize/canonical record)
          Canonize.java                    # component 8 (canonicalize + legend resolution)
          ByteReader.java  ByteWriter.java # explicit big-endian cursors (no ad-hoc slicing)
        context/
          EncryptionContextLegend.java     # component 10 (V2 aws-crypto-legend + Required-EC-CMM wrap)
      src/test/java/.../                    # golden-vector + byte-level + round-trip tests — §5
  dbesdk/test-server/server/.../registry/
    NativeStructuredClient.java            # [NEW, added at swap time] seam adapter — component 11 (D6)
```

`NativeStructuredClient` lives in the **test-server** module (it depends on both the published seam types and the
new native module); the native module itself has **no** dependency on the test server.

---

## 2. Dependencies (`dbesdk/structured-encryption/build.gradle.kts`)

- `implementation("software.amazon.cryptography:aws-cryptographic-material-providers:$materialProvidersVersion")` — CMM
  interface + materials I/O + algorithm-suite metadata (D4). Reuse the version property already in the repo.
- JDK 21 toolchain (repo convention; smithy-java baseline). JCE only for crypto (D5) — no extra crypto dependency
  unless D5's ACCP question resolves otherwise.
- `testImplementation` JUnit 5 + jqwik (match test-server module).
- **No** dependency on `aws-database-encryption-sdk-dynamodb` — the native module must not touch the Dafny library.

---

## 3. Internal type model (`internal/`) — component 0

Faithful to the spec §1 core types, flat-map-only (§5 non-goal: no nested paths).

```java
public record Terminal(byte[] value, byte[] typeId) {}   // typeId is 2 bytes (§4.9 TYPEID_LEN)

public enum CryptoAction { ENCRYPT_AND_SIGN, SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT, SIGN_ONLY, DO_NOTHING }
public enum AuthenticateAction { SIGN, DO_NOT_SIGN }

// Only StructureSegment (map member) is active today (§1, §5). Model Path as the ordered key list
// so canonicalization is faithful and nested support is a later additive change, not a reshape.
public record Path(List<String> segments) {
    public String terminalKey();     // last segment — the flat-map attribute name
}

public record CryptoItem(Path key, Terminal data, CryptoAction action) {}
public record AuthItem(Path key, Terminal data, AuthenticateAction action) {}

public record ParsedHeader(byte[] algorithmSuiteId, List<EncryptedDataKey> encryptedDataKeys,
                           Map<String,byte[]> storedEncryptionContext, Map<String,byte[]> encryptionContext) {}
```

**Code-quality notes (constraint 7):** records for immutable value carriers; enums named for the domain (not Dafny
identifiers); `byte[]` fields are passed by reference and never defensively copied to read one field (7e). No
`History` field (§3, spec §5). No builder for a 2–3 field struct (7a over-engineering signal).

---

## 4. Per-component design (bottom-up — each is a gated slice)

Ordered fewest-dependencies-first so every slice is unit-testable against Dafny vectors before the next builds on it.

### Component 1 — `Constants` (spec §4.9)
Static finals for every confirmed constant: `HEADER_FIELD="aws_dbe_head"`, `FOOTER_FIELD="aws_dbe_foot"`,
`RESERVED_PREFIX="aws_dbe_"`, `RESERVED_CRYPTO_CONTEXT_PREFIX="aws-crypto-"`, `ATTR_PREFIX="aws-crypto-attr."`,
`LEGEND_KEY="aws-crypto-legend"`, `KEY_SIZE=32`, `NONCE_SIZE=12`, `AUTH_TAG_SIZE=16`, `MSGID_LEN=32`,
`TYPEID_LEN=2`, `BYTES_TYPE_ID={(byte)0xFF,(byte)0xFF}`, `DBE_ALGORITHM_FAMILY=0x67`; the info strings
`"AWS_DBE_DERIVE_KEY"`, `"AWS_DBE_COMMIT_KEY"`, `"AwsDbeField"`; the legend chars `'e'/'c'/'s'`; the terminal
type-id table (Null `0x0000` … Binary `0xFFFF`). No logic. *Test:* none needed (pure constants) — do **not** write a
test that just re-asserts a literal (no-slop 7d).

### Component 2 — `CanonicalPath` (spec §4.1) — **the AAD**
```java
public static byte[] canonicalPath(String tableName, Path path);   // UTF8(table) ++ u64be(depth) ++ parts
static byte[] canonicalPart(String key);                            // 0x24 ++ u64be(len(UTF8(key))) ++ UTF8(key)
```
Big-endian `uint64` via `ByteWriter`. *Test (must-pass):* the `test/Paths.dfy` vector —
`canonicalPath("example_table",["name"])` equals the exact recorded byte sequence (spec §4.1).

### Component 3 — `CanonicalPathComparator` (spec §4.2)
```java
public final class CanonicalPathComparator implements Comparator<byte[]> {
    public int compare(byte[] a, byte[] b) { return Arrays.compareUnsigned(a, b); }   // JDK 9+, JVM intrinsic
}
```
Compares **canonical-path bytes**, not attribute names — ordering is length-major (spec §4.2). Sorting is
`list.sort(...)` on the precomputed canonical key; **do not port `OptimizedMergeSort`** (spec §5, recorded sort
decision). *Test:* `test/Header.dfy` `TestSchemaOrderLength` order `aa, zz, aaa, zzz, aaaa, zzzz` reproduced;
plus the signed-byte trap (a key byte ≥ 0x80 must sort after a smaller one) — a `Byte.compare`/`b1-b2`
implementation must fail this test.

### Component 4 — `FieldKeyDerivation` (spec §4.3) — golden vectors exist
```java
byte[] fieldRootKey(byte[] plaintextDataKey, byte[] msgId, MacAlg kdfHmac, int keyLen);   // HKDF, info DERIVE_KEY++msgId, salt=none
FieldKey fieldKey(byte[] fieldRootKey, int offset);          // first 44 B of AES-CTR keystream, IV=nonce(offset*3)
static byte[] fieldKeyNonce(int n);                          // "AwsDbeField" ++ 0x2c ++ u32be(n)  (16 B)
record FieldKey(byte[] cipherKey /*[0..32]*/, byte[] nonce /*[32..44]*/) {}
```
`offset` = index among ENCRYPT_AND_SIGN fields in canonical-sorted order; CTR IV uses `offset*3` (spec §4.3).
AES-CTR keystream = `Cipher("AES/CTR/NoPadding")` encrypting 44 zero bytes with IV = the 16-byte nonce.
*Test (must-pass):* the `test/Crypt.dfy` `(rootKey, offset) -> 44-byte` golden vectors, byte-for-byte.

### Component 5 — `TerminalCryptor` (spec §4.4)
```java
Terminal encryptTerminal(FieldKey k, byte[] canonicalPathAad, Terminal plaintext);
    // GCM(key,iv=nonce,aad); out.typeId=0xFFFF; out.value = originalTypeId(2) ++ ciphertext ++ tag(16)
Terminal decryptTerminal(FieldKey k, byte[] canonicalPathAad, Terminal encrypted);
    // require value.length>=18; split typeId(2) ++ ct ++ tag(last16); GCM-decrypt; out.typeId=parsed 2 bytes
```
`Cipher("AES/GCM/NoPadding")`, 128-bit tag; JCE returns `ciphertext||tag`, matching the layout directly.
*Test:* round-trip; tamper (flip a tag byte -> GCM `AEADBadTagException` mapped to the module error); AAD-mismatch
(wrong canonical path -> auth failure).

### Component 6 — `Header` (spec §4.5) — wire format + commitment
```java
byte[] serializePartialHeader(HeaderFields f);   // version,flavor,msgId,legend,ec,edks (exact order)
byte[] commitment(byte[] commitKey, byte[] partialHeader, MacAlg commitmentHmac);   // first 32 B of HMAC
byte[] serializeHeader(HeaderFields f, byte[] commitKey);                            // partial ++ commitment(32)
HeaderFields deserializeHeader(byte[] bytes);                                        // inverse; verifies EC ordering
void verifyCommitment(byte[] commitKey, byte[] bytes);                               // constant-time (component §ConstantTime)
```
Sub-serializers, each with a byte-level test: version (0x02 iff any SIGN_AND_INCLUDE, else 0x01), flavor
(`suite.binaryId[1]`), encrypt legend (`u16be(len) ++ e/c/s per signed field, canonical order`), encryption context
(`u16be(count) ++ per-KV u16be-len key/value, sorted, no dup` — out-of-order -> `"Context keys out of order."`),
EDKs (**1-byte** count, `0<n<=255`). Commitment = first 32 B of `HMAC(commitKey, partialHeader)` under the suite's
commitment HMAC (SHA-384 for both DBE suites, spec §4.5), constant-time verify. *Test:* `test/Header.dfy`
serialization vectors, `TestDuplicateContext` (-> ordering error), commitment tamper (-> `"Key commitment mismatch."`).

### Component 7 — `Footer` (spec §4.6) — recipient tags + signature + canonical record
```java
byte[] canonicalRecord(byte[] fullHeader, Map<String,byte[]> ec, List<SignedField> signedFieldsCanonicalOrder);
byte[] canonicalHash(byte[] canonicalRecord);                     // SHA-384
byte[] recipientTag(byte[] symmetricSigningKey, byte[] canonicalHash);   // HMAC, 48 B
byte[] sign(ECPrivateKey signingKey, byte[] canonicalHash);       // ECDSA P-384, MUST be 103 B  [OPEN D-open-1]
Terminal serializeFooter(List<byte[]> recipientTags, Optional<byte[]> signature);   // typeId 0xFFFF
Footer deserializeFooter(Terminal footer, int edkCount, boolean suiteHasEcdsa);     // split tags(48*n) + sig(103|0)
void verify(...);   // #tags==#EDKs; recompute hash; >=1 tag matches (constant-time); if ecdsa, verify sig; sig.present==suite.ecdsa
```
Canonical field encoding (spec §4.6): encrypted = `canonPath ++ u64be(valueLen-2) ++ "ENCRYPTED"(9) ++ value`;
plaintext = `canonPath ++ u64be(valueLen) ++ "PLAINTEXT"(9) ++ typeId(2) ++ value`. Signed fields = all
non-DO_NOTHING (spec §7 disagreement 2 — Dafny wins over stale prose). Signature 103 bytes (spec §7
disagreement 1) — resolve **[OPEN D-open-1]** first. *Test:* recipient-tag HMAC vector; signed round-trip;
signature-length assertion (== 103); tamper -> verify failure mapped to module error.

### Component 8 — `Canonize` (spec §4.2, §4.7)
```java
List<CanonCryptoItem> forEncrypt(String table, List<CryptoItem> input);   // canonicalize + sort by canonical key
List<CanonCryptoItem> forDecrypt(String table, List<AuthItem> input, byte[] headerLegend);  // canonicalize, sort, re-derive action
```
`forDecrypt` reconstructs each field's `CryptoAction` from the stored header legend in sorted order (spec §4.7):
DO_NOT_SIGN -> DO_NOTHING (consumes no legend byte); SIGN consumes next byte (`e`->ENCRYPT_AND_SIGN,
`c`->SIGN_AND_INCLUDE, `s`->SIGN_ONLY). Legend length != signed-field count -> the two exact "Schema changed"
errors (spec §3). Header/footer appended as two DO_NOTHING items on encrypt, stripped on decrypt (spec §2). *Test:*
`test/HappyCaseTests` field classification; legend length-mismatch -> exact error.

### Component 9 — `StructuredEncryptionClient` (spec §1–§2) — orchestration
Public internal-typed entry points:
```java
EncryptPathResult encryptPathStructure(String table, List<CryptoItem> plaintext,
        ICryptographicMaterialsManager cmm, Optional<byte[]> suiteId, Optional<Map<String,byte[]>> ec);
DecryptPathResult decryptPathStructure(String table, List<AuthItem> encrypted,
        ICryptographicMaterialsManager cmm, Optional<Map<String,byte[]>> reproducedEc);
Map<String,Terminal> encryptStructure(...);   // thin adapter: BuildCryptoMap -> encryptPathStructure -> UnBuildCryptoMap (spec §1)
Map<String,Terminal> decryptStructure(...);   // thin adapter over BuildAuthMap/decryptPathStructure
List<CryptoItem> resolveAuthActions(String table, List<AuthItem> authActions, byte[] headerBytes);  // legend-only, no CMM
```
**Encrypt sequence** (spec §2, §4): validate preconditions (§2) -> canonicalize+sort (comp 8) -> compute version +
build V2 legend/wrap Required-EC-CMM if any SIGN_AND_INCLUDE (comp 10) -> `cmm.GetEncryptionMaterials(policy=DBE
REQUIRE_ENCRYPT_REQUIRE_DECRYPT, maxPlaintextLength=n*2+totalEncSize, suite default
ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)` -> validate returned suite (ValidSuite;
governing suite is the **returned** one, spec §2) -> random 32-B msgId -> derive FieldRootKey + CommitKey ->
per ENCRYPT_AND_SIGN field in sorted order (offset++) GCM-encrypt (comp 4/5) -> build header (comp 6) -> build
footer over canonical record (comp 7) -> assemble output (|out|=|in|+2, header second-to-last, footer last, §2).
**Decrypt sequence:** validate (header+footer present, >=1 SIGN, §2) -> parse header (comp 6) ->
`cmm.DecryptMaterials(suiteId=header, edks=header, ec=header-parsed, reproducedEc=input)` -> validate returned
suite -> derive CommitKey, verify commitment -> canonicalize+sort+resolve legend (comp 8) -> verify footer (comp 7)
-> derive FieldRootKey, GCM-decrypt each ENCRYPT_AND_SIGN field -> strip header/footer, assemble. **Confirm exact
verify/decrypt interleaving against `Operations.dfy` [OPEN D-open-2].** *Test:* full `test/HappyCaseTests`
round-trip; each precondition error (exact message, one error kind per test — constraint 7d).

**Status — operations now return `parsedHeader`.** All four ops return `StructuredEncryptionOutput<T>(T structure,
ParsedHeader parsedHeader)` (was a bare structure), completing the Dafny output contract. Native `ParsedHeader`
(internal, MPL-free) mirrors the Dafny one: `algorithmSuite` (native descriptor, standing in for the suite id),
`encryptedDataKeys`, `storedEncryptionContext` (header-carried), `encryptionContext` (full, signature-bound) — the
last two differ only under a Required-EC CMM. Encrypt reads them from the resolved materials + the stored context it
computes; decrypt reads the stored context and EDKs from the parsed header and the full context from the decryption
materials. Not on the test-server conformance wire (the commons model's outputs carry only the structure — verified),
so the seam discards it; its consumer is the future item-encryptor layer. Covered by
`parsedHeaderReportsStoredAndFullContext` (the stored-vs-full distinction).

**Status — map operations also return `cryptoSchema`.** The two output shapes now match the Dafny model: path ops
return `PathStructureOutput(structure, parsedHeader)`; map ops return `MapStructureOutput(structure, cryptoSchema,
parsedHeader)` (the earlier generic `StructuredEncryptionOutput<T>` was removed once the shapes diverged — it only
ever held `List<CryptoItem>`). `cryptoSchema` is the schema half of `UnBuildCryptoMap`: every authenticated field
(any action but DO_NOTHING, per `Util.IsAuthAttr`) keyed to its Crypto Action — so the reserved header/footer and
DO_NOTHING fields are excluded. Like `parsedHeader`, it is not on the conformance wire (the commons map outputs carry
only the structure), so the seam discards it. Covered by the map round-trip test asserting the schema on both encrypt
(actions preserved) and decrypt (actions recovered from the header legend).

### Component 10 — `EncryptionContextLegend` (spec §4.8)
```java
Optional<String> buildLegend(List<CanonCryptoItem> signAndIncludeFields);   // one char per SIGN_AND_INCLUDE, sorted by UTF8
    // typeId==NULL->'L', STRING->'S', NUMBER->'N', BOOLEAN->'L', else->'B'  (Operations.dfy dispatch, spec §4.8)
Map<String,byte[]> legendEntries(...);   // key = "aws-crypto-attr." + dotted path; duplicate produced key -> error
ICryptographicMaterialsManager wrapRequiredEcCmm(ICryptographicMaterialsManager base, Set<String> requiredKeys);  // MPL Required-EC CMM
```
Distinct from the header encrypt legend (spec §4.8 — do not conflate). Built only when a SIGN_AND_INCLUDE action
exists. *Test:* the four type->char mappings; the `aws-crypto-attr.` key format; duplicate-key error.

**Status — landed as `V2EncryptionContext.build(List<CryptoItem>) -> Map<String,byte[]>`.** One method returns
the whole context (the `aws-crypto-attr.<path>` entries + the `aws-crypto-legend` entry) rather than a separate
`buildLegend`/`legendEntries` pair — the legend order is coupled to the sorted attribute keys, so splitting them
invited a mismatch. Port grounded in `Operations.dfy` `GetV2EncryptionContext2` (value encoding: NULL->"null",
BOOLEAN->"true"/"false", STRING/NUMBER->raw UTF-8 value, else->`UTF8(Base64(typeId ++ value))`; legend chars
sorted by the EC key's UTF-8 bytes). `wrapRequiredEcCmm` stayed at the seam (it is the only MPL touchpoint) and is
exercised in `CrossDecryptParityTest` via the MPL `CreateRequiredEncryptionContextCMM`. Covered by
`V2EncryptionContextTest` (type matrix + sorted legend + duplicate-key error) and the two `v2*` parity cases
(native<->Dafny, non-signing suite) — both green.

### Component 11 — `NativeStructuredClient` (D6) — seam adapter, added at swap time
`implements StructuredClient` (test-server interface, published types). Adapts published
`StructuredDataTerminal`/`CryptoItem`/`AuthItem`/`CryptoAction`/`AuthenticateAction` <-> native internal types,
holds the MPL `ICryptographicMaterialsManager` (as `RealStructuredClient` does), delegates to
`StructuredEncryptionClient`, maps native `StructuredEncryptionException` -> `DbesdkClientException` preserving the
message. No crypto here — pure adaptation (constraint 7a: no logic that belongs in the core).

**Status — landed and wired into the factory.** Correction to the note above: the seam is *not* pure adaptation,
because the native pipeline takes resolved materials while the test-server hands it a CMM. So
`NativeStructuredClient` also ports the outer layer of the Dafny `Encrypt/DecryptPathStructure`: resolve materials
from the CMM (`GetEncryptionMaterials`/`DecryptMaterials`, `maxPlaintextLength = 2*count + Σ encrypted-value-size`,
policy `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`), and for a SIGN_AND_INCLUDE record build the V2 context
(`V2EncryptionContext`) and wrap the CMM in a Required-EC CMM — the only MPL touchpoints, kept out of the core.
Split into `StructuredTypeAdapters` (published<->native marshalling, no MPL), `MplEcKeyDecoder` (MPL EC key
encoding -> JCE, signing suite), and `NativeStructuredClient` (orchestration). The native suite descriptor is read
from the resolved MPL `AlgorithmSuiteInfo` (flavor byte + ECDSA presence; the SHA-512/SHA-512/SHA-384/32/32
parameters are the shared DBE-suite constants). `StructuredClientFactory.create` now returns it and
`resolveAuthActions` runs natively; `RealStructuredClient` deleted (dead). Build: composite `includeBuild` of the
native module (`dbesdk/structured-encryption`). Verified: full test-server suite green (14 incl. 3 seam tests —
native round-trip, native-encrypt->Dafny-decrypt through a real Raw AES CMM, and the V2 SIGN_AND_INCLUDE path,
which the default DBE signing suite also runs through `MplEcKeyDecoder`); `make server-test` green against the
local commons dbesdk model. Not runnable on this host: the full cross-language `make test-server` (needs AWS creds
+ the Rust/.NET language servers).

---

## 5. Test strategy (constraint 7d, no-slop, esdk-test-patterns)

- **Golden vectors are the backbone:** `test/Paths.dfy` (canonical path), `test/Crypt.dfy` (FieldKey 44-byte
  outputs), `test/Header.dfy` (serialization + ordering + commitment tamper), `test/HappyCaseTests` (end-to-end).
  Port the concrete Dafny vectors as JUnit data — these are the must-pass parity checks.
- **Byte-level + round-trip shape** per esdk-test-patterns: for each wire component, assert exact bytes AND
  round-trip; for each crypt component, round-trip AND tamper.
- **One error kind per failing test (7d):** assert the specific `StructuredEncryptionException` with the exact
  §3 message; never an OR-chain, never a boolean "threw", never substring-only on an unrelated message.
- **Falsifiability check (review-checklist / no-slop):** before trusting any test green, confirm it fails against a
  stub and against one plausible wrong mutation (e.g. signed-byte comparator, wrong nonce offset multiplier,
  96- vs 103-byte signature). A test that can't fail is deleted, not kept.
- **Cross-decrypt parity (the real proof):** native-encrypt -> Dafny-decrypt and Dafny-encrypt -> native-decrypt,
  before the seam flip (D7). This is what certifies parity beyond same-implementation round-trips.
- **No shared test helper until 3+ tests need it (7g):** inline setup first.

---

## 6. Swap sequence (D7 — branch never broken)

1. Land components 1–10 in the native module with all unit/golden tests green.
2. Add cross-decrypt parity tests (native<->Dafny) in the native module (temporary test-scope dependency on the
   published library, test-only — the main module stays free of it).
3. Add `NativeStructuredClient` (component 11) in the test-server module.
4. Flip `StructuredClientFactory.create()` to return `NativeStructuredClient`; keep `RealStructuredClient` in tree
   until a green `make orchestrate` (or the local scoped subset) confirms the swap, then remove it in a later slice.
5. The same shared structured-encryption tests now validate native code.

## 7. Order of work & gating

Slices, each = write + test green + record in discovery/ledger before the next:
`Constants -> CanonicalPath -> Comparator -> Hkdf -> FieldKeyDerivation -> TerminalCryptor -> Header -> Footer
(resolve OPEN-1 first) -> Canonize -> EncryptionContextLegend -> StructuredEncryptionClient (confirm OPEN-2) ->
cross-decrypt parity -> NativeStructuredClient + seam flip`.

Phase gates (constraint 4): Phase 1 conformance (shared tests green after swap) and Phase 2 local correctness
(concurrency: fresh msgId + nonce uniqueness per record; no key-material leaks; a custom-CMM extension test) must
both be green before any Phase 4 performance work on this component. No confidence labels in shipped code/comments
(constraint 7) — those stay in this planning doc and the discovery checklist only.
