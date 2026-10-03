# BeaconKeyMaterials (HKDF-SHA512 beacon key derivation) — discovery checklist

- [x] 1. Locate the module's Dafny source tree — `DynamoDbEncryption/dafny/DynamoDbEncryption/src/SearchInfo.dfy` (module `SearchableEncryptionInfo`), same module as `Beacon.dfy`/`DynamoToStruct.dfy`.
- [x] 2. Read the module's Smithy model (public surface) — derivation is internal (no standalone operation); the consumed concept is MPL "Beacon Key Materials"/"HMAC Keys" (name→key map). Covered in prior Beacon discovery.
- [x] 3. Read every .dfy file under src/ for this component — read `SearchInfo.dfy:36-130` in full (GetAllKeys/GetHmacKeys/GetBeaconKey). Lines 149-470 (key-store/cache layer) read enough to confirm they are the MPL boundary (non-goal §7), not the derivation.
- [x] 4. Extract requires/ensures/invariant clauses — `GetBeaconKey` ensures (`:95-122`): HKDF digestAlgorithm=SHA_512, salt=None, ikm=key, info=UTF8("AWS_DBE_SCAN_BEACON"+name), expectedLength=64. `GetHmacKeys` requires HasNoDuplicates(stdNames); ensures every input name in output map.
- [x] 5. Read the module's own test/ for concrete pairs — `test/Beacon.dfy:88-105` (`TestOneBeaconValue`) + `GetBeaconValue` helper (`:380-402`): base key `[1,2,3,4,5]`, 8 golden beacon strings in `test/BeaconTestFixtures.dfy:96-103`. Confirmed composition: HKDF-SHA512 derive → HMAC-SHA384(value++partition)[..8] → BytesToHex.
- [x] 6. Cross-check against specification/ prose — `search-config.md#hmac-key-generation` inlined at `SearchInfo.dfy:108-122` as `//= type=implication`; matches body. No disagreement.
- [x] 7. Non-obvious behavior — TWO hashes (HKDF SHA-512 vs basicHash SHA-384); salt=None = 64 zero bytes (RFC 5869), not empty; derived key always 64 bytes regardless of beacon length; info uses raw beacon name, not the `aws_dbe_b_` attr name nor shared `keyName()`.
- [x] 8. Explicit non-goals — key-store/branch-key retrieval + caching (MPL boundary), shared-beacon keyName() selection, config assembly/GenerateEncryptedBeacons. Recorded §7.
- [x] 9. Write behavior spec — `dbesdk-behavior/BeaconKeyMaterials.md` written (template-conformant).
- [x] 10. Source pointers — recorded in spec §10 with exact paths/line ranges.

## Implementation (landed this session)
`BeaconKeyDerivation` (+ reuses structured-encryption `crypto/Hkdf.java`) in module
`dbesdk`. Verified: 5 tests incl. the 8 end-to-end Dafny golden
vectors (std2/Name/Title/std4/std6/NameTitleField/empty Name/Title) composing
DynamoToStruct → deriveBeaconKey → StandardBeacon, plus number-normalization equality and
the duplicate-name rejection. Module total 31 tests, 0 failures (JDK 21). Status recorded
in `Beacon.md` §11 scope note — this resolves the §6 "immediate next dependency".
