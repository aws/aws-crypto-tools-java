# BeaconValueLocation (TermLoc + set beaconization) — discovery checklist

- [x] 1. Locate the module's Dafny source tree — `DynamoDbEncryption/dafny/DynamoDbEncryption/src/` (`TermLoc.dfy`, `Beacon.dfy`, `Virtual.dfy`), same module as prior beacon work.
- [x] 2. Read the module's Smithy model (public surface) — TermLoc is internal (parsed form of a TerminalLocation string); the StandardBeacon surface (loc/style/asSet) was covered in Beacon discovery. No new standalone operation.
- [x] 3. Read every .dfy file under src/ — read `TermLoc.dfy` in full (285 lines); `Beacon.dfy:215-390` (ValueToSet/getHash/getHashSet/getHashNonSet/Beaconize*Set); `Virtual.dfy:375-387` (VirtToBytes). Virtual-field internals (GetVirtField) deferred (non-goal §7).
- [x] 4. Extract requires/ensures/invariant — ValidTermLoc (non-empty, first=Map); GetTerminal path-shape failures; getHashSet ensures SS + no-duplicates + non-Set→Failure; getHashNonSet ensures S + absent→None + basicHash composition. Recorded §3,§5,§6.
- [x] 5. Read tests for concrete pairs — NO dedicated `test/TermLoc.dfy`; TermLoc/sets exercised via `GenerateEncryptedBeacons` integration (`test/Beacon.dfy` TestNumbersNormalize/TestCompoundQueries). Recorded §8: build impl tests by composition, no unit golden vectors exist.
- [x] 6. Cross-check against specification/ prose — virtual.md (terminal-location/segments) + beacons.md (value-for-(set-)standard-beacon/asSet-init) inlined as `//= type=implication`, match bodies. No disagreement.
- [x] 7. Non-obvious behavior — TermToAttr turns internal GetTerminal *failure* (bad path/out-of-range/missing nested key) into None (absent), not error; dedup is on the beacon-value output keeping first-encounter order; number/binary sets still wrap as SS; GetNumber index cap ~2^60; asSet + non-Set value = write failure.
- [x] 8. Explicit non-goals — virtual fields (VirtToBytes virtual branch), compound beacons/partOnly/keyName(), expression-attribute-name alias resolution (query path), forContains, GenerateEncryptedBeacons orchestration + key-store beacon-key retrieval. Recorded §7.
- [x] 9. Write behavior spec — `dbesdk-behavior/BeaconValueLocation.md` written (template-conformant).
- [x] 10. Source pointers — recorded §10 with exact file paths + line ranges.

## Status
Discovery + spec only (no implementation this turn, per request). Next build step: the
native TermLoc (parse/navigate/serialize) + set-beaconization dispatch, composing the
already-native DynamoToStruct + BeaconKeyDerivation + StandardBeacon. After that, the
searchable-encryption seam (key-store beacon-key retrieval + GenerateEncryptedBeacons) is
the remaining piece to light up the `searchable-encryption` test-server feature end-to-end.
