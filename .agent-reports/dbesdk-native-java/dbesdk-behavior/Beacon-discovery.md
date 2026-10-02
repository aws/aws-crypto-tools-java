# Beacon (standard beacon) — discovery checklist

Component: the **standard beacon** primitive in the Dafny `DynamoDbEncryption` module
(`Beacon.dfy`) — the searchable-encryption feature's most foundational, purely
byte-testable piece (HMAC over a plaintext terminal value, truncated to a beacon
bit-length). Fewest-correct-answers-first slice of searchable-encryption, started
before CompoundBeacon / TermLoc / Virtual / SearchInfo / ConfigToInfo and before the
DDB-level query rewriting (FilterExpr/UpdateExpr).

Source repo: `/local/home/huaye/github/dbesdk/aws-database-encryption-sdk-dynamodb`
Spec written: `.agent-reports/dbesdk-native-java/dbesdk-behavior/Beacon.md`

- [x] 1. Locate the module's Dafny source tree
      `DynamoDbEncryption/dafny/DynamoDbEncryption/src/Beacon.dfy` (461 lines). Deps:
      `Util.dfy` (partition encoding), `Virtual.dfy`, `TermLoc.dfy`, `DynamoToStruct.dfy`
      (done), MPL `HexStrings.dfy`, AtomicPrimitives (HMac), `SearchInfo.dfy` (key HKDF).
- [x] 2. Read the module's Smithy model (public surface)
      `Model/DynamoDbEncryption.smithy`: `StandardBeacon{name, length:BeaconBitLength,
      loc, style, partitions}`; `integer BeaconBitLength`; `BeaconStyle` union
      (partOnly/asSet/shared/sharedSet). CompoundBeacon is a separate, later slice.
- [x] 3. Read every .dfy file under src/ for this slice — Beacon.dfy read IN FULL;
      dependency reductions confirmed: Virtual.VirtToBytes (src/Virtual.dfy:376) reduces
      to TermLoc.TermToBytes for a plain non-virtual beacon; value bytes via
      DynamoToStruct.TopLevelAttributeToBytes (already native).
- [x] 4. Extract requires/ensures/invariant clauses — captured in Beacon.md §2-§5:
      BeaconLength 1..63; getHmac = HMAC-SHA384 first 8 bytes; basicHash =
      BytesToHex(getHmac(val++part,key), length); BytesToHex bit-truncation (rightmost
      `length` bits, ceil(length/4) lowercase hex chars, top nibble % 2^(length mod 4));
      PartitionNumberToBytes(0)=[] / N->[N]; constrained_partition = partition mod
      numberOfPartitions (0-special-cased); non-set->"S", asSet->"SS" deduped.
- [x] 5. Read the module's own test/ directory — test/Beacon.dfy + test/BeaconTestFixtures.dfy
      read. Golden vectors captured in Beacon.md §8: direct-key ("7e"/"1d"/"ef"/"80",
      getHmac byte arrays) + end-to-end (std2 "ac6f5d"@24, std6 "2d99222"@26 non-byte-aligned,
      Name/Title @32, empty-value cases). Number normalization equivalence confirmed.
- [x] 6. Cross-check against specification/ prose — no disagreement. beacons.md
      requirements are inlined as //= type=implication in Beacon.dfy and match the ensures
      clauses. Recorded in Beacon.md §9.
- [x] 7. Identify non-obvious behavior — Beacon.md §3 (bit-truncation top-nibble rule +
      lowercase hex), §4 (partition-0 appends nothing), §2 (HMAC-SHA384 first 8 bytes),
      §5 (set dedup, number normalization, absent-field -> no value).
- [x] 8. Identify explicit non-goals — Beacon.md §7: beacon-partitions (>0), compound
      beacons, virtual fields, shared/sharedSet, key-materials HKDF layer, query rewriting.
- [x] 9. Write or update dbesdk-behavior-specs/Beacon.md — DONE (158 lines, template-conformant).
- [x] 10. Record source pointers — Beacon.md §10: Beacon.dfy, Util.dfy:15/86-106,
      Virtual.dfy:376, TermLoc.dfy, SearchInfo.dfy:~124, MPL HexStrings.dfy:12,
      Model/DynamoDbEncryption.smithy, test/Beacon.dfy, test/BeaconTestFixtures.dfy:96-103.

## Note for the implementing session
The standard-beacon PRIMITIVE takes the per-beacon HMAC key as an INPUT. To light up the
`searchable-encryption` test-server feature end-to-end, the beacon-key-materials layer
(§6: HKDF-SHA512, info "AWS_DBE_SCAN_BEACON"+name, len 64, from beacon key materials
supplied via MPL/keystore) is the immediate next dependency — analogous to how the
DynamoToStruct item layer followed the terminal layer. Decide at implementation time
whether the first native cut is the pure primitive (unit-tested against the direct-key
golden vectors) or the primitive + key-materials (needed for the conformance feature).
