# Model provenance

The old-API model classes and extension interfaces under `src/test/java` are copied from the
smithy-generated Java of the Dafny-based MPL, not written by hand. They are test-only: the test adapter
implements the old API on the native core so the differential tests can compare it with the Dafny-based MPL.

- `software/amazon/cryptography/materialproviders/model/**`
- `software/amazon/cryptography/keystore/model/**`
- `software/amazon/cryptography/primitives/model/**`
- `software/amazon/cryptography/materialproviders/I{Keyring,CryptographicMaterialsManager,CryptographicMaterialsCache,ClientSupplier,BranchKeyIdSupplier}.java`

They reference no Dafny types.
The copy drops one line per file: the "machine generated, do not modify" header.

| Source repository | Ref |
|---|---|
| `aws/aws-cryptographic-material-providers-library` | `a7be0b938` (`main`, 2026-09-01) |

Change these files only by re-running the copy, never by hand:

```
scripts/sync-model.sh <mpl-checkout> <ref>           # copy
scripts/sync-model.sh <mpl-checkout> <ref> --check   # verify the current copy
```

After a copy from a newer ref, bump `referenceMplVersion` in `gradle.properties` to the release that
contains it, so the copied model and the oracle match.
