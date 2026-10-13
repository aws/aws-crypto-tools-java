package software.amazon.cryptography.dbesdk.dynamodbencryption;

/**
 * Whether a beacon-key id is available for retrieval (Dafny {@code MaybeKeyId}). A query
 * against a multi-tenant key store may know the id ({@link Explicit}), know one is required
 * but not yet have it during query planning ({@link ShouldHave}), or be a single-tenant
 * context where no id is allowed ({@link DontUse}).
 */
public sealed interface MaybeKeyId
    permits MaybeKeyId.Explicit, MaybeKeyId.DontUse, MaybeKeyId.ShouldHave {

    record Explicit(String id) implements MaybeKeyId {}

    record DontUse() implements MaybeKeyId {}

    record ShouldHave() implements MaybeKeyId {}
}
