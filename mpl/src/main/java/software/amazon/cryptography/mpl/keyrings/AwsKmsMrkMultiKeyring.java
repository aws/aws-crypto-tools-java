// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;

/**
 * {@link AwsKmsMultiKeyring} whose keys treat multi-Region replicas as the same key when decrypting.
 * Two identifiers of the same multi-Region key are not allowed.
 * Thread-safe.
 *
 * <p>Behaves as a {@link MultiKeyring} whose generator and children are {@link AwsKmsMrkKeyring}s,
 * one per KMS key, each with the client the client supplier returned for the key's Region while building.
 * A key given as a key id or alias name (not an ARN) has no Region: its client is the one for {@code ""},
 * which {@link ClientSupplier#defaultSupplier()} creates for the SDK's default Region.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-mrk-multi-keyrings.md">AWS KMS MRK multi-keyrings</a>.
 */
public final class AwsKmsMrkMultiKeyring implements Keyring, AutoCloseable {

  private final String generator;
  private final List<String> kmsKeyIds;
  private final ClientSupplier clientSupplier;
  private final List<String> grantTokens;

  private AwsKmsMrkMultiKeyring() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The KMS key that generates the data key. */
  public Optional<String> generator() {
    return Optional.ofNullable(generator);
  }

  /** More KMS keys that each get an encrypted copy of the data key. */
  public List<String> kmsKeyIds() {
    return kmsKeyIds;
  }

  /** Supplies a KMS client per Region; default {@link ClientSupplier#defaultSupplier()}. */
  public Optional<ClientSupplier> clientSupplier() {
    return Optional.ofNullable(clientSupplier);
  }

  /** Grant tokens sent with every KMS call. */
  public List<String> grantTokens() {
    return grantTokens;
  }

  /**
   * Closes the clients of the default client supplier, if this keyring created one; a supplied {@code clientSupplier} is not closed.
   * Optional: it only releases those clients, so a keyring kept for the life of the application needs no close.
   * Do not use the keyring after closing it.
   */
  @Override
  public void close() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /**
   * Not thread-safe.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings.
   */
  public static final class Builder {

    private String generator;
    private Collection<String> kmsKeyIds;
    private ClientSupplier clientSupplier;
    private Collection<String> grantTokens;

    private Builder() {}

    /** The KMS key that generates the data key. */
    public Builder generator(String generator) {
      this.generator = generator;
      return this;
    }

    public Builder kmsKeyIds(Collection<String> kmsKeyIds) {
      this.kmsKeyIds = kmsKeyIds;
      return this;
    }

    /** Supplies a KMS client per Region; default {@link ClientSupplier#defaultSupplier()}. */
    public Builder clientSupplier(ClientSupplier clientSupplier) {
      this.clientSupplier = clientSupplier;
      return this;
    }

    public Builder grantTokens(Collection<String> grantTokens) {
      this.grantTokens = grantTokens;
      return this;
    }

    /** Gets each key's client from the client supplier. */
    public AwsKmsMrkMultiKeyring build() {
      throw new UnsupportedOperationException("not implemented yet");
    }
  }
}
