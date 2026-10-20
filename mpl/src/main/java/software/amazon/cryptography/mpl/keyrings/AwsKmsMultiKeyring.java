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
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.internal.KmsDataKeys;
import software.amazon.cryptography.mpl.internal.KmsMultiKeyrings;

/**
 * Encrypts under a generator KMS key and additional KMS keys; decrypts with any of them.
 * Thread-safe.
 *
 * <p>Behaves as a {@link MultiKeyring} whose generator and children are {@link AwsKmsKeyring}s,
 * one per KMS key, each with the client the client supplier returned for the key's Region while building.
 * A key given as a key id or alias name (not an ARN) has no Region: its client is the one for {@code ""},
 * which {@link ClientSupplier#defaultSupplier()} creates for the SDK's default Region.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/aws-kms/aws-kms-multi-keyrings.md">AWS KMS multi-keyrings</a>.
 */
public final class AwsKmsMultiKeyring implements Keyring, AutoCloseable {

  private final String generator;
  private final List<String> kmsKeyIds;
  private final ClientSupplier clientSupplier;
  private final List<String> grantTokens;
  private final KmsMultiKeyrings.Built built;

  private AwsKmsMultiKeyring(Builder builder, List<String> grantTokens) {
    this.generator = builder.generator;
    this.kmsKeyIds = KmsMultiKeyrings.copy(builder.kmsKeyIds);
    this.clientSupplier = builder.clientSupplier;
    this.grantTokens = grantTokens;
    this.built = KmsMultiKeyrings.strict(
      generator,
      kmsKeyIds,
      clientSupplier,
      false,
      //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
      //= type=implication
      //# If there is a generator input then the generator keyring MUST be a
      //# [AWS KMS Keyring](aws-kms-keyring.md) initialized with

      //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
      //= type=implication
      //# If there is a set of child identifiers then a set of [AWS KMS Keyring]
      //# (aws-kms-keyring.md) MUST be created for each AWS KMS key identifier
      //# by initializing each keyring with
      (client, keyId) -> AwsKmsKeyring.builder().kmsKeyId(keyId).kmsClient(client).grantTokens(grantTokens).build(),
      "generatorKeyring or child Keryings needed to create a multi keyring"
    );
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The KMS key that generates the data key. Without it the keyring can only add encrypted copies and decrypt. */
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
    built.close();
  }

  @Override
  public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
    return built.keyring.onEncrypt(request);
  }

  @Override
  public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
    return built.keyring.onDecrypt(request);
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

    /** The KMS key that generates the data key. Without it the keyring can only add encrypted copies and decrypt. */
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
    public AwsKmsMultiKeyring build() {
      return new AwsKmsMultiKeyring(this, KmsDataKeys.grantTokens(grantTokens));
    }
  }
}
