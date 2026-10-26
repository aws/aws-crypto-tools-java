// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.keystore.internal;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.dynamodb.model.InternalServerErrorException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;
import software.amazon.cryptography.oldapi.keystore.model.BeaconKeyMaterials;
import software.amazon.cryptography.oldapi.keystore.model.BranchKeyMaterials;
import software.amazon.cryptography.oldapi.keystore.model.Discovery;
import software.amazon.cryptography.oldapi.keystore.model.GetKeyStoreInfoOutput;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreException;
import software.amazon.cryptography.oldapi.keystore.model.MRDiscovery;
import software.amazon.cryptography.oldapi.materialproviders.internal.Boundary;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.exceptions.MaterialProvidersException;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;
import software.amazon.cryptography.mpl.keystore.GetKeyStoreInfoResponse;
import software.amazon.cryptography.mpl.keystore.KmsConfiguration;

/** Test adapter: old key store models to and from the native key store, and native exceptions as the old API threw them. */
public final class KeyStoreConvert {

  private KeyStoreConvert() {}

  /**
   * Runs a native call and rethrows its failure as the Dafny-based key store did:
   * a failed AWS call as the AWS SDK exception, any other failure as a {@link KeyStoreException} with the same message.
   *
   * <p>The Dafny-based store rebuilt a modeled SDK exception from its message, which drops the request id
   * and status code but keeps the class and {@code getMessage()}; the original exception carries both.
   */
  public static <T> T call(Supplier<T> operation) {
    try {
      return operation.get();
    } catch (MaterialProvidersException e) {
      throw toOld(e);
    }
  }

  /** A native key store failure as the Dafny-based key store threw it; see {@link #call}. */
  public static RuntimeException toOld(MaterialProvidersException e) {
    // The Dafny-based store reported a client it could not create as an internal error of that service.
    if (e.getMessage().startsWith("Could not create the key store's KMS client")) {
      return KmsInternalException.builder().message(e.getCause().getMessage()).build();
    }
    if (e.getMessage().startsWith("Could not create the key store's DynamoDB client")) {
      return InternalServerErrorException.builder().message(e.getCause().getMessage()).build();
    }
    if (e.getCause() instanceof SdkException) {
      return (SdkException) e.getCause();
    }
    return KeyStoreException.builder().message(e.getMessage()).build();
  }

  /** A builder holding the config, in the order the Dafny-based store converted and then checked it. */
  public static BranchKeyStore.Builder toNative(KeyStoreConfig config) {
    BranchKeyStore.Builder builder = BranchKeyStore.builder()
      .ddbTableName(config.ddbTableName())
      .logicalKeyStoreName(config.logicalKeyStoreName())
      .id(config.id())
      .kmsClient(config.kmsClient())
      .ddbClient(config.ddbClient());
    List<String> grantTokens = Boundary.optional(config.grantTokens());
    if (grantTokens != null) {
      builder.grantTokens(grantTokens);
    }
    return builder.kmsConfiguration(toNative(config.kmsConfiguration()));
  }

  static KmsConfiguration toNative(KMSConfiguration configuration) {
    if (configuration.kmsKeyArn() != null) {
      return KmsConfiguration.kmsKeyArn(configuration.kmsKeyArn());
    }
    if (configuration.kmsMRKeyArn() != null) {
      return KmsConfiguration.kmsMrKeyArn(configuration.kmsMRKeyArn());
    }
    if (configuration.discovery() != null) {
      return KmsConfiguration.discovery();
    }
    return KmsConfiguration.mrDiscovery(configuration.mrDiscovery().region());
  }

  /** The caller's encryption context as Dafny received it: UTF-8 strings, and an empty map meaning none. */
  public static EncryptionContext encryptionContext(Map<String, String> encryptionContext) {
    if (encryptionContext == null) {
      return null;
    }
    Boundary.encryptionContext(encryptionContext);
    return encryptionContext.isEmpty() ? null : EncryptionContext.copyOf(encryptionContext);
  }

  public static GetKeyStoreInfoOutput toOld(GetKeyStoreInfoResponse info) {
    return GetKeyStoreInfoOutput.builder()
      .keyStoreId(info.keyStoreId())
      .keyStoreName(info.keyStoreName())
      .logicalKeyStoreName(info.logicalKeyStoreName())
      .grantTokens(info.grantTokens())
      .kmsConfiguration(toOld(info.kmsConfiguration()))
      .build();
  }

  static KMSConfiguration toOld(KmsConfiguration configuration) {
    switch (configuration.kind()) {
      case KMS_KEY_ARN:
        return KMSConfiguration.builder().kmsKeyArn(configuration.arn().get()).build();
      case KMS_MR_KEY_ARN:
        return KMSConfiguration.builder().kmsMRKeyArn(configuration.arn().get()).build();
      case DISCOVERY:
        return KMSConfiguration.builder().discovery(Discovery.builder().build()).build();
      case MR_DISCOVERY:
        return KMSConfiguration.builder()
          .mrDiscovery(MRDiscovery.builder().region(configuration.region().get()).build())
          .build();
      default:
        throw new IllegalArgumentException(configuration.kind().name());
    }
  }

  public static BranchKeyMaterials toOld(software.amazon.cryptography.mpl.keystore.BranchKeyMaterials materials) {
    return BranchKeyMaterials.builder()
      .branchKeyIdentifier(materials.branchKeyIdentifier())
      .branchKeyVersion(materials.branchKeyVersion())
      .encryptionContext(new HashMap<>(materials.encryptionContext()))
      .branchKey(ByteBuffer.wrap(materials.branchKey().toByteArray()))
      .build();
  }

  /** The key store derives no HMAC keys, so they stay unset, as in the Dafny-based store. */
  public static BeaconKeyMaterials toOld(software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials materials) {
    return BeaconKeyMaterials.builder()
      .beaconKeyIdentifier(materials.beaconKeyIdentifier())
      .encryptionContext(new HashMap<>(materials.encryptionContext()))
      .beaconKey(ByteBuffer.wrap(materials.beaconKey().get().toByteArray()))
      .build();
  }
}
