// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import java.util.ArrayList;
import java.util.function.Function;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.oldapi.materialproviders.model.GetClientInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;

/**
 * {@link ReferenceMpl} for test code outside this package, such as the MPL test vector runner:
 * reference-side objects built and called by name, and failures thrown as the reference threw them.
 */
public final class ReferenceBridge {

  private ReferenceBridge() {}

  /** A reference {@code MaterialProviders} client. */
  public static Object materialProviders() {
    return ReferenceMpl.materialProviders();
  }

  /** A reference model value; see {@link ReferenceMpl#build}. Reference-side values pass through unchanged. */
  public static Object build(String relativeName, Object... setterAndValue) {
    return unwrapped(() -> ReferenceMpl.build(relativeName, setterAndValue));
  }

  /** Calls a reference object's method; a failure of the reference MPL is rethrown unwrapped. */
  public static Object call(Object target, String method, Object... args) {
    return unwrapped(() -> ReferenceMpl.call(target, method, args));
  }

  /** A reference model value rebuilt as the test adapter's model value of the same class name. */
  public static Object fromReference(Object value) {
    return ReferenceMpl.fromReference(value);
  }

  /** A reference {@code IKeyring} implemented by the given functions over the test adapter's models. */
  public static Object keyring(Function<OnEncryptInput, OnEncryptOutput> onEncrypt, Function<OnDecryptInput, OnDecryptOutput> onDecrypt) {
    return ReferenceMpl.customer(
      "materialproviders.IKeyring",
      new ArrayList<>(),
      argument -> argument instanceof OnEncryptInput ? onEncrypt.apply((OnEncryptInput) argument) : onDecrypt.apply((OnDecryptInput) argument)
    );
  }

  /** A reference KMS client of {@code fake}, labeled {@link ReferenceAws#REFERENCE}. */
  public static Object kmsClient(FakeAws fake, String region) {
    return fake.kmsClient(ReferenceMpl.loader(), ReferenceAws.REFERENCE, region);
  }

  /** A reference {@code IClientSupplier} returning a reference client of {@code fake} for each Region. */
  public static Object clientSupplier(FakeAws fake) {
    java.util.Map<String, Object> clients = new java.util.HashMap<>();
    return ReferenceMpl.customer(
      "materialproviders.IClientSupplier",
      new ArrayList<>(),
      argument -> {
        synchronized (clients) {
          return clients.computeIfAbsent(((GetClientInput) argument).region(), region -> kmsClient(fake, region));
        }
      }
    );
  }

  /** A reference key store over a table of {@code fake}, wrapping branch keys with {@code kmsKeyArn}. */
  public static Object keyStore(FakeAws fake, String region, String tableName, String logicalKeyStoreName, String kmsKeyArn) {
    KeyStoreConfig config = KeyStoreConfig
      .builder()
      .ddbTableName(tableName)
      .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKeyArn).build())
      .logicalKeyStoreName(logicalKeyStoreName)
      .ddbClient(ReferenceAws.dynamoDb(fake, region))
      .kmsClient(ReferenceAws.kms(fake, region))
      .build();
    return unwrapped(() -> ReferenceMpl.keyStore(config));
  }

  private static Object unwrapped(java.util.function.Supplier<Object> call) {
    try {
      return call.get();
    } catch (RuntimeException e) {
      if (e.getClass().getEnclosingClass() == ReferenceMpl.class && e.getCause() instanceof RuntimeException) {
        throw (RuntimeException) e.getCause();
      }
      throw e;
    }
  }
}
