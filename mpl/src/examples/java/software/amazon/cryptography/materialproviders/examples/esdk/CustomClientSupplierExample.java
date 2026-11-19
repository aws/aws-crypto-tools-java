// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;

/**
 * Pattern (f): the customer decides how KMS clients are built, for example to share one HTTP client.
 * The keyring never closes clients from a supplier it was given. ESDK example: CustomizeSDKClient.
 */
public final class CustomClientSupplierExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CustomClientSupplierExample() {}

  /**
   * @param newClient builds a client for a Region; real AWS:
   *   {@code region -> KmsClient.builder().region(Region.of(region)).httpClient(sharedHttpClient).build()}
   * @return the clients the supplier built, by Region; the caller closes them
   */
  public static Map<String, KmsClient> encryptAndDecrypt(String keyArn, Function<String, KmsClient> newClient) {
    Map<String, KmsClient> clients = new ConcurrentHashMap<>();
    ClientSupplier supplier = region -> clients.computeIfAbsent(region, newClient);

    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");
    // Closing a keyring is optional; it closes only clients it created, so these stay open for the caller.
    try (AwsKmsMultiKeyring keyring = AwsKmsMultiKeyring.builder().generator(keyArn).clientSupplier(supplier).build()) {
      byte[] ciphertext = crypto.encryptData(keyring, EXAMPLE_DATA, encryptionContext);
      Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyring, ciphertext, encryptionContext).getResult());
    }
    return clients;
  }
}
