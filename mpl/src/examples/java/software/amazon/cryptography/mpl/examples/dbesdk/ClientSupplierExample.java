// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.dbesdk;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.mpl.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.keyrings.DiscoveryFilter;

/**
 * Customer example (ClientSupplierExample, RegionalRoleClientSupplier): KMS clients that act as a different IAM role
 * in each Region. The supplier is a plain lambda-friendly interface from Region to client.
 */
public final class ClientSupplierExample {

  private ClientSupplierExample() {}

  /**
   * Gives each Region the client of its role; fails for a Region without one.
   * Thread-safe: the keyrings may ask from several threads.
   */
  public static final class RegionalRoleClientSupplier implements ClientSupplier {

    private final Map<String, String> roleArnByRegion;
    private final BiFunction<String, String, KmsClient> clientForRole;
    private final Map<String, KmsClient> clients = new HashMap<>();

    /**
     * @param clientForRole the client acting as a role in a Region; with real AWS, assume the role with STS and
     *   build {@code KmsClient.builder().region(Region.of(region)).credentialsProvider(...)}
     */
    public RegionalRoleClientSupplier(Map<String, String> roleArnByRegion, BiFunction<String, String, KmsClient> clientForRole) {
      this.roleArnByRegion = Collections.unmodifiableMap(new HashMap<>(roleArnByRegion));
      this.clientForRole = clientForRole;
    }

    @Override
    public synchronized KmsClient getClient(String region) {
      String roleArn = roleArnByRegion.get(region);
      if (roleArn == null) {
        throw new IllegalArgumentException("Missing region " + region);
      }
      return clients.computeIfAbsent(region, r -> clientForRole.apply(roleArn, r));
    }
  }

  /**
   * Encrypts with an MRK multi keyring and decrypts with an MRK discovery multi keyring in another Region,
   * both getting clients from {@code supplier}.
   *
   * @return the encrypted item
   */
  public static Map<String, String> encryptAndDecrypt(String mrkArn, String readerRegion, String accountId, ClientSupplier supplier) {
    try (
      AwsKmsMrkMultiKeyring writer = AwsKmsMrkMultiKeyring.builder().generator(mrkArn).clientSupplier(supplier).build();
      AwsKmsMrkDiscoveryMultiKeyring reader = AwsKmsMrkDiscoveryMultiKeyring
        .builder()
        .regions(Collections.singletonList(readerRegion))
        .discoveryFilter(DiscoveryFilter.of(Collections.singletonList(accountId), "aws"))
        .clientSupplier(supplier)
        .build()
    ) {
      Map<String, String> item = ExampleItems.item("clientSupplierItem");
      Map<String, String> encrypted = ExampleItems.encryptor(writer).encryptItem(item);
      ExampleItems.requireEqual(item, ExampleItems.encryptor(reader).decryptItem(encrypted));
      return encrypted;
    }
  }
}
