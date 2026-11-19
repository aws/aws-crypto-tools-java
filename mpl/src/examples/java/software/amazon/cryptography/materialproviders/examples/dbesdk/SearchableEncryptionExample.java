// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import software.amazon.cryptography.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cache.MultiThreadedCache;

/**
 * Customer example (BasicSearchableEncryptionExample, searchable-encryption-multitenant):
 * standard beacons keyed by beacon keys from the branch key store.
 * Every branch key has a beacon key with the same id.
 *
 * <p>The DB-ESDK configures this as
 * {@code BeaconVersion.builder().keyStore(keyStore).keySource(single(SingleKeyStore.builder().keyId(id).cacheTTL(6000)))};
 * {@link BeaconKeySource} is what that configuration becomes on the native MPL.
 */
public final class SearchableEncryptionExample {

  /** The beacon's name, which also selects its HMAC key. */
  public static final String BEACON_NAME = "inspector_id_last4";
  private static final int BEACON_LENGTH_BITS = 10;

  private SearchableEncryptionExample() {}

  /**
   * One beacon key for the whole table.
   *
   * @return the beacon of {@code value}: the attribute value written as {@code aws_dbe_b_inspector_id_last4},
   *   and the value to query with
   */
  public static String singleKeyStoreBeacon(DynamoDbKeyStore keyStore, String beaconKeyId, String value) {
    BeaconKeySource source = BeaconKeySource
      .singleKeyStore(keyStore, beaconKeyId)
      .beaconNames(Collections.singletonList(BEACON_NAME))
      .cacheTtlSeconds(6000)
      .build();
    return beacon(source, source.keyIdFor(Collections.<String, String>emptyMap()), value);
  }

  /**
   * One beacon key per tenant: the item attribute {@code tenant_key_id} names it.
   * The tenants share one cache, kept apart from other sources' entries by the partition id.
   *
   * @return each tenant item's beacon of the same {@code value}, by beacon key id
   */
  public static Map<String, String> multiKeyStoreBeacons(DynamoDbKeyStore keyStore, String tenant1KeyId, String tenant2KeyId, String value) {
    BeaconKeySource source = BeaconKeySource
      .multiKeyStore(keyStore, "tenant_key_id")
      .beaconNames(Collections.singletonList(BEACON_NAME))
      .cacheTtlSeconds(60)
      .cache(MultiThreadedCache.builder().entryCapacity(100).build())
      .partitionId("searchable-encryption-example")
      .build();
    Map<String, String> beacons = new LinkedHashMap<>();
    for (String tenantKeyId : new String[] { tenant1KeyId, tenant2KeyId }) {
      Map<String, String> item = Collections.singletonMap("tenant_key_id", tenantKeyId);
      beacons.put(tenantKeyId, beacon(source, source.keyIdFor(item), value));
    }
    return beacons;
  }

  static String beacon(BeaconKeySource source, String beaconKeyId, String value) {
    Map<String, SecretBytes> keys = source.hmacKeys(beaconKeyId);
    try {
      return standardBeacon(keys.get(BEACON_NAME), value, BEACON_LENGTH_BITS);
    } finally {
      keys.values().forEach(SecretBytes::destroy);
    }
  }

  // STAND-IN for the DB-ESDK's StandardBeacon.hash of a string, without partitions:
  // the low lengthBits bits of the first 8 bytes of HMAC-SHA-384, as zero-padded lowercase hex.
  static String standardBeacon(SecretBytes hmacKey, String value, int lengthBits) {
    try {
      Mac mac = Mac.getInstance("HmacSHA384");
      mac.init(hmacKey.toSecretKey("HmacSHA384"));
      long prefix = ByteBuffer.wrap(mac.doFinal(value.getBytes(StandardCharsets.UTF_8))).getLong();
      String hex = Long.toHexString(prefix & ((1L << lengthBits) - 1));
      StringBuilder padded = new StringBuilder();
      for (int i = hex.length(); i < (lengthBits + 3) / 4; i++) {
        padded.append('0');
      }
      return padded.append(hex).toString();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
