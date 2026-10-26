// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.EAST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.config;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.discovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.keyArn;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrDiscovery;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.mrKeyArn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;

// Key store construction and GetKeyStoreInfo, native (through the adapter) against the reference.
class KeyStoreConfigTest {

  private static final String ACCOUNT = "111122223333";
  private static final String KEY_ID = "1234abcd-12ab-34cd-56ef-1234567890ab";
  private static final String KEY_ARN = "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/" + KEY_ID;
  private static final String MRK_ARN = "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/mrk-" + KEY_ID;

  private final KeyStoreHarness harness = KeyStoreHarness.shared();
  private final KmsClient kms = harness.kms(WEST);
  private final DynamoDbClient ddb = harness.ddb(WEST);

  @AfterEach
  void close() {
    harness.close();
  }

  // Every ARN shape AwsArnParsing and KmsArn treat differently, for both ARN configurations.
  private static final List<String> ARNS = Arrays.asList(
    KEY_ARN,
    MRK_ARN,
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":alias/my-alias",
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":alias/mrk-alias",
    KEY_ID,
    "alias/my-alias",
    "",
    "arn:aws:kms:us-west-2:" + ACCOUNT,
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/" + KEY_ID + ":extra",
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key",
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/",
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key//",
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/a/b",
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":/" + KEY_ID,
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":KEY/" + KEY_ID,
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":keys/" + KEY_ID,
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":table/" + KEY_ID,
    "arn:aws:s3:us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    "arn:aws:KMS:us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    "arn::kms:us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    "arn:aws::us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    "arn:aws:kms::" + ACCOUNT + ":key/" + KEY_ID,
    "arn:aws:kms:us-west-2::key/" + KEY_ID,
    "ARN:aws:kms:us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    "aws:aws:kms:us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    ":aws:kms:us-west-2:" + ACCOUNT + ":key/" + KEY_ID,
    "arn:aws-cn:kms:cn-north-1:" + ACCOUNT + ":key/" + KEY_ID,
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/" + repeat('k', 2048 - "arn:aws:kms:us-west-2:111122223333:key/".length()),
    "arn:aws:kms:us-west-2:" + ACCOUNT + ":key/" + repeat('k', 2049 - "arn:aws:kms:us-west-2:111122223333:key/".length())
  );

  //= spec/framework/branch-key-store.md#aws-kms-configuration
  //= type=test
  //# This ARN MUST NOT be an Alias.

  //= spec/framework/branch-key-store.md#aws-kms-configuration
  //= type=test
  //# This ARN MUST be a valid
  //# [AWS KMS Key ARN](./aws-kms/aws-kms-key-arn.md#a-valid-aws-kms-arn).
  @Test
  void kmsKeyArnConfigurations() {
    for (String arn : ARNS) {
      assertSameInfo(config(outcomeOfModel(() -> keyArn(arn)), kms, ddb).build(), arn);
    }
  }

  @Test
  void kmsMrKeyArnConfigurations() {
    for (String arn : ARNS) {
      assertSameInfo(config(outcomeOfModel(() -> mrKeyArn(arn)), kms, ddb).build(), arn);
    }
  }

  @Test
  void discoveryConfigurations() {
    assertSameInfo(config(discovery(), kms, ddb).build(), "discovery");
    for (String region : Arrays.asList(WEST, EAST, "x", "not-a-region", repeat('r', 32))) {
      assertSameInfo(config(mrDiscovery(region), kms, ddb).build(), region);
    }
  }

  @Test
  void grantTokens() {
    List<List<String>> cases = new ArrayList<>();
    cases.add(Collections.emptyList());
    cases.add(Collections.singletonList("t"));
    cases.add(Collections.singletonList(""));
    cases.add(Collections.singletonList(repeat('g', 8192)));
    cases.add(Collections.singletonList(repeat('g', 8193)));
    cases.add(Arrays.asList("a", "", "c"));
    cases.add(tokens(10));
    cases.add(tokens(11));
    cases.add(Arrays.asList("\uD800", "\uDC00x"));
    for (List<String> tokens : cases) {
      assertSameInfo(config(keyArn(KEY_ARN), kms, ddb).grantTokens(tokens).build(), tokens.size() + " tokens " + tokens);
    }
    // An invalid ARN fails before invalid grant tokens.
    assertSameInfo(config(keyArn("not-an-arn"), kms, ddb).grantTokens(tokens(11)).build(), "ARN then tokens");
  }

  @Test
  void namesAndIds() {
    for (String name : Arrays.asList("abc", repeat('t', 255), "Table.With-Chars_9", "\uD800ab")) {
      assertSameInfo(config(keyArn(KEY_ARN), kms, ddb).ddbTableName(name).build(), name);
    }
    for (String name : Arrays.asList("", "logical", "\uD800 lone surrogate", repeat('l', 70000))) {
      assertSameInfo(config(keyArn(KEY_ARN), kms, ddb).logicalKeyStoreName(name).build(), name);
    }
    for (String id : Arrays.asList("", "my-key-store", "\uDFFF")) {
      assertSameInfo(config(keyArn(KEY_ARN), kms, ddb).id(id).build(), id);
    }
    // An invalid ARN fails before an invalid table name; the model already rejects table names outside 3..255.
    assertSameInfo(config(keyArn("not-an-arn"), kms, ddb).ddbTableName("abc").build(), "ARN then table");
  }

  //= spec/framework/branch-key-store.md#keystore-id
  //= type=test
  //# If one is not supplied, then a [version 4 UUID](https://www.ietf.org/rfc/rfc4122.txt) MUST be used.
  @Test
  void defaultIdIsARandomUuid() {
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(config(keyArn(KEY_ARN), kms, ddb).build());
    String info = stores.same("GetKeyStoreInfo", null);
    assertTrue(info.contains("keyStoreId=\"<uuid>\""), info);
  }

  @Test
  void storesWithoutClientsBuildWithoutCallingAws() {
    String previous = System.getProperty("aws.region");
    // Discovery stores create their clients in the SDK's default Region.
    System.setProperty("aws.region", EAST);
    try {
      for (KMSConfiguration configuration : Arrays.asList(keyArn(KEY_ARN), mrKeyArn(MRK_ARN), discovery(), mrDiscovery(EAST))) {
        assertSameInfo(config(configuration, null, null).build(), "no clients " + configuration);
        assertSameInfo(config(configuration, kms, null).build(), "no DynamoDB client " + configuration);
        assertSameInfo(config(configuration, null, ddb).build(), "no KMS client " + configuration);
      }
    } finally {
      restore("aws.region", previous);
    }
    assertEquals(Collections.emptyList(), harness.nativeAws.requests());
  }

  private static void restore(String property, String previous) {
    if (previous == null) {
      System.clearProperty(property);
    } else {
      System.setProperty(property, previous);
    }
  }

  // Building fails or succeeds alike, and a built store reports the same info.
  private static void assertSameInfo(KeyStoreConfig config, String description) {
    KeyStoreHarness.Stores stores;
    try {
      stores = KeyStoreHarness.stores(config);
    } catch (AssertionError e) {
      throw new AssertionError(description, e);
    }
    if (stores.nativeStore != null) {
      stores.same("GetKeyStoreInfo", null);
    }
  }

  // The model builders reject some values before the key store sees them; use a valid placeholder then.
  private static KMSConfiguration outcomeOfModel(java.util.function.Supplier<KMSConfiguration> model) {
    try {
      return model.get();
    } catch (IllegalArgumentException e) {
      return keyArn("rejected-by-the-model");
    }
  }

  private static List<String> tokens(int count) {
    List<String> tokens = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      tokens.add("token-" + i);
    }
    return tokens;
  }

  private static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }
}
