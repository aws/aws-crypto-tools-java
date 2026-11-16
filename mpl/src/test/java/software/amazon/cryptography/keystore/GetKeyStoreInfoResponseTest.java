// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

class GetKeyStoreInfoResponseTest {

  private static GetKeyStoreInfoResponse.Builder complete() {
    return GetKeyStoreInfoResponse
      .builder()
      .keyStoreId("id")
      .keyStoreName("table")
      .logicalKeyStoreName("logical")
      .kmsConfiguration(KmsConfiguration.discovery());
  }

  @Test
  void buildsWithNoGrantTokensByDefault() {
    GetKeyStoreInfoResponse info = complete().build();
    assertTrue(info.grantTokens().isEmpty());
    assertEquals("table", info.keyStoreName());
    assertEquals(info, info.toBuilder().build());
  }

  @Test
  void copiesGrantTokens() {
    List<String> tokens = new ArrayList<>(Arrays.asList("a", "b"));
    GetKeyStoreInfoResponse info = complete().grantTokens(tokens).build();
    tokens.clear();
    assertEquals(Arrays.asList("a", "b"), info.grantTokens());
    assertThrows(UnsupportedOperationException.class, () -> info.grantTokens().add("c"));
    assertEquals(Collections.singletonList("t"), info.toBuilder().grantTokens("t").build().grantTokens());
  }

  @Test
  void rejectsMissingMembers() {
    assertMessage("keyStoreId", complete().keyStoreId(null));
    assertMessage("keyStoreName", complete().keyStoreName(null));
    assertMessage("logicalKeyStoreName", complete().logicalKeyStoreName(null));
    assertMessage("kmsConfiguration", complete().kmsConfiguration(null));
  }

  private static void assertMessage(String field, GetKeyStoreInfoResponse.Builder builder) {
    assertEquals("Missing value for required field `" + field + "`", assertThrows(ValidationException.class, builder::build).getMessage());
  }
}
