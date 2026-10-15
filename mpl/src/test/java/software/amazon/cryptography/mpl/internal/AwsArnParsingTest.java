// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.AwsArnParsing.AwsKmsIdentifier;

class AwsArnParsingTest {

  // UTF8.IsASCIIString accepts characters below 128; the differential tests only use characters far above it.
  // AwsArnParsing.dfy checks the resource before the other ARN fields: an ARN failing both reports the resource.
  @Test
  void theResourceIsCheckedFirst() {
    ValidationException e = assertThrows(ValidationException.class, () -> AwsKmsIdentifier.parseArn("arn:aws:sns:us-east-1:123:foo"));
    assertEquals("Malformed resource: foo", e.getMessage());
  }

  @Test
  void asciiBoundary() {
    assertEquals("alias/\u007f", AwsKmsIdentifier.parseIdentifierString("alias/\u007f").toString());
    assertEquals("alias/\u007f", AwsKmsIdentifier.validateKeyId("alias/\u007f").toString());
    assertEquals(
      "Not a valid ASCII string.",
      assertThrows(ValidationException.class, () -> AwsKmsIdentifier.parseIdentifierString("alias/\u0080")).getMessage()
    );
    assertEquals(
      "Key identifier is not ASCII",
      assertThrows(ValidationException.class, () -> AwsKmsIdentifier.validateKeyId("alias/\u0080")).getMessage()
    );
  }
}
