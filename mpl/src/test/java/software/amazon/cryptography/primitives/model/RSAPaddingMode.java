// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.primitives.model;

public enum RSAPaddingMode {
  PKCS1("PKCS1"),

  OAEP_SHA1("OAEP_SHA1"),

  OAEP_SHA256("OAEP_SHA256"),

  OAEP_SHA384("OAEP_SHA384"),

  OAEP_SHA512("OAEP_SHA512");

  private final String value;

  private RSAPaddingMode(String value) {
    this.value = value;
  }

  public String toString() {
    return String.valueOf(value);
  }
}
