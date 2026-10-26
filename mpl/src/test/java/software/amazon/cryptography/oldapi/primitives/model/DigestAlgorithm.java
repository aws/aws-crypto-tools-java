// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.primitives.model;

public enum DigestAlgorithm {
  SHA_512("SHA_512"),

  SHA_384("SHA_384"),

  SHA_256("SHA_256");

  private final String value;

  private DigestAlgorithm(String value) {
    this.value = value;
  }

  public String toString() {
    return String.valueOf(value);
  }
}
