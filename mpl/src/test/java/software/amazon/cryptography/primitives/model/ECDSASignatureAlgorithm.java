// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.primitives.model;

public enum ECDSASignatureAlgorithm {
  ECDSA_P384("ECDSA_P384"),

  ECDSA_P256("ECDSA_P256");

  private final String value;

  private ECDSASignatureAlgorithm(String value) {
    this.value = value;
  }

  public String toString() {
    return String.valueOf(value);
  }
}
