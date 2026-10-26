// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.primitives.model;

public enum ECDHCurveSpec {
  ECC_NIST_P256("ECC_NIST_P256"),

  ECC_NIST_P384("ECC_NIST_P384"),

  ECC_NIST_P521("ECC_NIST_P521"),

  SM2("SM2");

  private final String value;

  private ECDHCurveSpec(String value) {
    this.value = value;
  }

  public String toString() {
    return String.valueOf(value);
  }
}
