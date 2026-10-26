// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.model;

public enum PaddingScheme {
  PKCS1("PKCS1"),

  OAEP_SHA1_MGF1("OAEP_SHA1_MGF1"),

  OAEP_SHA256_MGF1("OAEP_SHA256_MGF1"),

  OAEP_SHA384_MGF1("OAEP_SHA384_MGF1"),

  OAEP_SHA512_MGF1("OAEP_SHA512_MGF1");

  private final String value;

  private PaddingScheme(String value) {
    this.value = value;
  }

  public String toString() {
    return String.valueOf(value);
  }
}
