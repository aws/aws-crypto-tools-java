// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.model;

public enum AesWrappingAlg {
  ALG_AES128_GCM_IV12_TAG16("ALG_AES128_GCM_IV12_TAG16"),

  ALG_AES192_GCM_IV12_TAG16("ALG_AES192_GCM_IV12_TAG16"),

  ALG_AES256_GCM_IV12_TAG16("ALG_AES256_GCM_IV12_TAG16");

  private final String value;

  private AesWrappingAlg(String value) {
    this.value = value;
  }

  public String toString() {
    return String.valueOf(value);
  }
}
