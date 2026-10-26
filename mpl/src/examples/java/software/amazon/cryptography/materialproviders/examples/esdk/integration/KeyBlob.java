// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk.integration;

import software.amazon.cryptography.materialproviders.EncryptedDataKey;

/**
 * Stand-in for the ESDK's {@code com.amazonaws.encryptionsdk.model.KeyBlob}: an encrypted data key as the message header holds it.
 * Shows the conversion to and from the MPL's {@link EncryptedDataKey}.
 */
public final class KeyBlob {

  private final String providerId;
  private final byte[] providerInformation;
  private final byte[] encryptedDataKey;

  public KeyBlob(String providerId, byte[] providerInformation, byte[] encryptedDataKey) {
    this.providerId = providerId;
    this.providerInformation = providerInformation.clone();
    this.encryptedDataKey = encryptedDataKey.clone();
  }

  /** Replaces {@code new KeyBlob(edk.keyProviderId(), edk.keyProviderInfo().array(), edk.ciphertext().array())}. */
  public static KeyBlob from(EncryptedDataKey edk) {
    return new KeyBlob(edk.keyProviderId(), edk.keyProviderInfo(), edk.ciphertext());
  }

  /** Replaces the {@code EncryptedDataKey.builder()} with two {@code ByteBuffer.wrap} calls in {@code CMMHandler}. */
  public EncryptedDataKey toEncryptedDataKey() {
    return EncryptedDataKey.of(providerId, providerInformation, encryptedDataKey);
  }

  public String getProviderId() {
    return providerId;
  }

  public byte[] getProviderInformation() {
    return providerInformation.clone();
  }

  public byte[] getEncryptedDataKey() {
    return encryptedDataKey.clone();
  }
}
