// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;

/** Test adapter: a native keyring behind the old keyring interface. */
public final class NativeKeyring implements IKeyring {

  private final Keyring keyring;

  public NativeKeyring(Keyring keyring) {
    this.keyring = keyring;
  }

  public Keyring keyring() {
    return keyring;
  }

  @Override
  public OnEncryptOutput OnEncrypt(OnEncryptInput input) {
    Boundary.encryptionMaterials(input.materials());
    try {
      return OnEncryptOutput
        .builder()
        .materials(Convert.materials(keyring.onEncrypt(OnEncryptRequest.builder().materials(MaterialsAccess.encryption(Convert.fields(input.materials()))).build())))
        .build();
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  @Override
  public OnDecryptOutput OnDecrypt(OnDecryptInput input) {
    Boundary.decryptionMaterials(input.materials());
    List<software.amazon.cryptography.mpl.EncryptedDataKey> edks = new ArrayList<>();
    for (EncryptedDataKey edk : input.encryptedDataKeys()) {
      edks.add(Convert.edk(Boundary.encryptedDataKey(edk)));
    }
    try {
      return OnDecryptOutput
        .builder()
        .materials(Convert.materials(keyring.onDecrypt(
            OnDecryptRequest.builder().materials(MaterialsAccess.decryption(Convert.fields(input.materials()))).encryptedDataKeys(edks).build()
          )))
        .build();
    } catch (RuntimeException e) {
      if (isIncorrectDataKeysFailure(e)) {
        dafnyIncorrectDataKeysFailure(edks, Convert.suite(input.materials().algorithmSuite().id()));
      }
      throw Errors.toOld(e);
    }
  }

  // ErrorMessages.IncorrectDataKeys, or a failure while building it.
  private static boolean isIncorrectDataKeysFailure(RuntimeException e) {
    if (e instanceof NoMatchingDataKeyException && e.getMessage().startsWith(KeyringNames.INCORRECT_DATA_KEYS)) {
      return true;
    }
    for (StackTraceElement frame : e.getStackTrace()) {
      if (frame.getClassName().equals(KeyringNames.class.getName()) && frame.getMethodName().equals("incorrectDataKeys")) {
        return true;
      }
    }
    return false;
  }

  // Bug B11: while building the no-match message, the Dafny-based MPL decoded each key's provider info as UTF-8 and failed
  // on the first that was not (a Raw AES key's always is not), before reaching any later key's structure check.
  // The native message shows such info as hex instead.
  private static void dafnyIncorrectDataKeysFailure(
    List<software.amazon.cryptography.mpl.EncryptedDataKey> edks,
    software.amazon.cryptography.mpl.AlgorithmSuite suite
  ) {
    for (int i = 0; i < edks.size(); i++) {
      if (!isUtf8(edks.get(i).keyProviderInfo())) {
        // A malformed hierarchy key before this one fails first, as the native message builder reports it.
        try {
          KeyringNames.incorrectDataKeys(edks.subList(0, i), suite);
        } catch (RuntimeException e) {
          throw Errors.toOld(e);
        }
        throw AwsCryptographicMaterialProvidersException.builder().message("Could not encode input to Dafny Bytes.").build();
      }
    }
  }

  private static boolean isUtf8(byte[] bytes) {
    try {
      StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes));
      return true;
    } catch (CharacterCodingException e) {
      return false;
    }
  }
}
