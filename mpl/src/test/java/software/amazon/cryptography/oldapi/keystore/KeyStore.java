// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.keystore;

import java.util.Objects;
import java.util.function.Supplier;
import software.amazon.cryptography.oldapi.keystore.internal.KeyStoreConvert;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyOutput;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyStoreOutput;
import software.amazon.cryptography.oldapi.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.GetActiveBranchKeyOutput;
import software.amazon.cryptography.oldapi.keystore.model.GetBeaconKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.GetBeaconKeyOutput;
import software.amazon.cryptography.oldapi.keystore.model.GetBranchKeyVersionInput;
import software.amazon.cryptography.oldapi.keystore.model.GetBranchKeyVersionOutput;
import software.amazon.cryptography.oldapi.keystore.model.GetKeyStoreInfoOutput;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.oldapi.keystore.model.VersionKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.VersionKeyOutput;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.keystore.BranchKeyStore;

/** Test adapter: the Dafny-shaped key store client on top of {@link BranchKeyStore}. */
public class KeyStore {

  private final BranchKeyStore store;

  protected KeyStore(BuilderImpl builder) {
    KeyStoreConfig config = builder.KeyStoreConfig();
    this.store = KeyStoreConvert.call(() -> KeyStoreConvert.toNative(config).build());
  }

  public static Builder builder() {
    return new BuilderImpl();
  }

  /** The native key store behind this client. */
  public BranchKeyStore impl() {
    return store;
  }

  /** Create a new Branch Key in the Key Store. Additionally create a Beacon Key that is tied to this Branch Key. */
  public CreateKeyOutput CreateKey(CreateKeyInput input) {
    String branchKeyIdentifier = input.branchKeyIdentifier();
    EncryptionContext encryptionContext = KeyStoreConvert.encryptionContext(input.encryptionContext());
    String created = call(() -> store.createKey(b -> b.branchKeyIdentifier(branchKeyIdentifier).encryptionContext(encryptionContext)).branchKeyIdentifier());
    return CreateKeyOutput.builder().branchKeyIdentifier(created).build();
  }

  /** Create the DynamoDB table that backs this Key Store; if it exists, validate it is configured as expected. */
  public CreateKeyStoreOutput CreateKeyStore(CreateKeyStoreInput input) {
    Objects.requireNonNull(input);
    return CreateKeyStoreOutput.builder().tableArn(call(() -> store.createKeyStore().tableArn())).build();
  }

  /** Get the ACTIVE version for a particular Branch Key from the Key Store. */
  public GetActiveBranchKeyOutput GetActiveBranchKey(GetActiveBranchKeyInput input) {
    String branchKeyIdentifier = input.branchKeyIdentifier();
    return GetActiveBranchKeyOutput.builder()
      .branchKeyMaterials(KeyStoreConvert.toOld(call(() -> store.getActiveBranchKey(b -> b.branchKeyIdentifier(branchKeyIdentifier)).branchKeyMaterials())))
      .build();
  }

  /** Get a Beacon Key from the Key Store. */
  public GetBeaconKeyOutput GetBeaconKey(GetBeaconKeyInput input) {
    String branchKeyIdentifier = input.branchKeyIdentifier();
    return GetBeaconKeyOutput.builder()
      .beaconKeyMaterials(KeyStoreConvert.toOld(call(() -> store.getBeaconKey(b -> b.branchKeyIdentifier(branchKeyIdentifier)).beaconKeyMaterials())))
      .build();
  }

  /** Get a particular version of a Branch Key from the Key Store. */
  public GetBranchKeyVersionOutput GetBranchKeyVersion(GetBranchKeyVersionInput input) {
    String branchKeyIdentifier = input.branchKeyIdentifier();
    String branchKeyVersion = input.branchKeyVersion();
    return GetBranchKeyVersionOutput.builder()
      .branchKeyMaterials(KeyStoreConvert.toOld(call(() -> store.getBranchKeyVersion(b -> b.branchKeyIdentifier(branchKeyIdentifier).branchKeyVersion(branchKeyVersion)).branchKeyMaterials())))
      .build();
  }

  /** Returns the configuration information for a Key Store. */
  public GetKeyStoreInfoOutput GetKeyStoreInfo() {
    return KeyStoreConvert.toOld(store.getKeyStoreInfo());
  }

  /** Create a new ACTIVE version of an existing Branch Key, and set the previously ACTIVE version to DECRYPT_ONLY. */
  public VersionKeyOutput VersionKey(VersionKeyInput input) {
    String branchKeyIdentifier = input.branchKeyIdentifier();
    call(() -> {
      store.versionKey(b -> b.branchKeyIdentifier(branchKeyIdentifier));
      return null;
    });
    return VersionKeyOutput.builder().build();
  }

  private static <T> T call(Supplier<T> operation) {
    return KeyStoreConvert.call(operation);
  }

  public interface Builder {
    Builder KeyStoreConfig(KeyStoreConfig KeyStoreConfig);

    KeyStoreConfig KeyStoreConfig();

    KeyStore build();
  }

  static class BuilderImpl implements Builder {

    protected KeyStoreConfig KeyStoreConfig;

    protected BuilderImpl() {}

    public Builder KeyStoreConfig(KeyStoreConfig KeyStoreConfig) {
      this.KeyStoreConfig = KeyStoreConfig;
      return this;
    }

    public KeyStoreConfig KeyStoreConfig() {
      return this.KeyStoreConfig;
    }

    public KeyStore build() {
      if (Objects.isNull(this.KeyStoreConfig())) {
        throw new IllegalArgumentException("Missing value for required field `KeyStoreConfig`");
      }
      return new KeyStore(this);
    }
  }
}
