// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.EcdhEdkWrapping;
import software.amazon.cryptography.mpl.internal.EdkWrapping;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.MaterialsAccess;
import software.amazon.cryptography.mpl.internal.MaterialsRules;
import software.amazon.cryptography.mpl.internal.SecretBytesAccess;
import software.amazon.cryptography.mpl.internal.primitives.Bytes;
import software.amazon.cryptography.mpl.internal.primitives.Ecdh;

/**
 * Wraps data keys with a key derived by ECDH from local keys.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/raw-ecdh-keyring.md">Raw ECDH keyring</a>.
 *
 * <p>Each encrypted data key has provider id {@code raw-ecdh} and names the sender's and recipient's compressed public keys
 * in its provider info. On decrypt the keyring also tries {@code aws-kms-ecdh} keys,
 * and a static keyring accepts a key whose sender and recipient are its own recipient and sender.
 * Thread-safe.
 */
//= spec/framework/raw-ecdh-keyring.md#interface
//= type=implication
//# MUST implement the [AWS Encryption SDK Keyring interface](../keyring-interface.md#interface)
public final class RawEcdhKeyring implements Keyring {

  private final RawEcdhStaticConfigurations keyAgreementScheme;
  private final EcdhCurveSpec curveSpec;
  // The configured key, or for discovery the one derived from the recipient's private key.
  private final byte[] recipientPublicKey;
  private final byte[] compressedRecipientPublicKey;
  // Empty unless the sender key pair is static.
  private final byte[] compressedSenderPublicKey;

  private RawEcdhKeyring(Builder builder, byte[] recipientPublicKey, byte[] compressedRecipientPublicKey, byte[] compressedSenderPublicKey) {
    this.keyAgreementScheme = builder.keyAgreementScheme;
    this.curveSpec = builder.curveSpec;
    this.recipientPublicKey = recipientPublicKey;
    this.compressedRecipientPublicKey = compressedRecipientPublicKey;
    this.compressedSenderPublicKey = compressedSenderPublicKey;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** Which keys are fixed: see {@link RawEcdhStaticConfigurations}. */
  public RawEcdhStaticConfigurations keyAgreementScheme() {
    return keyAgreementScheme;
  }

  /** The curve of both key pairs. */
  public EcdhCurveSpec curveSpec() {
    return curveSpec;
  }

//= spec/framework/raw-ecdh-keyring.md#onencrypt
//= type=implication
//# OnEncrypt MUST take [encryption materials](structures.md#encryption-materials) as input.
  @Override
  public EncryptionMaterials onEncrypt(OnEncryptRequest request) {
    EncryptionMaterials materials = request.materials();
    RawEcdhStaticConfigurations.Kind kind = keyAgreementScheme.kind();
    //= spec/framework/raw-ecdh-keyring.md#onencrypt
    //= type=implication
    //# OnEncrypt MUST fail if configured with a
    //# [PublicKeyDiscovery Key Agreement Configuration](./key-agreement-schemas.md#publickeydiscovery)
    if (kind == RawEcdhStaticConfigurations.Kind.PUBLIC_KEY_DISCOVERY) {
      throw new ValidationException("PublicKeyDiscovery Key Agreement Scheme is forbidden on encrypt.");
    }
    byte[] sharedSecret;
    byte[] senderPublicKey;
    //= spec/framework/raw-ecdh-keyring.md#onencrypt
    //# The keyring MUST derive the shared secret
    //# according to the configured [Key Agreement Schema](#key-agreement-procedure).
    
    //= spec/framework/raw-ecdh-keyring.md#onencrypt
    //# If the keyring fails to compute the shared secret, the keyring MUST fail.
    if (kind == RawEcdhStaticConfigurations.Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY) {
      byte[][] ephemeral = Ecdh.generateKeyPair(curveSpec);
      try {
        senderPublicKey = Ecdh.compressPublicKey(ephemeral[1]);
        sharedSecret = Ecdh.deriveSharedSecret(curveSpec, ephemeral[0], recipientPublicKey);
      } finally {
        Bytes.zero(ephemeral[0]);
      }
    } else {
      senderPublicKey = compressedSenderPublicKey;
      sharedSecret = SecretBytesAccess.apply(keyAgreementScheme.privateKey(), key -> Ecdh.deriveSharedSecret(curveSpec, key, recipientPublicKey));
    }
    try {
      //= spec/framework/raw-ecdh-keyring.md#onencrypt
      //= type=implication
      //# If the keyring cannot serialize
      //# the encryption context, OnEncrypt MUST fail.
      byte[] fixedInfo = EcdhEdkWrapping.fixedInfo(curveSpec, senderPublicKey, compressedRecipientPublicKey, materials.encryptionContext());
      //= spec/framework/raw-ecdh-keyring.md#onencrypt
      //# The keyring MUST perform data key wrapping according to the [Data Key Wrapping section](#data-key-wrapping).
      EdkWrapping.WrapResult<Void> result = EdkWrapping.wrap(
        materials,
        EcdhEdkWrapping.wrap(sharedSecret, fixedInfo),
        EcdhEdkWrapping.generateAndWrap(sharedSecret, fixedInfo)
      );
      //= spec/framework/raw-ecdh-keyring.md#key-provider-information
      //# Both the recipient and the sender public keys MUST be in their compressed formats.
      byte[] providerInfo = EcdhEdkWrapping.providerInfo(senderPublicKey, compressedRecipientPublicKey);
      //= spec/framework/raw-ecdh-keyring.md#onencrypt
      //# - The [key provider id](../structures.md#key-provider-id) MUST be the UTF8 encoded string "raw-ecdh".
      
      //= spec/framework/raw-ecdh-keyring.md#data-key-wrapping
      //# If the keyring successfully wraps the plaintext data key it MUST set it on the [encryption materials](structures.md#encryption-materials).
      return result.addTo(materials, EncryptedDataKey.of(EcdhEdkWrapping.RAW_PROVIDER_ID, providerInfo, result.wrappedMaterial));
    } finally {
      Bytes.zero(sharedSecret);
    }
  }

  @Override
  public DecryptionMaterials onDecrypt(OnDecryptRequest request) {
    DecryptionMaterials materials = request.materials();
    List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //= type=implication
    //# OnDecrypt MUST fail if configured with a
    //# [EphemeralPrivateKeyToStaticPublicKey Key Agreement Configuration](./key-agreement-schemas.md#ephemeralprivatekeytostaticpublickey)
    
    //= spec/framework/key-agreement-schemas.md#ephemeralprivatekeytostaticpublickey
    //# On decrypt, the keyring MUST fail.
    if (keyAgreementScheme.kind() == RawEcdhStaticConfigurations.Kind.EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY) {
      throw new ValidationException("EphemeralPrivateKeyToStaticPublicKey Key Agreement Scheme is forbidden on decrypt.");
    }
    MaterialsRules.Decryption fields = MaterialsAccess.fields(materials);
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# If the decryption materials already contain a plaintext data key,
    //# the keyring MUST fail
    //# and MUST NOT modify the [decryption materials](structures.md#decryption-materials).
    if (fields.plaintextDataKey != null || !MaterialsRules.isValid(fields)) {
      throw new InvalidMaterialsException("Keyring received decryption materials that already contain a plaintext data key.");
    }
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# The set of encrypted data keys MUST first be filtered to match this keyring’s configuration.
    //# For the encrypted data key to match:
    // Every key is filtered before any is tried; a malformed provider info fails the whole call.
    List<EncryptedDataKey> matching = new ArrayList<>();
    List<EcdhEdkWrapping.ProviderInfo> infos = new ArrayList<>();
    for (EncryptedDataKey edk : encryptedDataKeys) {
      String id = edk.keyProviderId();
      //= spec/framework/raw-ecdh-keyring.md#ondecrypt
      //# - The key provider ID of the encrypted data key MUST have a value equal to the UTF8 encoded strings `raw-ecdh` OR `aws-kms-ecdh`.
      if (id.equals(EcdhEdkWrapping.RAW_PROVIDER_ID) || id.equals(EcdhEdkWrapping.KMS_PROVIDER_ID)) {
        //= spec/framework/raw-ecdh-keyring.md#ondecrypt
        //# - The [ciphertext](#ciphertext) and [key provider information](#key-provider-information) MUST be successfully deserialized.
        EcdhEdkWrapping.ProviderInfo info = EcdhEdkWrapping.parseProviderInfo(edk.keyProviderInfo());
        //= spec/framework/raw-ecdh-keyring.md#ondecrypt
        //# - MUST first verify that the uncompressed deserialized sender public key
        //#   and the uncompressed deserialized recipient public key match the public
        //#   keys configured on the keyring.
        if (matches(info)) {
          matching.add(edk);
          infos.add(info);
        }
      }
    }
    if (matching.isEmpty()) {
      throw new NoMatchingDataKeyException(KeyringNames.incorrectDataKeys(encryptedDataKeys, fields.suite), new ArrayList<>());
    }
    List<Throwable> errors = new ArrayList<>();
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# For each encrypted data key in the filtered set, one at a time, the OnDecrypt MUST attempt to decrypt the data key.
    //# If this attempt results in an error, then these errors MUST be collected.
    for (int i = 0; i < matching.size(); i++) {
      EdkWrapping.UnwrapResult<Void> unwrapped;
      try {
        unwrapped = decrypt(materials, matching.get(i), infos.get(i));
      } catch (RuntimeException e) {
        errors.add(e);
        continue;
      }
      //= spec/framework/raw-ecdh-keyring.md#ondecrypt
      //# - MUST set the plaintext data key on the [decryption materials](./structures.md#decryption-materials)
      //# - MUST immediately return the modified [decryption materials](../structures.md#decryption-materials).
      return unwrapped.addTo(materials);
    }
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# If OnDecrypt fails to successfully decrypt any encrypted data key,
    //# then it MUST yield an error that includes all the collected errors.
    throw new NoMatchingDataKeyException(
      "No Configured Key was able to decrypt the Data Key. The list of encountered Exceptions is available via `list`.",
      errors
    );
  }

  // Discovery checks only the recipient; a static keyring also accepts its own keys with the roles swapped.
  private boolean matches(EcdhEdkWrapping.ProviderInfo info) {
    boolean recipient = Arrays.equals(compressedRecipientPublicKey, info.recipientPublicKey);
    //= spec/framework/key-agreement-schemas.md#publickeydiscovery
    //# - MUST verify that the recipient public key stored on
    //# the message ciphertext matches the configured recipient's
    //# public key.
    if (keyAgreementScheme.kind() == RawEcdhStaticConfigurations.Kind.PUBLIC_KEY_DISCOVERY) {
      return recipient;
    }
    //= spec/framework/key-agreement-schemas.md#rawprivatekeytostaticpublickey
    //# - MUST verify that both the configured sender's and recipient's
    //#   public keys match the public keys stored on the message ciphertext.
    return (
      (recipient && Arrays.equals(compressedSenderPublicKey, info.senderPublicKey)) ||
      (Arrays.equals(compressedSenderPublicKey, info.recipientPublicKey) && Arrays.equals(compressedRecipientPublicKey, info.senderPublicKey))
    );
  }

  private EdkWrapping.UnwrapResult<Void> decrypt(DecryptionMaterials materials, EncryptedDataKey edk, EcdhEdkWrapping.ProviderInfo info) {
    byte[] ciphertext = edk.ciphertext();
    EdkWrapping.providerWrappedMaterial(ciphertext, materials.algorithmSuite());
    // The other party's key. A static keyring's matching encrypted data key names its configured recipient either as the recipient
    // (this keyring sent it) or as the sender (sent to this keyring), so the other key is always the configured recipient's,
    // already validated at creation. A discovery keyring takes the message's sender key.
    byte[] otherPublicKey;
    if (keyAgreementScheme.kind() == RawEcdhStaticConfigurations.Kind.PUBLIC_KEY_DISCOVERY) {
      otherPublicKey = Ecdh.decompressPublicKey(info.senderPublicKey, curveSpec);
      EcdhEdkWrapping.requireValidPublicKey(Ecdh.validatePublicKey(curveSpec, otherPublicKey), "sender public key in the provider info");
    } else {
      otherPublicKey = recipientPublicKey;
    }
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# The keyring MUST derive the shared secret
    //# according to the configured [Key Agreement Schema](#key-agreement-procedure).
    
    //= spec/framework/raw-ecdh-keyring.md#ondecrypt
    //# If the Key Agreement step fails, then an error MUST be collected
    //# and the next encrypted data key in the filtered set MUST be attempted.
    byte[] sharedSecret = SecretBytesAccess.apply(keyAgreementScheme.privateKey(), key -> Ecdh.deriveSharedSecret(curveSpec, key, otherPublicKey));
    try {
      //= spec/framework/raw-ecdh-keyring.md#ondecrypt
      //# The keyring MUST perform data key unwrapping according to the [Data Key Unwrapping section](#data-key-unwrapping).
      return EdkWrapping.unwrap(ciphertext, materials, EcdhEdkWrapping.unwrap(sharedSecret, curveSpec, info));
    } finally {
      Bytes.zero(sharedSecret);
    }
  }

  /**
   * Not thread-safe.
   * Requires {@code keyAgreementScheme}, {@code curveSpec}.
   * {@link #build()} throws {@link software.amazon.cryptography.mpl.exceptions.ValidationException} for invalid settings:
   * a key that does not parse, a key not on {@code curveSpec}, a recipient public key whose point has x = 0, or {@code SM2}.
   *
   * <p>On decrypt, an encrypted data key whose sender public key has x = 0 fails like any other key that does not decrypt.
   */
  public static final class Builder {

    // The DER length of a P-256, P-384, or P-521 public key with a named curve and an uncompressed point.
    private static final int[] PUBLIC_KEY_LENGTHS = { 91, 120, 158 };

    private RawEcdhStaticConfigurations keyAgreementScheme;
    private EcdhCurveSpec curveSpec;

    private Builder() {}

    /** Which keys are fixed: see {@link RawEcdhStaticConfigurations}. */
    public Builder keyAgreementScheme(RawEcdhStaticConfigurations keyAgreementScheme) {
      this.keyAgreementScheme = keyAgreementScheme;
      return this;
    }

    /** The curve of both key pairs. */
    public Builder curveSpec(EcdhCurveSpec curveSpec) {
      this.curveSpec = curveSpec;
      return this;
    }

    // CreateRawEcdhKeyring.
    public RawEcdhKeyring build() {
      //= spec/framework/raw-ecdh-keyring.md#initialization
      //= type=implication
      //# - MUST provide a [Key Agreement Schema](#key-agreement-schema)
      KeyringNames.requireSet(keyAgreementScheme, "keyAgreementScheme");
      //= spec/framework/raw-ecdh-keyring.md#initialization
      //= type=implication
      //# - MUST provide a [Curve Specification](#curve-specification)
      KeyringNames.requireSet(curveSpec, "curveSpec");
      byte[] recipientPublicKey;
      byte[] compressedSenderPublicKey = new byte[0];
      switch (keyAgreementScheme.kind()) {
        case RAW_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY:
          //= spec/framework/key-agreement-schemas.md#rawprivatekeytostaticpublickey
          //# - MUST provide the recipient's public key
          recipientPublicKey = keyAgreementScheme.recipientPublicKey();
          // Not validated: this key is on curveSpec by construction, and no private key for a point with x = 0 is known.
          //= spec/framework/key-agreement-schemas.md#rawprivatekeytostaticpublickey
          //# - MUST provide the sender's static private key
          byte[] senderPublicKey = SecretBytesAccess.apply(keyAgreementScheme.privateKey(), key -> Ecdh.publicKeyFromPrivateKey(curveSpec, key));
          compressedSenderPublicKey = Ecdh.compressPublicKey(senderPublicKey);
          break;
        case EPHEMERAL_PRIVATE_KEY_TO_STATIC_PUBLIC_KEY:
          //= spec/framework/key-agreement-schemas.md#ephemeralprivatekeytostaticpublickey
          //# - MUST provide the recipient's public key
          recipientPublicKey = keyAgreementScheme.recipientPublicKey();
          break;
        default:
          //= spec/framework/key-agreement-schemas.md#publickeydiscovery
          //# - MUST provide the recipient's static private key
          recipientPublicKey = SecretBytesAccess.apply(keyAgreementScheme.privateKey(), key -> Ecdh.publicKeyFromPrivateKey(curveSpec, key));
          break;
      }
      byte[] compressedRecipientPublicKey = Ecdh.compressPublicKey(recipientPublicKey);
      // Throws for a key not on curveSpec. A false result is rejected after the length check, which a key may also fail.
      //= spec/framework/raw-ecdh-keyring.md#initialization
      //# On initialization, the keyring MUST assert that the recipient's public key
      //# and the sender's private key belong to the same ECC Curve, and that
      //# the public key's ECC points are not the "points at infinity".
      boolean valid = Ecdh.validatePublicKey(curveSpec, recipientPublicKey);
      // The key validates on curveSpec, so only another encoding of it has another length (explicit parameters, compressed point).
      // A sender key comes from publicKeyFromPrivateKey, which always has the standard length.
      int length = recipientPublicKey.length;
      if (Arrays.stream(PUBLIC_KEY_LENGTHS).noneMatch(standard -> standard == length)) {
        throw new ValidationException("Invalid recipient public key length");
      }
      // For discovery this is the key derived from the private key, which cannot have x = 0 (no such private key is known),
      // like the derived sender key, which is not checked.
      EcdhEdkWrapping.requireValidPublicKey(valid, "recipient public key");
      //= spec/framework/raw-ecdh-keyring.md#initialization
      //= type=implication
      //# The keyring MUST set the sender's public key
      //# and the recipient's public key on the keyring.
      return new RawEcdhKeyring(this, recipientPublicKey, compressedRecipientPublicKey, compressedSenderPublicKey);
    }
  }
}
