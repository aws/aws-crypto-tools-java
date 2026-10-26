// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.vectors;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkKeyring;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawEcdhStaticConfigurations;
import software.amazon.cryptography.materialproviders.keyrings.RawRsaKeyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;

/** The native MPL, through its public API only: KeyringFromKeyDescription and CmmFromKeyDescription. */
final class NativeSide implements Side {

  /** Why the KMS RSA and KMS ECDH vectors are not run; the fake KMS cannot hold the manifest's private keys. */
  static final String KMS_ASYMMETRIC_SKIP =
    "the manifest's public key belongs to a private key that exists only in real KMS; the fake KMS cannot model it";

  private final VectorEnvironment env;

  NativeSide(VectorEnvironment env) {
    this.env = env;
  }

  @Override
  public String name() {
    return "native";
  }

  @Override
  public Cmm cmm(KeyDescription description) {
    CryptographicMaterialsManager cmm = toCmm(description);
    return new Cmm() {
      @Override
      public Encrypted getEncryptionMaterials(TestVectors.EncryptVector vector) {
        GetEncryptionMaterialsRequest.Builder request = GetEncryptionMaterialsRequest
          .builder()
          .encryptionContext(EncryptionContext.copyOf(vector.encryptionContext))
          .commitmentPolicy(vector.commitmentPolicy())
          .algorithmSuiteId(vector.algorithmSuite);
        vector.maxPlaintextLength.ifPresent(request::maxPlaintextLength);
        if (vector.requiredEncryptionContextKeys != null) {
          request.requiredEncryptionContextKeys(vector.requiredEncryptionContextKeys);
        }
        EncryptionMaterials materials = cmm.getEncryptionMaterials(request.build()).encryptionMaterials();
        List<TestVectors.Edk> edks = new ArrayList<>();
        for (EncryptedDataKey edk : materials.encryptedDataKeys()) {
          edks.add(new TestVectors.Edk(edk.keyProviderId(), edk.keyProviderInfo(), edk.ciphertext()));
        }
        List<byte[]> symmetricSigningKeys = new ArrayList<>();
        materials.symmetricSigningKeys().forEach(k -> symmetricSigningKeys.add(k.toByteArray()));
        return new Encrypted(
          materials.encryptionContext(),
          edks,
          materials.plaintextDataKey().map(SecretBytes::toByteArray).orElse(null),
          symmetricSigningKeys
        );
      }

      @Override
      public Decrypted decryptMaterials(TestVectors.DecryptVector vector) {
        List<EncryptedDataKey> edks = new ArrayList<>();
        for (TestVectors.Edk edk : vector.encryptedDataKeys) {
          edks.add(EncryptedDataKey.of(edk.keyProviderId, edk.keyProviderInfo, edk.ciphertext));
        }
        DecryptMaterialsRequest.Builder request = DecryptMaterialsRequest
          .builder()
          .algorithmSuiteId(vector.algorithmSuite)
          .commitmentPolicy(vector.commitmentPolicy())
          .encryptedDataKeys(edks)
          .encryptionContext(EncryptionContext.copyOf(vector.encryptionContext));
        if (vector.reproducedEncryptionContext != null) {
          request.reproducedEncryptionContext(EncryptionContext.copyOf(vector.reproducedEncryptionContext));
        }
        DecryptionMaterials materials = cmm.decryptMaterials(request.build()).decryptionMaterials();
        return new Decrypted(
          materials.plaintextDataKey().map(SecretBytes::toByteArray).orElse(null),
          materials.symmetricSigningKey().map(SecretBytes::toByteArray).orElse(null),
          materials.requiredEncryptionContextKeys()
        );
      }
    };
  }

  private CryptographicMaterialsManager toCmm(KeyDescription description) {
    if (description instanceof KeyDescription.RequiredEncryptionContext) {
      KeyDescription.RequiredEncryptionContext required = (KeyDescription.RequiredEncryptionContext) description;
      return RequiredEncryptionContextCryptographicMaterialsManager
        .builder()
        .underlyingCmm(toCmm(required.underlying))
        .requiredEncryptionContextKeys(required.requiredEncryptionContextKeys)
        .build();
    }
    return DefaultCryptographicMaterialsManager.of(toKeyring(description));
  }

  private Keyring toKeyring(KeyDescription description) {
    KeyMaterial material = env.keys.get(description.keyId());
    if (description instanceof KeyDescription.Static) {
      return new StaticMaterialsKeyring(need(material, KeyMaterial.StaticMaterial.class, "Not type: StaticMaterial"));
    }
    if (description instanceof KeyDescription.Kms) {
      String arn = need(material, KeyMaterial.Kms.class, "Not type: KMS").keyIdentifier;
      return AwsKmsKeyring.builder().kmsKeyId(arn).kmsClient(env.kms(VectorEnvironment.region(arn))).build();
    }
    if (description instanceof KeyDescription.KmsMrk) {
      String arn = need(material, KeyMaterial.Kms.class, "Not type: KMS").keyIdentifier;
      return AwsKmsMrkKeyring.builder().kmsKeyId(arn).kmsClient(env.kms(VectorEnvironment.region(arn))).build();
    }
    if (description instanceof KeyDescription.KmsRsa || description instanceof KeyDescription.KmsEcdh) {
      throw new Skipped(KMS_ASYMMETRIC_SKIP);
    }
    if (description instanceof KeyDescription.Hierarchy) {
      KeyMaterial.StaticBranchKey branchKey = need(material, KeyMaterial.StaticBranchKey.class, "Not type: StaticKeyStoreInformation");
      return AwsKmsHierarchicalKeyring.builder().branchKeyId(branchKey.keyIdentifier).keyStore(env.keyStore()).ttl(Duration.ofSeconds(11)).build();
    }
    if (description instanceof KeyDescription.KmsMrkDiscovery) {
      KeyDescription.KmsMrkDiscovery discovery = (KeyDescription.KmsMrkDiscovery) description;
      if (material != null) {
        throw new VectorException("Discovery has not key");
      }
      AwsKmsMrkDiscoveryMultiKeyring.Builder builder = AwsKmsMrkDiscoveryMultiKeyring
        .builder()
        .regions(java.util.Collections.singletonList(discovery.defaultMrkRegion))
        .clientSupplier(env::kms);
      discovery.filter.ifPresent(f -> builder.discoveryFilter(DiscoveryFilter.of(f.accountIds, f.partition)));
      return builder.build();
    }
    if (description instanceof KeyDescription.RawAes) {
      KeyDescription.RawAes aes = (KeyDescription.RawAes) description;
      KeyMaterial.Symmetric key = need(material, KeyMaterial.Symmetric.class, "Not type: Symmetric");
      return RawAesKeyring
        .builder()
        .keyNamespace(aes.providerId)
        .keyName(key.keyIdentifier)
        .wrappingKey(SecretBytes.copyOf(key.wrappingKey))
        .wrappingAlg(wrappingAlg(key.bits))
        .build();
    }
    if (description instanceof KeyDescription.RawRsa) {
      KeyDescription.RawRsa rsa = (KeyDescription.RawRsa) description;
      RawRsaKeyring.Builder builder = RawRsaKeyring.builder().keyNamespace(rsa.providerId).paddingScheme(rsa.padding);
      if (material instanceof KeyMaterial.PrivateRsa) {
        KeyMaterial.PrivateRsa key = (KeyMaterial.PrivateRsa) material;
        if (!key.decrypt) {
          throw new VectorException("Private RSA keys only supports decrypt.");
        }
        return builder.keyName(key.keyIdentifier).privateKey(SecretBytes.copyOf(utf8(key.pem))).build();
      }
      KeyMaterial.PublicRsa key = need(material, KeyMaterial.PublicRsa.class, "Not type: PrivateRSA or PublicRSA");
      if (!key.encrypt) {
        throw new VectorException("Public RSA keys only supports encrypt.");
      }
      return builder.keyName(key.keyIdentifier).publicKey(utf8(key.pem)).build();
    }
    if (description instanceof KeyDescription.RawEcdh) {
      return rawEcdh((KeyDescription.RawEcdh) description, material);
    }
    KeyDescription.Multi multi = (KeyDescription.Multi) description;
    MultiKeyring.Builder builder = MultiKeyring.builder();
    if (multi.generator != null) {
      builder.generator(childKeyring(multi.generator));
    }
    List<Keyring> children = new ArrayList<>();
    for (KeyDescription child : multi.childKeyrings) {
      children.add(childKeyring(child));
    }
    return builder.childKeyrings(children).build();
  }

  private Keyring childKeyring(KeyDescription child) {
    if (!child.isKeyring()) {
      throw new VectorException("Only Keyring key descriptions are supported.");
    }
    return toKeyring(child);
  }

  private Keyring rawEcdh(KeyDescription.RawEcdh ecdh, KeyMaterial material) {
    EcdhCurveSpec curve = curve(ecdh.curveSpec);
    RawEcdhStaticConfigurations scheme;
    switch (ecdh.keyAgreementScheme) {
      case "static":
        {
          KeyMaterial.PrivateEcdh key = need(material, KeyMaterial.PrivateEcdh.class, "Not type: PrivateECDH");
          scheme = RawEcdhStaticConfigurations.rawPrivateKeyToStaticPublicKey(
            SecretBytes.copyOf(utf8(key.senderPem)),
            Base64.getDecoder().decode(key.recipientPublicKey)
          );
          break;
        }
      case "ephemeral":
        {
          KeyMaterial.PrivateEcdh key = need(env.keys.get(ecdh.recipientKeyId), KeyMaterial.PrivateEcdh.class, "Not type: PrivateECDH");
          scheme = RawEcdhStaticConfigurations.ephemeralPrivateKeyToStaticPublicKey(Base64.getDecoder().decode(key.recipientPublicKey));
          break;
        }
      case "discovery":
        {
          KeyMaterial.PrivateEcdh key = need(env.keys.get(ecdh.recipientKeyId), KeyMaterial.PrivateEcdh.class, "Not type: PrivateECDH");
          scheme = RawEcdhStaticConfigurations.publicKeyDiscovery(SecretBytes.copyOf(utf8(key.recipientPem)));
          break;
        }
      default:
        throw new VectorException("key agreement schema not recognized");
    }
    return RawEcdhKeyring.builder().curveSpec(curve).keyAgreementScheme(scheme).build();
  }

  // KeyDescription.Curve2EccAlgorithmSpec.
  static EcdhCurveSpec curve(String curveSpec) {
    switch (curveSpec) {
      case "ecc-256":
        return EcdhCurveSpec.ECC_NIST_P256;
      case "ecc-384":
        return EcdhCurveSpec.ECC_NIST_P384;
      case "ecc-521":
        return EcdhCurveSpec.ECC_NIST_P521;
      default:
        throw new VectorException("Unknown curve spec");
    }
  }

  static AesWrappingAlg wrappingAlg(long bits) {
    switch ((int) bits) {
      case 128:
        return AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16;
      case 192:
        return AesWrappingAlg.ALG_AES192_GCM_IV12_TAG16;
      case 256:
        return AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16;
      default:
        throw new VectorException("Not a supported bit length");
    }
  }

  static <T extends KeyMaterial> T need(KeyMaterial material, Class<T> type, String message) {
    if (!type.isInstance(material)) {
      throw new VectorException(message);
    }
    return type.cast(material);
  }

  static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * CreateStaticKeyrings.StaticMaterialsKeyring: returns the manifest's materials whatever it is given, so the CMM's
   * checks of a keyring's result are what the vectors test. The native materials API cannot hold encrypted data keys
   * without a plaintext data key, so for such materials adding the first one throws here instead of the CMM rejecting
   * the result; the vector fails either way.
   */
  static final class StaticMaterialsKeyring implements Keyring {

    private final KeyMaterial.StaticMaterial material;

    StaticMaterialsKeyring(KeyMaterial.StaticMaterial material) {
      this.material = material;
    }

    @Override
    public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
      EncryptionMaterials materials = request.materials();
      EncryptionMaterials result = EncryptionMaterials
        .builder(material.algorithmSuite)
        .encryptionContext(EncryptionContext.copyOf(material.encryptionContext))
        .requiredEncryptionContextKeys(material.requiredEncryptionContextKeys)
        .build();
      if (material.plaintextDataKey != null) {
        result = result.withPlaintextDataKey(SecretBytes.copyOf(material.plaintextDataKey));
      }
      for (TestVectors.Edk edk : material.encryptedDataKeys) {
        result = result.withEncryptedDataKey(EncryptedDataKey.of(edk.keyProviderId, edk.keyProviderInfo, edk.ciphertext));
      }
      return OnEncryptResponse.builder().materials(result).build();
    }

    @Override
    public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
      DecryptionMaterials materials = request.materials();
      List<EncryptedDataKey> encryptedDataKeys = request.encryptedDataKeys();
      DecryptionMaterials result = DecryptionMaterials
        .builder(material.algorithmSuite)
        .encryptionContext(EncryptionContext.copyOf(material.encryptionContext))
        .requiredEncryptionContextKeys(material.requiredEncryptionContextKeys)
        .build();
      Optional<byte[]> plaintextDataKey = Optional.ofNullable(material.plaintextDataKey);
      return OnDecryptResponse.builder().materials(plaintextDataKey.isPresent() ? result.withPlaintextDataKey(SecretBytes.copyOf(plaintextDataKey.get())) : result).build();
    }
  }
}
