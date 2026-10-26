// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.vectors;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import software.amazon.cryptography.oldapi.materialproviders.ReferenceBridge;
import software.amazon.cryptography.oldapi.materialproviders.internal.Convert;
import software.amazon.cryptography.oldapi.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawEcdhKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EphemeralPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.PaddingScheme;
import software.amazon.cryptography.oldapi.materialproviders.model.PublicKeyDiscoveryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.RawEcdhStaticConfigurations;
import software.amazon.cryptography.oldapi.materialproviders.model.RawPrivateKeyToStaticPublicKeyInput;
import software.amazon.cryptography.mpl.DbeCommitmentPolicy;
import software.amazon.cryptography.oldapi.primitives.model.ECDHCurveSpec;

/**
 * The published Dafny-based MPL (the differential reference), driven as the Dafny runner drives it:
 * the same key descriptions and key material, and the same in-process AWS. It shows the runner's expectations hold
 * for the reference, and lets each side decrypt what the other encrypted.
 */
final class ReferenceSide implements Side {

  private final VectorEnvironment env;
  private final Object mpl = ReferenceBridge.materialProviders();
  private Object keyStore;

  ReferenceSide(VectorEnvironment env) {
    this.env = env;
  }

  @Override
  public String name() {
    return "reference";
  }

  @Override
  public Cmm cmm(KeyDescription description) {
    Object cmm = toCmm(description);
    return new Cmm() {
      @Override
      public Encrypted getEncryptionMaterials(TestVectors.EncryptVector vector) {
        GetEncryptionMaterialsInput input = GetEncryptionMaterialsInput
          .builder()
          .encryptionContext(vector.encryptionContext)
          .commitmentPolicy(policy(vector.commitmentPolicy()))
          .algorithmSuiteId(Convert.id(vector.algorithmSuite))
          .maxPlaintextLength(vector.maxPlaintextLength.isPresent() ? vector.maxPlaintextLength.getAsLong() : null)
          .requiredEncryptionContextKeys(vector.requiredEncryptionContextKeys)
          .build();
        GetEncryptionMaterialsOutput output = (GetEncryptionMaterialsOutput) ReferenceBridge.fromReference(
          ReferenceBridge.call(cmm, "GetEncryptionMaterials", input)
        );
        EncryptionMaterials materials = output.encryptionMaterials();
        List<TestVectors.Edk> edks = new ArrayList<>();
        for (EncryptedDataKey edk : materials.encryptedDataKeys()) {
          edks.add(new TestVectors.Edk(edk.keyProviderId(), bytes(edk.keyProviderInfo()), bytes(edk.ciphertext())));
        }
        List<byte[]> symmetricSigningKeys = new ArrayList<>();
        if (materials.symmetricSigningKeys() != null) {
          materials.symmetricSigningKeys().forEach(k -> symmetricSigningKeys.add(bytes(k)));
        }
        return new Encrypted(materials.encryptionContext(), edks, bytes(materials.plaintextDataKey()), symmetricSigningKeys);
      }

      @Override
      public Decrypted decryptMaterials(TestVectors.DecryptVector vector) {
        List<EncryptedDataKey> edks = new ArrayList<>();
        for (TestVectors.Edk edk : vector.encryptedDataKeys) {
          edks.add(edk(edk));
        }
        DecryptMaterialsInput input = DecryptMaterialsInput
          .builder()
          .algorithmSuiteId(Convert.id(vector.algorithmSuite))
          .commitmentPolicy(policy(vector.commitmentPolicy()))
          .encryptedDataKeys(edks)
          .encryptionContext(vector.encryptionContext)
          .reproducedEncryptionContext(vector.reproducedEncryptionContext)
          .build();
        DecryptMaterialsOutput output = (DecryptMaterialsOutput) ReferenceBridge.fromReference(
          ReferenceBridge.call(cmm, "DecryptMaterials", input)
        );
        DecryptionMaterials materials = output.decryptionMaterials();
        return new Decrypted(bytes(materials.plaintextDataKey()), bytes(materials.symmetricSigningKey()), materials.requiredEncryptionContextKeys());
      }
    };
  }

  private Object toCmm(KeyDescription description) {
    if (description instanceof KeyDescription.RequiredEncryptionContext) {
      KeyDescription.RequiredEncryptionContext required = (KeyDescription.RequiredEncryptionContext) description;
      Object input = ReferenceBridge.build(
        "materialproviders.model.CreateRequiredEncryptionContextCMMInput",
        "underlyingCMM",
        toCmm(required.underlying),
        "requiredEncryptionContextKeys",
        required.requiredEncryptionContextKeys
      );
      return ReferenceBridge.call(mpl, "CreateRequiredEncryptionContextCMM", input);
    }
    Object input = ReferenceBridge.build("materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput", "keyring", toKeyring(description));
    return ReferenceBridge.call(mpl, "CreateDefaultCryptographicMaterialsManager", input);
  }

  private Object toKeyring(KeyDescription description) {
    KeyMaterial material = env.keys.get(description.keyId());
    if (description instanceof KeyDescription.Static) {
      return staticKeyring(NativeSide.need(material, KeyMaterial.StaticMaterial.class, "Not type: StaticMaterial"));
    }
    if (description instanceof KeyDescription.Kms || description instanceof KeyDescription.KmsMrk) {
      String arn = NativeSide.need(material, KeyMaterial.Kms.class, "Not type: KMS").keyIdentifier;
      boolean mrk = description instanceof KeyDescription.KmsMrk;
      Object input = ReferenceBridge.build(
        mrk ? "materialproviders.model.CreateAwsKmsMrkKeyringInput" : "materialproviders.model.CreateAwsKmsKeyringInput",
        "kmsKeyId",
        arn,
        "kmsClient",
        ReferenceBridge.kmsClient(env.aws, VectorEnvironment.region(arn))
      );
      return ReferenceBridge.call(mpl, mrk ? "CreateAwsKmsMrkKeyring" : "CreateAwsKmsKeyring", input);
    }
    if (description instanceof KeyDescription.KmsRsa || description instanceof KeyDescription.KmsEcdh) {
      throw new Skipped(NativeSide.KMS_ASYMMETRIC_SKIP);
    }
    if (description instanceof KeyDescription.Hierarchy) {
      KeyMaterial.StaticBranchKey branchKey = NativeSide.need(material, KeyMaterial.StaticBranchKey.class, "Not type: StaticKeyStoreInformation");
      Object input = ReferenceBridge.build(
        "materialproviders.model.CreateAwsKmsHierarchicalKeyringInput",
        "branchKeyId",
        branchKey.keyIdentifier,
        "keyStore",
        keyStore(),
        "ttlSeconds",
        11L
      );
      return ReferenceBridge.call(mpl, "CreateAwsKmsHierarchicalKeyring", input);
    }
    if (description instanceof KeyDescription.KmsMrkDiscovery) {
      KeyDescription.KmsMrkDiscovery discovery = (KeyDescription.KmsMrkDiscovery) description;
      if (material != null) {
        throw new VectorException("Discovery has not key");
      }
      List<Object> fields = new ArrayList<>();
      Collections.addAll(
        fields,
        "regions",
        Collections.singletonList(discovery.defaultMrkRegion),
        "clientSupplier",
        ReferenceBridge.clientSupplier(env.aws)
      );
      if (discovery.filter.isPresent()) {
        fields.add("discoveryFilter");
        fields.add(DiscoveryFilter.builder().partition(discovery.filter.get().partition).accountIds(discovery.filter.get().accountIds).build());
      }
      Object input = ReferenceBridge.build("materialproviders.model.CreateAwsKmsMrkDiscoveryMultiKeyringInput", fields.toArray());
      return ReferenceBridge.call(mpl, "CreateAwsKmsMrkDiscoveryMultiKeyring", input);
    }
    if (description instanceof KeyDescription.RawAes) {
      KeyMaterial.Symmetric key = NativeSide.need(material, KeyMaterial.Symmetric.class, "Not type: Symmetric");
      return ReferenceBridge.call(
        mpl,
        "CreateRawAesKeyring",
        CreateRawAesKeyringInput
          .builder()
          .keyNamespace(((KeyDescription.RawAes) description).providerId)
          .keyName(key.keyIdentifier)
          .wrappingKey(ByteBuffer.wrap(key.wrappingKey))
          .wrappingAlg(AesWrappingAlg.valueOf(NativeSide.wrappingAlg(key.bits).name()))
          .build()
      );
    }
    if (description instanceof KeyDescription.RawRsa) {
      KeyDescription.RawRsa rsa = (KeyDescription.RawRsa) description;
      CreateRawRsaKeyringInput.Builder input = CreateRawRsaKeyringInput
        .builder()
        .keyNamespace(rsa.providerId)
        .paddingScheme(PaddingScheme.valueOf(rsa.padding.name()));
      if (material instanceof KeyMaterial.PrivateRsa) {
        KeyMaterial.PrivateRsa key = (KeyMaterial.PrivateRsa) material;
        if (!key.decrypt) {
          throw new VectorException("Private RSA keys only supports decrypt.");
        }
        input.keyName(key.keyIdentifier).privateKey(ByteBuffer.wrap(NativeSide.utf8(key.pem)));
      } else {
        KeyMaterial.PublicRsa key = NativeSide.need(material, KeyMaterial.PublicRsa.class, "Not type: PrivateRSA or PublicRSA");
        if (!key.encrypt) {
          throw new VectorException("Public RSA keys only supports encrypt.");
        }
        input.keyName(key.keyIdentifier).publicKey(ByteBuffer.wrap(NativeSide.utf8(key.pem)));
      }
      return ReferenceBridge.call(mpl, "CreateRawRsaKeyring", input.build());
    }
    if (description instanceof KeyDescription.RawEcdh) {
      return rawEcdh((KeyDescription.RawEcdh) description, material);
    }
    KeyDescription.Multi multi = (KeyDescription.Multi) description;
    List<Object> children = new ArrayList<>();
    for (KeyDescription child : multi.childKeyrings) {
      children.add(childKeyring(child));
    }
    Object input = multi.generator == null
      ? ReferenceBridge.build("materialproviders.model.CreateMultiKeyringInput", "childKeyrings", children)
      : ReferenceBridge.build("materialproviders.model.CreateMultiKeyringInput", "generator", childKeyring(multi.generator), "childKeyrings", children);
    return ReferenceBridge.call(mpl, "CreateMultiKeyring", input);
  }

  private Object childKeyring(KeyDescription child) {
    if (!child.isKeyring()) {
      throw new VectorException("Only Keyring key descriptions are supported.");
    }
    return toKeyring(child);
  }

  private Object rawEcdh(KeyDescription.RawEcdh ecdh, KeyMaterial material) {
    ECDHCurveSpec curve = ECDHCurveSpec.valueOf(NativeSide.curve(ecdh.curveSpec).name());
    RawEcdhStaticConfigurations scheme;
    switch (ecdh.keyAgreementScheme) {
      case "static":
        {
          KeyMaterial.PrivateEcdh key = NativeSide.need(material, KeyMaterial.PrivateEcdh.class, "Not type: PrivateECDH");
          scheme = RawEcdhStaticConfigurations
            .builder()
            .RawPrivateKeyToStaticPublicKey(
              RawPrivateKeyToStaticPublicKeyInput
                .builder()
                .senderStaticPrivateKey(ByteBuffer.wrap(NativeSide.utf8(key.senderPem)))
                .recipientPublicKey(ByteBuffer.wrap(Base64.getDecoder().decode(key.recipientPublicKey)))
                .build()
            )
            .build();
          break;
        }
      case "ephemeral":
        {
          KeyMaterial.PrivateEcdh key = NativeSide.need(env.keys.get(ecdh.recipientKeyId), KeyMaterial.PrivateEcdh.class, "Not type: PrivateECDH");
          scheme = RawEcdhStaticConfigurations
            .builder()
            .EphemeralPrivateKeyToStaticPublicKey(
              EphemeralPrivateKeyToStaticPublicKeyInput
                .builder()
                .recipientPublicKey(ByteBuffer.wrap(Base64.getDecoder().decode(key.recipientPublicKey)))
                .build()
            )
            .build();
          break;
        }
      case "discovery":
        {
          KeyMaterial.PrivateEcdh key = NativeSide.need(env.keys.get(ecdh.recipientKeyId), KeyMaterial.PrivateEcdh.class, "Not type: PrivateECDH");
          scheme = RawEcdhStaticConfigurations
            .builder()
            .PublicKeyDiscovery(
              PublicKeyDiscoveryInput.builder().recipientStaticPrivateKey(ByteBuffer.wrap(NativeSide.utf8(key.recipientPem))).build()
            )
            .build();
          break;
        }
      default:
        throw new VectorException("key agreement schema not recognized");
    }
    return ReferenceBridge.call(mpl, "CreateRawEcdhKeyring", CreateRawEcdhKeyringInput.builder().curveSpec(curve).KeyAgreementScheme(scheme).build());
  }

  // CreateStaticKeyrings.StaticMaterialsKeyring, as a caller keyring of the reference MPL.
  private static Object staticKeyring(KeyMaterial.StaticMaterial material) {
    List<EncryptedDataKey> edks = new ArrayList<>();
    for (TestVectors.Edk edk : material.encryptedDataKeys) {
      edks.add(edk(edk));
    }
    ByteBuffer plaintextDataKey = material.plaintextDataKey == null ? null : ByteBuffer.wrap(material.plaintextDataKey);
    EncryptionMaterials encrypt = EncryptionMaterials
      .builder()
      .algorithmSuite(Convert.info(material.algorithmSuite))
      .encryptionContext(material.encryptionContext)
      .encryptedDataKeys(edks)
      .requiredEncryptionContextKeys(material.requiredEncryptionContextKeys)
      .plaintextDataKey(plaintextDataKey)
      .build();
    DecryptionMaterials decrypt = DecryptionMaterials
      .builder()
      .algorithmSuite(Convert.info(material.algorithmSuite))
      .encryptionContext(material.encryptionContext)
      .requiredEncryptionContextKeys(material.requiredEncryptionContextKeys)
      .plaintextDataKey(plaintextDataKey)
      .build();
    return ReferenceBridge.keyring(
      input -> OnEncryptOutput.builder().materials(encrypt).build(),
      input -> OnDecryptOutput.builder().materials(decrypt).build()
    );
  }

  private synchronized Object keyStore() {
    if (keyStore == null) {
      keyStore = ReferenceBridge.keyStore(
        env.aws,
        VectorEnvironment.KEY_STORE_REGION,
        VectorEnvironment.KEY_STORE_TABLE,
        VectorEnvironment.LOGICAL_KEY_STORE_NAME,
        env.keyStoreKmsKey
      );
    }
    return keyStore;
  }

  private static CommitmentPolicy policy(software.amazon.cryptography.mpl.CommitmentPolicy policy) {
    String name = ((Enum<?>) policy).name();
    return policy instanceof DbeCommitmentPolicy
      ? CommitmentPolicy.builder().DBE(DBECommitmentPolicy.valueOf(name)).build()
      : CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.valueOf(name)).build();
  }

  private static EncryptedDataKey edk(TestVectors.Edk edk) {
    return EncryptedDataKey
      .builder()
      .keyProviderId(edk.keyProviderId)
      .keyProviderInfo(ByteBuffer.wrap(edk.keyProviderInfo))
      .ciphertext(ByteBuffer.wrap(edk.ciphertext))
      .build();
  }

  private static byte[] bytes(ByteBuffer buffer) {
    if (buffer == null) {
      return null;
    }
    byte[] bytes = new byte[buffer.remaining()];
    buffer.duplicate().get(bytes);
    return bytes;
  }
}
