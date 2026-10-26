// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import java.util.ArrayList;
import software.amazon.cryptography.oldapi.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.InitializeDecryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.InitializeEncryptionMaterialsInput;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.MaterialsRules;

/**
 * Test adapter: the old materials operations, implemented on the native core.
 * Boundary checks reproduce the Dafny-based MPL's Java conversion; the rules come from {@link MaterialsRules}
 * and the public materials types.
 */
public final class Materials {

  private Materials() {}

  public static EncryptionMaterials initializeEncryptionMaterials(InitializeEncryptionMaterialsInput input) {
    Boundary.encryptionContext(input.encryptionContext());
    Boundary.utf8List(input.requiredEncryptionContextKeys());
    software.amazon.cryptography.mpl.AlgorithmSuite suite = Convert.suite(input.algorithmSuiteId());
    SecretBytes signingKey = input.signingKey() == null ? null : SecretBytes.copyOf(Buffers.toArray(input.signingKey()));
    byte[] verificationKey = input.verificationKey() == null ? null : Buffers.toArray(input.verificationKey());
    software.amazon.cryptography.mpl.EncryptionMaterials.Builder builder = software.amazon.cryptography.mpl.EncryptionMaterials
      .builder(suite)
      .encryptionContext(EncryptionContext.copyOf(input.encryptionContext()))
      .requiredEncryptionContextKeys(input.requiredEncryptionContextKeys());
    try {
      // The old input can carry one key without the other, which the native signingKeyPair cannot express;
      // run the rule with the keys as given, so those inputs fail as in Dafny, then build.
      MaterialsRules.initialEncryptionContext(
        suite,
        input.encryptionContext(),
        new ArrayList<>(input.requiredEncryptionContextKeys()),
        signingKey,
        verificationKey
      );
      if (signingKey != null) {
        builder.signingKeyPair(signingKey, verificationKey);
      }
      return Convert.materials(builder.build());
    } catch (ValidationException e) {
      throw AwsCryptographicMaterialProvidersException.builder().message(e.getMessage()).build();
    }
  }

  public static DecryptionMaterials initializeDecryptionMaterials(InitializeDecryptionMaterialsInput input) {
    Boundary.encryptionContext(input.encryptionContext());
    Boundary.utf8List(input.requiredEncryptionContextKeys());
    try {
      return Convert.materials(
        software.amazon.cryptography.mpl.DecryptionMaterials
          .builder(Convert.suite(input.algorithmSuiteId()))
          .encryptionContext(EncryptionContext.copyOf(input.encryptionContext()))
          .requiredEncryptionContextKeys(input.requiredEncryptionContextKeys())
          .build()
      );
    } catch (ValidationException e) {
      throw AwsCryptographicMaterialProvidersException.builder().message(e.getMessage()).build();
    }
  }

  public static boolean validEncryptionMaterialsTransition(EncryptionMaterials previous, EncryptionMaterials next) {
    Boundary.encryptionMaterials(previous);
    Boundary.encryptionMaterials(next);
    return (
      AlgorithmSuite.isValid(previous.algorithmSuite()) &&
      AlgorithmSuite.isValid(next.algorithmSuite()) &&
      MaterialsRules.isValidTransition(Convert.fields(previous), Convert.fields(next))
    );
  }

  public static boolean encryptionMaterialsHasPlaintextDataKey(EncryptionMaterials materials) {
    Boundary.encryptionMaterials(materials);
    return AlgorithmSuite.isValid(materials.algorithmSuite()) && MaterialsRules.isReadyForEncrypt(Convert.fields(materials));
  }

  public static boolean validDecryptionMaterialsTransition(DecryptionMaterials previous, DecryptionMaterials next) {
    Boundary.decryptionMaterials(previous);
    Boundary.decryptionMaterials(next);
    return (
      AlgorithmSuite.isValid(previous.algorithmSuite()) &&
      AlgorithmSuite.isValid(next.algorithmSuite()) &&
      MaterialsRules.isValidTransition(Convert.fields(previous), Convert.fields(next))
    );
  }

  public static boolean decryptionMaterialsWithPlaintextDataKey(DecryptionMaterials materials) {
    Boundary.decryptionMaterials(materials);
    return AlgorithmSuite.isValid(materials.algorithmSuite()) && MaterialsRules.isReadyForDecrypt(Convert.fields(materials));
  }
}
