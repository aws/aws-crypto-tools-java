// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders.internal;

import software.amazon.cryptography.oldapi.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.InvalidAlgorithmSuiteInfoOnDecrypt;
import software.amazon.cryptography.oldapi.materialproviders.model.InvalidAlgorithmSuiteInfoOnEncrypt;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.CommitmentChecks;

/** Test adapter: a native materials manager behind the old interface. */
public final class NativeCmm implements ICryptographicMaterialsManager {


  private final CryptographicMaterialsManager cmm;

  public NativeCmm(CryptographicMaterialsManager cmm) {
    this.cmm = cmm;
  }

  public CryptographicMaterialsManager cmm() {
    return cmm;
  }

  @Override
  public GetEncryptionMaterialsOutput GetEncryptionMaterials(GetEncryptionMaterialsInput input) {
    try {
      return GetEncryptionMaterialsOutput
        .builder()
        .encryptionMaterials(Convert.materials(cmm.getEncryptionMaterials(Requests.request(input)).encryptionMaterials()))
        .build();
    } catch (ValidationException e) {
      if (fromCommitmentCheck(e)) {
        throw InvalidAlgorithmSuiteInfoOnEncrypt.builder().message(e.getMessage()).build();
      }
      throw Errors.toOld(e);
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  @Override
  public DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input) {
    try {
      return DecryptMaterialsOutput
        .builder()
        .decryptionMaterials(Convert.materials(cmm.decryptMaterials(Requests.request(input)).decryptionMaterials()))
        .build();
    } catch (ValidationException e) {
      if (fromCommitmentCheck(e)) {
        throw InvalidAlgorithmSuiteInfoOnDecrypt.builder().message(e.getMessage()).build();
      }
      throw Errors.toOld(e);
    } catch (RuntimeException e) {
      throw Errors.toOld(e);
    }
  }

  // The old API reported commitment policy failures as their own exception types.
  private static boolean fromCommitmentCheck(ValidationException e) {
    StackTraceElement[] trace = e.getStackTrace();
    return trace.length > 0 && trace[0].getClassName().equals(CommitmentChecks.class.getName());
  }
}
