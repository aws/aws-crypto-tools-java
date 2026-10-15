// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import software.amazon.cryptography.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.GetEncryptionMaterialsOutput;

public interface ICryptographicMaterialsManager {
  DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input);

  GetEncryptionMaterialsOutput GetEncryptionMaterials(
    GetEncryptionMaterialsInput input
  );
}
