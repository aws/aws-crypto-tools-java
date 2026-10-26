// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsOutput;

public interface ICryptographicMaterialsManager {
  DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input);

  GetEncryptionMaterialsOutput GetEncryptionMaterials(
    GetEncryptionMaterialsInput input
  );
}
