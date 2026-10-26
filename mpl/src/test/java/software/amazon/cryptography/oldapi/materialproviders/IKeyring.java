// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;

public interface IKeyring {
  OnDecryptOutput OnDecrypt(OnDecryptInput input);

  OnEncryptOutput OnEncrypt(OnEncryptInput input);
}
