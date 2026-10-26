// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.model.GetClientInput;

public interface IClientSupplier {
  /**
   * Returns an AWS KMS Client.
   *
   * @param input Inputs for getting a AWS KMS Client.
   *
   */
  KmsClient GetClient(GetClientInput input);
}
