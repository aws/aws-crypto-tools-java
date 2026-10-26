// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.client.config.SdkAdvancedClientOption;

/** The user-agent suffix on KMS clients the library creates (register R7). */
public final class UserAgent {

  public static final String SUFFIX = "AwsCryptographicMPL-Java";

  private UserAgent() {}

  public static ClientOverrideConfiguration overrideConfiguration() {
    return ClientOverrideConfiguration.builder().putAdvancedOption(SdkAdvancedClientOption.USER_AGENT_SUFFIX, SUFFIX).build();
  }
}
