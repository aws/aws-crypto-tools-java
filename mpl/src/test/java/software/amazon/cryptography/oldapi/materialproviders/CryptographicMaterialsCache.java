// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import java.util.Objects;
import software.amazon.cryptography.oldapi.materialproviders.model.DeleteCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetCacheEntryOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.PutCacheEntryInput;
import software.amazon.cryptography.oldapi.materialproviders.model.UpdateUsageMetadataInput;

/**
 * Test adapter: the old wrapper type, delegating to the wrapped implementation.
 * Written for this module; the generated old-API model (the oldApiModel task in build.gradle.kts) takes it.
 */
public final class CryptographicMaterialsCache implements ICryptographicMaterialsCache {

  private final ICryptographicMaterialsCache _impl;

  private CryptographicMaterialsCache(ICryptographicMaterialsCache iCryptographicMaterialsCache) {
    this._impl = iCryptographicMaterialsCache;
  }

  public static <I extends ICryptographicMaterialsCache> CryptographicMaterialsCache wrap(I iCryptographicMaterialsCache) {
    Objects.requireNonNull(
      iCryptographicMaterialsCache,
      "Missing value for required argument `iCryptographicMaterialsCache`"
    );
    if (iCryptographicMaterialsCache instanceof CryptographicMaterialsCache) {
      return ((CryptographicMaterialsCache) iCryptographicMaterialsCache);
    }
    return new CryptographicMaterialsCache(iCryptographicMaterialsCache);
  }

  public ICryptographicMaterialsCache impl() {
    return this._impl;
  }

  public void DeleteCacheEntry(DeleteCacheEntryInput input) {
    this._impl.DeleteCacheEntry(input);
  }

  public GetCacheEntryOutput GetCacheEntry(GetCacheEntryInput input) {
    return this._impl.GetCacheEntry(input);
  }

  public void PutCacheEntry(PutCacheEntryInput input) {
    this._impl.PutCacheEntry(input);
  }

  public void UpdateUsageMetadata(UpdateUsageMetadataInput input) {
    this._impl.UpdateUsageMetadata(input);
  }
}
