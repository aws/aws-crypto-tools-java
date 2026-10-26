// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Exceptions the library throws on purpose, all extending {@link MaterialProvidersException}.
 *
 * <p>Each exception has a {@link ErrorKind}; builders report invalid settings with {@link ValidationException}.
 * Exceptions thrown by caller-provided keyrings, managers, caches, and suppliers propagate unchanged,
 * except that a multi keyring collects its children's decrypt failures (see {@link NoMatchingDataKeyException}).
 * Message text is for people and may change in any release; branch on the exception type and accessors.
 */
package software.amazon.cryptography.materialproviders.exceptions;
