package aws.cryptography.dbesdk.testserver.server.config;

import aws.cryptography.dbesdk.testserver.server.model.DBEClientConfig;
import aws.cryptography.dbesdk.testserver.server.registry.RealStructuredClient;
import aws.cryptography.dbesdk.testserver.server.registry.StructuredClient;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.StructuredEncryption;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.StructuredEncryptionConfig;
import software.amazon.cryptography.materialproviders.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.MaterialProviders;
import software.amazon.cryptography.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;

/**
 * Translates a validated {@link DBEClientConfig} into a {@link StructuredClient}
 * backed by a real {@link StructuredEncryption} client plus the {@code CMM} the
 * config's keyring (or CMM) builds. The keyring / CMM construction is reused
 * verbatim from {@link ItemEncryptorFactory}, so a structured client and an item
 * encryptor built from the same config share identical materials. A keyring-only
 * config is wrapped in a Default CMM, since Encrypt/DecryptStructure take a CMM
 * (not a keyring) per operation.
 */
public final class StructuredClientFactory {

    private final ItemEncryptorFactory keyrings;
    private final MaterialProviders materialProviders;
    private final StructuredEncryption structured;

    public StructuredClientFactory(ItemEncryptorFactory keyrings) {
        this.keyrings = keyrings;
        this.materialProviders = MaterialProviders.builder()
            .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
            .build();
        this.structured = StructuredEncryption.builder()
            .StructuredEncryptionConfig(StructuredEncryptionConfig.builder().build())
            .build();
    }

    public StructuredClient create(DBEClientConfig config) {
        ICryptographicMaterialsManager cmm;
        if (config.getKeyring() != null) {
            cmm = materialProviders.CreateDefaultCryptographicMaterialsManager(
                CreateDefaultCryptographicMaterialsManagerInput.builder()
                    .keyring(keyrings.buildKeyring(config.getKeyring()))
                    .build());
        } else {
            cmm = keyrings.buildCmm(config.getCmm());
        }
        return new RealStructuredClient(structured, cmm);
    }
}
