package software.amazon.cryptography.dbesdk.structuredencryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.FieldKeyDerivation;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.FieldKeyDerivation.FieldKey;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.Hkdf;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.TerminalCryptor;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AlgorithmSuite;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.AuthenticateAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CanonicalField;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoAction;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.CryptoItem;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.DecryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.EncryptionMaterials;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.ParsedHeader;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Path;
import software.amazon.cryptography.dbesdk.structuredencryption.internal.Terminal;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.Canonize;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.Footer;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.Header;
import software.amazon.cryptography.dbesdk.structuredencryption.wire.PartialHeader;

/**
 * The StructuredEncryption path operations (behavior spec §1–§2, §4). Callers
 * supply resolved materials (a data key, suite descriptor, EDKs, signing keys);
 * the CMM and the V2 encryption-context CMM wrapping live at the seam above this
 * class, so the pipeline itself has no MPL dependency.
 *
 * <p>Both operations canonicalize and sort the fields, derive per-field keys
 * from a single HKDF root, and bind everything with a committed header and a
 * signed footer. Encrypt appends the reserved header and footer fields; decrypt
 * verifies then strips them.
 */
public final class StructuredEncryptionClient {

    private static final byte[] BYTES_TYPE_ID = {(byte) 0xFF, (byte) 0xFF};
    private static final byte[] COMMIT_KEY_LABEL =
        "AWS_DBE_COMMIT_KEY".getBytes(StandardCharsets.US_ASCII);
    private static final int MESSAGE_ID_LENGTH = 32;
    private static final Path HEADER_PATH = Path.ofAttribute("aws_dbe_head");
    private static final Path FOOTER_PATH = Path.ofAttribute("aws_dbe_foot");

    private static final SecureRandom RANDOM = new SecureRandom();

    private StructuredEncryptionClient() {}

    public static PathStructureOutput encryptPathStructure(
            String tableName, List<CryptoItem> plaintext, EncryptionMaterials materials) {
        requireAtLeastOneSignedField(plaintext);
        requireNoReservedPaths(plaintext);
        requireNoDuplicatePaths(plaintext);
        requireValidTableName(tableName);

        List<CanonicalField> canonical = Canonize.forEncrypt(tableName, plaintext);
        AlgorithmSuite suite = materials.algorithmSuite();
        byte[] dataKey = materials.plaintextDataKey();
        byte[] messageId = randomMessageId();

        byte[] fieldRootKey = FieldKeyDerivation.fieldRootKey(
            suite.keyDerivationHmac(), dataKey, messageId, suite.encryptionKeyLength());
        byte[] commitKey = Hkdf.deriveKey(
            suite.commitmentHmac(), null, dataKey, commitKeyInfo(messageId), suite.commitmentKeyLength());

        Map<String, byte[]> storedEncryptionContext = storedEncryptionContext(materials);
        PartialHeader header = new PartialHeader(
            versionFromSchema(canonical),
            suite.flavor(),
            messageId,
            Canonize.makeLegend(canonical),
            storedEncryptionContext,
            materials.encryptedDataKeys());
        byte[] headerBytes = Header.serializeWithCommitment(header, commitKey, suite.commitmentHmac());

        List<CanonicalField> encrypted = encryptFields(canonical, fieldRootKey);

        byte[] canonicalHash = Footer.canonicalHash(headerBytes, materials.encryptionContext(), encrypted);
        List<byte[]> recipientTags = new ArrayList<>(materials.symmetricSigningKeys().size());
        for (byte[] signingKey : materials.symmetricSigningKeys()) {
            recipientTags.add(Footer.recipientTag(suite.symmetricSignatureHmac(), signingKey, canonicalHash));
        }
        Optional<byte[]> signature = suite.hasEcdsaSignature()
            ? Optional.of(Footer.sign(materials.signingKey(), canonicalHash))
            : Optional.empty();

        List<CryptoItem> result = new ArrayList<>(Canonize.unCanon(encrypted));
        result.add(new CryptoItem(HEADER_PATH, new Terminal(headerBytes, BYTES_TYPE_ID.clone()), CryptoAction.DO_NOTHING));
        result.add(new CryptoItem(FOOTER_PATH, Footer.makeTerminal(recipientTags, signature), CryptoAction.DO_NOTHING));

        ParsedHeader parsedHeader = new ParsedHeader(
            suite, materials.encryptedDataKeys(), storedEncryptionContext, materials.encryptionContext());
        return new PathStructureOutput(result, parsedHeader);
    }

    public static PathStructureOutput decryptPathStructure(
            String tableName, List<AuthItem> encrypted, DecryptionMaterials materials) {
        byte[] headerBytes = reservedFieldValue(encrypted, HEADER_PATH, "header");
        byte[] footerBytes = reservedFieldValue(encrypted, FOOTER_PATH, "footer");
        PartialHeader header = Header.deserialize(headerBytes);
        requireValidTableName(tableName);

        List<CanonicalField> canonical = Canonize.forDecrypt(tableName, encrypted, header.legend());
        AlgorithmSuite suite = materials.algorithmSuite();
        byte[] dataKey = materials.plaintextDataKey();

        byte[] commitKey = Hkdf.deriveKey(
            suite.commitmentHmac(), null, dataKey,
            commitKeyInfo(header.messageId()), suite.commitmentKeyLength());
        Header.verifyCommitment(commitKey, headerBytes, suite.commitmentHmac());

        Footer.Parsed footer = Footer.deserialize(footerBytes, suite.hasEcdsaSignature());
        byte[] canonicalHash = Footer.canonicalHash(headerBytes, materials.encryptionContext(), canonical);
        Footer.validate(
            footer, canonicalHash, header.dataKeys().size(),
            suite.symmetricSignatureHmac(), materials.symmetricSigningKey(),
            suite.hasEcdsaSignature(), materials.verificationKey());

        byte[] fieldRootKey = FieldKeyDerivation.fieldRootKey(
            suite.keyDerivationHmac(), dataKey, header.messageId(), suite.encryptionKeyLength());
        List<CanonicalField> decrypted = decryptFields(canonical, fieldRootKey);

        List<CryptoItem> result = new ArrayList<>();
        for (CryptoItem item : Canonize.unCanon(decrypted)) {
            if (!isReservedPath(item.key())) {
                result.add(item);
            }
        }

        ParsedHeader parsedHeader = new ParsedHeader(
            suite, header.dataKeys(), header.encryptionContext(), materials.encryptionContext());
        return new PathStructureOutput(result, parsedHeader);
    }

    /** Resolve each field's crypto action from a serialized header's legend; no crypto. */
    public static List<CryptoItem> resolveAuthActions(
            String tableName, List<AuthItem> authActions, byte[] headerBytes) {
        PartialHeader header = Header.deserialize(headerBytes);
        return Canonize.unCanon(Canonize.forDecrypt(tableName, authActions, header.legend()));
    }

    /**
     * Map form of {@link #encryptPathStructure}: the plaintext and crypto-action
     * maps must cover the same keys. The returned map includes the reserved
     * header and footer fields.
     */
    public static MapStructureOutput encryptStructure(
            String tableName,
            Map<String, Terminal> plaintextStructure,
            Map<String, CryptoAction> cryptoSchema,
            EncryptionMaterials materials) {
        if (!plaintextStructure.keySet().equals(cryptoSchema.keySet())) {
            throw new StructuredEncryptionException("Crypto Keys don't match.");
        }
        List<CryptoItem> items = new ArrayList<>(plaintextStructure.size());
        for (Map.Entry<String, Terminal> entry : plaintextStructure.entrySet()) {
            items.add(new CryptoItem(
                Path.ofAttribute(entry.getKey()), entry.getValue(), cryptoSchema.get(entry.getKey())));
        }
        PathStructureOutput output = encryptPathStructure(tableName, items, materials);
        return new MapStructureOutput(
            toStructuredDataMap(output.structure()), toCryptoSchema(output.structure()), output.parsedHeader());
    }

    /**
     * Map form of {@link #decryptPathStructure}: the encrypted-structure and
     * authenticate-schema maps must cover the same keys, so the caller's schema
     * must include the reserved header and footer keys. The returned map has them
     * stripped.
     */
    public static MapStructureOutput decryptStructure(
            String tableName,
            Map<String, Terminal> encryptedStructure,
            Map<String, AuthenticateAction> authenticateSchema,
            DecryptionMaterials materials) {
        if (!encryptedStructure.keySet().equals(authenticateSchema.keySet())) {
            throw new StructuredEncryptionException(
                "DecryptStructure requires encryptedStructure and authenticateSchema have the same keys.");
        }
        List<AuthItem> items = new ArrayList<>(encryptedStructure.size());
        for (Map.Entry<String, Terminal> entry : encryptedStructure.entrySet()) {
            items.add(new AuthItem(
                Path.ofAttribute(entry.getKey()), entry.getValue(), authenticateSchema.get(entry.getKey())));
        }
        PathStructureOutput output = decryptPathStructure(tableName, items, materials);
        return new MapStructureOutput(
            toStructuredDataMap(output.structure()), toCryptoSchema(output.structure()), output.parsedHeader());
    }

    private static Map<String, Terminal> toStructuredDataMap(List<CryptoItem> items) {
        Map<String, Terminal> structuredData = new LinkedHashMap<>();
        for (CryptoItem item : items) {
            String key = item.key().segments().get(0);
            if (structuredData.put(key, item.data()) != null) {
                throw new StructuredEncryptionException("Duplicate Key " + key);
            }
        }
        return structuredData;
    }

    // The crypto-schema half of UnBuildCryptoMap: every authenticated field (any
    // action but DO_NOTHING, per Util.IsAuthAttr) keyed to its Crypto Action. The
    // reserved header/footer are DO_NOTHING, so they never appear here. Duplicate
    // keys are already rejected by toStructuredDataMap over the same list.
    private static Map<String, CryptoAction> toCryptoSchema(List<CryptoItem> items) {
        Map<String, CryptoAction> schema = new LinkedHashMap<>();
        for (CryptoItem item : items) {
            if (item.action() != CryptoAction.DO_NOTHING) {
                schema.put(item.key().segments().get(0), item.action());
            }
        }
        return schema;
    }

    private static List<CanonicalField> encryptFields(List<CanonicalField> canonical, byte[] fieldRootKey) {
        List<CanonicalField> out = new ArrayList<>(canonical.size());
        int offset = 0;
        for (CanonicalField field : canonical) {
            if (field.action() == CryptoAction.ENCRYPT_AND_SIGN) {
                FieldKey fieldKey = FieldKeyDerivation.fieldKey(fieldRootKey, offset++);
                Terminal encrypted = TerminalCryptor.encrypt(fieldKey, field.canonicalPath(), field.data());
                out.add(new CanonicalField(field.canonicalPath(), field.originalKey(), encrypted, field.action()));
            } else {
                out.add(field);
            }
        }
        return out;
    }

    private static List<CanonicalField> decryptFields(List<CanonicalField> canonical, byte[] fieldRootKey) {
        List<CanonicalField> out = new ArrayList<>(canonical.size());
        int offset = 0;
        for (CanonicalField field : canonical) {
            if (field.action() == CryptoAction.ENCRYPT_AND_SIGN) {
                FieldKey fieldKey = FieldKeyDerivation.fieldKey(fieldRootKey, offset++);
                Terminal plaintext = TerminalCryptor.decrypt(fieldKey, field.canonicalPath(), field.data());
                out.add(new CanonicalField(field.canonicalPath(), field.originalKey(), plaintext, field.action()));
            } else {
                out.add(field);
            }
        }
        return out;
    }

    private static int versionFromSchema(List<CanonicalField> fields) {
        for (CanonicalField field : fields) {
            if (field.action() == CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT) {
                return 2;
            }
        }
        return 1;
    }

    private static Map<String, byte[]> storedEncryptionContext(EncryptionMaterials materials) {
        Map<String, byte[]> stored = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : materials.encryptionContext().entrySet()) {
            if (!materials.requiredEncryptionContextKeys().contains(entry.getKey())) {
                stored.put(entry.getKey(), entry.getValue());
            }
        }
        return stored;
    }

    private static byte[] commitKeyInfo(byte[] messageId) {
        byte[] info = new byte[COMMIT_KEY_LABEL.length + messageId.length];
        System.arraycopy(COMMIT_KEY_LABEL, 0, info, 0, COMMIT_KEY_LABEL.length);
        System.arraycopy(messageId, 0, info, COMMIT_KEY_LABEL.length, messageId.length);
        return info;
    }

    private static byte[] randomMessageId() {
        byte[] messageId = new byte[MESSAGE_ID_LENGTH];
        RANDOM.nextBytes(messageId);
        return messageId;
    }

    private static byte[] reservedFieldValue(List<AuthItem> fields, Path reservedPath, String name) {
        for (AuthItem field : fields) {
            if (field.key().segments().equals(reservedPath.segments())) {
                return field.data().value();
            }
        }
        throw new StructuredEncryptionException("Structured data is missing the required " + name + " field.");
    }

    private static boolean isReservedPath(Path path) {
        return path.segments().equals(HEADER_PATH.segments())
            || path.segments().equals(FOOTER_PATH.segments());
    }

    private static void requireAtLeastOneSignedField(List<CryptoItem> plaintext) {
        for (CryptoItem field : plaintext) {
            if (field.action() != CryptoAction.DO_NOTHING) {
                return;
            }
        }
        throw new StructuredEncryptionException(
            "At least one field in the Crypto Schema must be ENCRYPT_AND_SIGN, "
                + "SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT or SIGN_ONLY.");
    }

    private static void requireNoReservedPaths(List<CryptoItem> plaintext) {
        for (CryptoItem field : plaintext) {
            if (isReservedPath(field.key())) {
                throw new StructuredEncryptionException(
                    "The paths aws_dbe_head and aws_dbe_foot are reserved.");
            }
        }
    }

    private static void requireNoDuplicatePaths(List<CryptoItem> plaintext) {
        Set<List<String>> seen = new HashSet<>();
        for (CryptoItem field : plaintext) {
            if (!seen.add(field.key().segments())) {
                throw new StructuredEncryptionException("Duplicate Paths");
            }
        }
    }

    private static void requireValidTableName(String tableName) {
        if (!StandardCharsets.UTF_8.newEncoder().canEncode(tableName)) {
            throw new StructuredEncryptionException("Bad Table Name");
        }
    }
}
