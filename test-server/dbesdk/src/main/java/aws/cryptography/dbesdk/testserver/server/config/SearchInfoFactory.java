package aws.cryptography.dbesdk.testserver.server.config;

import aws.cryptography.dbesdk.testserver.server.model.BeaconKeyStore;
import aws.cryptography.dbesdk.testserver.server.model.BeaconStyle;
import aws.cryptography.dbesdk.testserver.server.model.Constructor;
import aws.cryptography.dbesdk.testserver.server.model.ConstructorPart;
import aws.cryptography.dbesdk.testserver.server.model.EncryptedPart;
import aws.cryptography.dbesdk.testserver.server.model.GetPrefix;
import aws.cryptography.dbesdk.testserver.server.model.GetSegment;
import aws.cryptography.dbesdk.testserver.server.model.GetSegments;
import aws.cryptography.dbesdk.testserver.server.model.GetSubstring;
import aws.cryptography.dbesdk.testserver.server.model.GetSuffix;
import aws.cryptography.dbesdk.testserver.server.model.Insert;
import aws.cryptography.dbesdk.testserver.server.model.SearchConfig;
import aws.cryptography.dbesdk.testserver.server.model.SignedPart;
import aws.cryptography.dbesdk.testserver.server.model.SingleKeyStore;
import aws.cryptography.dbesdk.testserver.server.model.VirtualPart;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.dbesdk.dynamodbencryption.Beacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconException;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconKeySource;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconPart;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconVersion;
import software.amazon.cryptography.dbesdk.dynamodbencryption.CompoundBeacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.KeyStoreBeaconKeySource;
import software.amazon.cryptography.dbesdk.dynamodbencryption.StandardBeacon;
import software.amazon.cryptography.dbesdk.dynamodbencryption.TermLoc;
import software.amazon.cryptography.dbesdk.dynamodbencryption.VirtualField;
import software.amazon.cryptography.dbesdk.dynamodbencryption.VirtualTransform;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.SearchInfo;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.KMSConfiguration;
import software.amazon.cryptography.keystore.model.KeyStoreConfig;

/**
 * Builds a native {@link SearchInfo} from the test server's modeled {@link SearchConfig},
 * translating standard beacons, compound beacons, and virtual fields, and wiring the beacon
 * key source to the MPL key store via {@link MplBeaconKeyRetriever}.
 *
 * <p>Scope: a single beacon version over the modeled single key store. Multiple beacon
 * versions, the multi key store, and the shared-set beacon style are separate features;
 * this factory fails loudly rather than silently mis-handling them. The configuration-time
 * validations that depend on the table's attribute actions (a signed part must be SIGN_ONLY,
 * an encrypted beacon's field must be ENCRYPT_AND_SIGN, a beacon name must not collide with
 * an unencrypted attribute) are the item encryptor's config concern and are not re-checked
 * here; the beacon <em>values</em> this factory produces do not depend on them.
 */
final class SearchInfoFactory {

    private SearchInfoFactory() {
    }

    static SearchInfo create(SearchConfig search) {
        aws.cryptography.dbesdk.testserver.server.model.BeaconVersion version = singleVersion(search);

        Map<String, VirtualField> virtualFields = buildVirtualFields(version);

        List<Beacon> beacons = new ArrayList<>();
        Map<String, StandardBeacon> standardByName = new LinkedHashMap<>();
        List<String> standardNames = new ArrayList<>();
        for (aws.cryptography.dbesdk.testserver.server.model.StandardBeacon modeled : version.getStandardBeacons()) {
            StandardBeacon beacon = toNativeBeacon(modeled);
            standardByName.put(modeled.getName(), beacon);
            standardNames.add(modeled.getName());
            beacons.add(new Beacon.Standard(beacon));
        }

        Map<String, BeaconPart> globalSigned = buildSignedParts(version.getSignedParts());
        Map<String, BeaconPart> globalEncrypted = buildEncryptedParts(version.getEncryptedParts(), standardByName);
        for (aws.cryptography.dbesdk.testserver.server.model.CompoundBeacon modeled : version.getCompoundBeacons()) {
            beacons.add(new Beacon.Compound(toNativeCompound(modeled, standardByName, globalSigned, globalEncrypted)));
        }

        BeaconVersion nativeVersion = BeaconVersion.create(beacons, virtualFields);
        return new SearchInfo(nativeVersion, keySource(version, standardNames));
    }

    private static aws.cryptography.dbesdk.testserver.server.model.BeaconVersion singleVersion(SearchConfig search) {
        List<aws.cryptography.dbesdk.testserver.server.model.BeaconVersion> versions = search.getVersions();
        if (versions.size() != 1) {
            throw new UnsupportedOperationException(
                "The native test server supports exactly one beacon version; got " + versions.size() + ".");
        }
        return versions.get(0);
    }

    // --- virtual fields --------------------------------------------------

    private static Map<String, VirtualField> buildVirtualFields(
            aws.cryptography.dbesdk.testserver.server.model.BeaconVersion version) {
        Map<String, VirtualField> result = new LinkedHashMap<>();
        for (aws.cryptography.dbesdk.testserver.server.model.VirtualField modeled : version.getVirtualFields()) {
            List<VirtualField.Part> parts = new ArrayList<>();
            for (VirtualPart part : modeled.getParts()) {
                parts.add(new VirtualField.Part(TermLoc.make(part.getLoc()), toNativeTransforms(part.getTrans())));
            }
            result.put(modeled.getName(), VirtualField.create(modeled.getName(), parts));
        }
        return result;
    }

    private static List<VirtualTransform> toNativeTransforms(
            List<aws.cryptography.dbesdk.testserver.server.model.VirtualTransform> modeled) {
        List<VirtualTransform> result = new ArrayList<>(modeled.size());
        for (aws.cryptography.dbesdk.testserver.server.model.VirtualTransform transform : modeled) {
            result.add(toNativeTransform(transform));
        }
        return result;
    }

    private static VirtualTransform toNativeTransform(
            aws.cryptography.dbesdk.testserver.server.model.VirtualTransform transform) {
        if (transform.getUpper() != null) {
            return new VirtualTransform.Upper();
        }
        if (transform.getLower() != null) {
            return new VirtualTransform.Lower();
        }
        Insert insert = transform.getInsert();
        if (insert != null) {
            return new VirtualTransform.Insert(insert.getLiteral());
        }
        GetPrefix prefix = transform.getPrefix();
        if (prefix != null) {
            return new VirtualTransform.Prefix(prefix.getLength());
        }
        GetSuffix suffix = transform.getSuffix();
        if (suffix != null) {
            return new VirtualTransform.Suffix(suffix.getLength());
        }
        GetSubstring substring = transform.getSubstring();
        if (substring != null) {
            return new VirtualTransform.Substring(substring.getLow(), substring.getHigh());
        }
        GetSegment segment = transform.getSegment();
        if (segment != null) {
            return new VirtualTransform.Segment(singleChar(segment.getSplit()), segment.getIndex());
        }
        GetSegments segments = transform.getSegments();
        if (segments != null) {
            return new VirtualTransform.Segments(singleChar(segments.getSplit()), segments.getLow(), segments.getHigh());
        }
        throw new UnsupportedOperationException("Unknown virtual transform: " + transform);
    }

    // --- standard beacons ------------------------------------------------

    private static StandardBeacon toNativeBeacon(aws.cryptography.dbesdk.testserver.server.model.StandardBeacon beacon) {
        // Absent numberOfPartitions means the partition is left unconstrained (0), the base
        // searchable-encryption case; the beacon-partitions feature is separate.
        int partitions = beacon.getNumberOfPartitions() == null ? 0 : beacon.getNumberOfPartitions();
        // An absent loc defaults to the beacon's name (ConfigToInfo GetLocStr).
        String loc = beacon.getLoc() == null ? beacon.getName() : beacon.getLoc();
        BeaconStyle style = beacon.getStyle();
        if (style == null) {
            return StandardBeacon.create(beacon.getName(), beacon.getLength(), loc, false, partitions);
        }
        if (style.getSharedSet() != null) {
            throw new UnsupportedOperationException(
                "The shared-set beacon style is not yet wired into the native test server.");
        }
        boolean asSet = style.getAsSet() != null;
        boolean partOnly = style.getPartOnly() != null;
        String share = style.getShared() != null ? style.getShared().getOther() : null;
        return StandardBeacon.create(beacon.getName(), beacon.getLength(), loc, asSet, partitions, share, partOnly);
    }

    // --- compound beacons ------------------------------------------------

    private static CompoundBeacon toNativeCompound(
            aws.cryptography.dbesdk.testserver.server.model.CompoundBeacon modeled,
            Map<String, StandardBeacon> standardByName,
            Map<String, BeaconPart> globalSigned, Map<String, BeaconPart> globalEncrypted) {
        String name = modeled.getName();
        // Local parts are always included; a global part is pulled in only when a
        // constructor references it (ConfigToInfo GetAllSignedParts/GetAllEncryptedParts).
        Map<String, BeaconPart> signed = buildSignedParts(modeled.getSigned());
        Map<String, BeaconPart> encrypted = buildEncryptedParts(modeled.getEncrypted(), standardByName);
        for (Constructor constructor : modeled.getConstructors()) {
            for (ConstructorPart part : constructor.getParts()) {
                String partName = part.getName();
                if (signed.containsKey(partName) || encrypted.containsKey(partName)) {
                    continue;
                }
                if (globalSigned.containsKey(partName)) {
                    signed.put(partName, globalSigned.get(partName));
                } else if (globalEncrypted.containsKey(partName)) {
                    encrypted.put(partName, globalEncrypted.get(partName));
                }
            }
        }

        // Signed parts precede encrypted parts (CompoundBeacon OrderedParts).
        List<BeaconPart> allParts = new ArrayList<>(signed.values());
        allParts.addAll(encrypted.values());
        Map<String, BeaconPart> byName = new LinkedHashMap<>();
        for (BeaconPart part : allParts) {
            byName.put(part.name(), part);
        }

        List<List<CompoundBeacon.ConstructorPart>> constructors = new ArrayList<>();
        for (Constructor constructor : modeled.getConstructors()) {
            List<CompoundBeacon.ConstructorPart> nativeParts = new ArrayList<>();
            for (ConstructorPart part : constructor.getParts()) {
                BeaconPart resolved = byName.get(part.getName());
                if (resolved == null) {
                    throw new BeaconException(
                        "Constructor for compound beacon " + name + " refers to unknown part " + part.getName() + ".");
                }
                nativeParts.add(new CompoundBeacon.ConstructorPart(resolved, part.isRequired()));
            }
            constructors.add(nativeParts);
        }
        return CompoundBeacon.create(name, singleChar(modeled.getSplit()), allParts, constructors);
    }

    private static Map<String, BeaconPart> buildSignedParts(List<SignedPart> modeled) {
        Map<String, BeaconPart> result = new LinkedHashMap<>();
        for (SignedPart part : modeled) {
            // An absent loc defaults to the part's name (ConfigToInfo GetLoc).
            String loc = part.getLoc() == null ? part.getName() : part.getLoc();
            result.put(part.getName(), new BeaconPart.Signed(part.getPrefix(), part.getName(), TermLoc.make(loc)));
        }
        return result;
    }

    private static Map<String, BeaconPart> buildEncryptedParts(
            List<EncryptedPart> modeled, Map<String, StandardBeacon> standardByName) {
        Map<String, BeaconPart> result = new LinkedHashMap<>();
        for (EncryptedPart part : modeled) {
            StandardBeacon beacon = standardByName.get(part.getName());
            if (beacon == null) {
                throw new BeaconException(
                    "Encrypted part " + part.getName() + " refers to a standard beacon that is not configured.");
            }
            result.put(part.getName(), new BeaconPart.Encrypted(part.getPrefix(), beacon));
        }
        return result;
    }

    private static char singleChar(String split) {
        if (split.length() != 1) {
            throw new BeaconException("A split character must be exactly one character, got '" + split + "'.");
        }
        return split.charAt(0);
    }

    // --- key source ------------------------------------------------------

    private static BeaconKeySource keySource(
            aws.cryptography.dbesdk.testserver.server.model.BeaconVersion version, List<String> standardNames) {
        SingleKeyStore single = version.getKeySource().getSingle();
        if (single == null) {
            throw new UnsupportedOperationException(
                "The native test server supports only the single beacon key source.");
        }
        BeaconKeyStore store = version.getKeyStore();
        KeyStoreBeaconKeySource.Context context = new KeyStoreBeaconKeySource.Context(
            new MplBeaconKeyRetriever(buildKeyStore(store)),
            new InMemoryBeaconKeyCache(),
            single.getCacheTtlSeconds(),
            randomPartitionId(),
            store.getLogicalKeyStoreName().getBytes(StandardCharsets.UTF_8),
            Clock.systemUTC());
        return new KeyStoreBeaconKeySource(
            new KeyStoreBeaconKeySource.KeyLocation.Single(single.getKeyId()), standardNames, context);
    }

    private static KeyStore buildKeyStore(BeaconKeyStore store) {
        String region = resolveRegion();
        return KeyStore.builder()
            .KeyStoreConfig(KeyStoreConfig.builder()
                .ddbTableName(store.getDdbTableName())
                .logicalKeyStoreName(store.getLogicalKeyStoreName())
                .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(store.getKmsKeyArn()).build())
                .ddbClient(DynamoDbClient.builder().region(Region.of(region)).build())
                .kmsClient(KmsClient.builder().region(Region.of(region)).build())
                .build())
            .build();
    }

    // No partition id is modeled, so the cache namespace is a fresh UUID per client, matching
    // the Dafny fallback (ConfigToInfo generates UUID bytes when no partitionId is configured).
    private static byte[] randomPartitionId() {
        UUID uuid = UUID.randomUUID();
        return ByteBuffer.allocate(16)
            .putLong(uuid.getMostSignificantBits())
            .putLong(uuid.getLeastSignificantBits())
            .array();
    }

    private static String resolveRegion() {
        String region = System.getProperty("aws.region");
        if (isBlank(region)) {
            region = System.getenv("AWS_REGION");
        }
        if (isBlank(region)) {
            region = System.getenv("AWS_DEFAULT_REGION");
        }
        return isBlank(region) ? "us-west-2" : region.trim();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
