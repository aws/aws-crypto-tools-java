package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * A virtual field: a value computed by concatenating, in order, the transformed
 * string value at each of its parts' locations. A faithful port of the Dafny
 * {@code DdbVirtualFields.GetVirtField} (see virtual.md).
 *
 * <p>The field evaluates to absent if any part's location is missing or does not
 * resolve to a plain string value — matching the Dafny contract that a virtual
 * part is defined only over a plain string terminal.
 */
public final class VirtualField {

    /** One part: a source location and the transforms applied to its string value, in order. */
    public record Part(TermLoc loc, List<VirtualTransform> transforms) {
        public Part {
            transforms = List.copyOf(transforms);
        }
    }

    private final String name;
    private final List<Part> parts;

    private VirtualField(String name, List<Part> parts) {
        this.name = name;
        this.parts = parts;
    }

    public static VirtualField create(String name, List<Part> parts) {
        return new VirtualField(name, List.copyOf(parts));
    }

    public String name() {
        return name;
    }

    /**
     * The stored attributes this virtual field reads: the root key of each part's
     * location, in order (DdbVirtualFields {@code GetFields}). Used by a beacon to report
     * which item fields feed it.
     */
    public List<String> getFields() {
        List<String> fields = new ArrayList<>(parts.size());
        for (Part part : parts) {
            fields.add(part.loc().rootKey());
        }
        return List.copyOf(fields);
    }

    /**
     * The virtual field's value for an item: each part's located string value with
     * its transforms applied in order, concatenated. Absent if any part's location
     * is absent or is not a plain string.
     */
    public Optional<String> getValue(Map<String, AttributeValue> item) {
        StringBuilder acc = new StringBuilder();
        for (Part part : parts) {
            Optional<String> located = part.loc().termToString(item);
            if (located.isEmpty()) {
                return Optional.empty();
            }
            String value = located.get();
            for (VirtualTransform transform : part.transforms()) {
                value = transform.apply(value);
            }
            acc.append(value);
        }
        return Optional.of(acc.toString());
    }
}
