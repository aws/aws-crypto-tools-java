package software.amazon.cryptography.dbesdk.dynamodbencryption;

import java.util.ArrayList;
import java.util.List;

/**
 * One transform applied to a virtual-field part's located string value. A faithful
 * port of the Dafny {@code DdbVirtualFields} transforms (see virtual.md): each
 * transform maps a string to a string, and a part applies its transforms in order.
 */
public sealed interface VirtualTransform
    permits VirtualTransform.Upper, VirtualTransform.Lower, VirtualTransform.Insert,
            VirtualTransform.Prefix, VirtualTransform.Suffix, VirtualTransform.Substring,
            VirtualTransform.Segment, VirtualTransform.Segments {

    String apply(String s);

    /** Uppercase every ASCII a-z. */
    record Upper() implements VirtualTransform {
        @Override public String apply(String s) {
            char[] out = s.toCharArray();
            for (int i = 0; i < out.length; i++) {
                if (out[i] >= 'a' && out[i] <= 'z') {
                    out[i] = (char) (out[i] - 'a' + 'A');
                }
            }
            return new String(out);
        }
    }

    /** Lowercase every ASCII A-Z. */
    record Lower() implements VirtualTransform {
        @Override public String apply(String s) {
            char[] out = s.toCharArray();
            for (int i = 0; i < out.length; i++) {
                if (out[i] >= 'A' && out[i] <= 'Z') {
                    out[i] = (char) (out[i] - 'A' + 'a');
                }
            }
            return new String(out);
        }
    }

    /** Append a literal to the input. */
    record Insert(String literal) implements VirtualTransform {
        @Override public String apply(String s) {
            return s + literal;
        }
    }

    /** The first {@code length} chars; a negative length drops the last {@code -length}. */
    record Prefix(int length) implements VirtualTransform {
        @Override public String apply(String s) {
            return length >= 0 ? s.substring(0, min(length, s.length()))
                : s.substring(0, s.length() - min(-length, s.length()));
        }
    }

    /** The last {@code length} chars; a negative length drops the first {@code -length}. */
    record Suffix(int length) implements VirtualTransform {
        @Override public String apply(String s) {
            return length >= 0 ? s.substring(s.length() - min(length, s.length()))
                : s.substring(min(-length, s.length()));
        }
    }

    /** The range [low, high) using positional indexing (see {@link #position}). */
    record Substring(int low, int high) implements VirtualTransform {
        @Override public String apply(String s) {
            int lo = position(low, s.length());
            int hi = position(high, s.length());
            return lo < hi ? s.substring(lo, hi) : "";
        }
    }

    /** The item at {@code index} of the split, or "" if out of range. */
    record Segment(char split, int index) implements VirtualTransform {
        @Override public String apply(String s) {
            List<String> parts = splitOn(s, split);
            if (index >= parts.size() || -index > parts.size()) {
                return "";
            }
            return parts.get(position(index, parts.size()));
        }
    }

    /** The range [low, high) of the split, re-joined on the split char. */
    record Segments(char split, int low, int high) implements VirtualTransform {
        @Override public String apply(String s) {
            List<String> parts = splitOn(s, split);
            int lo = position(low, parts.size());
            int hi = position(high, parts.size());
            if (lo >= hi) {
                return "";
            }
            return String.join(String.valueOf(split), parts.subList(lo, hi));
        }
    }

    // --- shared transform helpers (Dafny Min/GetPos/Split) ---------------

    private static int min(int x, int y) {
        return Math.min(x, y);
    }

    /**
     * Resolve a possibly-negative position into [0, limit) (Dafny GetPos): a
     * non-negative position is clamped to {@code limit-1}; a negative position is
     * the one-based index from the end, clamped to 0.
     */
    static int position(int pos, int limit) {
        if (limit == 0) {
            return 0;
        }
        if (pos >= 0) {
            return min(pos, limit - 1);
        }
        return limit + pos < 0 ? 0 : limit + pos;
    }

    /**
     * Split on every occurrence of {@code delimiter}, keeping empty segments
     * (Dafny StandardLibrary Split): N delimiters yield N+1 pieces.
     */
    static List<String> splitOn(String s, char delimiter) {
        List<String> parts = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == delimiter) {
                parts.add(s.substring(start, i));
                start = i + 1;
            }
        }
        parts.add(s.substring(start));
        return parts;
    }
}
