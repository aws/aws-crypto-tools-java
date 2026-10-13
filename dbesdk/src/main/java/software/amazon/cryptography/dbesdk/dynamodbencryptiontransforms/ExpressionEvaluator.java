package software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbesdk.dynamodbencryption.FloatCompare;
import software.amazon.cryptography.dbesdk.dynamodbencryption.NumberNormalizer;
import software.amazon.cryptography.dbesdk.dynamodbencryptiontransforms.ExpressionTokenizer.Token;

/**
 * Evaluates a parsed condition expression against a single item (DynamoDBFilterExpr's
 * {@code ConvertToPrefix} / {@code ConvertToRpn} / {@code EvalExpr}). The output filter uses
 * it to re-check each decrypted item against the original key/filter predicate and discard
 * the false positives a beacon query's truncated-hash matching lets through.
 *
 * <p>Evaluation is three steps: {@link #convertToPrefix} rewrites {@code A IN (X,Y)} and
 * {@code A BETWEEN X AND Y} into prefix function form, {@link #convertToRpn} converts the
 * infix tokens to reverse Polish notation with a shunting-yard pass, and {@link #evalExpr}
 * runs the RPN on a value stack.
 *
 * <p>Faithful-parity note: the Dafny shunting-yard does not push an open paren and pops a
 * single operator per close paren, so grouping parentheses do not override operator
 * precedence (e.g. {@code (a = :x OR b = :y) AND c = :z} evaluates as
 * {@code a = :x OR (b = :y AND c = :z)}, since {@code AND} binds tighter than {@code OR}).
 * Function-call parentheses still work. This is replicated exactly for cross-language parity;
 * key-condition expressions disallow {@code OR}, so only parenthesized mixed {@code AND}/
 * {@code OR} filter expressions are affected.
 */
final class ExpressionEvaluator {

    private ExpressionEvaluator() {
    }

    /** The evaluation stack holds a boolean, a located value, or the "attribute absent" marker. */
    private sealed interface StackValue permits BoolValue, StrValue, Absent {
    }

    private record BoolValue(boolean value) implements StackValue {
    }

    private record StrValue(AttributeValue value) implements StackValue {
    }

    private enum Absent implements StackValue {
        ABSENT
    }

    /**
     * Rewrite {@code A IN (X, Y, ...)} to {@code IN ( A , X , Y )} and
     * {@code A BETWEEN X AND Y} to {@code BETWEEN ( A , X , Y )}, so both read as ordinary
     * prefix function calls for {@link #convertToRpn} (Dafny {@code ConvertToPrefix}).
     */
    static List<Token> convertToPrefix(List<Token> input) {
        List<Token> out = new ArrayList<>(input.size());
        int pos = 0;
        int n = input.size();
        while (pos < n) {
            if (n - pos < 5) {
                out.addAll(input.subList(pos, n));
                break;
            }
            if (isIn(input, pos)) {
                out.add(input.get(pos + 1)); // IN
                out.add(input.get(pos + 2)); // (
                out.add(input.get(pos)); // the attribute
                out.add(Token.Symbol.COMMA);
                pos += 3;
                continue;
            }
            int[] between = isBetween(input, pos);
            if (between != null) {
                int p1 = between[0];
                int p2 = between[1];
                int p3 = between[2];
                out.add(Token.Symbol.BETWEEN);
                out.add(Token.Symbol.OPEN);
                out.addAll(input.subList(pos, pos + p1)); // the attribute
                out.add(Token.Symbol.COMMA);
                out.addAll(input.subList(pos + p1 + 1, pos + p1 + p2 + 1)); // lower bound
                out.add(Token.Symbol.COMMA);
                out.addAll(input.subList(pos + p1 + p2 + 2, pos + p1 + p2 + p3 + 2)); // upper bound
                out.add(Token.Symbol.CLOSE);
                pos += p1 + p2 + p3 + 2;
                continue;
            }
            out.add(input.get(pos));
            pos++;
        }
        return out;
    }

    // "A IN (" — a variable, then IN, then an open paren.
    private static boolean isIn(List<Token> input, int pos) {
        return pos + 2 < input.size()
            && isVar(input.get(pos))
            && input.get(pos + 1) == Token.Symbol.IN
            && input.get(pos + 2) == Token.Symbol.OPEN;
    }

    // "VAR_OR_SIZE BETWEEN VAR_OR_SIZE AND VAR_OR_SIZE" starting at pos; returns the three
    // operand token-lengths {p1, p2, p3} or null if the shape does not match (Dafny IsBetween).
    private static int[] isBetween(List<Token> input, int pos) {
        int n = input.size();
        if (n < pos + 5) {
            return null;
        }
        int p1 = varOrSize(input, pos);
        if (p1 <= 0 || pos + p1 + 1 >= n || input.get(pos + p1) != Token.Symbol.BETWEEN) {
            return null;
        }
        int p2 = varOrSize(input, pos + p1 + 1);
        if (p2 <= 0 || pos + p1 + p2 + 2 >= n || input.get(pos + p1 + p2 + 1) != Token.Symbol.AND) {
            return null;
        }
        int p3 = varOrSize(input, pos + p1 + p2 + 2);
        return p3 > 0 ? new int[] {p1, p2, p3} : null;
    }

    // Token-length of an operand: 1 for a value/attribute, 4 for size(var), else 0 (VarOrSize).
    private static int varOrSize(List<Token> input, int pos) {
        if (pos >= input.size()) {
            return 0;
        }
        if (isVar(input.get(pos))) {
            return 1;
        }
        if (pos + 3 < input.size()
                && input.get(pos) == Token.Symbol.SIZE
                && input.get(pos + 1) == Token.Symbol.OPEN
                && isVar(input.get(pos + 2))
                && input.get(pos + 3) == Token.Symbol.CLOSE) {
            return 4;
        }
        return 0;
    }

    /**
     * Convert infix tokens to reverse Polish notation (Dafny {@code ConvertToRpn}). Functions
     * are pushed and emitted when their arguments close; comparison and boolean operators are
     * emitted by precedence. See the class note on parenthesis handling.
     */
    static List<Token> convertToRpn(List<Token> input) {
        List<Token> out = new ArrayList<>(input.size());
        List<Token> stack = new ArrayList<>();
        int pos = 0;
        int n = input.size();
        while (pos < n) {
            Token t = input.get(pos);
            if (t instanceof Token.Attr || t instanceof Token.Value) {
                out.add(t);
                pos++;
            } else if (isFunction(t)) {
                stack.add(t);
                pos++;
            } else if (t == Token.Symbol.COMMA) {
                if (!stack.isEmpty() && !isFunction(top(stack))) {
                    out.add(pop(stack));
                }
                pos++;
            } else if (t == Token.Symbol.CLOSE) {
                if (!stack.isEmpty()) {
                    if (top(stack) == Token.Symbol.OPEN) {
                        pop(stack);
                    } else {
                        out.add(pop(stack));
                    }
                }
                pos++;
            } else if (isComp(t) || t == Token.Symbol.AND || t == Token.Symbol.OR) {
                if (!stack.isEmpty() && precedence(top(stack)) >= precedence(t)) {
                    out.add(pop(stack)); // keep popping against this same token
                } else {
                    stack.add(t);
                    pos++;
                }
            } else {
                // Open (never stacked) and any stray token: skip.
                pos++;
            }
        }
        while (!stack.isEmpty()) {
            out.add(pop(stack));
        }
        return out;
    }

    private static Token top(List<Token> stack) {
        return stack.get(stack.size() - 1);
    }

    private static Token pop(List<Token> stack) {
        return stack.remove(stack.size() - 1);
    }

    /**
     * Whether {@code item} satisfies the RPN-form predicate (Dafny {@code EvalExpr}). Values
     * resolve through {@code values}, attributes through {@code names}/the item; the single
     * remaining boolean on the stack is the result.
     *
     * @throws DynamoDbEncryptionTransformsException if the expression is malformed (bad stack,
     *     wrong operand types) or references a value name absent from {@code values}
     */
    static boolean evalExpr(
            List<Token> rpn, Map<String, AttributeValue> item,
            Map<String, String> names, Map<String, AttributeValue> values) {
        List<StackValue> stack = new ArrayList<>();
        for (Token t : rpn) {
            if (t instanceof Token.Value value) {
                stack.add(stackValueFromValue(value.s(), values));
            } else if (t instanceof Token.Attr attr) {
                stack.add(stackValueFromAttr(attr, item, names));
            } else if (t == Token.Symbol.NOT) {
                if (stack.isEmpty()) {
                    throw error("Empty stack for unary op");
                }
                stack.add(applyUnary(stack.remove(stack.size() - 1)));
            } else if (isBinary(t)) {
                if (stack.size() < 2) {
                    throw error("Empty stack for binary op");
                }
                StackValue y = stack.remove(stack.size() - 1);
                StackValue x = stack.remove(stack.size() - 1);
                stack.add(applyBinary(t, x, y));
            } else if (isFunction(t)) {
                int numArgs = numArgs(t, stack);
                if (stack.size() < numArgs) {
                    throw error("Empty stack for function call");
                }
                StackValue result = applyFunction(t, stack, numArgs);
                stack.subList(stack.size() - numArgs, stack.size()).clear();
                stack.add(result);
            } else {
                // Dafny returns true on any other token (Open/Close/Comma never reach here in
                // well-formed RPN).
                return true;
            }
        }
        if (stack.size() == 1 && stack.get(0) instanceof BoolValue bool) {
            return bool.value();
        }
        throw error("ended with bad stack");
    }

    private static StackValue stackValueFromValue(String name, Map<String, AttributeValue> values) {
        AttributeValue value = values == null ? null : values.get(name);
        return value == null ? Absent.ABSENT : new StrValue(value);
    }

    // #name -> the real attribute looked up flatly in the item; otherwise the located path
    // value (Dafny StackValueFromAttr / StackValueFromItem / TermToAttr).
    private static StackValue stackValueFromAttr(
            Token.Attr attr, Map<String, AttributeValue> item, Map<String, String> names) {
        if (names != null && names.containsKey(attr.s())) {
            AttributeValue value = item.get(names.get(attr.s()));
            return value == null ? Absent.ABSENT : new StrValue(value);
        }
        return attr.loc().termToAttr(item).<StackValue>map(StrValue::new).orElse(Absent.ABSENT);
    }

    private static StackValue applyUnary(StackValue operand) {
        if (operand instanceof BoolValue bool) {
            return new BoolValue(!bool.value());
        }
        throw error("wrong type for Not");
    }

    private static StackValue applyBinary(Token op, StackValue x, StackValue y) {
        if (isComp(op)) {
            if (x instanceof StrValue sx && y instanceof StrValue sy) {
                return new BoolValue(compare(op, sx.value(), sy.value()));
            }
            throw error("wrong types for comparison");
        }
        if (x instanceof BoolValue bx && y instanceof BoolValue by) {
            return new BoolValue(op == Token.Symbol.AND ? bx.value() && by.value() : bx.value() || by.value());
        }
        throw error("wrong types for boolean binary");
    }

    // Reads the top numArgs stack entries (the caller removes them). Returns a boolean for a
    // predicate function, or a numeric string for size() (Dafny apply_function).
    private static StackValue applyFunction(Token fn, List<StackValue> stack, int numArgs) {
        int topIndex = stack.size() - 1;
        if (fn == Token.Symbol.BETWEEN) {
            StackValue middle = stack.get(stack.size() - 3);
            StackValue low = stack.get(stack.size() - 2);
            StackValue high = stack.get(topIndex);
            if (middle instanceof StrValue m && low instanceof StrValue l && high instanceof StrValue h) {
                return new BoolValue(attributeLe(l.value(), m.value()) && attributeLe(m.value(), h.value()));
            }
            throw error("Wrong Types for Between");
        }
        if (fn == Token.Symbol.IN) {
            if (numArgs == 0) {
                throw error("In has no args");
            }
            AttributeValue target = getStr(stack.get(stack.size() - numArgs));
            for (int i = stack.size() - numArgs + 1; i < stack.size(); i++) {
                if (getStr(stack.get(i)).equals(target)) {
                    return new BoolValue(true);
                }
            }
            return new BoolValue(false);
        }
        if (fn == Token.Symbol.ATTRIBUTE_EXISTS) {
            return new BoolValue(!(stack.get(topIndex) instanceof Absent));
        }
        if (fn == Token.Symbol.ATTRIBUTE_NOT_EXISTS) {
            return new BoolValue(stack.get(topIndex) instanceof Absent);
        }
        if (fn == Token.Symbol.ATTRIBUTE_TYPE) {
            return new BoolValue(
                attrTypeToStr(getStr(stack.get(stack.size() - 2))).equals(attrToStr(getStr(stack.get(topIndex)))));
        }
        if (fn == Token.Symbol.BEGINS_WITH) {
            if (stack.get(stack.size() - 2) instanceof StrValue h && stack.get(topIndex) instanceof StrValue n) {
                return new BoolValue(beginsWith(h.value(), n.value()));
            }
            throw error("Wrong Types for BeginsWith");
        }
        if (fn == Token.Symbol.CONTAINS) {
            if (stack.get(stack.size() - 2) instanceof StrValue h && stack.get(topIndex) instanceof StrValue n) {
                return new BoolValue(doesContain(h.value(), n.value()));
            }
            throw error("Wrong Types for contains");
        }
        if (fn == Token.Symbol.SIZE) {
            if (stack.get(topIndex) instanceof StrValue s) {
                return new StrValue(AttributeValue.fromN(Integer.toString(getSize(s.value()))));
            }
            throw error("Wrong Types for Size");
        }
        return new BoolValue(true);
    }

    // Number of arguments a function pops: In takes every string currently atop the stack
    // (Dafny NumArgs / StringsFollowing); the rest are fixed-arity.
    private static int numArgs(Token fn, List<StackValue> stack) {
        if (fn == Token.Symbol.BETWEEN) {
            return 3;
        }
        if (fn == Token.Symbol.ATTRIBUTE_TYPE || fn == Token.Symbol.BEGINS_WITH || fn == Token.Symbol.CONTAINS) {
            return 2;
        }
        if (fn == Token.Symbol.ATTRIBUTE_EXISTS || fn == Token.Symbol.ATTRIBUTE_NOT_EXISTS || fn == Token.Symbol.SIZE) {
            return 1;
        }
        if (fn == Token.Symbol.IN) {
            int count = 0;
            for (int i = stack.size() - 1; i >= 0 && stack.get(i) instanceof StrValue; i--) {
                count++;
            }
            return count;
        }
        return 0;
    }

    // --- comparison --------------------------------------------------------

    private static boolean compare(Token op, AttributeValue x, AttributeValue y) {
        return switch ((Token.Symbol) op) {
            case EQ -> attributeEq(x, y);
            case NE -> !attributeEq(x, y);
            case LE -> attributeLe(x, y);
            case LT -> !attributeLe(y, x);
            case GE -> attributeLe(y, x);
            case GT -> !attributeLe(x, y);
            default -> throw error("invalid comparison operator");
        };
    }

    // Numbers compare numerically; everything else by structural equality (Dafny AttributeEQ).
    private static boolean attributeEq(AttributeValue a, AttributeValue b) {
        if (a.type() == AttributeValue.Type.N && b.type() == AttributeValue.Type.N) {
            return compareFloat(a.n(), b.n()) == 0;
        }
        return a.equals(b);
    }

    // Numbers numeric; strings surrogate-aware unicode; binary unsigned-lexicographic; mixed
    // or unorderable types are "not <=" (Dafny AttributeLE returns false).
    private static boolean attributeLe(AttributeValue a, AttributeValue b) {
        if (a.type() == AttributeValue.Type.N && b.type() == AttributeValue.Type.N) {
            return compareFloat(a.n(), b.n()) <= 0;
        }
        if (a.type() == AttributeValue.Type.S && b.type() == AttributeValue.Type.S) {
            return !unicodeLess(b.s(), a.s());
        }
        if (a.type() == AttributeValue.Type.B && b.type() == AttributeValue.Type.B) {
            return byteCompare(a.b().asByteArrayUnsafe(), b.b().asByteArrayUnsafe()) <= 0;
        }
        return false;
    }

    private static int compareFloat(String x, String y) {
        return FloatCompare.compareFloat(NumberNormalizer.normalizeNumber(x), NumberNormalizer.normalizeNumber(y));
    }

    // Surrogate-aware code-unit comparison: with one surrogate pair, the high surrogate ranks
    // higher so comparison matches Unicode scalar order (Dafny UnicodeLess).
    private static boolean unicodeLess(String a, String b) {
        int n = Math.min(a.length(), b.length());
        for (int i = 0; i < n; i++) {
            char ca = a.charAt(i);
            char cb = b.charAt(i);
            if (ca == cb) {
                continue;
            }
            boolean aHigh = isHighSurrogate(ca);
            boolean bHigh = isHighSurrogate(cb);
            return aHigh == bHigh ? ca < cb : bHigh;
        }
        return a.length() < b.length();
    }

    private static boolean isHighSurrogate(char ch) {
        return ch >= '\ud800' && ch <= '\udbff';
    }

    // Unsigned lexicographic byte comparison; a shorter prefix sorts first.
    private static int byteCompare(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int cmp = Integer.compare(a[i] & 0xff, b[i] & 0xff);
            if (cmp != 0) {
                return cmp;
            }
        }
        return Integer.compare(a.length, b.length);
    }

    private static boolean beginsWith(AttributeValue haystack, AttributeValue needle) {
        return switch (haystack.type()) {
            case S -> needle.type() == AttributeValue.Type.S && haystack.s().startsWith(needle.s());
            case N -> needle.type() == AttributeValue.Type.N && haystack.n().startsWith(needle.n());
            case B -> needle.type() == AttributeValue.Type.B
                && startsWith(haystack.b().asByteArrayUnsafe(), needle.b().asByteArrayUnsafe());
            case L -> beginsWithList(haystack.l(), needle);
            default -> false;
        };
    }

    private static boolean beginsWithList(List<AttributeValue> list, AttributeValue needle) {
        if (list.isEmpty()) {
            return false;
        }
        if (list.get(0).equals(needle)) {
            return true;
        }
        return needle.type() == AttributeValue.Type.L && isPrefix(needle.l(), list);
    }

    private static boolean doesContain(AttributeValue haystack, AttributeValue needle) {
        return switch (haystack.type()) {
            case S -> needle.type() == AttributeValue.Type.S && haystack.s().contains(needle.s());
            case N -> needle.type() == AttributeValue.Type.N && haystack.n().contains(needle.n());
            case B -> needle.type() == AttributeValue.Type.B
                && indexOfBytes(haystack.b().asByteArrayUnsafe(), needle.b().asByteArrayUnsafe()) >= 0;
            case SS -> needle.type() == AttributeValue.Type.S && haystack.ss().contains(needle.s());
            case NS -> needle.type() == AttributeValue.Type.N && haystack.ns().contains(needle.n());
            case BS -> needle.type() == AttributeValue.Type.B && haystack.bs().contains(needle.b());
            case L -> haystack.l().contains(needle);
            default -> false;
        };
    }

    private static boolean startsWith(byte[] haystack, byte[] needle) {
        if (needle.length > haystack.length) {
            return false;
        }
        for (int i = 0; i < needle.length; i++) {
            if (haystack[i] != needle[i]) {
                return false;
            }
        }
        return true;
    }

    private static int indexOfBytes(byte[] haystack, byte[] needle) {
        if (needle.length == 0) {
            return 0;
        }
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static boolean isPrefix(List<AttributeValue> prefix, List<AttributeValue> list) {
        if (prefix.size() > list.size()) {
            return false;
        }
        return prefix.equals(list.subList(0, prefix.size()));
    }

    // The number of elements the value holds (Dafny GetSize): string/number length, or set,
    // list and map cardinality. NULL/BOOL count as 1.
    private static int getSize(AttributeValue value) {
        return switch (value.type()) {
            case S -> value.s().length();
            case N -> value.n().length();
            case B -> value.b().asByteArrayUnsafe().length;
            case SS -> value.ss().size();
            case NS -> value.ns().size();
            case BS -> value.bs().size();
            case M -> value.m().size();
            case L -> value.l().size();
            default -> 1;
        };
    }

    // A located value as the attribute it is, or NULL for a boolean/absent entry (Dafny GetStr).
    private static AttributeValue getStr(StackValue sv) {
        return sv instanceof StrValue str ? str.value() : AttributeValue.fromNul(true);
    }

    // The DynamoDB type code of a value (Dafny AttrTypeToStr); for attribute_type's left arg.
    private static String attrTypeToStr(AttributeValue value) {
        return switch (value.type()) {
            case S -> "S";
            case N -> "N";
            case B -> "B";
            case SS -> "SS";
            case NS -> "NS";
            case BS -> "BS";
            case M -> "M";
            case L -> "L";
            case NUL -> "NULL";
            case BOOL -> "BOOL";
            default -> "";
        };
    }

    // The string carried by a value, else "" (Dafny AttrToStr); for attribute_type's type arg.
    private static String attrToStr(AttributeValue value) {
        return switch (value.type()) {
            case S -> value.s();
            case N -> value.n();
            default -> "";
        };
    }

    // --- token classification (Dafny Precedence / Is*) --------------------

    private static int precedence(Token t) {
        if (t instanceof Token.Attr || t instanceof Token.Value) {
            return 10;
        }
        return switch ((Token.Symbol) t) {
            case OPEN, CLOSE, COMMA -> 11;
            case EQ, NE, LT, GT, LE, GE -> 9;
            case IN -> 8;
            case BETWEEN -> 7;
            case ATTRIBUTE_EXISTS, ATTRIBUTE_NOT_EXISTS, ATTRIBUTE_TYPE, BEGINS_WITH, CONTAINS, SIZE -> 6;
            case NOT -> 5;
            case AND -> 4;
            case OR -> 3;
        };
    }

    private static boolean isComp(Token t) {
        return t == Token.Symbol.EQ || t == Token.Symbol.NE || t == Token.Symbol.LT
            || t == Token.Symbol.GT || t == Token.Symbol.LE || t == Token.Symbol.GE;
    }

    private static boolean isBinary(Token t) {
        return isComp(t) || t == Token.Symbol.AND || t == Token.Symbol.OR;
    }

    private static boolean isVar(Token t) {
        return t instanceof Token.Attr || t instanceof Token.Value;
    }

    private static boolean isFunction(Token t) {
        return t == Token.Symbol.BETWEEN || t == Token.Symbol.IN || t == Token.Symbol.ATTRIBUTE_EXISTS
            || t == Token.Symbol.ATTRIBUTE_NOT_EXISTS || t == Token.Symbol.ATTRIBUTE_TYPE
            || t == Token.Symbol.BEGINS_WITH || t == Token.Symbol.CONTAINS || t == Token.Symbol.SIZE;
    }

    private static DynamoDbEncryptionTransformsException error(String message) {
        return new DynamoDbEncryptionTransformsException(message);
    }
}
