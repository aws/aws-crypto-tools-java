#!/usr/bin/env python3
"""Extract the HKDF (RFC 5869) and KDF-in-counter-mode test vectors from the Dafny-based MPL's tests into JSON.

Usage: scripts/extract-dafny-vectors.py <mpl-checkout-or-archive> <output-dir>
Reads AwsCryptographyPrimitives/test/TestHKDF_Rfc5869TestVectors.dfy and TestKDF_TestVectors.dfy.
"""
import json
import re
import sys

FIELD = re.compile(r'(\w+)\s*:=\s*(\[[^\]]*\]|"[^"]*"|[\w.]+(?:\s+as\s+int32)?)', re.S)


def constants(text):
    out = {}
    for name, body in re.findall(r'const (?:\{[^}]*\}\s*)?(\w+)\s*:=\s*\w+\((.*?)\n\s*\)\n', text, re.S):
        fields = {}
        for key, value in FIELD.findall(body):
            if value.startswith('['):
                fields[key] = bytes(int(v) for v in re.findall(r'\d+', value)).hex()
            elif value.startswith('"'):
                fields[key] = value.strip('"')
            elif value.startswith('AtomicPrimitives.Types.'):
                fields[key] = value.split('.')[-1]
            elif re.match(r'^\d+', value):
                fields[key] = int(value.split()[0])
            else:
                fields[key] = value
        out[name] = fields
    return out


def ordered(text, list_name, consts):
    names = re.search(r'const ' + list_name + r'\b[^=]*:=\s*\[([^\]]*)\]', text).group(1)
    return [consts[n.strip()] for n in names.split(',')]


root, out_dir = sys.argv[1], sys.argv[2]
test = root + '/AwsCryptographyPrimitives/test/'

hkdf = open(test + 'TestHKDF_Rfc5869TestVectors.dfy').read()
json.dump(ordered(hkdf, 'testVectors', constants(hkdf)), open(out_dir + '/hkdf-rfc5869.json', 'w'), indent=2)

kdf = open(test + 'TestKDF_TestVectors.dfy').read()
consts = constants(kdf)
purpose = bytes(int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})', re.search(r'const PURPOSE.*?\[(.*?)\]', kdf, re.S).group(1))).hex()
public = ordered(kdf, 'testVectors', consts)
for vector in public:
    vector['purpose'] = purpose
json.dump(
    {'raw': ordered(kdf, 'rawTestVectors', consts), 'public': public},
    open(out_dir + '/kdf-counter-mode.json', 'w'),
    indent=2,
)
