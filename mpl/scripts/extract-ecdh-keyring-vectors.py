#!/usr/bin/env python3
"""Extract the fixed ECDH keyring keys from the Dafny-based MPL's tests and test vectors into JSON.

Usage: scripts/extract-ecdh-keyring-vectors.py <mpl-checkout-or-archive> <output-dir>
Reads AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/test/TestUtils.dfy (the keys
TesRawECDHKeyring.dfy uses) and the raw ECDH keys of TestVectorsAwsCryptographicMaterialProviders' keys.json;
writes ecdh-keyring.json. Neither source has fixed ciphertexts: their keyring tests and vectors encrypt and decrypt.
"""
import base64
import json
import re
import sys

LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')


def constants(text):
    """Every `const NAME := "..." + ...` whose value is only string literals."""
    out = {}
    for name, body in re.findall(r'const (\w+)\s*:=\s*((?:\s*\+?\s*"(?:[^"\\]|\\.)*")+)', text):
        out[name] = ''.join(json.loads('"' + part + '"') for part in LITERAL.findall(body))
    return out


def der(b64):
    return base64.b64decode(b64).hex()


root, out_dir = sys.argv[1], sys.argv[2]
c = constants(open(root + '/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/test/TestUtils.dfy').read())
keys = json.load(open(root + '/TestVectorsAwsCryptographicMaterialProviders/dafny/TestVectorsAwsCryptographicMaterialProviders/test/keys.json'))['keys']
curves = [('ECC_NIST_P256', '256'), ('ECC_NIST_P384', '384'), ('ECC_NIST_P521', '521')]

vectors = {
    'testUtils': [
        {
            'curve': curve,
            'senderPrivatePem': c['ECC_P%s_PRIVATE' % bits],
            'senderPublicDer': der(c['ECC_P%s_PUBLIC' % bits]),
            'recipientPrivatePem': c['ECC_P%s_PRIVATE_R' % bits],
            'recipientPublicDer': der(c['ECC_P%s_PUBLIC_R' % bits]),
        }
        for curve, bits in curves
    ],
    'testVectorKeys': [
        {
            'curve': curve,
            'senderPrivatePem': keys['ecc-%s-private' % bits]['sender-material'],
            'senderPublicDer': der(keys['ecc-%s-private' % bits]['sender-material-public-key']),
            'recipientPrivatePem': keys['ecc-%s-private' % bits]['recipient-material'],
            'recipientPublicDer': der(keys['ecc-%s-private' % bits]['recipient-material-public-key']),
        }
        for curve, bits in curves
    ],
}
json.dump(vectors, open(out_dir + '/ecdh-keyring.json', 'w'), indent=2)
