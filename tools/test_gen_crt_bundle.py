import pathlib
import shutil
import struct
import subprocess
import tempfile
import unittest

from gen_crt_bundle import build, pem_certs, subject_and_spki


def make_cert(directory, cn, key_args):
    """Self-signed cert via the openssl CLI; returns (pem_text, spki_der)."""
    key, crt = directory / f'{cn}.key', directory / f'{cn}.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', *key_args, '-nodes', '-keyout', key,
                    '-out', crt, '-subj', f'/CN={cn}/O=Test', '-days', '1'],
                   check=True, capture_output=True)
    spki = subprocess.run(['openssl', 'pkey', '-in', key, '-pubout', '-outform', 'DER'],
                          check=True, capture_output=True).stdout
    return crt.read_text(), spki


@unittest.skipUnless(shutil.which('openssl'), 'openssl CLI not available')
class GenCrtBundleTests(unittest.TestCase):
    def test_bundle_layout_matches_openssl(self):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            certs = [make_cert(d, 'zeta', ['rsa:2048']),
                     make_cert(d, 'alpha', ['ec', '-pkeyopt', 'ec_paramgen_curve:P-256'])]
            pem = ''.join(c[0] for c in certs) + certs[0][0]     # duplicate is dropped
            blob, n = build(pem)

        self.assertEqual(n, 2)
        self.assertEqual(struct.unpack('>H', blob[:2])[0], 2)
        i, names, keys = 2, [], []
        while i < len(blob):
            name_len, key_len = struct.unpack('>HH', blob[i:i + 4])
            names.append(blob[i + 4:i + 4 + name_len])
            keys.append(blob[i + 4 + name_len:i + 4 + name_len + key_len])
            i += 4 + name_len + key_len
        self.assertEqual(i, len(blob))
        self.assertEqual(names, sorted(names))                   # device binary-searches by name
        self.assertEqual(sorted(keys), sorted(c[1] for c in certs))
        for name in names:
            self.assertEqual(name[0], 0x30)                      # Name is a DER SEQUENCE

    def test_subject_equals_issuer_for_self_signed(self):
        with tempfile.TemporaryDirectory() as d:
            pem, spki = make_cert(pathlib.Path(d), 'root', ['rsa:2048'])
        der = next(pem_certs(pem))
        name, key = subject_and_spki(der)
        self.assertEqual(key, spki)
        self.assertIn(b'root', name)
        self.assertEqual(der.count(name), 2)                     # issuer and subject


if __name__ == '__main__':
    unittest.main()
