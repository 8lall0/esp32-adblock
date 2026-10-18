#!/usr/bin/env python3
"""Build the CA certificate bundle the firmware uses to verify HTTPS blocklist downloads.

Output format (what WiFiClientSecure::setCACertBundle / esp_crt_bundle.c expects, same as
ESP-IDF's gen_crt_bundle.py):

    u16be  number of certificates
    per certificate, sorted by subject DER bytes (the device binary-searches it):
        u16be  subject length    u16be  public key length
        subject Name DER         SubjectPublicKeyInfo DER

Only the subject and public key of each root are kept, which is all a chain check needs.
No third-party packages: the few DER fields required are parsed by hand.

usage: gen_crt_bundle.py OUT.bin [cacert.pem | URL]
       (default source: Mozilla's CA list as published by curl, https://curl.se/ca/cacert.pem)
"""
import base64, re, struct, sys, urllib.request

DEFAULT_SRC = 'https://curl.se/ca/cacert.pem'

def tlv(b, i):
    """Parse one DER TLV at b[i]. Returns (tag, value_start, end)."""
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(b[i:i + k], 'big')
        i += k
    return tag, i, i + n

def subject_and_spki(der):
    """Return (subject Name DER, SubjectPublicKeyInfo DER) of an X.509 certificate."""
    _, cert, _ = tlv(der, 0)                      # Certificate ::= SEQUENCE
    _, i, _ = tlv(der, cert)                      # tbsCertificate ::= SEQUENCE
    fields = []
    while len(fields) < 7:
        tag, _, end = tlv(der, i)
        fields.append((tag, i, end))
        i = end
    if fields[0][0] != 0xA0:                      # v1 certs have no [0] version field
        fields.insert(0, None)
    # version, serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    (_, s0, s1), (_, k0, k1) = fields[5], fields[6]
    if der[s0] != 0x30 or der[k0] != 0x30:
        raise ValueError('unexpected certificate layout')
    return der[s0:s1], der[k0:k1]

def pem_certs(text):
    for m in re.finditer(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', text, re.S):
        yield base64.b64decode(''.join(m.group(1).split()))

def build(pem_text):
    entries = {}
    for der in pem_certs(pem_text):
        name, key = subject_and_spki(der)
        entries[name + key] = (name, key)         # dedupe identical roots
    out = [struct.pack('>H', len(entries))]
    for name, key in sorted(entries.values(), key=lambda e: e[0]):
        out.append(struct.pack('>HH', len(name), len(key)) + name + key)
    return b''.join(out), len(entries)

def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    src = sys.argv[2] if len(sys.argv) == 3 else DEFAULT_SRC
    if re.match(r'https?://', src):
        with urllib.request.urlopen(src, timeout=60) as r:
            text = r.read().decode()
    else:
        with open(src) as f:
            text = f.read()
    blob, n = build(text)
    with open(sys.argv[1], 'wb') as f:
        f.write(blob)
    print(f'{n} certificates, {len(blob):,} bytes -> {sys.argv[1]}')

if __name__ == '__main__':
    main()
