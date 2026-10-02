<!-- SPDX-FileCopyrightText: Mistial Dev -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Synthetic TWIC and PIV card fixtures

These are **test credentials** built with new, checked-in private keys. The binary
objects contain invented FASC-N values, UUIDs, names, minutiae, a generated JPEG
test pattern, and AES keys. Test keys live only under these test vectors and must
never be provisioned on a card or trusted outside tests.

The `legacy/` and `nexgen/` manifests distinguish observed **structure** from
synthetic **payloads**. Contact-reader observations supplied the AIDs, object
presence and absence, TLV hierarchy, selected certificate OIDs and EKUs,
Security Object map order and digest choice, AES-128-ECB/PKCS#7 wrapping, and
PIV/TWIC differences. The `observed_lengths` and `synthetic_lengths` entries
show exact remaining size differences. The new CA, issuer, content signer, and
card certificates form separate test chains for each profile. Each profile
includes a synthetic RFC 5914 TrustAnchorList with a TrustAnchorInfo entry and
an alternate certificate entry. The Security Objects and CHUIDs are signed;
biometric CBEFF/CMS signatures and hashes are recomputed from synthetic data.
Both profiles' PIV fingerprints contain the same signed CBEFF bytes that their
TWIC objects encrypt. NEXGEN's PIV face does the same.

Raw real-card APDUs and contents are kept in the restricted private capture
workspace for review. The committed APDU command/response replays contain only
these synthetic payloads. `tests/twic/apdu_replay.py` regenerates all four
transcript files and `--check` verifies them. The transcripts follow the
library's command order: GET DATA and SELECT with Le `00`, the TWIC catalog
inventory, and GET RESPONSE with Le `FF` after `61 00` on the TWIC
application. Contact and contactless status
and chaining patterns follow identity-bound captures with synthetic payloads.

Routine CTest runs use the committed binary vectors and require no OpenSSL,
Python cryptography, or Pillow installation. The following maintenance commands
regenerate the corpus after changing the builder or test keys:

```sh
python3 tests/twic/make_test_face.py
cc -std=c99 -Wno-unused-function -Itests/support -Isrc \
  $(pkg-config --cflags openssl) \
  tests/twic/generate_synthetic_fixture.c tests/support/munit.c \
  $(pkg-config --libs openssl) -o /tmp/twic-synthetic-fixture-builder
/tmp/twic-synthetic-fixture-builder legacy \
  tests/vectors/twic/synthetic/legacy tests/vectors/twic/synthetic/legacy/keys
/tmp/twic-synthetic-fixture-builder nexgen \
  tests/vectors/twic/synthetic/nexgen tests/vectors/twic/synthetic/nexgen/keys
python3 tests/twic/synthetic_fixture_test.py
python3 tests/twic/apdu_replay.py
python3 tests/twic/apdu_replay.py --check
```

With `TINY_CRYPTO_TEST_OPENSSL=ON`, `test_twic_synthetic_fixture_builder`
builds the generator and checks that its output equals the committed files.

The Python validator independently checks X.509 signatures, extension OIDs and
criticality, RFC 5914 encodings, CMS signatures, Security Object hashes, AES
decrypt/re-encrypt, CBEFF records, JPEG decoding, and PIV/TWIC shared-data
relationships. C munit tests exercise TPK, AES, parsers, signed CHUID, CMS,
revocation, biometric and Security validation, including tampered inputs.
Fixture generation uses OpenSSL and Pillow as optional maintenance tools. The
generator produces byte-identical binary and DER outputs from the checked-in
test keys and inputs.
