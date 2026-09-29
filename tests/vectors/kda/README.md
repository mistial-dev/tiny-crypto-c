# Single-step KDF vectors

## NIST KAS 2014

`nist_kas_2014.inc` contains 18 passing KDFConcat records from NIST CAVP's
[ECC](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/keymgmt/KASTestVectorsECC2014.zip)
and [FFC](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/keymgmt/KASTestVectorsFFC2014.zip)
KAS 2014 archives. The archive SHA-256 hashes are:

```
ECC  293f25702327dedec32205612ee4000ae5f404f9de645564e8d3ed9ebf64dfaf
FFC  24c1914921586a075993b629a3d665f89b2fabd9cc757e7c7203f9df02b881a4
```

Each entry preserves the archive's `Z`, `OI`, and `DKM` bytes. The preceding
comment identifies its source file and `COUNT`. The selected records have a
passing `Result` and independently satisfy
`DKM = leftmost-L(SHA(counter32be || Z || OI))` with counter 1. The test passes
`OI` as two spans, exercising the public SSKDF API's concatenation behavior.

These are SP 800-56A KDFConcat answers using the same hash-based one-step
construction specified by SP 800-56C Rev. 2. They supply NIST-produced SHA-256
and SHA-384 expected outputs of 14 to 32 bytes.

## NIST ACVP KDA OneStep

`acvp_onestep.inc` holds 24 hash-based one-step cases from the NIST
[ACVP-Server](https://github.com/usnistgov/ACVP-Server) repository at commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, under
`gen-val/json-files/KDA-OneStep-Sp800-56Cr1` and `KDA-OneStep-Sp800-56Cr2`.
The source file SHA-256 hashes are:

```
Sp800-56Cr1/prompt.json           b8888716c8247debaef4ac8be301d16b863bf911c16e323d03ba1ea6a43b251f
Sp800-56Cr1/expectedResults.json  0a11beb45da6383c71a10486efdd4844ec9b0cd14f5d18cb809b94856691c8ed
Sp800-56Cr2/prompt.json           1633c34cf4e52e52d7d768052092771042ab7166a2be22b4ed36df0b81a193a4
Sp800-56Cr2/expectedResults.json  9c8cdf62f0fa242fa04920c0f62e57447897619e3fc460d49eab52e4d418cc6b
```

The corpus exercises the SHA2-224 and SHA2-512 auxiliary functions. For each
revision and hash, `extract_acvp_onestep.py` keeps the three AFT and the three
VAL cases with the shortest `Z` and checks each one against `hashlib`. Each
record keeps `Z`, the expected or supplied DKM, the VAL verdict and the six
fixedInfo fields in pattern order: `t`, party U `partyId` and
`ephemeralData`, party V `partyId` and `ephemeralData`, and `[L]_32`. Every
case derives 1024 bits, which spans several digest blocks.

Regenerate the file with the two unchanged ACVP directories:

```
python3 tests/vectors/kda/extract_acvp_onestep.py <Sp800-56Cr1 dir> <Sp800-56Cr2 dir>
```

NIST publishes no one-step SHA-1 vectors. `tests/kdf/sskdf_test.c` covers
SHA-1 with a `hashlib` answer, and covers longer outputs and every counter
block for all five hashes the same way.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file here, and
`tests/test_vector_manifests.py` checks them.
