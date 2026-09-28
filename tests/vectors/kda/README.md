# NIST KAS 2014 single-step KDF vectors

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
construction specified by SP 800-56C Rev. 2. The public NIST ACVP-Server
OneStep sample corpus currently exercises SHA2-224 and SHA2-512, but has no
SHA2-256 or SHA2-384 groups. The KAS records provide NIST-produced SHA-256 and
SHA-384 expected outputs for the exact construction implemented here. Their
outputs range from 14 to 32 bytes. The separate SSKDF tests cover longer
outputs and multiple counter blocks with a Python `hashlib` oracle.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file here, and
`tests/test_vector_manifests.py` checks them.
