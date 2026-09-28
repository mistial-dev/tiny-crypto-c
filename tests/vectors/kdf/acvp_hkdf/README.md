# NIST ACVP HKDF vectors

The `r1` and `r2` directories contain unchanged `prompt.json` and
`expectedResults.json` from the NIST [ACVP-Server](https://github.com/usnistgov/ACVP-Server)
repository at commit `975de31eb83d87039ec88934fdc47d8c312b892d`, under
`gen-val/json-files/KDA-HKDF-Sp800-56Cr1` and `KDA-HKDF-Sp800-56Cr2`.
The files are checked by `SHA256SUMS`.

The HKDF ACVP test runs every SHA2-224, SHA2-256, SHA2-384 and SHA2-512 case:
400 revision 1 cases and 800 revision 2 cases. This includes default and random
salts, hybrid `Z || T` secrets, multi-expansion, and validation cases with
incorrect supplied output. Other SHA-2 variants and SHA-3 cases remain in the
corpus, but are skipped because those hashes are not implemented by this library.
The ACVP JSON adapter is test-only; applications construct their protocol's
`fixedInfo` and pass it as HKDF `info`.
