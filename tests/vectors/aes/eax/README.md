# AES-EAX test vectors

The Wycheproof EAX tests read `aes_eax_test.json` from the shared Wycheproof
tree in `../../wycheproof/testvectors_v1/`, described in
`../../wycheproof/README.md`.

The RFC-style vectors in the EAX tests are from M. Bellare, P. Rogaway, and
D. Wagner, *The EAX Mode of Operation*, ePrint 2003/069, Appendix G:
<https://eprint.iacr.org/2003/069>. The paper states that the EAX work is
placed in the **public domain** and is free and unencumbered for all uses.

`eax_prime_worked.json` contains twelve Wycheproof-style positive worked
vectors generated independently with Python's `cryptography` AES backend and
the C12.22 Annex I algorithm. The C implementation checks ciphertext and tag
against these values as a cross-implementation regression set.

Run `python3 tools/verify_eax_prime_vectors.py` from the repository root to
verify the same corpus with OpenSSL's AES-128 implementation. This third-party
cross-check is independent of the Python implementation that generated the
values.

The EAX' vector in `c12-22-eax-prime.txt` is transcribed from ANSI C12.22-2008,
Example 9 and Annex I.4.

## Checksums

`SHA256SUMS` lists the SHA-256 of every file here, and
`tests/test_vector_manifests.py` checks them.
