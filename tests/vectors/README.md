# Vendored test vectors

These files are test inputs. They are excluded from the installed library.

`wycheproof.zip` is the C2SP Wycheproof archive at commit
`3fa63dd0344abb611f1fb1d77e119938603ea230` (Apache-2.0). Its SHA-256 is
`5dc00fae83575135c3147bfd4a04ee8889b1f0482ac6ca21aa486a8abccf2260`.
The runner verifies that digest before reading any vectors.

The NIST DSS archives and their checksums are documented in
`nist_dss/README.md`.

`nist_ecccdh.zip` is NIST's ECCCDH Primitive Test Vectors archive from the
[CAVP component-testing page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing).
Its SHA-256 is
`5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39`.
The runner checks that digest before using the 50 supported answers.
