# Vendored test vectors

These files are test inputs. They are excluded from the installed library and
from source archives. Each directory's README records the source, version,
license and retained scope, and its `SHA256SUMS` lists every file's digest.
`tests/test_vector_manifests.py` checks the manifests.

| Directory | Contents |
| --- | --- |
| `aes/cavp/` | NIST CAVP AES ECB, CBC, OFB, GCM and CCM response files |
| `aes/cmac/` | NIST CAVP AES CMAC response files |
| `aes/eax/` | EAX paper vectors and EAX' worked examples |
| `aes/kw/` | NIST CAVP KWVS AES KW and KWP files |
| `des/` | NIST CAVP TDES KAT, MMT, MCT and CMAC files, and generated edge cases |
| `drbg/` | NIST CAVP SP 800-90A Hash_DRBG, HMAC_DRBG and CTR_DRBG answers |
| `hash/` | NIST CAVP SHA and HMAC response files |
| `kda/` | NIST KAS 2014 single-step KDF answers |
| `kdf/cavp/` | NIST CAVP SP 800-108 KBKDF response files |
| `kmac/` | NIST ACVP and OpenSSL KMAC256 answers |
| `nist_dss/` | NIST CAVP FIPS 186-3 RSA and FIPS 186-4 ECDSA files |
| `nist_ecccdh/` | NIST CAVP ECC CDH primitive vectors |
| `wycheproof/` | C2SP Wycheproof `testvectors_v1` at a pinned commit |

The PIV, TWIC, X.509 and EAC corpora document their sources in their own
READMEs.
