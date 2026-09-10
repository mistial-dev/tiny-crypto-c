# TWIC certification authorities

`CertsIssuedToTWICCA1.p7c` is TSA's public PKCS#7 certificate bundle, downloaded
verbatim from [TWIC CA 1 AIA](http://twicaia-twic.tsa.dhs.gov/AIA/CertsIssuedToTWICCA1.p7c)
on September 9, 2026. It contains three TWIC CA 1 certificates and three
self-issued TWIC ROOT certificates.

SHA-256: `b2b2543e79b79b83fd6fe772507817cc05e9af915e7002f8d6b9591d98307168`.

The download used HTTP. Applications must establish trust in a selected root
through their provisioning policy. Bundle membership and self-signatures alone
do not establish trust. Certificate validity periods and signature algorithms
vary across generations.

These are public CA certificates published by TSA. The download provides no
separate license notice. Keep this provenance with redistributed copies.

Inspect the bundle with:

```sh
openssl pkcs7 -inform DER -in CertsIssuedToTWICCA1.p7c -print_certs -noout
```
