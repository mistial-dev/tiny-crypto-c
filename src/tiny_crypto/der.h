/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_DER_H_
#define TINY_CRYPTO_DER_H_
#include <tiny_crypto/tlv.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Readers take the complete DER encoding, including tag and length, as a
 * borrowed span and return spans that borrow it. The input must stay unchanged
 * while a span is used. The *_contents forms take only an IMPLICIT value.
 * Every reader returns one of:
 *   OK          the encoding is valid and outputs are written.
 *   INVALID     malformed, truncated or trailing input, or a wrong tag.
 *   LIMIT       a value exceeds the output type, such as UINT32_MAX.
 *   UNSUPPORTED a recognised version that this reader does not handle.
 *   ARGUMENT    a NULL output, or a span with NULL data and a nonzero length.
 * Outputs are unchanged on every failure. END and MORE are never returned. */
TC_TLV_result TC_DER_integer(TC_bytes encoded, TC_bytes* twos_complement, int* negative);
/* Strictly positive INTEGER as a borrowed unsigned magnitude. */
TC_TLV_result TC_DER_positive_integer(TC_bytes encoded, TC_bytes* magnitude);
/* Validate an IMPLICIT INTEGER's contents without limiting its width or sign. */
TC_TLV_result TC_DER_integer_contents(TC_bytes contents);
TC_TLV_result TC_DER_uint32(TC_bytes encoded, uint32_t* out);
/* Contents-only form for an IMPLICIT-tagged nonnegative INTEGER.
 * DER sign/minimality rules still apply. Values above UINT32_MAX return LIMIT. */
TC_TLV_result TC_DER_uint32_contents(TC_bytes contents, uint32_t* out);
TC_TLV_result TC_DER_bit_string(TC_bytes encoded, TC_bytes* bits, unsigned* unused);
/* OID contents remain encoded, so arcs of any size need no integer conversion. */
TC_TLV_result TC_DER_oid(TC_bytes encoded, TC_bytes* oid);
/* Contents-only form for an IMPLICIT-tagged OBJECT IDENTIFIER. */
TC_TLV_result TC_DER_oid_contents(TC_bytes contents);
TC_TLV_result TC_DER_boolean(TC_bytes encoded, int* out);
TC_TLV_result TC_DER_null(TC_bytes encoded);
TC_TLV_result TC_DER_sequence(TC_bytes encoded, TC_bytes* contents);
TC_TLV_result TC_DER_set(TC_bytes encoded, TC_bytes* contents);
/* The caller checks SET OF sorting and schema-dependent SET/DEFAULT rules. */

typedef struct {
  TC_bytes oid;
  /* Complete parameter encoding, or {NULL, 0} when absent. */
  TC_bytes parameters;
} TC_DER_algorithm;
/* Parameter rules depend on the OID and are checked by the caller. */
TC_TLV_result TC_DER_algorithm_identifier(TC_bytes encoded, TC_DER_algorithm* out);
typedef struct {
  TC_DER_algorithm algorithm;
  TC_bytes key;
} TC_DER_public_key;
/* SubjectPublicKeyInfo with a byte-aligned, nonempty subjectPublicKey. */
TC_TLV_result TC_DER_subject_public_key(TC_bytes encoded, TC_DER_public_key* out);

typedef struct {
  TC_DER_algorithm algorithm;
  TC_bytes key;
  /* IMPLICIT SET OF contents, or {NULL, 0} when absent. */
  TC_bytes attributes;
  /* BIT STRING payload, or {NULL, 0} when absent. */
  TC_bytes public_key;
  unsigned public_key_unused;
} TC_DER_private_key;
/* DER PKCS #8 PrivateKeyInfo / RFC 5958 OneAsymmetricKey.
 * Version 0 carries a private key. Version 1 also carries its public key.
 * All spans borrow the encoded input.
 * Checks the container fields. Callers validate algorithm parameters, key
 * contents, public/private consistency and attribute schemas.
 * Other versions return UNSUPPORTED.
 * Keep the output object separate from input and protect the key bytes. */
TC_TLV_result TC_DER_private_key_info(TC_bytes encoded, TC_DER_private_key* out);

typedef struct {
  TC_bytes r, s;
} TC_DER_signature_pair;
typedef struct {
  TC_bytes modulus, exponent;
} TC_DER_rsa_public_key;
/* PKCS #1 RSAPublicKey with positive, borrowed integer magnitudes.
 * Validate modulus and exponent constraints before cryptographic use. */
TC_TLV_result TC_DER_rsa_public(TC_bytes encoded, TC_DER_rsa_public_key* out);
typedef struct {
  TC_bytes modulus, public_exponent, private_exponent;
  TC_bytes prime1, prime2, exponent1, exponent2, coefficient;
} TC_DER_rsa_private_key;
/* PKCS #1 two-prime RSAPrivateKey. Components borrow the input buffer.
 * Checks DER structure and positive integers. Validate key mathematics before use.
 * Version 1 returns UNSUPPORTED. Keep the output object separate from input. */
TC_TLV_result TC_DER_rsa_private(TC_bytes encoded, TC_DER_rsa_private_key* out);
/* Positive INTEGERs as unsigned magnitudes, with any sign octet removed.
 * The caller checks r and s against the signing key's group order. */
TC_TLV_result TC_DER_ecdsa_signature(TC_bytes encoded, TC_DER_signature_pair* out);
#ifdef __cplusplus
}
#endif
#endif
