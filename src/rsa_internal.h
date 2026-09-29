/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_RSA_INTERNAL_H_
#define TC_RSA_INTERNAL_H_
#include <tiny_crypto/common.h>
#include <tiny_crypto/rsa.h>
#include "mp_internal.h"
#include "hash_info_internal.h"
#include "pki_storage_internal.h"

/* prefix is the canonical DER DigestInfo header for the selected hash.
 * The caller supplies its matching fixed-length digest. */
static inline uint8_t tc_rsa_v15_byte(size_t index, size_t separator, const uint8_t* prefix,
                                      size_t prefix_length, const uint8_t* digest)
{
  if (!index || index == separator)
    return 0;
  if (index == 1)
    return 1;
  if (index < separator)
    return 0xff;
  index -= separator + 1;
  return index < prefix_length ? prefix[index] : digest[index - prefix_length];
}

static inline int tc_rsa_v15_size(size_t length, size_t prefix_length, size_t digest_length)
{
  return prefix_length && digest_length && length >= 11 && prefix_length <= length - 11 &&
         digest_length <= length - 11 - prefix_length;
}

/* RFC 8017 section 9.2 encoding step. Inputs and output are disjoint, and pointers
 * cover the stated lengths. Invalid sizing leaves output unchanged. */
static inline TC_status tc_rsa_v15_encode(uint8_t* out, size_t length, const uint8_t* prefix,
                                          size_t prefix_length, const uint8_t* digest,
                                          size_t digest_length)
{
  size_t separator;
  if (!out || !prefix || !digest || !tc_rsa_v15_size(length, prefix_length, digest_length))
    return TC_ERROR;
  separator = length - prefix_length - digest_length - 1;
  for (size_t i = 0; i < length; ++i)
    out[i] = tc_rsa_v15_byte(i, separator, prefix, prefix_length, digest);
  return TC_OK;
}

/* Compare the full representative, including padding and exact DER header.
 * Recovered representatives with invalid lengths or bytes return MISMATCH. */
static inline TC_status tc_rsa_v15_check(const uint8_t* encoded, size_t length,
                                         const uint8_t* prefix, size_t prefix_length,
                                         const uint8_t* digest, size_t digest_length)
{
  size_t separator;
  unsigned difference = 0;
  if (!encoded || !prefix || !digest)
    return TC_ERROR;
  if (!tc_rsa_v15_size(length, prefix_length, digest_length))
    return TC_MISMATCH;
  separator = length - prefix_length - digest_length - 1;
  for (size_t i = 0; i < length; ++i)
    difference |= encoded[i] ^ tc_rsa_v15_byte(i, separator, prefix, prefix_length, digest);
  return difference ? TC_MISMATCH : TC_OK;
}

static inline int tc_rsa_supported_modulus_size(size_t length)
{
  return length == 128 || length == 256 || length == 384 || length == TC_RSA_MAX_MODULUS_BYTES;
}

static inline int tc_rsa_supported_bits(size_t bits)
{
  return bits % 8 == 0 && tc_rsa_supported_modulus_size(bits / 8);
}

/* Structural public-key checks: a supported modulus size with the top and
 * bottom bits set, and an odd minimal exponent 3 <= e < n. */
static inline TC_RSA_result tc_rsa_public_key_check(const TC_RSA_public_key* key)
{
  if (!key || !key->modulus.data || !key->exponent.data)
    return TC_RSA_ARGUMENT;
  const uint8_t* modulus = key->modulus.data;
  const uint8_t* exponent = key->exponent.data;
  const size_t length = key->modulus.length, exponent_length = key->exponent.length;
  /* A size outside the supported set is well formed but not implemented. */
  if (!tc_rsa_supported_modulus_size(length))
    return TC_RSA_UNSUPPORTED;
  if (!exponent_length || exponent_length > length || !exponent[0] ||
      !(exponent[exponent_length - 1] & 1) || (exponent_length == 1 && exponent[0] < 3) ||
      !(modulus[0] & 0x80) || !(modulus[length - 1] & 1) ||
      (exponent_length == length && memcmp(exponent, modulus, length) >= 0))
    return TC_RSA_INVALID;
  return TC_RSA_OK;
}

/* Internal public-key exponentiation. Modulus and input
 * have length bytes; out has the same capacity. Exponent is minimally encoded.
 * All ranges, work and scratch are disjoint. The caller validates address ranges.
 * Scratch needs 8*(length/sizeof(word))+2 limbs and is wiped after use.
 * Work counts modular additions/multiplications plus one setup unit when R²
 * is computed here; each has a size-bounded loop. Prepared R² belongs to the
 * same unchanged modulus and stays outside scratch.
 * Output changes only on OK. Validation covers encodings and numeric bounds. */
static inline TC_RSA_result tc_rsa_public_operation(const TC_RSA_public_key* key,
                                                    const uint8_t* input, uint8_t* out,
                                                    tc_mp_scratch scratch_area, uint32_t* work,
                                                    const tc_mp_word* prepared_r2)
{
  size_t n, required, cost;
  tc_mp_word *p, *base, *one, *result, *temporary, *reduced, *product, factor;
  tc_mp_word* scratch = scratch_area.words;
  if (!input || !out || !scratch || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result checked = tc_rsa_public_key_check(key);
  if (checked != TC_RSA_OK)
    return checked;
  const uint8_t* modulus = key->modulus.data;
  const TC_bytes exponent = key->exponent;
  const size_t length = key->modulus.length;
  if (memcmp(input, modulus, length) >= 0)
    return TC_RSA_INVALID;
  n = length / sizeof(tc_mp_word);
  required = 8 * n + 2;
  cost = (prepared_r2 ? 0 : 16 * length) + 16 * exponent.length + 4;
  if (scratch_area.capacity < required || *work < cost)
    return TC_RSA_LIMIT;
  *work -= cost;
  p = scratch;
  base = p + n;
  one = base + n;
  result = one + n;
  temporary = result + n;
  reduced = temporary + n;
  product = reduced + n;
  tc_mp_from_be(p, modulus, length);
  tc_mp_from_be(base, input, length);
  factor = tc_mp_montgomery_factor(p[0]);
  if (!prepared_r2) {
    tc_mp_montgomery_r2(temporary, p, n, reduced);
    prepared_r2 = temporary;
  }
  memset(one, 0, length);
  one[0] = 1;
  const tc_mp_modulus field = {p, n, factor, product, reduced};
  tc_mp_montgomery(one, one, prepared_r2, &field);
  tc_mp_montgomery(base, base, prepared_r2, &field);
  tc_mp_power_public(result, base, exponent, one, &field);
  memset(one, 0, length);
  one[0] = 1;
  tc_mp_montgomery(result, result, one, &field);
  tc_mp_to_be(out, result, length);
  TC_secure_zero(scratch, required * sizeof *scratch);
  return TC_RSA_OK;
}

/* digest is a precomputed hash. No key-size acceptance policy
 * is implied. Scratch needs 9n+2 limbs, including the recovered representative.
 * Other storage preconditions match tc_rsa_public_operation. */
static inline TC_RSA_result tc_rsa_verify_v15(const TC_RSA_public_key* key, TC_hash_algorithm hash,
                                              TC_bytes digest, TC_bytes signature,
                                              tc_mp_scratch scratch, uint32_t* work,
                                              const tc_mp_word* prepared_r2)
{
  size_t n, arithmetic_words;
  uint8_t* encoded;
  TC_RSA_result result;
  TC_status checked;
  tc_hash_info info;
  if (!key || !key->modulus.data || !key->exponent.data || !signature.data || !digest.data ||
      !scratch.words || !work)
    return TC_RSA_ARGUMENT;
  const size_t length = key->modulus.length, digest_length = digest.length;
  if (!tc_hash_info_get(hash, &info))
    return TC_RSA_UNSUPPORTED;
  if (digest_length != info.digest_length)
    return TC_RSA_ARGUMENT;
  if (!tc_rsa_supported_modulus_size(length))
    return TC_RSA_UNSUPPORTED;
  if (signature.length != length ||
      !tc_rsa_v15_size(length, info.digest_info.length, digest_length))
    return TC_RSA_INVALID;
  n = length / sizeof(tc_mp_word);
  arithmetic_words = 8 * n + 2;
  if (scratch.capacity < arithmetic_words + n || *work < length)
    return TC_RSA_LIMIT;
  *work -= length;
  encoded = (uint8_t*)(scratch.words + arithmetic_words);
  result =
      tc_rsa_public_operation(key, signature.data, encoded,
                              (tc_mp_scratch){scratch.words, arithmetic_words}, work, prepared_r2);
  if (result != TC_RSA_OK)
    return result;
  checked = tc_rsa_v15_check(encoded, length, info.digest_info.data, info.digest_info.length,
                             digest.data, digest_length);
  TC_secure_zero(encoded, length);
  return checked == TC_OK ? TC_RSA_OK : TC_RSA_INVALID;
}

/* Shared RSA argument checks. Each helper checks that workspace words are
 * aligned, that scratch and output are disjoint from each other and from the
 * borrowed inputs, and returns TC_RSA_ARGUMENT for invalid storage. */

/* Maps a sealed plan's final status to an RSA result. */
TC_RSA_result tc_rsa_storage_status(const tc_pki_storage_plan* plan);

/* Workspace only. Inputs must stay clear of scratch. */
TC_RSA_result tc_rsa_workspace_inputs(const TC_RSA_workspace* workspace, const TC_bytes* inputs,
                                      size_t count);

/* Workspace and output: both are written, so neither may overlap an input. */
TC_RSA_result tc_rsa_output_inputs(const TC_RSA_workspace* workspace, const TC_bytes* inputs,
                                   size_t count, TC_bytes output);

/* Two caller control structures (key, options) against workspace and output. */
TC_RSA_result tc_rsa_control_inputs(const TC_RSA_workspace* workspace, TC_bytes output,
                                    const void* first, size_t first_size, const void* second,
                                    size_t second_size);

/* Public key plus up to two message spans. */
TC_RSA_result tc_rsa_public_inputs(const TC_RSA_public_key* key, TC_bytes first, TC_bytes second,
                                   TC_bytes output, const TC_RSA_workspace* workspace);

/* Private key and digest. Also rejects empty or oversized d, p and q. */
TC_RSA_result tc_rsa_private_inputs(const TC_RSA_private_key* key, TC_bytes digest, TC_bytes output,
                                    const TC_RSA_workspace* workspace);

/* CRT parameters. Rejects values longer than a prime after leading zeros. */
TC_RSA_result tc_rsa_crt_inputs(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                TC_bytes output, const TC_RSA_workspace* workspace);
#endif
