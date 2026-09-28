/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/hkdf.h>

#if TC_ENABLE_HKDF
#include <string.h>
#include "kdf_prf_internal.h"

static int tc_hkdf_length_ok(size_t hash_len, size_t output_len)
{
  return output_len != 0 && output_len <= 255u * hash_len;
}

static TC_status tc_hkdf_extract(const tc_hash_algorithm_info* hash, void* ctx, size_t ctx_size,
                                 size_t hash_len, const uint8_t* salt, size_t salt_len,
                                 const uint8_t* ikm, size_t ikm_len, const uint8_t* auxiliary,
                                 size_t auxiliary_len, uint8_t* prk)
{
  const struct tc_kdf_prf prf = tc_kdf_hmac_prf(hash, ctx_size, (uint8_t)hash_len);
  TC_status status;
  if (!prk || !tc_internal_span_valid(salt, salt_len) || !tc_internal_span_valid(ikm, ikm_len) ||
      !tc_internal_span_valid(auxiliary, auxiliary_len) ||
      !tc_kdf_output_disjoint(prk, hash_len, salt, salt_len) ||
      !tc_kdf_output_disjoint(prk, hash_len, ikm, ikm_len) ||
      !tc_kdf_output_disjoint(prk, hash_len, auxiliary, auxiliary_len))
    return TC_ERROR;

  /* An empty HMAC key pads to a zero block, as does RFC 5869's omitted salt. */
  status = tc_kdf_mac_init(&prf, ctx, salt, salt_len);
  if (status == TC_OK)
    status = tc_kdf_mac_update(&prf, ctx, ikm, ikm_len);
  if (status == TC_OK && auxiliary_len != 0)
    status = tc_kdf_mac_update(&prf, ctx, auxiliary, auxiliary_len);
  if (status == TC_OK)
    status = tc_kdf_mac_final(&prf, ctx, prk);
  tc_kdf_mac_clear(&prf, ctx);
  if (status != TC_OK)
    TC_secure_zero(prk, hash_len);
  return status;
}

static TC_status tc_hkdf_expand(const tc_hash_algorithm_info* hash, void* initialized, void* ctx,
                                size_t ctx_size, uint8_t* previous, size_t hash_len,
                                const uint8_t* prk, size_t prk_len, const uint8_t* info,
                                size_t info_len, uint8_t* output, size_t output_len)
{
  const struct tc_kdf_prf prf = tc_kdf_hmac_prf(hash, ctx_size, (uint8_t)hash_len);
  struct tc_kdf_segment segments[3];
  TC_status status;
  size_t offset = 0;
  uint8_t counter = 1;

  if (!prk || prk_len < hash_len || !tc_internal_span_valid(info, info_len) || !output ||
      !tc_hkdf_length_ok(hash_len, output_len) ||
      !tc_kdf_output_disjoint(output, output_len, prk, prk_len) ||
      !tc_kdf_output_disjoint(output, output_len, info, info_len))
    return TC_ERROR;

  status = tc_kdf_mac_init(&prf, initialized, prk, prk_len);
  while (status == TC_OK && offset < output_len) {
    size_t take = output_len - offset;
    segments[0].data = previous;
    segments[0].len = offset != 0 ? hash_len : 0;
    segments[1].data = info;
    segments[1].len = info_len;
    segments[2].data = &counter;
    segments[2].len = 1;
    status = tc_kdf_prf_run(&prf, initialized, ctx, segments, 3, previous);
    if (status != TC_OK)
      break;
    if (take > hash_len)
      take = hash_len;
    memcpy(output + offset, previous, take);
    offset += take;
    ++counter;
  }

  tc_kdf_mac_clear(&prf, initialized);
  tc_kdf_mac_clear(&prf, ctx);
  TC_secure_zero(previous, hash_len);
  if (status != TC_OK)
    TC_secure_zero(output, output_len);
  return status;
}

#define TC_HKDF_DEFINE(N, DIGESTLEN)                                                               \
  TC_status TC_HKDF_SHA##N##_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm,     \
                                     size_t ikm_len, uint8_t* prk)                                 \
  {                                                                                                \
    struct TC_HMAC_SHA##N##_ctx ctx;                                                               \
    return tc_hkdf_extract(&tc_sha##N##_info, &ctx, sizeof ctx, DIGESTLEN, salt, salt_len, ikm,    \
                           ikm_len, NULL, 0, prk);                                                 \
  }                                                                                                \
  TC_status TC_HKDF_SHA##N##_extract_hybrid(const uint8_t* salt, size_t salt_len,                  \
                                            const uint8_t* z, size_t z_len, const uint8_t* t,      \
                                            size_t t_len, uint8_t* prk)                            \
  {                                                                                                \
    struct TC_HMAC_SHA##N##_ctx ctx;                                                               \
    return tc_hkdf_extract(&tc_sha##N##_info, &ctx, sizeof ctx, DIGESTLEN, salt, salt_len, z,      \
                           z_len, t, t_len, prk);                                                  \
  }                                                                                                \
  TC_status TC_HKDF_SHA##N##_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info,       \
                                    size_t info_len, uint8_t* output, size_t output_len)           \
  {                                                                                                \
    struct TC_HMAC_SHA##N##_ctx initialized, ctx;                                                  \
    uint8_t previous[DIGESTLEN];                                                                   \
    return tc_hkdf_expand(&tc_sha##N##_info, &initialized, &ctx, sizeof ctx, previous, DIGESTLEN,  \
                          prk, prk_len, info, info_len, output, output_len);                       \
  }                                                                                                \
  TC_status TC_HKDF_SHA##N##_derive(const uint8_t* salt, size_t salt_len, const uint8_t* ikm,      \
                                    size_t ikm_len, const uint8_t* info, size_t info_len,          \
                                    uint8_t* output, size_t output_len)                            \
  {                                                                                                \
    return TC_HKDF_SHA##N##_derive_hybrid(salt, salt_len, ikm, ikm_len, NULL, 0, info, info_len,   \
                                          output, output_len);                                     \
  }                                                                                                \
  TC_status TC_HKDF_SHA##N##_derive_hybrid(                                                        \
      const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len,                    \
      const uint8_t* auxiliary, size_t auxiliary_len, const uint8_t* info, size_t info_len,        \
      uint8_t* output, size_t output_len)                                                          \
  {                                                                                                \
    uint8_t prk[DIGESTLEN];                                                                        \
    TC_status status;                                                                              \
    if (!tc_internal_span_valid(salt, salt_len) || !tc_internal_span_valid(ikm, ikm_len) ||        \
        !tc_internal_span_valid(auxiliary, auxiliary_len) ||                                       \
        !tc_internal_span_valid(info, info_len) || !output ||                                      \
        !tc_hkdf_length_ok(DIGESTLEN, output_len) ||                                               \
        !tc_kdf_output_disjoint(output, output_len, salt, salt_len) ||                             \
        !tc_kdf_output_disjoint(output, output_len, ikm, ikm_len) ||                               \
        !tc_kdf_output_disjoint(output, output_len, auxiliary, auxiliary_len) ||                   \
        !tc_kdf_output_disjoint(output, output_len, info, info_len))                               \
      return TC_ERROR;                                                                             \
    status = TC_HKDF_SHA##N##_extract_hybrid(salt, salt_len, ikm, ikm_len, auxiliary,              \
                                             auxiliary_len, prk);                                  \
    if (status == TC_OK)                                                                           \
      status = TC_HKDF_SHA##N##_expand(prk, sizeof prk, info, info_len, output, output_len);       \
    TC_secure_zero(prk, sizeof prk);                                                               \
    return status;                                                                                 \
  }

#if TC_ENABLE_SHA1
TC_HKDF_DEFINE(1, TC_SHA1_DIGESTLEN)
#endif
#if TC_ENABLE_SHA224
TC_HKDF_DEFINE(224, TC_SHA224_DIGESTLEN)
#endif
#if TC_ENABLE_SHA256
TC_HKDF_DEFINE(256, TC_SHA256_DIGESTLEN)
#endif
#if TC_ENABLE_SHA384
TC_HKDF_DEFINE(384, TC_SHA384_DIGESTLEN)
#endif
#if TC_ENABLE_SHA512
TC_HKDF_DEFINE(512, TC_SHA512_DIGESTLEN)
#endif

#undef TC_HKDF_DEFINE
#endif /* TC_ENABLE_HKDF */
