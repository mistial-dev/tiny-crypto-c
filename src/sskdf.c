/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/sskdf.h>
#include "internal.h"
#include <string.h>
#if TC_ENABLE_SSKDF
#include "hash_dispatch_internal.h"

/* ctx is the typed context for info's algorithm, and digest holds one digest. */
static TC_status derive(const tc_hash_algorithm_info* hash, void* ctx, size_t ctx_size,
                        uint8_t* digest, const uint8_t* z, size_t z_len, const TC_bytes* info,
                        size_t count, uint8_t* output, size_t output_len)
{
  uint8_t counter[4];
  size_t total, i, offset = 0, take;
  uint32_t round = 1;
  const size_t digest_length = tc_hash_core_digest_bytes(hash);
  TC_status status = TC_ERROR;
  if (!z || !z_len || !output || !output_len || (!info && count) ||
      count > SIZE_MAX / sizeof *info || z_len > SIZE_MAX - 4 ||
      !tc_internal_ranges_disjoint(z, z_len, output, output_len) ||
      !tc_internal_ranges_disjoint(info, count * sizeof *info, output, output_len))
    return TC_ERROR;
  total = 4 + z_len;
  for (i = 0; i < count; ++i) {
    if ((!info[i].data && info[i].length) || info[i].length > SIZE_MAX - total ||
        !tc_internal_ranges_disjoint(info[i].data, info[i].length, output, output_len))
      return TC_ERROR;
    total += info[i].length;
  }
#if SIZE_MAX > UINT64_MAX / 8
  if (total > UINT64_MAX / 8)
    return TC_ERROR;
#endif
#if SIZE_MAX > UINT32_MAX
  {
    size_t blocks = output_len / digest_length + (output_len % digest_length != 0);
    if (blocks > UINT32_MAX)
      return TC_ERROR;
  }
#endif
  while (offset < output_len) {
    counter[0] = (uint8_t)(round >> 24);
    counter[1] = (uint8_t)(round >> 16);
    counter[2] = (uint8_t)(round >> 8);
    counter[3] = (uint8_t)round;
    if (tc_hash_core_init(hash, ctx) != TC_OK ||
        tc_hash_core_update(hash, ctx, counter, 4) != TC_OK ||
        tc_hash_core_update(hash, ctx, z, z_len) != TC_OK)
      goto done;
    for (i = 0; i < count; ++i)
      if (tc_hash_core_update(hash, ctx, info[i].data, info[i].length) != TC_OK)
        goto done;
    if (tc_hash_core_final(hash, ctx, digest) != TC_OK)
      goto done;
    take = output_len - offset;
    if (take > digest_length)
      take = digest_length;
    memcpy(output + offset, digest, take);
    offset += take;
    ++round;
  }
  status = TC_OK;
done:
  TC_secure_zero(ctx, ctx_size);
  TC_secure_zero(digest, digest_length);
  if (status != TC_OK)
    TC_secure_zero(output, output_len);
  return status;
}

#define TC_SSKDF_FAMILY(N, BYTES)                                                                  \
  TC_status TC_SSKDF_SHA##N(const uint8_t* z, size_t z_len, const TC_bytes* info, size_t count,    \
                            uint8_t* output, size_t output_len)                                    \
  {                                                                                                \
    struct TC_SHA##N##_ctx ctx;                                                                    \
    uint8_t digest[BYTES];                                                                         \
    return derive(&tc_sha##N##_info, &ctx, sizeof ctx, digest, z, z_len, info, count, output,      \
                  output_len);                                                                     \
  }
#if TC_ENABLE_SHA256
TC_SSKDF_FAMILY(256, TC_SHA256_DIGESTLEN)
#endif
#if TC_ENABLE_SHA384
TC_SSKDF_FAMILY(384, TC_SHA384_DIGESTLEN)
#endif
#endif
