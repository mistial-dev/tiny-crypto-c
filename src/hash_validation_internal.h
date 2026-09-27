/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_HASH_VALIDATION_INTERNAL_H_
#define TC_HASH_VALIDATION_INTERNAL_H_

#include "internal.h"

static inline int tc_hash_update_args(const void* ctx, size_t ctx_len,
                                      const uint8_t* data, size_t data_len)
{
  return ctx != NULL && (data != NULL || data_len == 0) &&
         data_len <= UINTPTR_MAX - (uintptr_t)data &&
         tc_internal_ranges_disjoint(ctx, ctx_len, data, data_len);
}

static inline int tc_hash_final_args(const void* ctx, size_t ctx_len,
                                     const uint8_t* digest, size_t digest_len)
{
  return ctx != NULL && digest != NULL &&
         digest_len <= UINTPTR_MAX - (uintptr_t)digest &&
         tc_internal_ranges_disjoint(ctx, ctx_len, digest, digest_len);
}

#endif
