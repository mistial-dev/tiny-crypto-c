/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "hash_adapter_internal.h"
#include <string.h>
#if defined(__AVR__) && TC_AVR_PROGMEM
#include <avr/pgmspace.h>
#define TC_HASH_ADAPTER_STORAGE PROGMEM
#define TC_HASH_ADAPTER_COPY(dst, src) memcpy_P(dst, src, sizeof *(dst))
#else
#define TC_HASH_ADAPTER_STORAGE
#define TC_HASH_ADAPTER_COPY(dst, src) memcpy(dst, src, sizeof *(dst))
#endif

#define TC_HASH_ADAPTER_FAMILY(N, MEMBER) \
  static void* tc_hash_workspace_##N(tc_hash_workspace* workspace) \
  { return &workspace->MEMBER; } \
  static TC_status tc_hash_##N##_init(void* ctx) \
  { return TC_SHA##N##_init((struct TC_SHA##N##_ctx*)ctx); } \
  static TC_status tc_hash_##N##_update(void* ctx, const uint8_t* data, size_t len) \
  { return TC_SHA##N##_update((struct TC_SHA##N##_ctx*)ctx, data, len); } \
  static TC_status tc_hash_##N##_final(void* ctx, uint8_t* digest) \
  { return TC_SHA##N##_final((struct TC_SHA##N##_ctx*)ctx, digest); }

#if TC_ENABLE_HMAC
#define TC_HMAC_ADAPTER_FAMILY(N) \
  static TC_status tc_hmac_##N##_init(void* ctx, const uint8_t* key, size_t keylen) \
  { return TC_HMAC_SHA##N##_init((struct TC_HMAC_SHA##N##_ctx*)ctx, key, keylen); } \
  static TC_status tc_hmac_##N##_update(void* ctx, const uint8_t* data, size_t len) \
  { return TC_HMAC_SHA##N##_update((struct TC_HMAC_SHA##N##_ctx*)ctx, data, len); } \
  static TC_status tc_hmac_##N##_final(void* ctx, uint8_t* tag) \
  { return TC_HMAC_SHA##N##_final((struct TC_HMAC_SHA##N##_ctx*)ctx, tag); } \
  static void tc_hmac_##N##_clear(void* ctx) \
  { TC_HMAC_SHA##N##_ctx_clear((struct TC_HMAC_SHA##N##_ctx*)ctx); } \
  static const tc_hmac_adapter tc_hmac_adapter_##N TC_HASH_ADAPTER_STORAGE = { \
    TC_SHA##N##_DIGESTLEN, sizeof(struct TC_HMAC_SHA##N##_ctx), \
    tc_hmac_##N##_init, tc_hmac_##N##_update, tc_hmac_##N##_final, \
    tc_hmac_##N##_clear \
  }; \
  void tc_hmac_adapter_load_##N(tc_hmac_adapter* out) \
  { TC_HASH_ADAPTER_COPY(out, &tc_hmac_adapter_##N); }
#else
#define TC_HMAC_ADAPTER_FAMILY(N)
#endif

#define TC_HASH_ADAPTER_DEFINE(N, MEMBER) \
  TC_HASH_ADAPTER_FAMILY(N, MEMBER) \
  TC_HMAC_ADAPTER_FAMILY(N) \
  static const tc_hash_adapter tc_hash_adapter_##N TC_HASH_ADAPTER_STORAGE = { \
    TC_SHA##N##_DIGESTLEN, sizeof(struct TC_SHA##N##_ctx), \
    tc_hash_workspace_##N, tc_hash_##N##_init, tc_hash_##N##_update, \
    tc_hash_##N##_final \
  }; \
  void tc_hash_adapter_load_##N(tc_hash_adapter* out) \
  { TC_HASH_ADAPTER_COPY(out, &tc_hash_adapter_##N); }

#if TC_ENABLE_SHA1
TC_HASH_ADAPTER_DEFINE(1, sha1)
#endif
#if TC_ENABLE_SHA224
TC_HASH_ADAPTER_DEFINE(224, sha224)
#endif
#if TC_ENABLE_SHA256
TC_HASH_ADAPTER_DEFINE(256, sha256)
#endif
#if TC_ENABLE_SHA384
TC_HASH_ADAPTER_DEFINE(384, sha384)
#endif
#if TC_ENABLE_SHA512
TC_HASH_ADAPTER_DEFINE(512, sha512)
#endif

int tc_hash_adapter_get(TC_hash_algorithm algorithm, tc_hash_adapter* out)
{
  const tc_hash_adapter* selected;
  switch (algorithm) {
#if TC_ENABLE_SHA1
    case TC_HASH_SHA1: selected = &tc_hash_adapter_1; break;
#endif
#if TC_ENABLE_SHA224
    case TC_HASH_SHA224: selected = &tc_hash_adapter_224; break;
#endif
#if TC_ENABLE_SHA256
    case TC_HASH_SHA256: selected = &tc_hash_adapter_256; break;
#endif
#if TC_ENABLE_SHA384
    case TC_HASH_SHA384: selected = &tc_hash_adapter_384; break;
#endif
#if TC_ENABLE_SHA512
    case TC_HASH_SHA512: selected = &tc_hash_adapter_512; break;
#endif
    default: return 0;
  }
  if (out) TC_HASH_ADAPTER_COPY(out, selected);
  return 1;
}
