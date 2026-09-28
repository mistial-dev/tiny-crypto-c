/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Shared HMAC/CMAC PRF driver for key derivation. Inputs remain borrowed spans. */
#ifndef TC_KDF_PRF_INTERNAL_H_
#define TC_KDF_PRF_INTERNAL_H_

#include <string.h>
#include <tiny_crypto/kdf.h>
#include "hash_core_internal.h"
#include "internal.h"

static inline int tc_kdf_input_ok(const uint8_t* input, size_t length)
{
  return input != NULL || length == 0;
}

/* A later PRF block may reread each input after output bytes are written. */
static inline int tc_kdf_output_disjoint(const uint8_t* output, size_t output_len,
                                         const uint8_t* input, size_t input_len)
{
  return input_len == 0 || tc_internal_ranges_disjoint(output, output_len, input, input_len);
}

#define TC_KDF_HAVE_CMAC (TC_KBKDF_HAVE_AES_CMAC || TC_KBKDF_HAVE_DES_CMAC)

#if TC_KDF_HAVE_CMAC
struct tc_kdf_cmac {
  int (*key_ok)(size_t key_len);
  TC_status (*init)(void* ctx, const uint8_t* key, size_t key_len);
  TC_status (*update)(void* ctx, const uint8_t* data, size_t len);
  TC_status (*final)(void* ctx, uint8_t* out);
  void (*clear)(void* ctx);
};
#endif

enum tc_kdf_prf_kind { TC_KDF_PRF_HMAC, TC_KDF_PRF_CMAC };

/* Typed wrappers own the matching context storage. The core copies only
 * ctx_size bytes and reads only the selected descriptor arm. */
struct tc_kdf_prf {
  enum tc_kdf_prf_kind kind;
  uint8_t out_len;
  size_t ctx_size;
  union {
#if TC_KBKDF_HAVE_HMAC
    const tc_hash_algorithm_info* hash;
#endif
#if TC_KDF_HAVE_CMAC
    const struct tc_kdf_cmac* cmac;
#endif
  } mac;
};

struct tc_kdf_segment {
  const uint8_t* data;
  size_t len;
};

#if TC_KBKDF_HAVE_HMAC
static inline struct tc_kdf_prf tc_kdf_hmac_prf(const tc_hash_algorithm_info* hash, size_t ctx_size,
                                                uint8_t out_len)
{
  struct tc_kdf_prf prf;
  prf.kind = TC_KDF_PRF_HMAC;
  prf.out_len = out_len;
  prf.ctx_size = ctx_size;
  prf.mac.hash = hash;
  return prf;
}
#endif

static inline int tc_kdf_key_ok(const struct tc_kdf_prf* prf, size_t key_len)
{
#if TC_KBKDF_HAVE_HMAC
  if (prf->kind == TC_KDF_PRF_HMAC)
    return 1;
#endif
#if TC_KDF_HAVE_CMAC
  return prf->mac.cmac->key_ok(key_len);
#else
  (void)key_len;
  return 0;
#endif
}

static inline TC_status tc_kdf_mac_init(const struct tc_kdf_prf* prf, void* ctx, const uint8_t* key,
                                        size_t key_len)
{
#if TC_KBKDF_HAVE_HMAC
  if (prf->kind == TC_KDF_PRF_HMAC)
    return tc_hmac_core_init(prf->mac.hash, ctx, key, key_len);
#endif
#if TC_KDF_HAVE_CMAC
  return prf->mac.cmac->init(ctx, key, key_len);
#else
  (void)ctx;
  (void)key;
  (void)key_len;
  return TC_ERROR;
#endif
}

static inline TC_status tc_kdf_mac_update(const struct tc_kdf_prf* prf, void* ctx,
                                          const uint8_t* data, size_t len)
{
#if TC_KBKDF_HAVE_HMAC
  if (prf->kind == TC_KDF_PRF_HMAC)
    return tc_hmac_core_update(prf->mac.hash, ctx, data, len);
#endif
#if TC_KDF_HAVE_CMAC
  return prf->mac.cmac->update(ctx, data, len);
#else
  (void)ctx;
  (void)data;
  (void)len;
  return TC_ERROR;
#endif
}

static inline TC_status tc_kdf_mac_final(const struct tc_kdf_prf* prf, void* ctx, uint8_t* out)
{
#if TC_KBKDF_HAVE_HMAC
  if (prf->kind == TC_KDF_PRF_HMAC)
    return tc_hmac_core_final(prf->mac.hash, ctx, out);
#endif
#if TC_KDF_HAVE_CMAC
  return prf->mac.cmac->final(ctx, out);
#else
  (void)ctx;
  (void)out;
  return TC_ERROR;
#endif
}

static inline void tc_kdf_mac_clear(const struct tc_kdf_prf* prf, void* ctx)
{
#if TC_KBKDF_HAVE_HMAC
  if (prf->kind == TC_KDF_PRF_HMAC) {
    tc_hmac_core_clear(prf->mac.hash, ctx);
    return;
  }
#endif
#if TC_KDF_HAVE_CMAC
  prf->mac.cmac->clear(ctx);
#else
  TC_secure_zero(ctx, prf->ctx_size);
#endif
}

/* Begin from a cached keyed context and feed each segment in order. */
static inline TC_status tc_kdf_prf_run(const struct tc_kdf_prf* prf, const void* initialized,
                                       void* ctx, const struct tc_kdf_segment* segments,
                                       unsigned count, uint8_t* block)
{
  unsigned i;
  memcpy(ctx, initialized, prf->ctx_size);
  for (i = 0; i < count; ++i) {
    if (segments[i].len != 0 &&
        tc_kdf_mac_update(prf, ctx, segments[i].data, segments[i].len) != TC_OK) {
      tc_kdf_mac_clear(prf, ctx);
      return TC_ERROR;
    }
  }
  return tc_kdf_mac_final(prf, ctx, block);
}

#endif /* TC_KDF_PRF_INTERNAL_H_ */
