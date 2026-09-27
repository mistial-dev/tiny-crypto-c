/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_HASH_ADAPTER_INTERNAL_H_
#define TC_HASH_ADAPTER_INTERNAL_H_

#include <tiny_crypto/common.h>
#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || TC_ENABLE_SHA384 || TC_ENABLE_SHA512
#include <tiny_crypto/hash.h>
#endif

/* Typed union members let callers use one workspace without aliasing casts. */
typedef union {
  uint8_t unused;
#if TC_ENABLE_SHA1
  struct TC_SHA1_ctx sha1;
#endif
#if TC_ENABLE_SHA224
  struct TC_SHA224_ctx sha224;
#endif
#if TC_ENABLE_SHA256
  struct TC_SHA256_ctx sha256;
#endif
#if TC_ENABLE_SHA384
  struct TC_SHA384_ctx sha384;
#endif
#if TC_ENABLE_SHA512
  struct TC_SHA512_ctx sha512;
#endif
} tc_hash_workspace;

typedef struct {
  uint8_t digest_length;
  size_t hash_context_size;
  void* (*workspace_context)(tc_hash_workspace*);
  TC_status (*hash_init)(void*);
  TC_status (*hash_update)(void*, const uint8_t*, size_t);
  TC_status (*hash_final)(void*, uint8_t*);
} tc_hash_adapter;

#if TC_ENABLE_HMAC
typedef struct {
  uint8_t digest_length;
  size_t hmac_context_size;
  TC_status (*hmac_init)(void*, const uint8_t*, size_t);
  TC_status (*hmac_update)(void*, const uint8_t*, size_t);
  TC_status (*hmac_final)(void*, uint8_t*);
  void (*hmac_clear)(void*);
} tc_hmac_adapter;
#endif

/* Returns zero when the implementation is absent. Passing NULL checks availability. */
int tc_hash_adapter_get(TC_hash_algorithm algorithm, tc_hash_adapter* out);

#if TC_ENABLE_SHA1
void tc_hash_adapter_load_1(tc_hash_adapter* out);
#if TC_ENABLE_HMAC
void tc_hmac_adapter_load_1(tc_hmac_adapter* out);
#endif
#endif
#if TC_ENABLE_SHA224
void tc_hash_adapter_load_224(tc_hash_adapter* out);
#if TC_ENABLE_HMAC
void tc_hmac_adapter_load_224(tc_hmac_adapter* out);
#endif
#endif
#if TC_ENABLE_SHA256
void tc_hash_adapter_load_256(tc_hash_adapter* out);
#if TC_ENABLE_HMAC
void tc_hmac_adapter_load_256(tc_hmac_adapter* out);
#endif
#endif
#if TC_ENABLE_SHA384
void tc_hash_adapter_load_384(tc_hash_adapter* out);
#if TC_ENABLE_HMAC
void tc_hmac_adapter_load_384(tc_hmac_adapter* out);
#endif
#endif
#if TC_ENABLE_SHA512
void tc_hash_adapter_load_512(tc_hash_adapter* out);
#if TC_ENABLE_HMAC
void tc_hmac_adapter_load_512(tc_hmac_adapter* out);
#endif
#endif

#endif
