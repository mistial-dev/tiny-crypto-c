/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_HASH64_INTERNAL_H_
#define TC_HASH64_INTERNAL_H_
#include "hash_stream_internal.h"

enum { TC_HASH64_BLOCK_BYTES = 64, TC_HASH64_LENGTH_BYTES = 8,
       TC_HASH64_LENGTH_OFFSET = TC_HASH64_BLOCK_BYTES - TC_HASH64_LENGTH_BYTES };
typedef void (*tc_hash_compress_fn)(uint32_t* state, const uint8_t* block);
typedef struct {
  uint32_t* state;
  tc_hash_compress_fn compress;
} tc_hash64_operation;

static inline void tc_hash64_compress_block(void* context, const uint8_t* block)
{
  tc_hash64_operation* operation = (tc_hash64_operation*)context;
  operation->compress(operation->state, block);
}

/* Count handling belongs to the digest. Complete input blocks are borrowed;
 * only a partial block is copied into the context. */
static inline void tc_hash64_absorb(uint32_t* state, uint8_t* used, uint8_t* buffer,
    const uint8_t* data, size_t length, tc_hash_compress_fn compress)
{
  tc_hash64_operation operation = { state, compress };
  tc_hash_stream_absorb(&operation, used, buffer, data, length,
                        TC_HASH64_BLOCK_BYTES, tc_hash64_compress_block);
}

/* Append the one-bit padding and encoded bit length, then compress the tail.
 * The caller serializes the resulting chaining words into its digest. */
static inline void tc_hash64_finish(uint32_t* state, uint64_t count,
    uint8_t* used, uint8_t* buffer, tc_hash_compress_fn compress,
    tc_hash_length_encoding encoding)
{
  tc_hash64_operation operation = { state, compress };
  tc_hash_stream_finish(&operation, count, used, buffer,
                        TC_HASH64_BLOCK_BYTES, TC_HASH64_LENGTH_BYTES,
                        encoding, tc_hash64_compress_block);
}
#endif
