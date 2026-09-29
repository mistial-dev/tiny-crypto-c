/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Bounded GZIP decompression of complete members with CRC32 and ISIZE checks.
 * Standards: RFC 1952 (GZIP), RFC 1951 (DEFLATE).
 * Configuration: TC_ENABLE_GZIP.
 * Limitations: complete input only. The output buffer holds the whole
 * decoded result and doubles as back-reference history.
 * Contracts: docs/api.md, including its size_t work units. Guide: docs/gzip.md. */
#ifndef TINY_CRYPTO_GZIP_H_
#define TINY_CRYPTO_GZIP_H_
#include <tiny_crypto/common.h>
#ifdef __cplusplus
extern "C" {
#endif
enum { TC_GZIP_CODE_BITS = 15, TC_GZIP_LITERAL_CODES = 288, TC_GZIP_DISTANCE_CODES = 32 };
/* Workspace members are private. No initialization is required. */
typedef struct {
  uint16_t counts[TC_GZIP_CODE_BITS + 1];
  uint16_t* symbols;
} TC_GZIP_tree;
typedef struct {
  TC_GZIP_tree literal, distance;
  uint16_t literal_symbols[TC_GZIP_LITERAL_CODES], distance_symbols[TC_GZIP_DISTANCE_CODES];
  uint8_t lengths[TC_GZIP_LITERAL_CODES + TC_GZIP_DISTANCE_CODES];
} TC_GZIP_workspace;
/* Results share the RSA and EC order.
 *   TC_GZIP_INVALID      malformed framing, compressed data, or a CRC32 or
 *                        size mismatch in the received input.
 *   TC_GZIP_LIMIT        output capacity or the work budget ran out.
 *   TC_GZIP_ARGUMENT     NULL pointers or overlapping storage.
 *   TC_GZIP_UNSUPPORTED  a compression method other than deflate. */
typedef enum {
  TC_GZIP_OK,
  TC_GZIP_INVALID,
  TC_GZIP_LIMIT,
  TC_GZIP_ARGUMENT,
  TC_GZIP_UNSUPPORTED
} TC_GZIP_result;

/* Decode complete GZIP members (RFC 1952) with CRC32 and ISIZE checks.
 *   input          complete members. Borrowed and read-only for the call.
 *   workspace      caller-owned scratch. Needs no initialization and is wiped
 *                  before return. Size it with sizeof(TC_GZIP_workspace).
 *   work           remaining work budget, decremented by bounded decoding steps
 *                  (input bits, table entries and output/checksum bytes).
 *   output         caller-owned storage for the decoded bytes. output.data may
 *                  be NULL when output.capacity is zero. Decoded output doubles
 *                  as back-reference history.
 *   output_length  receives the decoded length on OK.
 * Concatenated members share output capacity and the remaining work budget.
 * Trailing non-member bytes return INVALID. Input, output, workspace, work and
 * output_length must be disjoint. ARGUMENT preserves all storage. Other
 * failures wipe output.capacity bytes and leave output_length unchanged.
 * Requires GZIP support. */
TC_GZIP_result TC_GZIP_decode(TC_bytes input, TC_GZIP_workspace* workspace, size_t* work,
                              TC_buffer output, size_t* output_length);
#ifdef __cplusplus
}
#endif
#endif
