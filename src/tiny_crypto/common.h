/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TINY_CRYPTO_COMMON_H_
#define TINY_CRYPTO_COMMON_H_

#include <tiny_crypto/config.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Every fallible API uses one three-state result. Authentication failures are
 * separate from malformed arguments so protocols can reject packets without
 * treating normal hostile input as an internal error. */
typedef int TC_status;

#define TC_ERROR    (-1)
#define TC_OK       0
#define TC_MISMATCH 1

#if (TC_ZEROIZE != 0) && (TC_ZEROIZE != 1)
#error "TC_ZEROIZE must be 0 or 1"
#endif

#if (TC_STRICT != 0) && (TC_STRICT != 1)
#error "TC_STRICT must be 0 or 1"
#endif

/* Best-effort secret wipe. memory must be valid for length bytes; NULL is
 * accepted only when length is zero. The compiler barrier prevents common
 * dead-store removal, but cannot clear copies already held in CPU registers. */
void TC_secure_zero(void* memory, size_t length);

/* Compare all public-length bytes without returning at the first mismatch. */
TC_status TC_ct_equal(const uint8_t* a, const uint8_t* b, size_t length);

#ifdef __cplusplus
}
#endif

#endif
