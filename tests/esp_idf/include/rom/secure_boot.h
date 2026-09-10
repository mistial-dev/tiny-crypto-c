/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdint.h>

/* RSA secure-boot v2 wire layout. The device build uses IDF's real headers. */
typedef struct {
    uint8_t n[384];
    uint32_t e;
    uint8_t rinv[384];
    uint32_t mdash;
} ets_rsa_pubkey_t;
typedef struct {
    uint8_t magic_byte, version, reserved[2], image_digest[32];
#if defined(TC_TEST_IDF_ECDSA)
    struct {
        struct { uint8_t curve_id, point[64]; } key;
        uint8_t signature[64];
        uint8_t padding[1031];
    } ecdsa;
#else
    ets_rsa_pubkey_t key;
    uint8_t signature[384];
#endif
    uint32_t block_crc;
    uint8_t padding[16];
} ets_secure_boot_sig_block_t;
typedef struct { ets_secure_boot_sig_block_t block[3]; } ets_secure_boot_signature_t;
typedef char tc_test_signature_block_size[sizeof(ets_secure_boot_sig_block_t) == 1216 ? 1 : -1];
