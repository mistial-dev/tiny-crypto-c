/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include "esp_secure_boot.h"
#define ESP_FAIL (-1)
#define ESP_ERR_NOT_FOUND 0x105
#define SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS 3
#define SECURE_BOOT_NUM_BLOCKS 3
#define ESP_SECURE_BOOT_DIGEST_LEN 32
#define ESP_SECURE_BOOT_KEY_DIGEST_LEN 32
#define ESP_SECURE_BOOT_KEY_DIGEST_SHA_256_LEN 32
#define ETS_SECURE_BOOT_V2_SIGNATURE_MAGIC 0xe7
#define CRC_SIGN_BLOCK_LEN 1196
#define FLASH_SECTOR_SIZE 4096
#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
#define CONFIG_SECURE_BOOT_V2_ENABLED 1
#define SOC_SUPPORT_SECURE_BOOT_REVOKE_KEY 1
#endif
#if defined(TC_TEST_IDF_ECDSA)
#define CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME 1
#define ESP_SECURE_BOOT_SCHEME 3
#define test_key(block) ((block).ecdsa.key)
#define test_verify_block verify_ecdsa_signature_block
#else
#define CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME 1
#define ESP_SECURE_BOOT_SCHEME 2
#define test_key(block) ((block).key)
#define test_verify_block verify_rsa_signature_block
#endif
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGD(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGV(tag, ...) ((void)(tag))
typedef struct { uint32_t offset, size; } esp_partition_pos_t;
typedef struct { uint32_t address, size; } esp_partition_t;
typedef struct { uint32_t start_addr, image_len; } esp_image_metadata_t;
typedef struct { uint8_t key_digests[3][32]; unsigned num_digests; } esp_image_sig_public_key_digests_t;
typedef struct { const uint8_t* key_digests[3]; } esp_secure_boot_key_digests_t;
uint32_t esp_rom_crc32_le(uint32_t crc, const uint8_t* data, size_t length);
esp_err_t esp_image_get_metadata(const esp_partition_pos_t* position, esp_image_metadata_t* metadata);
esp_err_t bootloader_sha256_flash_contents(uint32_t address, uint32_t length, uint8_t* digest);
esp_err_t bootloader_flash_read(size_t address, void* output, size_t length, bool decrypt);
const void* bootloader_mmap(uint32_t address, size_t length);
void bootloader_munmap(const void* address);
const esp_partition_t* esp_ota_get_running_partition(void);
bool esp_secure_boot_enabled(void);
esp_err_t esp_secure_boot_read_key_digests(esp_secure_boot_key_digests_t* digests);
bool ets_rsa_pss_verify(const ets_rsa_pubkey_t* key, const uint8_t* signature,
    const uint8_t* digest, uint8_t* verified);
bool ets_ecdsa_verify(const uint8_t* point, const uint8_t* signature,
    unsigned curve, const uint8_t* digest, uint8_t* verified);
esp_err_t esp_secure_boot_verify_sbv2_signature_block(const ets_secure_boot_signature_t* blocks,
    const uint8_t* digest, uint8_t* verified);
bool esp_efuse_get_digest_revoke(int index);
esp_err_t esp_secure_boot_verify_with_efuse_digest_index(int index, esp_partition_pos_t* partition);
