/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "platform.h"
#include "bootloader_sha.h"
#include "secure_boot_signature_priv.h"
#include "munit.h"
#include <string.h>

static uint8_t trusted[3][32];
static unsigned trusted_mask;
static esp_err_t read_result;
#ifndef TC_TEST_IDF_REAL_CRYPTO
static unsigned crypto_calls;
static esp_err_t crypto_result;
#endif
static bool secure_enabled = true, partition_available;
static esp_err_t metadata_result, flash_result;
static ets_secure_boot_signature_t running_blocks;
static const esp_partition_t running_partition = {0x10000, 0x100000};
static bool revoked, rom_valid;
bool esp_efuse_get_digest_revoke(int index) { (void)index; return revoked; }

uint32_t esp_rom_crc32_le(uint32_t crc, const uint8_t* data, size_t length)
{
  crc = ~crc;
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (unsigned j = 0; j < 8; ++j)
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}

bool esp_secure_boot_enabled(void) { return secure_enabled; }
esp_err_t esp_secure_boot_read_key_digests(esp_secure_boot_key_digests_t* digests)
{
  for (unsigned i = 0; i < 3; ++i)
    digests->key_digests[i] = trusted_mask & (1u << i) ? trusted[i] : NULL;
  return read_result;
}

esp_err_t esp_image_get_metadata(const esp_partition_pos_t* p, esp_image_metadata_t* m)
{
  munit_assert_uint32(p->offset, ==, running_partition.address);
  m->start_addr = p->offset;
  m->image_len = FLASH_SECTOR_SIZE;
  return metadata_result;
}
esp_err_t bootloader_sha256_flash_contents(uint32_t a, uint32_t n, uint8_t* d)
{ (void)a; (void)n; memset(d, 0, 32); return flash_result; }
esp_err_t bootloader_flash_read(size_t a, void* out, size_t n, bool decrypt)
{
  size_t start = running_partition.address + FLASH_SECTOR_SIZE;
  munit_assert_true(decrypt);
  if (flash_result != ESP_OK) return flash_result;
  if (a < start || a - start > sizeof running_blocks || n > sizeof running_blocks - (a - start))
    return ESP_FAIL;
  memcpy(out, (const uint8_t*)&running_blocks + a - start, n);
  return ESP_OK;
}
const void* bootloader_mmap(uint32_t a, size_t n) { (void)a; (void)n; return NULL; }
void bootloader_munmap(const void* a) { (void)a; }
const esp_partition_t* esp_ota_get_running_partition(void)
{ return partition_available ? &running_partition : NULL; }
bool ets_rsa_pss_verify(const ets_rsa_pubkey_t* k, const uint8_t* s,
    const uint8_t* d, uint8_t* v)
{ (void)k; (void)s; (void)d; (void)v; return rom_valid; }
bool ets_ecdsa_verify(const uint8_t* p, const uint8_t* s,
    unsigned c, const uint8_t* d, uint8_t* v)
{ (void)p; (void)s; (void)c; (void)d; (void)v; return rom_valid; }

#ifndef TC_TEST_IDF_REAL_CRYPTO
esp_err_t test_verify_block(const ets_secure_boot_signature_t* blocks,
    const uint8_t* digest, const ets_secure_boot_sig_block_t* block)
{
  (void)blocks; (void)digest; (void)block;
  ++crypto_calls;
  return crypto_result;
}
#endif

static void seal(ets_secure_boot_sig_block_t* block)
{
  block->block_crc = esp_rom_crc32_le(0, (const uint8_t*)block, CRC_SIGN_BLOCK_LEN);
}

#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
static void trust(unsigned slot, const ets_secure_boot_sig_block_t* block)
{
  bootloader_sha256_handle_t hash = bootloader_sha256_start();
  munit_assert_not_null(hash);
  bootloader_sha256_data(hash, &test_key(*block), sizeof test_key(*block));
  bootloader_sha256_finish(hash, trusted[slot]);
  trusted_mask |= 1u << slot;
}

#endif

#ifndef TC_TEST_IDF_REAL_CRYPTO
#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
static MunitResult policy(const MunitParameter params[], void* data)
{
  ets_secure_boot_signature_t blocks;
  uint8_t digest[32] = {0}, verified[32];
  (void)params; (void)data;
  secure_enabled = true;
  memset(&blocks, 0, sizeof blocks);
  memset(trusted, 0, sizeof trusted);
  trusted_mask = 0; read_result = ESP_OK; crypto_result = ESP_OK; crypto_calls = 0;
  blocks.block[0].magic_byte = ETS_SECURE_BOOT_V2_SIGNATURE_MAGIC;
  blocks.block[0].version = ESP_SECURE_BOOT_SCHEME;
  memset(&test_key(blocks.block[0]), 0x37, sizeof test_key(blocks.block[0]));
  seal(&blocks.block[0]);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_FAIL);
  munit_assert_uint(crypto_calls, ==, 0);
  /* A trusted key in the last slot must work even when earlier slots are revoked. */
  trust(2, &blocks.block[0]);
  memset(verified, 0xa5, sizeof verified);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,verified), ==, ESP_OK);
  munit_assert_uint(crypto_calls, ==, 1);
  for (unsigned i = 0; i < sizeof verified; ++i) munit_assert_uint8(verified[i], ==, 0);
  blocks.block[0].block_crc ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  munit_assert_uint(crypto_calls, ==, 1);
  blocks.block[0].magic_byte ^= 1; seal(&blocks.block[0]);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  blocks.block[0].magic_byte ^= 1;
  blocks.block[0].version ^= 1; seal(&blocks.block[0]);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  blocks.block[0].version ^= 1; seal(&blocks.block[0]);
  trusted[2][0] ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  munit_assert_uint(crypto_calls, ==, 1);
  trusted[2][0] ^= 1;
  crypto_result = ESP_ERR_IMAGE_INVALID;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  munit_assert_uint(crypto_calls, ==, 2);
  crypto_result = ESP_ERR_NO_MEM;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  crypto_result = ESP_OK;
  blocks.block[2] = blocks.block[0];
  blocks.block[0].block_crc ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_OK);
  trusted_mask = 0;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_FAIL);
  trusted_mask = 1u << 2;
  read_result = ESP_FAIL;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_FAIL);
  return MUNIT_OK;
}

#endif

static MunitResult running_image(const MunitParameter params[], void* data)
{
  ets_secure_boot_signature_t candidate;
  uint8_t digest[32] = {0};
  (void)params; (void)data;
  secure_enabled = false; partition_available = true;
  metadata_result = ESP_OK; flash_result = ESP_OK;
  crypto_result = ESP_OK; crypto_calls = 0;
  memset(&running_blocks, 0, sizeof running_blocks);
  running_blocks.block[0].magic_byte = ETS_SECURE_BOOT_V2_SIGNATURE_MAGIC;
  running_blocks.block[0].version = ESP_SECURE_BOOT_SCHEME;
  memset(&test_key(running_blocks.block[0]), 0x49, sizeof test_key(running_blocks.block[0]));
  seal(&running_blocks.block[0]);
  candidate = running_blocks;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_OK);
  munit_assert_uint(crypto_calls, ==, 1);
  ((uint8_t*)&test_key(candidate.block[0]))[0] ^= 1;
  seal(&candidate.block[0]);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  munit_assert_uint(crypto_calls, ==, 1);
  candidate = running_blocks;
  candidate.block[2] = candidate.block[0];
  candidate.block[0].block_crc ^= 1;
#ifdef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
#else
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_OK);
#endif
  candidate = running_blocks;
  running_blocks.block[0].block_crc ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_FAIL);
  running_blocks.block[0].block_crc ^= 1;
  flash_result = ESP_FAIL;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_FAIL);
  flash_result = ESP_OK; metadata_result = ESP_FAIL;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_FAIL);
  metadata_result = ESP_OK; partition_available = false;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&candidate,digest,NULL), ==, ESP_FAIL);
#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
  esp_partition_pos_t position = {running_partition.address, running_partition.size};
  flash_result = ESP_OK; read_result = ESP_OK; rom_valid = true; revoked = false;
  trusted_mask = 0;
  trust(1, &running_blocks.block[0]);
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(1,&position), ==, ESP_OK);
  revoked = true;
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(1,&position), ==, ESP_FAIL);
  revoked = false;
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(0,&position), ==, ESP_FAIL);
  trusted[1][0] ^= 1;
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(1,&position), ==, ESP_FAIL);
  trusted[1][0] ^= 1; read_result = ESP_FAIL;
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(1,&position), ==, ESP_FAIL);
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(-1,&position), ==, ESP_ERR_INVALID_ARG);
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(3,&position), ==, ESP_ERR_INVALID_ARG);
  munit_assert_int(esp_secure_boot_verify_with_efuse_digest_index(1,NULL), ==, ESP_ERR_INVALID_ARG);
#endif
  return MUNIT_OK;
}

#endif

#ifdef TC_TEST_IDF_REAL_CRYPTO
#include "image_fixture.h"
static const char* image_path;
static MunitResult image_policy(const MunitParameter params[], void* data)
{
  ets_secure_boot_signature_t blocks;
  uint8_t digest[32];
  (void)params; (void)data;
  if (!image_path) return MUNIT_SKIP;
  read_image_fixture(image_path, &blocks, digest);
  secure_enabled = true; read_result = ESP_OK; trusted_mask = 0;
  trust(2, &blocks.block[0]);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_OK);
  digest[0] ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  digest[0] ^= 1;
  blocks.block[0].block_crc ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
#if defined(TC_TEST_IDF_ECDSA)
  blocks.block[0].ecdsa.signature[0] ^= 1;
#else
  blocks.block[0].signature[0] ^= 1;
#endif
  seal(&blocks.block[0]);
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  read_image_fixture(image_path, &blocks, digest);
  trusted[2][0] ^= 1;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_ERR_IMAGE_INVALID);
  trusted[2][0] ^= 1;
  running_blocks = blocks; secure_enabled = false; partition_available = true;
  metadata_result = ESP_OK; flash_result = ESP_OK;
  munit_assert_int(esp_secure_boot_verify_sbv2_signature_block(&blocks,digest,NULL), ==, ESP_OK);
  return MUNIT_OK;
}
#endif

int main(int argc, char** argv)
{
  MunitTest tests[] = {
#ifdef TC_TEST_IDF_REAL_CRYPTO
    {"/image-policy", image_policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#else
#ifndef CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT
    {"/efuse-trust", policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {"/running-image-trust", running_image, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
  };
  MunitSuite suite = {"/idf-policy", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
#ifdef TC_TEST_IDF_REAL_CRYPTO
  if (argc == 3 && strcmp(argv[1], "--image") == 0) { image_path = argv[2]; argc = 1; }
#endif
  return munit_suite_main(&suite, NULL, argc, argv);
}
