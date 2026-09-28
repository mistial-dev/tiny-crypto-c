/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * Opt-in CAVP response-file validation. Test-only translation unit.
 */

#include <tiny_crypto/aes.h>
#include "cavp.h"
#include "munit.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CAVP_VECTOR_DIR
#define CAVP_VECTOR_DIR "tests/vectors/aes/cavp"
#endif

#if TC_AES_CAVP

#if TC_AES_ENABLE_ECB || TC_AES_ENABLE_CBC || TC_AES_ENABLE_OFB || TC_AES_ENABLE_GCM ||            \
    TC_AES_ENABLE_CCM
#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
static void cavp_initialize_sbox(void)
{
  TC_AES_init_sbox();
}
#else
static void cavp_initialize_sbox(void)
{}
#endif
#endif

enum cavp_mode { CAVP_ECB, CAVP_CBC, CAVP_OFB };

struct cavp_record {
  uint8_t* key;
  size_t key_len;
  uint8_t* iv;
  size_t iv_len;
  uint8_t* plaintext;
  size_t plaintext_len;
  uint8_t* ciphertext;
  size_t ciphertext_len;
  size_t count;
};

static void cavp_record_clear(struct cavp_record* record)
{
  free(record->key);
  free(record->iv);
  free(record->plaintext);
  free(record->ciphertext);
  memset(record, 0, sizeof(*record));
}

/* Decode a whole hex value into a new allocation. An empty value yields NULL
 * with length 0. */
static int cavp_decode_hex(const char* text, uint8_t** output, size_t* length)
{
  const size_t digits = strlen(text);
  uint8_t* result = digits == 0 ? NULL : (uint8_t*)malloc(digits / 2u);
  long decoded;

  if (digits != 0 && result == NULL)
    return 0;
  decoded = tc_cavp_parse_hex(text, result, digits / 2u);
  if (decoded < 0 || (size_t)decoded * 2u != digits) {
    free(result);
    return 0;
  }
  *output = result;
  *length = (size_t)decoded;
  return 1;
}

/* Replace *output with the current field's decoded value. */
static int cavp_take(const tc_cavp_reader* reader, uint8_t** output, size_t* length)
{
  free(*output);
  *output = NULL;
  *length = 0;
  return cavp_decode_hex(reader->value, output, length);
}

/* One line buffer serves every file. GCM and CCM lines reach 1 MiB. */
static char cavp_line[1024 * 1024];

static int cavp_open(tc_cavp_reader* reader, const char* relative)
{
  if (tc_cavp_open(reader, CAVP_VECTOR_DIR, relative, cavp_line, sizeof cavp_line))
    return 1;
  fprintf(stderr, "CAVP file not found: %s/%s\n", CAVP_VECTOR_DIR, relative);
  return 0;
}

static int cavp_compare(const char* file, size_t count, const char* field, const uint8_t* actual,
                        size_t actual_len, const uint8_t* expected, size_t expected_len)
{
  if (actual_len == expected_len && (actual_len == 0 || memcmp(actual, expected, actual_len) == 0))
    return 1;
  fprintf(stderr, "CAVP failure: %s Count=%lu field=%s\n", file, (unsigned long)count, field);
  tc_cavp_print_bytes("expected", expected, expected_len);
  tc_cavp_print_bytes("actual", actual, actual_len);
  return 0;
}

#if TC_AES_ENABLE_ECB || TC_AES_ENABLE_CBC || TC_AES_ENABLE_OFB
static void cavp_xor(uint8_t* dst, const uint8_t* src, size_t length)
{
  size_t i;
  for (i = 0; i < length; ++i)
    dst[i] ^= src[i];
}

static void cavp_ecb_block(const uint8_t* key, size_t key_len, int encrypt,
                           const uint8_t input[TC_AES_BLOCKLEN], uint8_t output[TC_AES_BLOCKLEN])
{
  uint8_t block[TC_AES_BLOCKLEN];

  (void)key_len;
  memcpy(block, input, sizeof(block));
  munit_assert_int(encrypt ? TC_AES_CAVP_encrypt_block(key, block)
                           : TC_AES_CAVP_decrypt_block(key, block),
                   ==, TC_OK);
  memcpy(output, block, sizeof(block));
}

static int cavp_standard_case(enum cavp_mode mode, const char* file, int encrypt,
                              const struct cavp_record* record)
{
  const uint8_t* input = encrypt ? record->plaintext : record->ciphertext;
  const uint8_t* expected = encrypt ? record->ciphertext : record->plaintext;
  const size_t input_len = encrypt ? record->plaintext_len : record->ciphertext_len;
  const size_t expected_len = encrypt ? record->ciphertext_len : record->plaintext_len;
  uint8_t* actual;

  if (input_len != expected_len || (mode == CAVP_ECB && (input_len & 15u) != 0)) {
    fprintf(stderr, "CAVP malformed %s Count=%lu input=%lu expected=%lu key=%lu\n", file,
            (unsigned long)record->count, (unsigned long)input_len, (unsigned long)expected_len,
            (unsigned long)record->key_len);
    return 0;
  }
  actual = input_len == 0 ? NULL : (uint8_t*)malloc(input_len);
  if (input_len != 0 && actual == NULL)
    return 0;
  if (input_len != 0)
    memcpy(actual, input, input_len);

  if (mode == CAVP_ECB) {
#if TC_AES_ENABLE_ECB
    struct TC_AES_ctx ctx;
    size_t offset;
    TC_AES_init_ctx(&ctx, record->key);
    for (offset = 0; offset < input_len; offset += TC_AES_BLOCKLEN) {
      if (encrypt) {
        if (TC_AES_ECB_encrypt(&ctx.key, actual + offset) != TC_OK)
          return 0;
      } else {
        if (TC_AES_ECB_decrypt(&ctx.key, actual + offset) != TC_OK)
          return 0;
      }
    }
#else
    free(actual);
    return 0;
#endif
  } else if (mode == CAVP_CBC) {
#if TC_AES_ENABLE_CBC
    struct TC_AES_ctx ctx;
    TC_AES_init_ctx_iv(&ctx, record->key, record->iv);
    if (encrypt)
      TC_AES_CBC_encrypt(&ctx, actual, input_len);
    else
      TC_AES_CBC_decrypt(&ctx, actual, input_len);
#else
    free(actual);
    return 0;
#endif
  } else {
#if TC_AES_ENABLE_OFB
    struct TC_AES_ctx ctx;
    TC_AES_init_ctx_iv(&ctx, record->key, record->iv);
    TC_AES_OFB_crypt(&ctx, actual, input_len);
#else
    free(actual);
    return 0;
#endif
  }

  if (!cavp_compare(file, record->count, encrypt ? "CIPHERTEXT" : "PLAINTEXT", actual, input_len,
                    expected, expected_len)) {
    tc_cavp_print_bytes("key", record->key, record->key_len);
    if (record->iv != NULL)
      tc_cavp_print_bytes("iv", record->iv, record->iv_len);
    tc_cavp_print_bytes(encrypt ? "plaintext" : "ciphertext", input, input_len);
    free(actual);
    return 0;
  }
  free(actual);
  return 1;
}

static void cavp_mct_block(enum cavp_mode mode, int encrypt, const uint8_t* key, size_t key_len,
                           const uint8_t iv[TC_AES_BLOCKLEN], int first,
                           const uint8_t input[TC_AES_BLOCKLEN], uint8_t output[TC_AES_BLOCKLEN])
{
  uint8_t block[TC_AES_BLOCKLEN];
  uint8_t stream[TC_AES_BLOCKLEN];

  if (mode == CAVP_ECB) {
    cavp_ecb_block(key, key_len, encrypt, input, output);
    return;
  }
  if (mode == CAVP_CBC) {
    memcpy(block, input, sizeof(block));
    if (encrypt) {
      cavp_xor(block, iv, TC_AES_BLOCKLEN);
      cavp_ecb_block(key, key_len, 1, block, output);
    } else {
      cavp_ecb_block(key, key_len, 0, block, output);
      cavp_xor(output, iv, TC_AES_BLOCKLEN);
    }
    return;
  }
  memcpy(stream, first ? iv : input, TC_AES_BLOCKLEN);
  cavp_ecb_block(key, key_len, 1, stream, stream);
  memcpy(output, input, TC_AES_BLOCKLEN);
  cavp_xor(output, stream, TC_AES_BLOCKLEN);
}

static int cavp_mct_intermediates(const char* response_file, size_t count, int encrypt,
                                  uint8_t expected[5][TC_AES_BLOCKLEN])
{
  char relative[512];
  tc_cavp_reader reader;
  tc_cavp_event event;
  size_t name_len = strlen(response_file);
  size_t current = (size_t)-1;
  size_t found = 0;
  int section_encrypt = 1;

  if (name_len < 4 || strcmp(response_file + name_len - 4, ".rsp") != 0)
    return 0;
  snprintf(relative, sizeof(relative), "%.*s.txt", (int)(name_len - 4), response_file);
  if (!cavp_open(&reader, relative))
    return 0;

  while ((event = tc_cavp_next(&reader)) != TC_CAVP_END && event != TC_CAVP_FAILURE) {
    uint8_t* decoded = NULL;
    size_t decoded_len = 0;

    if (event == TC_CAVP_HEADER) {
      if (tc_cavp_is(&reader, "ENCRYPT"))
        section_encrypt = 1;
      else if (tc_cavp_is(&reader, "DECRYPT"))
        section_encrypt = 0;
      continue;
    }
    if (event != TC_CAVP_FIELD)
      continue;
    if (tc_cavp_is(&reader, "COUNT")) {
      current = (size_t)strtoull(reader.value, NULL, 10);
      if (section_encrypt == encrypt && current == count)
        found = 0;
      else if (section_encrypt == encrypt && current > count && found == 5)
        break;
      continue;
    }
    if (section_encrypt != encrypt || current != count ||
        strstr(reader.name, "Intermediate") == NULL ||
        strstr(reader.name, encrypt ? "CIPHERTEXT" : "PLAINTEXT") == NULL)
      continue;
    if (!cavp_decode_hex(reader.value, &decoded, &decoded_len) || decoded_len != TC_AES_BLOCKLEN ||
        found == 5) {
      free(decoded);
      continue;
    }
    memcpy(expected[found++], decoded, TC_AES_BLOCKLEN);
    free(decoded);
  }
  tc_cavp_close(&reader);
  return found == 5;
}

static int cavp_mct_case(enum cavp_mode mode, const char* file, int encrypt,
                         const struct cavp_record* record)
{
  uint8_t key[32];
  uint8_t iv[TC_AES_BLOCKLEN] = {0};
  uint8_t initial_iv[TC_AES_BLOCKLEN] = {0};
  uint8_t input[TC_AES_BLOCKLEN];
  uint8_t before_previous[TC_AES_BLOCKLEN] = {0};
  uint8_t previous[TC_AES_BLOCKLEN] = {0};
  uint8_t output[TC_AES_BLOCKLEN] = {0};
  uint8_t ofb_state[TC_AES_BLOCKLEN] = {0};
  uint8_t expected[TC_AES_BLOCKLEN];
  uint8_t intermediate_expected[5][TC_AES_BLOCKLEN];
  unsigned j;

  if (record->plaintext_len != TC_AES_BLOCKLEN || record->ciphertext_len != TC_AES_BLOCKLEN ||
      record->key_len > sizeof(key))
    return 0;
  memcpy(key, record->key, record->key_len);
  if (record->iv != NULL)
    memcpy(iv, record->iv, TC_AES_BLOCKLEN);
  memcpy(initial_iv, iv, TC_AES_BLOCKLEN);
  memcpy(ofb_state, iv, TC_AES_BLOCKLEN);
  memcpy(input, encrypt ? record->plaintext : record->ciphertext, TC_AES_BLOCKLEN);
  if (!cavp_mct_intermediates(file, record->count, encrypt, intermediate_expected)) {
    fprintf(stderr, "CAVP intermediate records missing: %s Count=%lu\n", file,
            (unsigned long)record->count);
    return 0;
  }

  for (j = 0; j < 1000; ++j) {
    const int first = j == 0;
    if (mode == CAVP_OFB) {
      munit_assert_int(TC_AES_CAVP_encrypt_block(key, ofb_state), ==, TC_OK);
      memcpy(output, input, TC_AES_BLOCKLEN);
      cavp_xor(output, ofb_state, TC_AES_BLOCKLEN);
    } else
      cavp_mct_block(mode, encrypt, key, record->key_len, iv, first, input, output);
    if (mode == CAVP_CBC)
      memcpy(iv, encrypt ? output : input, sizeof(iv));
    memcpy(before_previous, previous, sizeof(before_previous));
    memcpy(previous, output, sizeof(previous));
    if (mode != CAVP_ECB && j == 0)
      memcpy(input, initial_iv, sizeof(input));
    else if (mode != CAVP_ECB)
      memcpy(input, before_previous, sizeof(input));
    else
      memcpy(input, previous, sizeof(input));
    if (j < 5 && memcmp(output, intermediate_expected[j], TC_AES_BLOCKLEN) != 0) {
      fprintf(stderr, "CAVP intermediate failure: %s Count=%lu Intermediate=%u\n", file,
              (unsigned long)record->count, j);
      tc_cavp_print_bytes("expected", intermediate_expected[j], TC_AES_BLOCKLEN);
      tc_cavp_print_bytes("actual", output, TC_AES_BLOCKLEN);
      return 0;
    }
  }
  memcpy(expected, encrypt ? record->ciphertext : record->plaintext, TC_AES_BLOCKLEN);
  if (!cavp_compare(file, record->count, encrypt ? "CIPHERTEXT" : "PLAINTEXT", output,
                    TC_AES_BLOCKLEN, expected, TC_AES_BLOCKLEN))
    return 0;
  return 1;
}

static int cavp_run_block_file(enum cavp_mode mode, const char* directory, const char* filename)
{
  char relative[512];
  tc_cavp_reader reader;
  tc_cavp_event event;
  struct cavp_record record;
  int encrypt = 1;
  int mct;
  int ok = 1;

  snprintf(relative, sizeof(relative), "%s/%s", directory, filename);
  if (!cavp_open(&reader, relative))
    return 0;
  memset(&record, 0, sizeof(record));
  mct = strstr(filename, "MCT") != NULL;

  while (ok && (event = tc_cavp_next(&reader)) != TC_CAVP_END) {
    if (event == TC_CAVP_FAILURE) {
      ok = 0;
      break;
    }
    if (event == TC_CAVP_HEADER) {
      if (tc_cavp_is(&reader, "DECRYPT"))
        encrypt = 0;
      else if (tc_cavp_is(&reader, "ENCRYPT"))
        encrypt = 1;
      continue;
    }
    if (event != TC_CAVP_FIELD)
      continue;
    if (tc_cavp_is(&reader, "COUNT"))
      record.count = (size_t)strtoull(reader.value, NULL, 10);
    else if (tc_cavp_is(&reader, "KEY"))
      ok = cavp_take(&reader, &record.key, &record.key_len);
    else if (tc_cavp_is(&reader, "IV"))
      ok = cavp_take(&reader, &record.iv, &record.iv_len);
    else if (tc_cavp_is(&reader, "PLAINTEXT") || tc_cavp_is(&reader, "CIPHERTEXT")) {
      const int plaintext = tc_cavp_is(&reader, "PLAINTEXT");
      ok = plaintext ? cavp_take(&reader, &record.plaintext, &record.plaintext_len)
                     : cavp_take(&reader, &record.ciphertext, &record.ciphertext_len);
      /* The second of the two texts completes a record. */
      if (ok && plaintext != encrypt) {
        ok = mct ? cavp_mct_case(mode, filename, encrypt, &record)
                 : cavp_standard_case(mode, filename, encrypt, &record);
        cavp_record_clear(&record);
      }
    }
  }
  cavp_record_clear(&record);
  tc_cavp_close(&reader);
  return ok;
}
#endif

#if TC_AES_ENABLE_CCM
struct cavp_ccm_record {
  uint8_t *key, *nonce, *aad, *payload, *ct;
  size_t key_len, nonce_len, aad_len, payload_len, ct_len;
  size_t count, tag_len;
  int expected_fail;
};

static void cavp_ccm_clear(struct cavp_ccm_record* record)
{
  free(record->key);
  free(record->nonce);
  free(record->aad);
  free(record->payload);
  free(record->ct);
  memset(record, 0, sizeof(*record));
}

static int cavp_run_ccm_case(const char* file, const struct cavp_ccm_record* record, int decrypt)
{
  uint8_t* output = record->payload_len == 0 ? NULL : (uint8_t*)malloc(record->payload_len);
  uint8_t tag[16] = {0};
  int result;
  int ok;

  if (record->payload_len != 0 && output == NULL)
    return 0;
  if (decrypt) {
    if (record->ct_len < record->tag_len ||
        record->ct_len - record->tag_len != record->payload_len) {
      free(output);
      return 0;
    }
    result = TC_AES_CCM_decrypt(record->key, record->nonce, record->nonce_len, record->aad,
                                record->aad_len, record->ct, record->payload_len,
                                record->ct + record->payload_len, record->tag_len, output);
    ok = record->expected_fail
             ? result == TC_MISMATCH
             : result == TC_OK && (record->payload_len == 0 ||
                                   memcmp(output, record->payload, record->payload_len) == 0);
  } else {
    result = TC_AES_CCM_encrypt(record->key, record->nonce, record->nonce_len, record->aad,
                                record->aad_len, record->payload, record->payload_len, output, tag,
                                record->tag_len);
    ok = !record->expected_fail && result == TC_OK &&
         record->ct_len == record->payload_len + record->tag_len &&
         (record->payload_len == 0 || memcmp(output, record->ct, record->payload_len) == 0) &&
         memcmp(tag, record->ct + record->payload_len, record->tag_len) == 0;
  }
  if (!ok)
    fprintf(stderr, "CAVP failure: %s Count=%lu CCM result=%d expected=%s\n", file,
            (unsigned long)record->count, result, record->expected_fail ? "FAIL" : "PASS");
  free(output);
  return ok;
}

/* CCM parameters appear as file-level fields (Plen = 24) and in headers,
 * alone ([Alen = 0]) or together ([Alen = 0, Plen = 0, Nlen = 7, Tlen = 4]). */
static void cavp_ccm_parameter(const char* name, const char* value, size_t* aad_len,
                               size_t* payload_len, size_t* nonce_len, size_t* tag_len)
{
  const size_t number = (size_t)strtoull(value, NULL, 10);
  if (strcmp(name, "Alen") == 0)
    *aad_len = number;
  else if (strcmp(name, "Plen") == 0)
    *payload_len = number;
  else if (strcmp(name, "Nlen") == 0)
    *nonce_len = number;
  else if (strcmp(name, "Tlen") == 0)
    *tag_len = number;
}

static int cavp_run_ccm_file(const char* filename)
{
  static const char* const parameters[] = {"Alen", "Plen", "Nlen", "Tlen"};
  char relative[512];
  tc_cavp_reader reader;
  tc_cavp_event event;
  struct cavp_ccm_record record;
  size_t configured_aad_len = 0, configured_payload_len = 0;
  size_t configured_nonce_len = 0, configured_tag_len = 0;
  const int decrypt = strstr(filename, "DVPT") != NULL;
  size_t records_seen = 0, records_executed = 0;
  int ok = 1;
  size_t i;

  snprintf(relative, sizeof(relative), "ccm/%s", filename);
  if (!cavp_open(&reader, relative))
    return 0;
  memset(&record, 0, sizeof(record));
  while (ok && (event = tc_cavp_next(&reader)) != TC_CAVP_END) {
    if (event == TC_CAVP_FAILURE) {
      ok = 0;
      break;
    }
    if (event == TC_CAVP_HEADER) {
      char value[32];
      for (i = 0; i < sizeof parameters / sizeof parameters[0]; ++i)
        if (tc_cavp_header_value(&reader, parameters[i], value, sizeof value) != NULL)
          cavp_ccm_parameter(parameters[i], value, &configured_aad_len, &configured_payload_len,
                             &configured_nonce_len, &configured_tag_len);
      continue;
    }
    if (event == TC_CAVP_RECORD_END) {
      struct cavp_ccm_record effective = record;
      effective.aad_len = configured_aad_len;
      effective.payload_len = configured_payload_len;
      effective.nonce_len = configured_nonce_len == 0 ? record.nonce_len : configured_nonce_len;
      if (effective.tag_len == 0 && record.ct_len >= effective.payload_len)
        effective.tag_len = record.ct_len - effective.payload_len;
      if (record.key != NULL && record.nonce != NULL && record.ct != NULL) {
        ok = cavp_run_ccm_case(filename, &effective, decrypt);
        ++records_executed;
      }
      free(record.aad);
      free(record.payload);
      free(record.ct);
      record.aad = record.payload = record.ct = NULL;
      record.aad_len = record.payload_len = record.ct_len = 0;
      continue;
    }
    if (tc_cavp_is(&reader, "Alen") || tc_cavp_is(&reader, "Plen") || tc_cavp_is(&reader, "Nlen") ||
        tc_cavp_is(&reader, "Tlen"))
      cavp_ccm_parameter(reader.name, reader.value, &configured_aad_len, &configured_payload_len,
                         &configured_nonce_len, &configured_tag_len);
    else if (tc_cavp_is(&reader, "Count")) {
      free(record.aad);
      free(record.payload);
      free(record.ct);
      record.aad = record.payload = record.ct = NULL;
      record.aad_len = record.payload_len = record.ct_len = 0;
      record.count = (size_t)strtoull(reader.value, NULL, 10);
      record.expected_fail = 0;
      record.tag_len = configured_tag_len;
      ++records_seen;
    } else if (tc_cavp_is(&reader, "Result"))
      record.expected_fail = strcmp(reader.value, "Fail") == 0;
    else if (tc_cavp_is(&reader, "Key"))
      ok = cavp_take(&reader, &record.key, &record.key_len);
    else if (tc_cavp_is(&reader, "Nonce"))
      ok = cavp_take(&reader, &record.nonce, &record.nonce_len);
    else if (tc_cavp_is(&reader, "Adata"))
      ok = cavp_take(&reader, &record.aad, &record.aad_len);
    else if (tc_cavp_is(&reader, "Payload"))
      ok = cavp_take(&reader, &record.payload, &record.payload_len);
    else if (tc_cavp_is(&reader, "CT"))
      ok = cavp_take(&reader, &record.ct, &record.ct_len);
  }
  cavp_ccm_clear(&record);
  tc_cavp_close(&reader);
  /* Every Count record runs, including the last one in the file. */
  if (ok && (records_seen == 0 || records_executed != records_seen)) {
    fprintf(stderr, "CAVP CCM record mismatch: %s seen=%lu executed=%lu\n", filename,
            (unsigned long)records_seen, (unsigned long)records_executed);
    ok = 0;
  }
  return ok;
}
#endif

#if TC_AES_ENABLE_GCM
static int cavp_run_gcm_decrypt_record(const char* filename, size_t count, const uint8_t* key,
                                       const uint8_t* iv, size_t iv_len, const uint8_t* aad,
                                       size_t aad_len, const uint8_t* ct, size_t ct_len,
                                       const uint8_t* tag, size_t tag_len, const uint8_t* pt,
                                       size_t pt_len, int expected_fail)
{
  struct TC_AES_GCM_ctx ctx;
  uint8_t* output = ct_len == 0 ? NULL : (uint8_t*)malloc(ct_len);
  int result;
  int init_result, aad_result, update_result, finish_result;
  int ok;

  if ((!expected_fail && ct_len != pt_len) || (ct_len != 0 && output == NULL)) {
    free(output);
    return 0;
  }
  if (ct_len != 0)
    memcpy(output, ct, ct_len);
  cavp_initialize_sbox();
  init_result = tag_len < 12 ? TC_AES_GCM_init_short_tag(&ctx, key, iv, iv_len, tag_len)
                             : TC_AES_GCM_init(&ctx, key, iv, iv_len, tag_len);
  aad_result = init_result == TC_OK ? TC_AES_GCM_aad_update(&ctx, aad, aad_len) : TC_ERROR;
  update_result = aad_result == TC_OK ? TC_AES_GCM_decrypt_update(&ctx, output, ct_len) : TC_ERROR;
  finish_result = update_result == TC_OK ? TC_AES_GCM_decrypt_finish(&ctx, tag) : TC_ERROR;
  result = finish_result;
  ok = expected_fail
           ? result == TC_MISMATCH
           : result == TC_OK && cavp_compare(filename, count, "PT", output, ct_len, pt, pt_len);
  if (!ok) {
    fprintf(stderr, "CAVP GCM failure: %s Count=%lu result=%d stages=%d/%d/%d/%d expected=%s\n",
            filename, (unsigned long)count, result, init_result, aad_result, update_result,
            finish_result, expected_fail ? "FAIL" : "PASS");
    tc_cavp_print_bytes("key", key, TC_AES_KEYLEN);
    tc_cavp_print_bytes("iv", iv, iv_len);
    tc_cavp_print_bytes("tag", tag, tag_len);
  }
  free(output);
  return ok;
}

static int cavp_run_gcm_file(const char* filename)
{
  char relative[512];
  tc_cavp_reader reader;
  tc_cavp_event event;
  uint8_t *key = NULL, *iv = NULL, *pt = NULL, *aad = NULL;
  uint8_t *ct = NULL, *tag = NULL;
  size_t key_len = 0, iv_len = 0, pt_len = 0, aad_len = 0;
  size_t ct_len = 0, tag_len = 0, count = 0;
  size_t records_seen = 0, records_executed = 0, failed_records = 0;
  int decrypt = strstr(filename, "Decrypt") != NULL;
  int ok = 1;

  snprintf(relative, sizeof(relative), "gcm/%s", filename);
  if (!cavp_open(&reader, relative))
    return 0;
  while (ok && (event = tc_cavp_next(&reader)) != TC_CAVP_END) {
    if (event == TC_CAVP_FAILURE) {
      ok = 0;
      break;
    }
    if (event != TC_CAVP_FIELD)
      continue;
    if (tc_cavp_is(&reader, "Count")) {
      ++records_seen;
      free(key);
      free(iv);
      free(pt);
      free(aad);
      free(ct);
      free(tag);
      key = iv = pt = aad = ct = tag = NULL;
      key_len = iv_len = pt_len = aad_len = ct_len = tag_len = 0;
      count = (size_t)strtoull(reader.value, NULL, 10);
    } else if (tc_cavp_is(&reader, "Key"))
      ok = cavp_take(&reader, &key, &key_len);
    else if (tc_cavp_is(&reader, "IV"))
      ok = cavp_take(&reader, &iv, &iv_len);
    else if (tc_cavp_is(&reader, "PT")) {
      ok = cavp_take(&reader, &pt, &pt_len);
      if (ok && decrypt) {
        ++records_executed;
        ok = cavp_run_gcm_decrypt_record(filename, count, key, iv, iv_len, aad, aad_len, ct, ct_len,
                                         tag, tag_len, pt, pt_len, 0);
      }
    } else if (tc_cavp_is(&reader, "AAD"))
      ok = cavp_take(&reader, &aad, &aad_len);
    else if (tc_cavp_is(&reader, "CT"))
      ok = cavp_take(&reader, &ct, &ct_len);
    else if (tc_cavp_is(&reader, "Tag")) {
      ok = cavp_take(&reader, &tag, &tag_len);
      if (ok && !decrypt) {
        struct TC_AES_GCM_ctx ctx;
        uint8_t* output = pt_len == 0 ? NULL : (uint8_t*)malloc(pt_len);
        uint8_t actual_tag[16];
        int result;
        if (pt_len != 0 && output == NULL) {
          ok = 0;
          continue;
        }
        if (pt_len != 0)
          memcpy(output, pt, pt_len);
        cavp_initialize_sbox();
        result = tag_len < 12 ? TC_AES_GCM_init_short_tag(&ctx, key, iv, iv_len, tag_len)
                              : TC_AES_GCM_init(&ctx, key, iv, iv_len, tag_len);
        if (result == TC_OK)
          result = TC_AES_GCM_aad_update(&ctx, aad, aad_len);
        if (result == TC_OK)
          result = TC_AES_GCM_encrypt_update(&ctx, output, pt_len);
        if (result == TC_OK)
          result = TC_AES_GCM_encrypt_finish(&ctx, actual_tag);
        ok = result == TC_OK && cavp_compare(filename, count, "CT", output, pt_len, ct, ct_len) &&
             cavp_compare(filename, count, "Tag", actual_tag, tag_len, tag, tag_len);
        if (!ok)
          fprintf(stderr, "CAVP GCM failure: %s Count=%lu\n", filename, (unsigned long)count);
        free(output);
        ++records_executed;
      }
    } else if (tc_cavp_is(&reader, "FAIL")) {
      ++failed_records;
      if (decrypt) {
        ++records_executed;
        ok = cavp_run_gcm_decrypt_record(filename, count, key, iv, iv_len, aad, aad_len, ct, ct_len,
                                         tag, tag_len, NULL, 0, 1);
      }
    }
  }
  free(key);
  free(iv);
  free(pt);
  free(aad);
  free(ct);
  free(tag);
  tc_cavp_close(&reader);
  if (records_seen == 0 || records_executed != records_seen) {
    fprintf(stderr, "CAVP GCM record mismatch: %s seen=%lu executed=%lu\n", filename,
            (unsigned long)records_seen, (unsigned long)records_executed);
    ok = 0;
  }
  if (decrypt) {
    size_t expected_failures = 0;
    if (strcmp(filename, "gcmDecrypt128.rsp") == 0)
      expected_failures = 4011u;
    else if (strcmp(filename, "gcmDecrypt192.rsp") == 0)
      expected_failures = 3978u;
    else if (strcmp(filename, "gcmDecrypt256.rsp") == 0)
      expected_failures = 3919u;
    if (records_seen != 7875u || failed_records != expected_failures) {
      fprintf(stderr, "CAVP GCM corpus count changed: %s records=%lu failures=%lu\n", filename,
              (unsigned long)records_seen, (unsigned long)failed_records);
      ok = 0;
    }
  }
  return ok;
}
#endif

static int cavp_run_all(void)
{
#if TC_AES_ENABLE_ECB
  static const char* const ecb[] = {"ECBGFSbox128.rsp",  "ECBGFSbox192.rsp",  "ECBGFSbox256.rsp",
                                    "ECBKeySbox128.rsp", "ECBKeySbox192.rsp", "ECBKeySbox256.rsp",
                                    "ECBVarKey128.rsp",  "ECBVarKey192.rsp",  "ECBVarKey256.rsp",
                                    "ECBVarTxt128.rsp",  "ECBVarTxt192.rsp",  "ECBVarTxt256.rsp",
                                    "ECBMCT128.rsp",     "ECBMCT192.rsp",     "ECBMCT256.rsp",
                                    "ECBMMT128.rsp",     "ECBMMT192.rsp",     "ECBMMT256.rsp"};
#endif
#if TC_AES_ENABLE_CBC
  static const char* const cbc[] = {"CBCGFSbox128.rsp",  "CBCGFSbox192.rsp",  "CBCGFSbox256.rsp",
                                    "CBCKeySbox128.rsp", "CBCKeySbox192.rsp", "CBCKeySbox256.rsp",
                                    "CBCVarKey128.rsp",  "CBCVarKey192.rsp",  "CBCVarKey256.rsp",
                                    "CBCVarTxt128.rsp",  "CBCVarTxt192.rsp",  "CBCVarTxt256.rsp",
                                    "CBCMCT128.rsp",     "CBCMCT192.rsp",     "CBCMCT256.rsp",
                                    "CBCMMT128.rsp",     "CBCMMT192.rsp",     "CBCMMT256.rsp"};
#endif
#if TC_AES_ENABLE_OFB
  static const char* const ofb[] = {"OFBGFSbox128.rsp",  "OFBGFSbox192.rsp",  "OFBGFSbox256.rsp",
                                    "OFBKeySbox128.rsp", "OFBKeySbox192.rsp", "OFBKeySbox256.rsp",
                                    "OFBVarKey128.rsp",  "OFBVarKey192.rsp",  "OFBVarKey256.rsp",
                                    "OFBVarTxt128.rsp",  "OFBVarTxt192.rsp",  "OFBVarTxt256.rsp",
                                    "OFBMCT128.rsp",     "OFBMCT192.rsp",     "OFBMCT256.rsp",
                                    "OFBMMT128.rsp",     "OFBMMT192.rsp",     "OFBMMT256.rsp"};
#endif
#if TC_AES_ENABLE_CCM
  static const char* const ccm[] = {"DVPT128.rsp", "DVPT192.rsp", "DVPT256.rsp", "VADT128.rsp",
                                    "VADT192.rsp", "VADT256.rsp", "VNT128.rsp",  "VNT192.rsp",
                                    "VNT256.rsp",  "VPT128.rsp",  "VPT192.rsp",  "VPT256.rsp",
                                    "VTT128.rsp",  "VTT192.rsp",  "VTT256.rsp"};
#endif
#if TC_AES_ENABLE_ECB || TC_AES_ENABLE_CBC || TC_AES_ENABLE_OFB || TC_AES_ENABLE_GCM ||            \
    TC_AES_ENABLE_CCM
  size_t i;
#endif
  int ok = 1;

#if TC_AES_ENABLE_ECB || TC_AES_ENABLE_CBC || TC_AES_ENABLE_OFB || TC_AES_ENABLE_GCM ||            \
    TC_AES_ENABLE_CCM
#if TC_AES_KEY_BITS == 256
  const char* key_suffix = "256";
#elif TC_AES_KEY_BITS == 192
  const char* key_suffix = "192";
#else
  const char* key_suffix = "128";
#endif
#endif

#if TC_AES_ENABLE_ECB
  for (i = 0; ok && i < sizeof(ecb) / sizeof(ecb[0]); ++i)
    if (strstr(ecb[i], key_suffix) != NULL)
      ok = cavp_run_block_file(CAVP_ECB, "ecb", ecb[i]);
#endif
#if TC_AES_ENABLE_CBC
  for (i = 0; ok && i < sizeof(cbc) / sizeof(cbc[0]); ++i)
    if (strstr(cbc[i], key_suffix) != NULL)
      ok = cavp_run_block_file(CAVP_CBC, "cbc", cbc[i]);
#endif
#if TC_AES_ENABLE_OFB
  for (i = 0; ok && i < sizeof(ofb) / sizeof(ofb[0]); ++i)
    if (strstr(ofb[i], key_suffix) != NULL)
      ok = cavp_run_block_file(CAVP_OFB, "ofb", ofb[i]);
#endif
#if TC_AES_ENABLE_GCM
  {
    static const char* const gcm[] = {"gcmDecrypt128.rsp",      "gcmDecrypt192.rsp",
                                      "gcmDecrypt256.rsp",      "gcmEncryptExtIV128.rsp",
                                      "gcmEncryptExtIV192.rsp", "gcmEncryptExtIV256.rsp"};
    for (i = 0; ok && i < sizeof(gcm) / sizeof(gcm[0]); ++i)
      if (strstr(gcm[i], key_suffix) != NULL)
        ok = cavp_run_gcm_file(gcm[i]);
  }
#endif
#if TC_AES_ENABLE_CCM
  for (i = 0; ok && i < sizeof(ccm) / sizeof(ccm[0]); ++i)
    if (strstr(ccm[i], key_suffix) != NULL)
      ok = cavp_run_ccm_file(ccm[i]);
#endif
  return ok;
}

MunitResult test_cavp(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
#if TC_AES_ENABLE_ECB || TC_AES_ENABLE_CBC || TC_AES_ENABLE_OFB || TC_AES_ENABLE_GCM ||            \
    TC_AES_ENABLE_CCM
  cavp_initialize_sbox();
#endif
  /* A missing key fails and leaves the block unchanged. */
  {
    uint8_t block[TC_AES_BLOCKLEN] = {1, 2, 3}, saved[TC_AES_BLOCKLEN];
    memcpy(saved, block, sizeof block);
    munit_assert_int(TC_AES_CAVP_encrypt_block(NULL, block), ==, TC_ERROR);
    munit_assert_int(TC_AES_CAVP_decrypt_block(NULL, block), ==, TC_ERROR);
    munit_assert_memory_equal(sizeof block, block, saved);
  }
  return cavp_run_all() ? MUNIT_OK : MUNIT_FAIL;
}

#else

MunitResult test_cavp(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}

#endif
