/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RSAES-OAEP encryption and decryption (RFC 8017 section 7.1). */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_private_internal.h"
#include "rsa_padding_internal.h"
#include "rsa_internal.h"

/* Additional output metadata uses the same disjoint-range rules as bytes. */
static TC_RSA_result tc_rsa_decrypt_inputs(const TC_RSA_private_key* key, TC_bytes ciphertext,
                                           TC_bytes label, uint8_t* plaintext, size_t capacity,
                                           size_t* plaintext_length,
                                           const TC_RSA_workspace* workspace)
{
  if (!plaintext_length || (uintptr_t)plaintext_length % sizeof *plaintext_length)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status =
      tc_rsa_private_inputs(key, ciphertext, (TC_bytes){plaintext, capacity}, workspace);
  if (status != TC_RSA_OK)
    return status;
  TC_bytes writes[3];
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, writes, 3, SIZE_MAX);
  TC_PKI_PLAN_WRITE(&plan, workspace->words, workspace->capacity);
  TC_PKI_PLAN_WRITE(&plan, plaintext, capacity);
  TC_PKI_PLAN_WRITE(&plan, plaintext_length, 1);
  tc_pki_storage_plan_seal(&plan);
  tc_pki_storage_plan_input_span(&plan, label);
  if (tc_rsa_storage_status(&plan) != TC_RSA_OK)
    return TC_RSA_ARGUMENT;
  /* Treat the length object as another output when checking key and ciphertext. */
  return tc_rsa_private_inputs(key, ciphertext, writes[2], workspace);
}

TC_RSA_result TC_RSA_encrypt_oaep(const TC_RSA_public_key* key, const TC_RSA_oaep_options* options,
                                  TC_bytes plaintext, const TC_RSA_workspace* workspace,
                                  TC_buffer ciphertext, TC_RSA_execution* execution)
{
  if (!options || !execution || !execution->random.fill || !ciphertext.data)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status =
      tc_rsa_control_inputs(workspace, (TC_bytes){ciphertext.data, ciphertext.capacity}, options,
                            sizeof *options, execution, sizeof *execution);
  if (status == TC_RSA_OK)
    status = tc_rsa_public_inputs(key, plaintext, options->label,
                                  (TC_bytes){ciphertext.data, ciphertext.capacity}, workspace);
  if (status == TC_RSA_OK)
    status = tc_rsa_public_key_check(key);
  if (status != TC_RSA_OK)
    return status;
  const size_t length = key->modulus.length;
  if (ciphertext.capacity != length)
    return TC_RSA_INVALID;
  tc_hash_info info;
  size_t encode_cost;
  status = tc_rsa_oaep_plan(length, options->hash, options->mgf_hash, options->label, &info,
                            &encode_cost);
  if (status != TC_RSA_OK)
    return status;
  if (plaintext.length > length - 2 * info.digest_length - 2)
    return TC_RSA_INVALID;
  const size_t n = length / sizeof(TC_RSA_word), arithmetic_words = 8 * n + 2;
  const size_t required = arithmetic_words + n;
  uint32_t* work = &execution->work.remaining;
  /* One unit for the seed request, then the encoding cost. */
  if (workspace->capacity < required || *work <= encode_cost)
    return TC_RSA_LIMIT;
  TC_hash_context hash_workspace;
  uint8_t block[64];
  /* Seed storage is reused by the modular operation after OAEP encoding. */
  uint8_t* seed = (uint8_t*)workspace->words;
  uint8_t* encoded = (uint8_t*)(workspace->words + arithmetic_words);
  --*work;
  if (execution->random.fill(execution->random.context, seed, info.digest_length) != TC_OK)
    status = TC_RSA_ERROR;
  else {
    status = tc_rsa_oaep_encode(options, (TC_buffer){encoded, length}, plaintext,
                                (TC_bytes){seed, info.digest_length},
                                (tc_rsa_hash_scratch){block, &hash_workspace}, work);
    if (status == TC_RSA_OK)
      status =
          tc_rsa_public_operation(key, encoded, ciphertext.data,
                                  (tc_mp_scratch){workspace->words, arithmetic_words}, work, NULL);
  }
  TC_secure_zero(workspace->words, required * sizeof(TC_RSA_word));
  TC_secure_zero(block, sizeof block);
  TC_secure_zero(&hash_workspace, sizeof hash_workspace);
  return status;
}

TC_RSA_result TC_RSA_decrypt_oaep(const TC_RSA_private_key* key, const TC_RSA_oaep_options* options,
                                  TC_bytes ciphertext, const TC_RSA_workspace* workspace,
                                  TC_buffer plaintext, size_t* plaintext_length,
                                  TC_RSA_execution* execution)
{
  tc_hash_info info;
  size_t decode_cost;
  if (!key || !options || !execution || !execution->random.fill)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status =
      tc_rsa_control_inputs(workspace, (TC_bytes){plaintext.data, plaintext.capacity}, options,
                            sizeof *options, execution, sizeof *execution);
  if (status != TC_RSA_OK)
    return status;
  if (!plaintext_length ||
      !tc_internal_ranges_disjoint(options, sizeof *options, plaintext_length,
                                   sizeof *plaintext_length) ||
      !tc_internal_ranges_disjoint(execution, sizeof *execution, plaintext_length,
                                   sizeof *plaintext_length))
    return TC_RSA_ARGUMENT;
  status = tc_rsa_decrypt_inputs(key, ciphertext, options->label, plaintext.data,
                                 plaintext.capacity, plaintext_length, workspace);
  if (status == TC_RSA_OK && key->crt)
    status =
        tc_rsa_crt_inputs(key, key->crt, (TC_bytes){plaintext.data, plaintext.capacity}, workspace);
  if (status == TC_RSA_OK)
    status = tc_rsa_public_key_check(&key->public_key);
  if (status != TC_RSA_OK)
    return status;
  const size_t length = key->public_key.modulus.length;
  if (ciphertext.length != length)
    return TC_RSA_INVALID;
  status = tc_rsa_oaep_plan(length, options->hash, options->mgf_hash, options->label, &info,
                            &decode_cost);
  if (status != TC_RSA_OK)
    return status;
  const size_t n = length / sizeof(TC_RSA_word), required = 14 * n;
  uint32_t* work = &execution->work.remaining;
  if (!execution->random_attempts || workspace->capacity < required || *work < decode_cost)
    return TC_RSA_LIMIT;
  TC_hash_context hash_workspace;
  uint8_t block[64];
  uint8_t* encoded = (uint8_t*)(workspace->words + 13 * n);
  TC_bytes message = {0};
  const tc_rsa_random rng = {execution->random, execution->random_attempts};
  status = tc_rsa_private_apply(key, key->crt, ciphertext.data, encoded, &rng,
                                (tc_mp_scratch){workspace->words, 13 * n}, work);
  if (status == TC_RSA_OK)
    status = tc_rsa_oaep_decode(options, (TC_buffer){encoded, length},
                                (tc_rsa_hash_scratch){block, &hash_workspace}, work, &message);
  if (status == TC_RSA_OK) {
    if (message.length > plaintext.capacity)
      status = TC_RSA_LIMIT;
    else {
      if (message.length)
        memcpy(plaintext.data, message.data, message.length);
      *plaintext_length = message.length;
    }
  }
  TC_secure_zero(workspace->words, required * sizeof(TC_RSA_word));
  TC_secure_zero(block, sizeof block);
  TC_secure_zero(&hash_workspace, sizeof hash_workspace);
  return status;
}
#endif
