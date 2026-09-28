/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RSAES-OAEP encryption and decryption (RFC 8017 section 7.1). */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_crt_internal.h"
#include "rsa_oaep_internal.h"
#include "rsa_keygen_internal.h"
#include "rsa_inputs_internal.h"

/* Additional output metadata uses the same disjoint-range rules as bytes. */
static TC_RSA_result tc_rsa_decrypt_inputs(const TC_RSA_private_key* key,
    TC_bytes ciphertext, TC_bytes label, uint8_t* plaintext, size_t capacity,
    size_t* plaintext_length, const TC_RSA_workspace* workspace)
{
  if (!plaintext_length || (uintptr_t)plaintext_length % sizeof *plaintext_length)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status = tc_rsa_private_inputs(key,ciphertext,
      (TC_bytes){plaintext,capacity},workspace);
  if (status != TC_RSA_OK) return status;
  TC_bytes writes[3];
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan,writes,3,SIZE_MAX);
  TC_PKI_PLAN_WRITE(&plan,workspace->words,workspace->capacity);
  TC_PKI_PLAN_WRITE(&plan,plaintext,capacity);
  TC_PKI_PLAN_WRITE(&plan,plaintext_length,1);
  tc_pki_storage_plan_seal(&plan);
  tc_pki_storage_plan_input_span(&plan,label);
  if (tc_rsa_storage_status(&plan) != TC_RSA_OK) return TC_RSA_ARGUMENT;
  /* Treat the length object as another output when checking key and ciphertext. */
  return tc_rsa_private_inputs(key,ciphertext,writes[2],workspace);
}

static TC_RSA_result tc_rsa_encrypt_oaep(const TC_RSA_public_key* key,
    TC_hash_algorithm hash, TC_hash_algorithm mgf_hash, TC_bytes label,
    TC_bytes plaintext, uint8_t* ciphertext, size_t ciphertext_length,
    TC_random_fn random, void* random_context,
    const TC_RSA_workspace* workspace, size_t* work)
{
  size_t max_work = *work;
  if (!random || !ciphertext) return TC_RSA_ARGUMENT;
  TC_RSA_result status = tc_rsa_public_inputs(key,plaintext,label,
      (TC_bytes){ciphertext,ciphertext_length},workspace);
  if (status != TC_RSA_OK) return status;
  const size_t length = key->modulus.length;
  status = tc_rsa_public_key_check(key->modulus.data,length,key->exponent.data,key->exponent.length);
  if (status != TC_RSA_OK) return status;
  if (ciphertext_length != length) return TC_RSA_INVALID;
  tc_hash_info info;
  size_t validation_work = SIZE_MAX;
  status = tc_rsa_oaep_prepare(length,hash,mgf_hash,label,&validation_work,&info);
  if (status != TC_RSA_OK) return status;
  if (plaintext.length > length - 2 * info.digest_length - 2) return TC_RSA_INVALID;
  const size_t n = length / sizeof(TC_RSA_word), arithmetic_words = 8 * n + 2;
  const size_t required = arithmetic_words + n;
  if (workspace->capacity < required || max_work <= SIZE_MAX - validation_work)
    return TC_RSA_LIMIT;
  TC_hash_context hash_workspace;
  uint8_t block[64];
  /* Seed storage is reused by the modular operation after OAEP encoding. */
  uint8_t* seed = (uint8_t*)workspace->words;
  uint8_t* encoded = (uint8_t*)(workspace->words + arithmetic_words);
  --max_work;
  if (random(random_context,seed,info.digest_length) != TC_OK) status = TC_RSA_ERROR;
  else {
    status = tc_rsa_oaep_encode(encoded,length,hash,mgf_hash,label,plaintext,
        (TC_bytes){seed,info.digest_length},block,&hash_workspace,&max_work);
    if (status == TC_RSA_OK)
      status = tc_rsa_public_operation(key->modulus.data,length,key->exponent.data,
          key->exponent.length,encoded,ciphertext,workspace->words,arithmetic_words,&max_work,NULL);
  }
  TC_secure_zero(workspace->words,required * sizeof(TC_RSA_word));
  TC_secure_zero(block,sizeof block);
  TC_secure_zero(&hash_workspace,sizeof hash_workspace);
  *work = max_work;
  return status;
}

TC_RSA_result TC_RSA_encrypt_oaep(const TC_RSA_public_key* key,
    const TC_RSA_oaep_options* options, TC_bytes plaintext,
    const TC_RSA_workspace* workspace, TC_buffer ciphertext,
    TC_RSA_execution* execution)
{
  if (!options || !execution) return TC_RSA_ARGUMENT;
  TC_RSA_result result = tc_rsa_control_inputs(workspace,
      (TC_bytes){ciphertext.data,ciphertext.capacity},options,sizeof *options,
      execution,sizeof *execution);
  if (result != TC_RSA_OK) return result;
  size_t work = execution->work.remaining;
  result = tc_rsa_encrypt_oaep(key,options->hash,
      options->mgf_hash,options->label,plaintext,ciphertext.data,
      ciphertext.capacity,execution->random.fill,execution->random.context,
      workspace,&work);
  execution->work.remaining = (uint32_t)work;
  return result;
}

static TC_RSA_result tc_rsa_decrypt_oaep(const TC_RSA_private_key* key,
    const TC_RSA_crt* crt,
    TC_hash_algorithm hash, TC_hash_algorithm mgf_hash, TC_bytes label,
    TC_bytes ciphertext, uint8_t* plaintext, size_t plaintext_capacity,
    size_t* plaintext_length, TC_random_fn random, void* random_context,
    size_t max_attempts, const TC_RSA_workspace* workspace, size_t* work)
{
  size_t max_work = *work;
  tc_hash_info info;
  size_t validation_work = SIZE_MAX;
  if (!random) return TC_RSA_ARGUMENT;
  TC_RSA_result status = tc_rsa_decrypt_inputs(key,ciphertext,label,plaintext,
      plaintext_capacity,plaintext_length,workspace);
  if (status != TC_RSA_OK) return status;
  if (crt) {
    status = tc_rsa_crt_inputs(key,crt,(TC_bytes){plaintext,plaintext_capacity},workspace);
    if (status != TC_RSA_OK) return status;
  }
  const size_t length = key->public_key.modulus.length;
  status = tc_rsa_public_key_check(key->public_key.modulus.data,length,
      key->public_key.exponent.data,key->public_key.exponent.length);
  if (status != TC_RSA_OK) return status;
  if (ciphertext.length != length) return TC_RSA_INVALID;
  status = tc_rsa_oaep_prepare(length,hash,mgf_hash,label,&validation_work,&info);
  if (status != TC_RSA_OK) return status;
  const size_t n = length / sizeof(TC_RSA_word), required = 14 * n;
  if (!max_attempts || workspace->capacity < required || max_work < SIZE_MAX - validation_work)
    return TC_RSA_LIMIT;
  TC_hash_context hash_workspace;
  uint8_t block[64];
  uint8_t* encoded = (uint8_t*)(workspace->words + 13 * n);
  TC_bytes message = {0};
  if (crt) status = tc_rsa_crt_private_operation(key->public_key.modulus.data,length,
      key->public_key.exponent.data,key->public_key.exponent.length,key->p,key->q,crt,
      ciphertext.data,encoded,random,random_context,max_attempts,
      workspace->words,13 * n,&max_work);
  else status = tc_rsa_private_operation_magnitude(key->public_key.modulus.data,length,
      key->public_key.exponent.data,key->public_key.exponent.length,key->d,
      ciphertext.data,encoded,random,random_context,max_attempts,
      workspace->words,13 * n,&max_work);
  if (status == TC_RSA_OK)
    status = tc_rsa_oaep_decode(encoded,length,hash,mgf_hash,label,block,
        &hash_workspace,&max_work,&message);
  if (status == TC_RSA_OK) {
    if (message.length > plaintext_capacity) status = TC_RSA_LIMIT;
    else {
      if (message.length) memcpy(plaintext,message.data,message.length);
      *plaintext_length = message.length;
    }
  }
  TC_secure_zero(workspace->words,required * sizeof(TC_RSA_word));
  TC_secure_zero(block,sizeof block);
  TC_secure_zero(&hash_workspace,sizeof hash_workspace);
  *work = max_work;
  return status;
}

TC_RSA_result TC_RSA_decrypt_oaep(const TC_RSA_private_key* key,
    const TC_RSA_oaep_options* options, TC_bytes ciphertext,
    const TC_RSA_workspace* workspace, TC_buffer plaintext,
    size_t* plaintext_length, TC_RSA_execution* execution)
{
  if (!key || !options || !execution) return TC_RSA_ARGUMENT;
  TC_RSA_result result = tc_rsa_control_inputs(workspace,
      (TC_bytes){plaintext.data,plaintext.capacity},options,sizeof *options,
      execution,sizeof *execution);
  if (result != TC_RSA_OK) return result;
  if (!plaintext_length ||
      !tc_internal_ranges_disjoint(options,sizeof *options,plaintext_length,
        sizeof *plaintext_length) ||
      !tc_internal_ranges_disjoint(execution,sizeof *execution,plaintext_length,
        sizeof *plaintext_length)) return TC_RSA_ARGUMENT;
  size_t work = execution->work.remaining;
  result = tc_rsa_decrypt_oaep(key,key->crt,options->hash,
      options->mgf_hash,options->label,ciphertext,plaintext.data,
      plaintext.capacity,plaintext_length,execution->random.fill,
      execution->random.context,execution->random_attempts,workspace,&work);
  execution->work.remaining = (uint32_t)work;
  return result;
}
#endif
