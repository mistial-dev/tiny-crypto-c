/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RSA private-key operations: raw private, CRT validation and derivation,
 * key validation and PKCS #1 v1.5 and PSS signing. */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_pss_internal.h"
#include "rsa_crt_internal.h"
#include "rsa_keygen_internal.h"
#include "rsa_inputs_internal.h"

TC_RSA_result TC_RSA_encode_v15_digest(const TC_RSA_v15_options* options, TC_bytes digest,
                                       TC_buffer encoded, TC_work_budget* work)
{
  tc_hash_info info;
  if (!options || !work || !digest.data || !encoded.data ||
      !tc_internal_ranges_disjoint(digest.data, digest.length, encoded.data, encoded.capacity) ||
      !tc_internal_ranges_disjoint(options, sizeof *options, encoded.data, encoded.capacity) ||
      !tc_internal_ranges_disjoint(work, sizeof *work, encoded.data, encoded.capacity))
    return TC_RSA_ARGUMENT;
  if (!tc_hash_info_get(options->hash, &info))
    return TC_RSA_UNSUPPORTED;
  if (digest.length != info.digest_length)
    return TC_RSA_ARGUMENT;
  if (!tc_rsa_supported_modulus_size(encoded.capacity))
    return TC_RSA_UNSUPPORTED;
  if (work->remaining < encoded.capacity)
    return TC_RSA_LIMIT;
  work->remaining -= (uint32_t)encoded.capacity;
  return tc_rsa_v15_encode(encoded.data, encoded.capacity, info.digest_info.data,
                           info.digest_info.length, digest.data, digest.length) == TC_OK
             ? TC_RSA_OK
             : TC_RSA_ARGUMENT;
}

TC_RSA_result TC_RSA_encode_pss_digest(const TC_RSA_pss_options* options, TC_bytes digest,
                                       TC_bytes salt, TC_buffer encoded, TC_work_budget* work)
{
  if (!options || !work || !digest.data || (salt.length && !salt.data) || !encoded.data)
    return TC_RSA_ARGUMENT;
  const TC_bytes inputs[] = {{(const uint8_t*)options, sizeof *options}, digest, salt};
  if (!tc_internal_ranges_disjoint(work, sizeof *work, encoded.data, encoded.capacity))
    return TC_RSA_ARGUMENT;
  for (size_t i = 0; i < sizeof inputs / sizeof *inputs; ++i) {
    if (!tc_internal_ranges_disjoint(inputs[i].data, inputs[i].length, encoded.data,
                                     encoded.capacity) ||
        !tc_internal_ranges_disjoint(inputs[i].data, inputs[i].length, work, sizeof *work))
      return TC_RSA_ARGUMENT;
  }
  if (salt.length != options->salt_length)
    return TC_RSA_ARGUMENT;
  if (!tc_rsa_supported_modulus_size(encoded.capacity))
    return TC_RSA_UNSUPPORTED;
  tc_hash_info info;
  size_t remaining = work->remaining;
  TC_RSA_result result =
      tc_rsa_pss_prepare(encoded.capacity, encoded.capacity * 8 - 1, options->hash,
                         options->mgf_hash, digest.length, salt.length, &remaining, &info);
  if (result != TC_RSA_OK)
    return result;
  TC_hash_context workspace;
  uint8_t block[64];
  remaining = work->remaining;
  result =
      tc_rsa_pss_encode(encoded.data, encoded.capacity, encoded.capacity * 8 - 1, options->hash,
                        options->mgf_hash, digest, salt, block, &workspace, &remaining);
  work->remaining = (uint32_t)remaining;
  if (result != TC_RSA_OK)
    TC_secure_zero(encoded.data, encoded.capacity);
  TC_secure_zero(block, sizeof block);
  TC_secure_zero(&workspace, sizeof workspace);
  return result;
}

TC_RSA_result TC_RSA_raw_private(const TC_RSA_public_key* key, TC_bytes private_exponent,
                                 TC_bytes input, const TC_RSA_workspace* workspace,
                                 TC_buffer output, TC_RSA_execution* execution)
{
  if (!key || !workspace || !execution || !execution->random.fill)
    return TC_RSA_ARGUMENT;
  const TC_bytes controls[] = {{(const uint8_t*)key, sizeof *key},
                               {(const uint8_t*)workspace, sizeof *workspace},
                               key->modulus,
                               key->exponent,
                               private_exponent,
                               input,
                               {(const uint8_t*)execution, sizeof *execution}};
  TC_RSA_result result =
      tc_rsa_output_inputs(workspace, controls, sizeof controls / sizeof *controls,
                           (TC_bytes){output.data, output.capacity});
  if (result != TC_RSA_OK)
    return result;
  const size_t length = key->modulus.length;
  if (input.length != length || !private_exponent.length || private_exponent.length > length)
    return TC_RSA_INVALID;
  if (output.capacity < length ||
      workspace->capacity < TC_RSA_raw_private_workspace_words(length * 8))
    return TC_RSA_LIMIT;
  size_t available = execution->work.remaining;
  result = tc_rsa_private_operation_magnitude(
      key->modulus.data, length, key->exponent.data, key->exponent.length, private_exponent,
      input.data, output.data, execution->random.fill, execution->random.context,
      execution->random_attempts, workspace->words, workspace->capacity, &available);
  execution->work.remaining = (uint32_t)available;
  return result;
}

TC_RSA_result TC_RSA_validate_crt(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                  const TC_RSA_workspace* workspace, TC_work_budget* work)
{
  if (!crt || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result =
      tc_rsa_private_inputs(key, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, workspace);
  if (result != TC_RSA_OK)
    return result;
  result = tc_rsa_workspace_inputs(workspace, &(TC_bytes){(const uint8_t*)work, sizeof *work}, 1);
  if (result != TC_RSA_OK)
    return result;
  const TC_bytes inputs[] = {{(const uint8_t*)crt, sizeof *crt},
                             {crt->dp.data, crt->dp.length},
                             {crt->dq.data, crt->dq.length},
                             {crt->q_inverse.data, crt->q_inverse.length}};
  result = tc_rsa_workspace_inputs(workspace, inputs, sizeof inputs / sizeof *inputs);
  if (result != TC_RSA_OK)
    return result;
  result = tc_rsa_public_key_check(key->public_key.modulus.data, key->public_key.modulus.length,
                                   key->public_key.exponent.data, key->public_key.exponent.length);
  if (result != TC_RSA_OK)
    return result;
  size_t available = work->remaining;
  result = tc_rsa_crt_consistent(key->public_key.modulus.length, key->d, key->p, key->q, crt->dp,
                                 crt->dq, crt->q_inverse, workspace->words, workspace->capacity,
                                 &available);
  work->remaining = (uint32_t)available;
  return result;
}

TC_RSA_result TC_RSA_derive_crt(const TC_RSA_private_key* key, const TC_RSA_crt_output* output,
                                const TC_RSA_workspace* workspace, TC_work_budget* work)
{
  if (!output || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status =
      tc_rsa_private_inputs(key, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, workspace);
  if (status != TC_RSA_OK)
    return status;
  status = tc_rsa_workspace_inputs(workspace, &(TC_bytes){(const uint8_t*)work, sizeof *work}, 1);
  if (status != TC_RSA_OK)
    return status;
  status = tc_rsa_public_key_check(key->public_key.modulus.data, key->public_key.modulus.length,
                                   key->public_key.exponent.data, key->public_key.exponent.length);
  if (status != TC_RSA_OK)
    return status;
  const size_t length = key->public_key.modulus.length, prime_length = length / 2;
  const TC_buffer buffers[] = {output->dp, output->dq, output->q_inverse};
  const TC_bytes metadata = {(const uint8_t*)output, sizeof *output};
  for (size_t i = 0; i < sizeof buffers / sizeof *buffers; ++i) {
    if (!buffers[i].data)
      return TC_RSA_ARGUMENT;
    if (buffers[i].capacity < prime_length)
      return TC_RSA_LIMIT;
    status = tc_rsa_private_inputs(key, (TC_bytes){NULL, 0},
                                   (TC_bytes){buffers[i].data, buffers[i].capacity}, workspace);
    if (status != TC_RSA_OK)
      return status;
    status = tc_rsa_output_inputs(workspace, &metadata, 1,
                                  (TC_bytes){buffers[i].data, buffers[i].capacity});
    if (status != TC_RSA_OK)
      return status;
    if (!tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, work, sizeof *work))
      return TC_RSA_ARGUMENT;
    for (size_t j = 0; j < i; ++j)
      if (!tc_internal_ranges_disjoint(buffers[i].data, buffers[i].capacity, buffers[j].data,
                                       buffers[j].capacity))
        return TC_RSA_ARGUMENT;
  }
  tc_mp_word *dp, *dq, *inverse;
  size_t available = work->remaining;
  status = tc_rsa_crt_derive(length, key->d, key->p, key->q, workspace->words, workspace->capacity,
                             &available, &dp, &dq, &inverse);
  work->remaining = (uint32_t)available;
  if (status == TC_RSA_OK) {
    tc_mp_to_be(output->dp.data, dp, prime_length);
    tc_mp_to_be(output->dq.data, dq, prime_length);
    tc_mp_to_be(output->q_inverse.data, inverse, prime_length);
  }
  if (workspace->capacity >= TC_RSA_CRT_WORKSPACE_WORDS(length * 8))
    TC_secure_zero(workspace->words,
                   TC_RSA_CRT_WORKSPACE_WORDS(length * 8) * sizeof *workspace->words);
  return status;
}

static TC_RSA_result tc_rsa_validate_private_key(const TC_RSA_private_key* key, TC_random_fn random,
                                                 void* random_context, size_t max_attempts,
                                                 const TC_RSA_workspace* workspace, uint32_t* work)
{
  if (!random)
    return TC_RSA_ARGUMENT;
  TC_RSA_result checked =
      tc_rsa_private_inputs(key, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, workspace);
  if (checked != TC_RSA_OK)
    return checked;
  const size_t length = key->public_key.modulus.length;
  return tc_rsa_private_magnitudes_check(
      key->public_key.modulus.data, length, key->public_key.exponent.data,
      key->public_key.exponent.length, key->d, key->p, key->q, TC_RSA_VALIDATION_ROUNDS, random,
      random_context, max_attempts, workspace->words, workspace->capacity, work);
}

TC_RSA_result TC_RSA_validate_private_key(const TC_RSA_private_key* key,
                                          const TC_RSA_workspace* workspace,
                                          TC_RSA_execution* execution)
{
  if (!workspace || !execution)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result = tc_rsa_workspace_inputs(
      workspace, &(TC_bytes){(const uint8_t*)execution, sizeof *execution}, 1);
  if (result != TC_RSA_OK)
    return result;
  result = tc_rsa_validate_private_key(key, execution->random.fill, execution->random.context,
                                       execution->random_attempts, workspace,
                                       &execution->work.remaining);
  return result;
}

static TC_RSA_result tc_rsa_sign_inputs(const TC_RSA_private_key* key, TC_bytes digest,
                                        uint8_t* signature, size_t signature_length,
                                        TC_random_fn random, size_t max_attempts,
                                        const TC_RSA_workspace* workspace)
{
  if (!random)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status =
      tc_rsa_private_inputs(key, digest, (TC_bytes){signature, signature_length}, workspace);
  if (status != TC_RSA_OK)
    return status;
  status = tc_rsa_public_key_check(key->public_key.modulus.data, key->public_key.modulus.length,
                                   key->public_key.exponent.data, key->public_key.exponent.length);
  if (status != TC_RSA_OK)
    return status;
  if (signature_length != key->public_key.modulus.length)
    return TC_RSA_INVALID;
  if (!max_attempts || workspace->capacity < 14 * (signature_length / sizeof(TC_RSA_word)))
    return TC_RSA_LIMIT;
  return TC_RSA_OK;
}

static TC_RSA_result tc_rsa_sign_encoded(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                         uint8_t* signature, TC_random_fn random,
                                         void* random_context, size_t max_attempts,
                                         const TC_RSA_workspace* workspace, size_t* work)
{
  const size_t length = key->public_key.modulus.length, n = length / sizeof(TC_RSA_word);
  if (crt)
    return tc_rsa_crt_private_operation(
        key->public_key.modulus.data, length, key->public_key.exponent.data,
        key->public_key.exponent.length, key->p, key->q, crt,
        (const uint8_t*)(workspace->words + 13 * n), signature, random, random_context,
        max_attempts, workspace->words, 13 * n, work);
  return tc_rsa_private_operation_magnitude(
      key->public_key.modulus.data, length, key->public_key.exponent.data,
      key->public_key.exponent.length, key->d, (const uint8_t*)(workspace->words + 13 * n),
      signature, random, random_context, max_attempts, workspace->words, 13 * n, work);
}

static TC_RSA_result tc_rsa_sign_v15_digest(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                            TC_hash_algorithm hash, TC_bytes digest,
                                            uint8_t* signature, size_t signature_length,
                                            TC_random_fn random, void* random_context,
                                            size_t max_attempts, const TC_RSA_workspace* workspace,
                                            size_t* work)
{
  size_t max_work = *work;
  tc_hash_info info;
  TC_RSA_result status =
      tc_rsa_sign_inputs(key, digest, signature, signature_length, random, max_attempts, workspace);
  if (status != TC_RSA_OK)
    return status;
  if (crt) {
    status = tc_rsa_crt_inputs(key, crt, (TC_bytes){signature, signature_length}, workspace);
    if (status != TC_RSA_OK)
      return status;
  }
  if (!tc_hash_info_get(hash, &info))
    return TC_RSA_UNSUPPORTED;
  if (!digest.data || digest.length != info.digest_length)
    return TC_RSA_ARGUMENT;
  const size_t length = key->public_key.modulus.length;
  if (!tc_rsa_v15_size(length, info.digest_info.length, digest.length))
    return TC_RSA_INVALID;
  const size_t n = length / sizeof(TC_RSA_word), required = 14 * n;
  if (max_work < length)
    return TC_RSA_LIMIT;
  max_work -= length;
  uint8_t* encoded = (uint8_t*)(workspace->words + 13 * n);
  if (tc_rsa_v15_encode(encoded, length, info.digest_info.data, info.digest_info.length,
                        digest.data, digest.length) != TC_OK)
    status = TC_RSA_ARGUMENT;
  else
    status = tc_rsa_sign_encoded(key, crt, signature, random, random_context, max_attempts,
                                 workspace, &max_work);
  TC_secure_zero(workspace->words, required * sizeof(TC_RSA_word));
  *work = max_work;
  return status;
}

TC_RSA_result TC_RSA_sign_v15_digest(const TC_RSA_private_key* key,
                                     const TC_RSA_v15_options* options, TC_bytes digest,
                                     const TC_RSA_workspace* workspace, TC_buffer signature,
                                     TC_RSA_execution* execution)
{
  if (!key || !options || !execution)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result =
      tc_rsa_control_inputs(workspace, (TC_bytes){signature.data, signature.capacity}, options,
                            sizeof *options, execution, sizeof *execution);
  if (result != TC_RSA_OK)
    return result;
  size_t work = execution->work.remaining;
  result =
      tc_rsa_sign_v15_digest(key, key->crt, options->hash, digest, signature.data,
                             signature.capacity, execution->random.fill, execution->random.context,
                             execution->random_attempts, workspace, &work);
  execution->work.remaining = (uint32_t)work;
  return result;
}

static TC_RSA_result tc_rsa_sign_pss_digest(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                            TC_hash_algorithm hash, TC_hash_algorithm mgf_hash,
                                            size_t salt_length, TC_bytes digest, uint8_t* signature,
                                            size_t signature_length, TC_random_fn random,
                                            void* random_context, size_t max_attempts,
                                            const TC_RSA_workspace* workspace, size_t* work)
{
  size_t max_work = *work;
  tc_hash_info info;
  size_t validation_work = SIZE_MAX;
  TC_RSA_result status =
      tc_rsa_sign_inputs(key, digest, signature, signature_length, random, max_attempts, workspace);
  if (status != TC_RSA_OK)
    return status;
  if (crt) {
    status = tc_rsa_crt_inputs(key, crt, (TC_bytes){signature, signature_length}, workspace);
    if (status != TC_RSA_OK)
      return status;
  }
  const size_t length = key->public_key.modulus.length, n = length / sizeof(TC_RSA_word);
  status = tc_rsa_pss_prepare(length, length * 8 - 1, hash, mgf_hash, digest.length, salt_length,
                              &validation_work, &info);
  if (status != TC_RSA_OK)
    return status;
  if (!digest.data)
    return TC_RSA_ARGUMENT;
  if (max_work < SIZE_MAX - validation_work + (salt_length != 0))
    return TC_RSA_LIMIT;
  TC_hash_context hash_workspace;
  uint8_t block[64];
  uint8_t* salt = (uint8_t*)workspace->words;
  uint8_t* encoded = (uint8_t*)(workspace->words + 13 * n);
  if (salt_length) {
    --max_work;
    if (random(random_context, salt, salt_length) != TC_OK) {
      status = TC_RSA_ERROR;
      goto cleanup;
    }
  }
  status = tc_rsa_pss_encode(encoded, length, length * 8 - 1, hash, mgf_hash, digest,
                             (TC_bytes){salt, salt_length}, block, &hash_workspace, &max_work);
  if (status == TC_RSA_OK)
    status = tc_rsa_sign_encoded(key, crt, signature, random, random_context, max_attempts,
                                 workspace, &max_work);
cleanup:
  TC_secure_zero(workspace->words, 14 * n * sizeof(TC_RSA_word));
  TC_secure_zero(block, sizeof block);
  TC_secure_zero(&hash_workspace, sizeof hash_workspace);
  *work = max_work;
  return status;
}

TC_RSA_result TC_RSA_sign_pss_digest(const TC_RSA_private_key* key,
                                     const TC_RSA_pss_options* options, TC_bytes digest,
                                     const TC_RSA_workspace* workspace, TC_buffer signature,
                                     TC_RSA_execution* execution)
{
  if (!key || !options || !execution)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result =
      tc_rsa_control_inputs(workspace, (TC_bytes){signature.data, signature.capacity}, options,
                            sizeof *options, execution, sizeof *execution);
  if (result != TC_RSA_OK)
    return result;
  size_t work = execution->work.remaining;
  result = tc_rsa_sign_pss_digest(key, key->crt, options->hash, options->mgf_hash,
                                  options->salt_length, digest, signature.data, signature.capacity,
                                  execution->random.fill, execution->random.context,
                                  execution->random_attempts, workspace, &work);
  execution->work.remaining = (uint32_t)work;
  return result;
}
#endif
