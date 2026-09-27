/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RSA workspace sizing and shared argument and storage checks. */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_inputs_internal.h"

size_t TC_RSA_verify_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_VERIFY_WORKSPACE_WORDS(bits);
}

size_t TC_RSA_validate_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_VALIDATE_WORKSPACE_WORDS(bits);
}

size_t TC_RSA_crt_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_CRT_WORKSPACE_WORDS(bits);
}

size_t TC_RSA_sign_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_SIGN_WORKSPACE_WORDS(bits);
}

size_t TC_RSA_decrypt_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_DECRYPT_WORKSPACE_WORDS(bits);
}

size_t TC_RSA_encrypt_workspace_words(size_t bits)
{
  return TC_RSA_verify_workspace_words(bits);
}

size_t TC_RSA_raw_public_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(bits);
}

size_t TC_RSA_raw_private_workspace_words(size_t bits)
{
  if (bits != 1024 && bits != 2048 && bits != 3072) return 0;
  return TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(bits);
}

TC_RSA_result tc_rsa_storage_status(const tc_pki_storage_plan* plan)
{
  return tc_pki_storage_plan_finish(plan,NULL) == TC_TLV_OK ? TC_RSA_OK : TC_RSA_ARGUMENT;
}

TC_RSA_result tc_rsa_workspace_inputs(const TC_RSA_workspace* workspace,
    const TC_bytes* inputs, size_t count)
{
  TC_bytes writes;
  tc_pki_storage_plan plan;
  if ((uintptr_t)workspace->words % sizeof(TC_RSA_word)) return TC_RSA_ARGUMENT;
  tc_pki_storage_plan_begin(&plan,&writes,1,SIZE_MAX);
  TC_PKI_PLAN_WRITE(&plan,workspace->words,workspace->capacity);
  tc_pki_storage_plan_seal(&plan);
  tc_pki_storage_plan_input_spans(&plan,inputs,count);
  return tc_rsa_storage_status(&plan);
}

/* Output and scratch are separate from each other and every borrowed input. */
TC_RSA_result tc_rsa_output_inputs(const TC_RSA_workspace* workspace,
    const TC_bytes* inputs, size_t count, TC_bytes output)
{
  TC_bytes writes[2];
  tc_pki_storage_plan plan;
  if ((uintptr_t)workspace->words % sizeof(TC_RSA_word)) return TC_RSA_ARGUMENT;
  tc_pki_storage_plan_begin(&plan,writes,2,SIZE_MAX);
  TC_PKI_PLAN_WRITE(&plan,workspace->words,workspace->capacity);
  tc_pki_storage_plan_write_span(&plan,output);
  tc_pki_storage_plan_seal(&plan);
  tc_pki_storage_plan_input_spans(&plan,inputs,count);
  return tc_rsa_storage_status(&plan);
}

TC_RSA_result tc_rsa_control_inputs(const TC_RSA_workspace* workspace,
    TC_bytes output, const void* first, size_t first_size,
    const void* second, size_t second_size)
{
  if (!workspace || !first || !second) return TC_RSA_ARGUMENT;
  const TC_bytes controls[] = {
    {(const uint8_t*)first,first_size},{(const uint8_t*)second,second_size}
  };
  return tc_rsa_output_inputs(workspace,controls,2,output);
}

TC_RSA_result tc_rsa_public_inputs(const TC_RSA_public_key* key,
    TC_bytes first, TC_bytes second, TC_bytes output, const TC_RSA_workspace* workspace)
{
  TC_bytes inputs[6];
  if (!key || !workspace) return TC_RSA_ARGUMENT;
  inputs[0] = (TC_bytes){(const uint8_t*)key,sizeof *key};
  inputs[1] = (TC_bytes){(const uint8_t*)workspace,sizeof *workspace};
  inputs[2] = (TC_bytes){key->modulus.data,key->modulus.length};
  inputs[3] = (TC_bytes){key->exponent.data,key->exponent.length};
  inputs[4] = (TC_bytes){first.data,first.length};
  inputs[5] = (TC_bytes){second.data,second.length};
  return tc_rsa_output_inputs(workspace,inputs,sizeof inputs / sizeof *inputs,output);
}

TC_RSA_result tc_rsa_private_inputs(const TC_RSA_private_key* key,
    TC_bytes digest, TC_bytes output, const TC_RSA_workspace* workspace)
{
  if (!key || !workspace) return TC_RSA_ARGUMENT;
  const TC_bytes inputs[] = {
    {(const uint8_t*)key,sizeof *key},
    {(const uint8_t*)workspace,sizeof *workspace},
    {key->public_key.modulus.data,key->public_key.modulus.length},
    {key->public_key.exponent.data,key->public_key.exponent.length},
    {key->d.data,key->d.length},{key->p.data,key->p.length},{key->q.data,key->q.length},
    {digest.data,digest.length}
  };
  TC_RSA_result checked = tc_rsa_output_inputs(workspace,inputs,sizeof inputs / sizeof *inputs,output);
  if (checked != TC_RSA_OK) return checked;
  const size_t length = key->public_key.modulus.length;
  if (!key->d.length || !key->p.length || !key->q.length ||
      key->d.length > length || key->p.length > length || key->q.length > length)
    return TC_RSA_INVALID;
  return TC_RSA_OK;
}

TC_RSA_result tc_rsa_crt_inputs(const TC_RSA_private_key* key,
    const TC_RSA_crt* crt, TC_bytes output, const TC_RSA_workspace* workspace)
{
  if (!crt) return TC_RSA_ARGUMENT;
  const TC_bytes inputs[] = {
    {(const uint8_t*)crt,sizeof *crt},
    {crt->dp.data,crt->dp.length},{crt->dq.data,crt->dq.length},
    {crt->q_inverse.data,crt->q_inverse.length}
  };
  TC_RSA_result status = tc_rsa_output_inputs(workspace,inputs,
      sizeof inputs / sizeof *inputs,output);
  if (status != TC_RSA_OK) return status;
  const size_t prime_length = key->public_key.modulus.length / 2;
  for (size_t i = 1; i < sizeof inputs / sizeof *inputs; ++i) {
    if (!inputs[i].data) return TC_RSA_ARGUMENT;
    if (!inputs[i].length || inputs[i].length > 2 * prime_length) return TC_RSA_INVALID;
    size_t excess = inputs[i].length > prime_length ? inputs[i].length - prime_length : 0;
    for (size_t j = 0; j < excess; ++j)
      if (inputs[i].data[j]) return TC_RSA_INVALID;
  }
  return TC_RSA_OK;
}
#endif
