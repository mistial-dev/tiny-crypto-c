/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_crypto.h>
#if TC_ENABLE_X509
#include "pki_verify_internal.h"
#include "pki_storage_internal.h"
#include "hash_dispatch_internal.h"
#include "x509_path_internal.h"

static TC_X509_signature_result native_status(TC_TLV_result result)
{
  return result == TC_TLV_LIMIT ? TC_X509_SIGNATURE_LIMIT :
    result == TC_TLV_UNSUPPORTED ? TC_X509_SIGNATURE_UNSUPPORTED :
    result == TC_TLV_ARGUMENT ? TC_X509_SIGNATURE_ERROR : TC_X509_SIGNATURE_INVALID;
}

static TC_X509_signature_result native_storage(const TC_X509_native_workspace* workspace,
    const TC_bytes* message, size_t count, TC_bytes algorithm_metadata,
    const TC_bytes* algorithm_fields, size_t field_count, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  TC_bytes writes[3];
  tc_pki_storage_plan plan;
  size_t budget;
  if (!workspace || !key || !work || (count && !message)) return TC_X509_SIGNATURE_ERROR;
  const TC_bytes fields[] = {
    key->algorithm.oid, key->algorithm.parameters,
    key->key, key->modulus, key->exponent, key->curve_oid, signature
  };
  tc_pki_storage_plan_begin(&plan,writes,3,*work);
  TC_PKI_PLAN_WRITE(&plan,workspace->ec,workspace->ec ? 1 : 0);
  tc_pki_storage_plan_write(&plan,workspace->rsa ? workspace->rsa->words : NULL,
      workspace->rsa ? workspace->rsa->capacity : 0,sizeof(TC_RSA_word));
  TC_PKI_PLAN_WRITE(&plan,work,1);
  tc_pki_storage_plan_seal(&plan);
  TC_PKI_PLAN_INPUT(&plan,message,count);
  TC_PKI_PLAN_INPUT(&plan,workspace,1);
  TC_PKI_PLAN_INPUT(&plan,workspace->rsa,workspace->rsa ? 1 : 0);
  tc_pki_storage_plan_input_span(&plan,algorithm_metadata);
  TC_PKI_PLAN_INPUT(&plan,key,1);
  tc_pki_storage_plan_input_spans(&plan,fields,sizeof fields / sizeof *fields);
  tc_pki_storage_plan_input_spans(&plan,algorithm_fields,field_count);
  tc_pki_storage_plan_input_spans(&plan,message,count);
  TC_TLV_result checked = tc_pki_storage_plan_finish(&plan,&budget);
  if (checked != TC_TLV_OK) return native_status(checked);
  /* Charge encoded bytes before parsing OIDs, PSS parameters and signatures. */
  for (size_t i = 0; i < field_count; ++i)
    if (tc_pki_work_charge(&budget,algorithm_fields[i].length) != TC_TLV_OK)
      return TC_X509_SIGNATURE_LIMIT;
  for (size_t i = 0; i < count; ++i)
    if (tc_pki_work_charge(&budget,message[i].length) != TC_TLV_OK) return TC_X509_SIGNATURE_LIMIT;
  for (size_t i = 0; i < sizeof fields / sizeof *fields; ++i)
    if (tc_pki_work_charge(&budget,fields[i].length) != TC_TLV_OK) return TC_X509_SIGNATURE_LIMIT;
  *work = budget;
  return TC_X509_SIGNATURE_VALID;
}

static TC_X509_signature_result native_verify_digest(void* context, TC_bytes digest,
    const TC_signature_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  const TC_X509_native_workspace* workspace = context;
  TC_X509_signature_result result;
  TC_TLV_result checked;
  if (!algorithm) return TC_X509_SIGNATURE_ERROR;
  result = native_storage(workspace,&digest,1,
      (TC_bytes){(const uint8_t*)algorithm,sizeof *algorithm},NULL,0,signature,key,work);
  if (result != TC_X509_SIGNATURE_VALID) return result;
  checked = tc_pki_signature_key_check(algorithm,key);
  if (checked != TC_TLV_OK) return native_status(checked);
  if (tc_pki_work_charge(work,workspace->signature_work) != TC_TLV_OK)
    return TC_X509_SIGNATURE_LIMIT;
  return tc_pki_verify_digest(algorithm,key,digest,signature,workspace->ec,workspace->rsa,
      workspace->signature_work);
}

static TC_X509_signature_result native_verify(void* context, const TC_bytes* message,
    size_t count, const TC_DER_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  const TC_X509_native_workspace* workspace = context;
  TC_signature_algorithm selected;
  tc_hash_workspace hash_workspace;
  tc_hash_info hash;
  enum { MAX_DIGEST_BYTES = 64 };
  uint8_t digest[MAX_DIGEST_BYTES];
  TC_X509_signature_result result;
  TC_TLV_result checked;
  if (!algorithm) return TC_X509_SIGNATURE_ERROR;
  const TC_bytes fields[] = {algorithm->oid,algorithm->parameters};
  result = native_storage(workspace,message,count,
      (TC_bytes){(const uint8_t*)algorithm,sizeof *algorithm},fields,
      sizeof fields / sizeof *fields,signature,key,work);
  if (result != TC_X509_SIGNATURE_VALID) return result;
  checked = tc_pki_signature_resolve(algorithm,key,&selected);
  if (checked != TC_TLV_OK) return native_status(checked);
  if (!tc_hash_available(selected.hash) || !tc_hash_info_get(selected.hash,&hash))
    return TC_X509_SIGNATURE_UNSUPPORTED;
  if (tc_pki_work_charge(work,workspace->signature_work) != TC_TLV_OK) return TC_X509_SIGNATURE_LIMIT;
  if (tc_hash_digest_parts(selected.hash,message,count,digest,&hash_workspace) != TC_OK)
    return TC_X509_SIGNATURE_ERROR;
  result = tc_pki_verify_digest(&selected,key,(TC_bytes){digest,hash.digest_length},
      signature,workspace->ec,workspace->rsa,workspace->signature_work);
  TC_secure_zero(digest,sizeof digest);
  return result;
}

TC_X509_signature_provider TC_X509_native_provider(const TC_X509_native_workspace* workspace)
{
  TC_X509_signature_provider provider = {native_verify,(void*)workspace,native_verify_digest};
  return provider;
}
#endif
