/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Store sources and signature probes shared by the native CMS tests in
 * native.c, path.c and revocation.c. */
#ifndef TEST_CMS_NATIVE_SUPPORT_H_
#define TEST_CMS_NATIVE_SUPPORT_H_
#include <tiny_crypto/cms.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_store.h>

static const TC_CMS_verification_policy cms_policy = {.envelope = TC_CMS_ENVELOPE_BER};

typedef struct {
  const TC_X509_store_source* certificates;
  const TC_X509_store_source* anchors;
} combined_store_source;

static inline TC_TLV_result combined_candidate(void* context, size_t index, size_t* work,
                                               TC_bytes* out)
{
  const TC_X509_store_source* source = ((combined_store_source*)context)->certificates;
  return source->candidate(source->context, index, work, out);
}

static inline TC_TLV_result combined_anchor(void* context, size_t index, size_t* work,
                                            TC_X509_store_anchor* out)
{
  const TC_X509_store_source* source = ((combined_store_source*)context)->anchors;
  return source->anchor(source->context, index, work, out);
}

static inline TC_TLV_result crl_trust_anchor(void* context, size_t index, size_t* work,
                                             TC_X509_store_anchor* out)
{
  if (!*work)
    return TC_TLV_LIMIT;
  --*work;
  *out = ((const TC_X509_store_anchor*)context)[index];
  return TC_TLV_OK;
}

typedef struct {
  TC_X509_signature_provider native;
  size_t calls, failure_call;
  TC_X509_signature_result failure;
} signature_retry_probe;

static inline TC_X509_signature_result retry_signature(void* context, const TC_bytes* message,
                                                       size_t count,
                                                       const TC_DER_algorithm* algorithm,
                                                       TC_bytes signature,
                                                       const TC_X509_public_key* key, size_t* work)
{
  signature_retry_probe* probe = context;
  if (++probe->calls == probe->failure_call)
    return probe->failure;
  return probe->native.verify(probe->native.context, message, count, algorithm, signature, key,
                              work);
}

static inline TC_X509_signature_result retry_digest(void* context, TC_bytes digest,
                                                    const TC_signature_algorithm* algorithm,
                                                    TC_bytes signature,
                                                    const TC_X509_public_key* key, size_t* work)
{
  signature_retry_probe* probe = context;
  if (++probe->calls == probe->failure_call)
    return probe->failure;
  return probe->native.verify_digest(probe->native.context, digest, algorithm, signature, key,
                                     work);
}

#endif
