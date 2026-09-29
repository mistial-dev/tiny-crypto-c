/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "cms_reader.h"

enum { MAX_INPUT = 16 * 1024, MAX_ELEMENTS = 1024 };
static const TC_TLV_limits limits = {MAX_INPUT, MAX_INPUT, MAX_ELEMENTS,
                                     EXAMPLE_CMS_FRAME_CAPACITY};

static TC_CMS_signature_workspace signature_workspace(ExampleCMSVerifyWorkspace* workspace)
{
  TC_CMS_signature_workspace view = {workspace->parser.frames, EXAMPLE_CMS_FRAME_CAPACITY,
                                     workspace->signature, sizeof workspace->signature};
  return view;
}

TC_X509_signature_result
example_verify_cms_digest(const TC_CMS_signer_info* signer, TC_bytes content_type, TC_bytes digest,
                          const TC_X509_public_key* key, const TC_X509_signature_provider* provider,
                          size_t work_limit, ExampleCMSVerifyWorkspace* workspace)
{
  const TC_CMS_signer_verify_request request = {
      signer, content_type, {TC_CMS_ATTRIBUTES_DER, TC_CMS_RSA_PARAMETERS_NULL},
      key,    provider,     &limits};
  TC_CMS_signature_workspace verification;
  if (!workspace)
    return TC_X509_SIGNATURE_ERROR;
  verification = signature_workspace(workspace);
  return TC_CMS_signer_verify_digest(&request, digest, &verification, &work_limit);
}

TC_X509_signature_result example_verify_cms_content(const TC_CMS_signer_info* signer,
                                                    TC_bytes content_type, TC_bytes content,
                                                    TC_CMS_content_encoding content_encoding,
                                                    const TC_X509_public_key* key,
                                                    const TC_X509_signature_provider* provider,
                                                    size_t work_limit,
                                                    ExampleCMSVerifyWorkspace* workspace)
{
  const TC_CMS_signer_verify_request request = {
      signer, content_type, {TC_CMS_ATTRIBUTES_DER, TC_CMS_RSA_PARAMETERS_NULL},
      key,    provider,     &limits};
  TC_CMS_signature_workspace verification;
  if (!workspace)
    return TC_X509_SIGNATURE_ERROR;
  verification = signature_workspace(workspace);
  return TC_CMS_signer_verify_content(&request, content, content_encoding, &verification,
                                      &work_limit);
}

TC_TLV_result example_read_cms(TC_bytes input, size_t work_limit, ExampleCMSWorkspace* workspace,
                               TC_CMS_signed_data* out)
{
  if (!workspace)
    return TC_TLV_ARGUMENT;
  return TC_CMS_signed_data_read(input, &limits,
                                 (TC_TLV_frames){workspace->frames, EXAMPLE_CMS_FRAME_CAPACITY},
                                 &work_limit, out);
}

TC_TLV_result example_read_cms_signer(TC_bytes input, size_t work_limit,
                                      ExampleCMSWorkspace* workspace, TC_CMS_signer_info* out)
{
  if (!workspace)
    return TC_TLV_ARGUMENT;
  return TC_CMS_signer_info_read(input, TC_TLV_BER, &limits,
                                 (TC_TLV_frames){workspace->frames, EXAMPLE_CMS_FRAME_CAPACITY},
                                 &work_limit, out);
}

TC_TLV_result example_parse_cms_signers(TC_bytes encoded_set, size_t work_limit,
                                        ExampleCMSWorkspace* workspace)
{
  TC_TLV_reader reader;
  TC_CMS_signer_info signer;
  TC_TLV_result result;
  if (!workspace)
    return TC_TLV_ARGUMENT;
  result = TC_CMS_signers_init(encoded_set, &limits,
                               (TC_TLV_frames){workspace->frames, EXAMPLE_CMS_FRAME_CAPACITY},
                               &work_limit, &reader);
  if (result != TC_TLV_OK)
    return result;
  while ((result = TC_CMS_signer_next(
              &reader, (TC_TLV_frames){workspace->frames, EXAMPLE_CMS_FRAME_CAPACITY}, &work_limit,
              &signer)) == TC_TLV_OK) {
    /* Applications can inspect each signer here before reusing the view. */
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}
