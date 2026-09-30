/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "piv_inspect_trust.h"
#include <string.h>

enum { TRUST_WORK = 200000000 };

int example_piv_inspect_trust_init(ExamplePIVInspectTrust* trust,
                                   const ExamplePIVInspectOptions* options)
{
  if (!options->anchor_count || options->anchor_count > EXAMPLE_PIV_INSPECT_ANCHORS ||
      options->crl_count > EXAMPLE_PIV_INSPECT_CRLS)
    return 0;
  const TC_TLV_limits limits = {EXAMPLE_PIV_TRUST_CERTIFICATE_BYTES,
                                EXAMPLE_PIV_TRUST_CERTIFICATE_BYTES, 512, EXAMPLE_PIV_TRUST_FRAMES};
  trust->parser = (TC_X509_workspace){
      {trust->frames, EXAMPLE_PIV_TRUST_FRAMES}, trust->oids, EXAMPLE_PIV_TRUST_OIDS};
  trust->rsa = (TC_RSA_workspace){trust->words, sizeof trust->words / sizeof *trust->words};
  trust->native =
      (TC_X509_native_workspace){&trust->ec, &trust->rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_validation_capacity capacity;
  if (TC_validation_capacity_init(TC_VALIDATION_DESKTOP, &capacity) != TC_RESULT_OK ||
      TC_validation_workspace_init(&capacity,
                                   (TC_buffer){(uint8_t*)trust->arena, sizeof trust->arena},
                                   &trust->workspace) != TC_RESULT_OK)
    return 0;
  for (size_t i = 0; i < options->anchor_count; ++i) {
    TC_X509_certificate view;
    if (TC_X509_read(options->anchors[i], &limits, &trust->parser, &view) != TC_TLV_OK ||
        TC_X509_store_anchor_from_certificate(&view, &limits, &trust->parser, &trust->anchors[i]) !=
            TC_TLV_OK)
      return 0;
  }
  /* The anchor certificates are also the candidates of CRL signer searches. */
  trust->array = (TC_X509_store_array){options->anchors, options->anchor_count, trust->anchors,
                                       options->anchor_count};
  static const TC_bytes no_crl = {NULL, 0};
  size_t work = TRUST_WORK;
  if (TC_X509_store_array_source(&trust->array, &trust->source) != TC_TLV_OK ||
      TC_X509_crl_index_init(options->crl_count ? options->crls : &no_crl, options->crl_count,
                             &limits, &trust->parser, &work, trust->records,
                             EXAMPLE_PIV_INSPECT_CRLS, &trust->index) != TC_TLV_OK)
    return 0;
  memset(&trust->options, 0, sizeof trust->options);
  trust->options.at = options->at;
  trust->options.signatures = TC_X509_native_provider(&trust->native);
  trust->options.parsing = limits;
  trust->options.max_certificates = 8;
  trust->options.max_input = 8 * EXAMPLE_PIV_TRUST_CERTIFICATE_BYTES;
  trust->options.max_candidates = EXAMPLE_PIV_INSPECT_ANCHORS;
  trust->options.max_candidate_bytes =
      EXAMPLE_PIV_INSPECT_ANCHORS * EXAMPLE_PIV_TRUST_CERTIFICATE_BYTES;
  trust->options.revocation = options->revocation;
  const TC_validation_trust sources = {&trust->source, &trust->index};
  return TC_validation_context_init(&sources, &trust->options, &trust->workspace.credential,
                                    &trust->context) == TC_RESULT_OK;
}
