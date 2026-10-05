/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The unsigned TWIC CHUID validator (TWIC Part 2 v5 4.6.3): its bytes must
 * equal the copy that the authenticated Security Object hashes. */
#include <string.h>
#include <tiny_crypto/credential.h>

#if TC_ENABLE_TWIC && TC_ENABLE_CREDENTIAL
#include "internal.h"
#include "pki_budget_internal.h"
#include "pki_storage_internal.h"
#include "credential_session_internal.h"
#include "credential_status_internal.h"
#include "credential_policy_internal.h"
#include "twic_profile_internal.h"

static TC_TLV_result security_object_equals(const TC_PIV_security_report* security,
                                            uint16_t container, TC_bytes expected, size_t* work,
                                            int* matched)
{
  const TC_PIV_security_data* selected = NULL;
  for (size_t i = 0; i < security->count; ++i)
    if (security->objects[i].container == container)
      selected = &security->objects[i];
  if (!selected) {
    *matched = 0;
    return TC_TLV_OK;
  }
  if (selected->count && !selected->parts)
    return TC_TLV_ARGUMENT;
  size_t offset = 0;
  for (size_t i = 0; i < selected->count; ++i) {
    const TC_bytes part = selected->parts[i];
    if ((!part.data && part.length) || part.length > expected.length - offset) {
      *matched = 0;
      return TC_TLV_OK;
    }
    if (tc_pki_work_charge(work, part.length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    if (part.length && memcmp(part.data, expected.data + offset, part.length)) {
      *matched = 0;
      return TC_TLV_OK;
    }
    offset += part.length;
  }
  *matched = offset == expected.length;
  return TC_TLV_OK;
}

/* Validate borrowed inventory ranges before charging the caller's counter. */
static TC_TLV_result
unsigned_chuid_storage(const TC_TWIC_unsigned_CHUID_validation_request* request,
                       const TC_validation_context* context, size_t* work)
{
  const TC_PIV_security_report* security = request->security;
  /* The only write is the caller's work counter. */
  TC_bytes counter;
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, &counter, 1, *work);
  TC_PKI_PLAN_WRITE(&plan, work, 1);
  tc_pki_storage_plan_seal(&plan);
  const TC_bytes fields[] = {request->encoded, request->card->fascn, request->card->fascn_oid,
                             request->card->uuid_urn, security->signer};
  TC_PKI_PLAN_INPUT(&plan, request, 1);
  TC_PKI_PLAN_INPUT(&plan, request->card, 1);
  TC_PKI_PLAN_INPUT(&plan, security, 1);
  TC_PKI_PLAN_INPUT(&plan, context, 1);
  TC_PKI_PLAN_INPUT(&plan, context->options, 1);
  tc_pki_storage_plan_input_spans(&plan, fields, sizeof fields / sizeof *fields);
  TC_PKI_PLAN_INPUT(&plan, security->objects, security->count);
  for (size_t i = 0; plan.status == TC_TLV_OK && i < security->count; ++i) {
    const TC_PIV_security_data* object = &security->objects[i];
    TC_PKI_PLAN_INPUT(&plan, object->parts, object->count);
    tc_pki_storage_plan_input_spans(&plan, object->parts, object->count);
  }
  return tc_pki_storage_plan_finish(&plan, work);
}

TC_credential_status
TC_TWIC_unsigned_CHUID_validate(const TC_TWIC_unsigned_CHUID_validation_request* request,
                                const TC_validation_context* context, size_t* work)
{
  if (!request || !request->encoded.data || !request->encoded.length || !request->card ||
      !request->security || !tc_twic_card_profile(request->profile) || !context ||
      !context->options || !work || !request->security->objects || !request->security->count ||
      request->security->count > TC_LDS_MAX_GROUPS ||
      !tc_credential_result_current(request->security->profile, &request->security->at,
                                    request->profile, context))
    return TC_CREDENTIAL_ERROR;
  TC_TLV_result parsed = unsigned_chuid_storage(request, context, work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (request->encoded.length > context->options->parsing.max_input)
    return TC_CREDENTIAL_LIMIT;
  int matched;
  parsed = security_object_equals(request->security, TC_TWIC_UNSIGNED_CHUID_CONTAINER,
                                  request->encoded, work, &matched);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (!matched)
    return TC_CREDENTIAL_INVALID;
  TC_PIV_CHUID chuid;
  parsed = TC_PIV_CHUID_read(request->encoded, request->encoding, TC_CHUID_PROFILE_TWIC_UNSIGNED,
                             &chuid);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  int current;
  parsed = tc_credential_chuid_expiration_check(chuid.expiration, &context->options->at, &current);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (!current)
    return TC_CREDENTIAL_INVALID;
  parsed =
      TC_TWIC_card_identifiers_match(request->card, chuid.fascn, chuid.card_uuid, work, &matched);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  return matched ? TC_CREDENTIAL_VALID : TC_CREDENTIAL_INVALID;
}

#endif
