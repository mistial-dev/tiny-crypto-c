/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * PIV and TWIC credential validators: CHUID, biometric, security object,
 * unsigned TWIC CHUID and card verifiable certificate. Each validator checks
 * request storage, verifies the signed object, builds and validates the
 * signer path and maps the outcome to TC_credential_status. */
#include "internal.h"
#include "pki_budget_internal.h"
#include "pki_source_internal.h"
#include "validation_internal.h"
#include "cms_internal.h"
#include "credential_status_internal.h"
#include "credential_policy_internal.h"
#include "x509_time_internal.h"
#include <string.h>
#include <tiny_crypto/credential.h>
#include <tiny_crypto/piv_biometric.h>
#include <tiny_crypto/piv_cms.h>

#if TC_ENABLE_CREDENTIAL

/* Per-call state shared by the credential validators: path and revocation
 * policy from the context, the card profile, and the trust source guarded
 * against every write range. The guard and source refer to this struct, so it
 * stays in place for the whole call. */
enum { SESSION_WRITES = TC_VALIDATION_WRITES + 1 };
typedef struct {
  TC_CMS_path_options policy;
  TC_X509_path_options crl_policy;
  TC_CMS_revocation_policy revocation;
  int piv;
  TC_PIV_oid_profile oids;
  TC_bytes writes[SESSION_WRITES];
  tc_pki_source_guard guard;
  TC_X509_store_source source;
} credential_session;

/* Caller buffers checked by credential_session_bind. scratch is an optional
 * extra write range. objects adds each inventory part as an input. */
typedef struct {
  const TC_bytes* inputs;
  size_t input_count;
  void* out;
  size_t out_size;
  uint8_t* scratch;
  size_t scratch_size;
  const TC_PIV_security_data* objects;
  size_t object_count;
} credential_storage;

/* Resolve policies and the card profile. Returns 0 for an incomplete context,
 * an unknown profile or a purpose the profile does not accept. */
static int credential_session_open(credential_session* session,
                                   const TC_validation_context* context,
                                   TC_PIV_card_profile profile)
{
  return tc_validation_policies(context, &session->policy, &session->crl_policy,
                                &session->revocation) &&
         tc_credential_profile(profile, context->options, &session->piv, &session->oids);
}

/* Check every write range against the others and every input against the
 * writes, commit the preflight work, then guard the trust source. */
static TC_TLV_result credential_session_bind(credential_session* session,
                                             const TC_validation_context* context,
                                             const credential_storage* storage, size_t* work)
{
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, session->writes, SESSION_WRITES, *work);
  tc_validation_plan_writes(&plan, context, work, storage->out, storage->out_size);
  if (storage->scratch)
    tc_pki_storage_plan_write(&plan, storage->scratch, storage->scratch_size, 1);
  tc_pki_storage_plan_seal(&plan);
  tc_validation_plan_inputs(&plan, context, storage->inputs, storage->input_count);
  if (storage->objects)
    TC_PKI_PLAN_INPUT(&plan, storage->objects, storage->object_count);
  for (size_t i = 0; plan.status == TC_TLV_OK && i < storage->object_count; ++i) {
    TC_PKI_PLAN_INPUT(&plan, storage->objects[i].parts, storage->objects[i].count);
    tc_pki_storage_plan_input_spans(&plan, storage->objects[i].parts, storage->objects[i].count);
  }
  TC_TLV_result result = tc_pki_storage_plan_finish(&plan, work);
  if (result != TC_TLV_OK)
    return result;
  session->guard = (tc_pki_source_guard){context->trust.certificates, session->writes, plan.count};
  session->source = tc_pki_source_guard_bind(&session->guard);
  return TC_TLV_OK;
}

/* Charge the encoded object against the input limit and work. */
static TC_TLV_result credential_session_input(const credential_session* session, TC_bytes encoded,
                                              size_t* work)
{
  if (encoded.length > session->policy.path.parsing.max_input)
    return TC_TLV_LIMIT;
  return tc_pki_work_charge(work, encoded.length);
}

static const TC_X509_path_workspace* credential_storage_of(const TC_validation_context* context)
{
  return &context->workspace->path->validation;
}

static TC_TLV_frames credential_frames(const TC_validation_context* context)
{
  const TC_X509_path_workspace* storage = credential_storage_of(context);
  return (TC_TLV_frames){storage->frames, storage->frame_capacity};
}

/* Verify the CMS signature and the signer path with the prepared envelope. */
static TC_credential_status credential_session_verify(credential_session* session,
                                                      const TC_validation_context* context,
                                                      const TC_CMS_validation_request* cms,
                                                      const TC_PIV_CMS_object* object, size_t* work)
{
  const tc_cms_prepared_signed_data prepared = {&object->envelope, &object->signer};
  const tc_cms_validation_extras extras = {NULL, 0, &prepared};
  return tc_cms_credential_validate_internal(cms, &session->source, &session->policy,
                                             &session->revocation, context->workspace, work,
                                             &extras);
}

/* A dependent object binds to a result accepted under the same card profile
 * at the context's evaluation time. */
static int credential_result_current(TC_PIV_card_profile result_profile,
                                     const TC_X509_time* result_at, TC_PIV_card_profile profile,
                                     const TC_validation_context* context)
{
  int order;
  return result_profile == profile &&
         TC_X509_time_compare(&context->options->at, result_at, &order) == TC_TLV_OK && !order;
}

static int chuid_result_bound(const TC_PIV_CHUID_result* chuid, TC_PIV_card_profile profile,
                              const TC_validation_context* context)
{
  enum { FASCN_BYTES = 25, GUID_BYTES = 16 };
  return chuid && chuid->object.fascn.data && chuid->object.fascn.length == FASCN_BYTES &&
         chuid->object.card_uuid.data && chuid->object.card_uuid.length == GUID_BYTES &&
         chuid->signer.data && chuid->signer.length &&
         credential_result_current(chuid->profile, &chuid->at, profile, context);
}

/* SP 800-76-2 section 9.3: a biometric signed with the CHUID key omits the
 * certificate, so an embedded certificate must carry a different key. Returns
 * INVALID for the same RSA modulus and exponent or the same EC curve and x
 * coordinate with the same y parity. */
static TC_TLV_result biometric_signer_distinct(const TC_X509_public_key* embedded,
                                               const TC_X509_public_key* chuid, size_t* work)
{
  const TC_X509_public_key* keys[2] = {embedded, chuid};
  TC_bytes parts[2][2];
  uint8_t parity[2] = {0, 0};
  for (size_t i = 0; i < 2; ++i) {
    const TC_X509_public_key* key = keys[i];
    if (key->type == TC_KEY_RSA || key->type == TC_KEY_RSA_PSS) {
      parts[i][0] = key->modulus;
      parts[i][1] = key->exponent;
    } else if (key->type == TC_KEY_EC) {
      if (!key->bits)
        return TC_TLV_UNSUPPORTED;
      const TC_bytes point = key->key;
      parity[i] = (point.data[0] == 4 ? point.data[point.length - 1] : point.data[0]) & 1u;
      parts[i][0] = key->curve_oid;
      parts[i][1] = (TC_bytes){point.data + 1, (key->bits + 7u) / 8u};
    } else
      return TC_TLV_UNSUPPORTED;
  }
  if ((keys[0]->type == TC_KEY_EC) != (keys[1]->type == TC_KEY_EC) || parity[0] != parity[1])
    return TC_TLV_OK;
  for (size_t i = 0; i < 2; ++i) {
    if (parts[0][i].length != parts[1][i].length)
      return TC_TLV_OK;
    if (tc_pki_work_charge(work, parts[0][i].length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    if (memcmp(parts[0][i].data, parts[1][i].data, parts[0][i].length))
      return TC_TLV_OK;
  }
  return TC_TLV_INVALID;
}

TC_credential_status TC_PIV_CHUID_validate(const TC_PIV_CHUID_validation_request* request,
                                           const TC_validation_context* context, size_t* work,
                                           TC_PIV_CHUID_result* out)
{
  credential_session session;
  if (!request || !request->encoded.data || !request->encoded.length || !request->card ||
      !request->card_expiration || !context || !work || !out ||
      (request->twic_reader_policy != 0 && request->twic_reader_policy != 1) ||
      (request->profile != TC_PIV_CARD && request->twic_reader_policy) ||
      (request->profile == TC_PIV_CARD
           ? request->chuid_profile != TC_CHUID_PROFILE_PIV &&
                 request->chuid_profile != TC_CHUID_PROFILE_LEGACY_KEY_MAP
           : request->chuid_profile != TC_CHUID_PROFILE_TWIC_SIGNED) ||
      !credential_session_open(&session, context, request->profile))
    return TC_CREDENTIAL_ERROR;
  const int strict_piv = session.piv && !request->twic_reader_policy;
  const TC_PIV_oid_profile oids =
      request->twic_reader_policy ? TC_PIV_OIDS_TWIC_COMPATIBLE : session.oids;

  const TC_bytes inputs[] = {
      request->encoded,
      {(const uint8_t*)request, sizeof *request},
      {(const uint8_t*)request->card, sizeof *request->card},
      {(const uint8_t*)request->card_expiration, sizeof *request->card_expiration},
      request->card->fascn,
      request->card->uuid_urn,
      request->card->fascn_oid};
  const credential_storage storage = {
      inputs, sizeof inputs / sizeof *inputs, out, sizeof *out, NULL, 0, NULL, 0};
  TC_TLV_result parsed = credential_session_bind(&session, context, &storage, work);
  if (parsed == TC_TLV_OK)
    parsed = credential_session_input(&session, request->encoded, work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  const TC_TLV_limits* limits = &session.policy.path.parsing;

  TC_PIV_CHUID chuid;
  parsed = TC_PIV_CHUID_read(request->encoded, request->encoding, request->chuid_profile, &chuid);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);

  int current, matched;
  parsed =
      tc_credential_chuid_expiration_check(chuid.expiration, &session.policy.path.at, &current);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (!current)
    return TC_CREDENTIAL_INVALID;
  parsed = strict_piv ? TC_PIV_card_identifiers_match(request->card, chuid.fascn, chuid.card_uuid,
                                                      work, &matched)
                      : TC_TWIC_card_identifiers_match(request->card, chuid.fascn, chuid.card_uuid,
                                                       work, &matched);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (!matched)
    return TC_CREDENTIAL_INVALID;

  TC_PIV_CMS_object object;
  parsed = TC_PIV_CMS_read(chuid.signature, TC_PIV_CMS_CHUID, oids, session.policy.attributes,
                           limits, credential_frames(context), work, &object);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  parsed = TC_PIV_CMS_identifiers_match(&object, TC_PIV_CMS_CHUID, chuid.fascn, chuid.card_uuid,
                                        limits, credential_frames(context), work, &matched);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (!matched)
    return TC_CREDENTIAL_INVALID;
  TC_X509_certificate signer;
  parsed = tc_credential_signer_read(object.certificate, limits, credential_storage_of(context),
                                     work, &signer);
  if (parsed == TC_TLV_OK)
    parsed = tc_credential_signer_policy(
        &signer, session.piv, request->twic_reader_policy || !session.piv, request->card_expiration,
        &session.policy.path, credential_storage_of(context), work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);

  const TC_CMS_validation_request cms = {chuid.signature,      0, object.envelope.content_type,
                                         chuid.signed_content, 2, object.certificate};
  TC_credential_status status = credential_session_verify(&session, context, &cms, &object, work);
  if (status == TC_CREDENTIAL_VALID) {
    const TC_PIV_CHUID_result result = {chuid, object.certificate, context->options->at,
                                        request->profile};
    *out = result;
  }
  return status;
}

/* Check the CBEFF header against the request and parse the record under the
 * card's profile. The FASC-N comes from the accepted CHUID. */
static TC_credential_status
biometric_contents_check(const TC_PIV_biometric_validation_request* request,
                         const TC_validation_context* context, TC_PIV_CBEFF* cbeff,
                         TC_PIV_CBEFF_metadata* metadata)
{
  TC_TLV_result parsed = TC_PIV_CBEFF_read(request->encoded, cbeff);
  if (parsed == TC_TLV_OK)
    parsed = TC_PIV_CBEFF_metadata_read(request->encoded, metadata);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (TC_PIV_CBEFF_format_identify(metadata) != request->format)
    return TC_CREDENTIAL_INVALID;
  if (request->require_current) {
    int current;
    if (tc_x509_time_window(&context->options->at, 0, &metadata->valid_from, &metadata->valid_until,
                            &current) != TC_TLV_OK ||
        !current)
      return TC_CREDENTIAL_INVALID;
  }
  if (request->format == TC_PIV_CBEFF_FINGERPRINT_TEMPLATE) {
    TC_PIV_fingerprint_record fingerprint;
    parsed = TC_PIV_fingerprint_read(cbeff->record, &fingerprint);
  } else {
    TC_PIV_face_record face;
    const TC_PIV_face_profile face_profile =
        request->profile == TC_PIV_CARD ? TC_PIV_FACE_PROFILE_PIV : TC_PIV_FACE_PROFILE_TWIC;
    parsed = TC_PIV_face_read(cbeff->record, face_profile, &face);
  }
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  const TC_bytes fascn = request->chuid->object.fascn;
  if (cbeff->fascn.length != fascn.length || memcmp(cbeff->fascn.data, fascn.data, fascn.length))
    return TC_CREDENTIAL_INVALID;
  return TC_CREDENTIAL_VALID;
}

TC_credential_status TC_PIV_biometric_validate(const TC_PIV_biometric_validation_request* request,
                                               const TC_validation_context* context, size_t* work,
                                               TC_PIV_biometric_result* out)
{
  credential_session session;
  if (!request || !request->encoded.data || !request->encoded.length ||
      (request->signature_profile != TC_PIV_CMS_BIOMETRIC &&
       request->signature_profile != TC_PIV_CMS_BIOMETRIC_LEGACY) ||
      (request->format != TC_PIV_CBEFF_FINGERPRINT_TEMPLATE &&
       request->format != TC_PIV_CBEFF_FACE_IMAGE && request->format != TC_PIV_CBEFF_IRIS_IMAGE) ||
      !request->card_expiration || !work || !out ||
      !credential_session_open(&session, context, request->profile) ||
      !chuid_result_bound(request->chuid, request->profile, context))
    return TC_CREDENTIAL_ERROR;
  if (request->format == TC_PIV_CBEFF_IRIS_IMAGE)
    return TC_CREDENTIAL_UNSUPPORTED;
  const TC_PIV_CHUID_result* chuid = request->chuid;
  const TC_bytes inputs[] = {
      request->encoded,
      chuid->object.fascn,
      chuid->object.card_uuid,
      chuid->signer,
      {(const uint8_t*)request, sizeof *request},
      {(const uint8_t*)chuid, sizeof *chuid},
      {(const uint8_t*)request->card_expiration, sizeof *request->card_expiration}};
  const credential_storage storage = {
      inputs, sizeof inputs / sizeof *inputs, out, sizeof *out, NULL, 0, NULL, 0};
  TC_TLV_result parsed = credential_session_bind(&session, context, &storage, work);
  if (parsed == TC_TLV_OK)
    parsed = credential_session_input(&session, request->encoded, work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  const TC_TLV_limits* limits = &session.policy.path.parsing;
  const TC_X509_path_workspace* scratch = credential_storage_of(context);

  TC_PIV_CBEFF cbeff;
  TC_PIV_CBEFF_metadata metadata;
  TC_credential_status status = biometric_contents_check(request, context, &cbeff, &metadata);
  if (status != TC_CREDENTIAL_VALID)
    return status;
  TC_PIV_CMS_object object;
  int matched;
  parsed =
      TC_PIV_CMS_read(cbeff.signature, request->signature_profile, session.oids,
                      session.policy.attributes, limits, credential_frames(context), work, &object);
  if (parsed == TC_TLV_OK)
    parsed = TC_PIV_CMS_identifiers_match(&object, request->signature_profile, chuid->object.fascn,
                                          chuid->object.card_uuid, limits,
                                          credential_frames(context), work, &matched);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  if (!matched)
    return TC_CREDENTIAL_INVALID;

  /* Parse each certificate once. The views borrow certificate bytes, so the
   * CHUID signer view survives the second parse. */
  TC_X509_certificate chuid_signer, embedded;
  const TC_X509_certificate* signer = &chuid_signer;
  parsed = tc_credential_signer_read(chuid->signer, limits, scratch, work, &chuid_signer);
  if (parsed == TC_TLV_OK && object.certificate.length) {
    parsed = tc_credential_signer_read(object.certificate, limits, scratch, work, &embedded);
    if (parsed == TC_TLV_OK)
      parsed = biometric_signer_distinct(&embedded.public_key, &chuid_signer.public_key, work);
    signer = &embedded;
  }
  if (parsed == TC_TLV_OK)
    parsed =
        tc_credential_signer_policy(signer, session.piv, !session.piv, request->card_expiration,
                                    &session.policy.path, scratch, work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  const TC_CMS_validation_request cms = {cbeff.signature,       0, object.envelope.content_type,
                                         &cbeff.signed_content, 1, signer->encoded};
  status = credential_session_verify(&session, context, &cms, &object, work);
  if (status == TC_CREDENTIAL_VALID) {
    const TC_PIV_biometric_result result = {request->format,  metadata,
                                            cbeff.record,     signer->encoded,
                                            request->profile, context->options->at};
    *out = result;
  }
  return status;
}

/* Check each signed LDS digest against the supplied inventory. Every signed
 * group must be supplied exactly once. */
static TC_credential_status
security_inventory_check(const TC_PIV_security_validation_request* request,
                         const TC_PIV_security_object* container, const TC_LDS_security_object* lds,
                         const TC_validation_context* context, const TC_TLV_limits* limits,
                         size_t* work)
{
  if (container->groups != lds->groups)
    return TC_CREDENTIAL_INVALID;
  uint16_t checked = 0;
  for (size_t i = 0; i < request->count; ++i) {
    unsigned group;
    int matched;
    TC_TLV_result parsed =
        TC_PIV_security_group_find(container, request->objects[i].container, &group);
    if (parsed == TC_TLV_END)
      return TC_CREDENTIAL_INVALID;
    if (parsed != TC_TLV_OK)
      return tc_validation_status(parsed);
    const uint16_t bit = (uint16_t)(1u << (group - 1));
    if (checked & bit)
      return TC_CREDENTIAL_INVALID;
    parsed = TC_LDS_hash_check(lds, group, request->objects[i].parts, request->objects[i].count,
                               limits, credential_frames(context), work, &matched);
    if (parsed != TC_TLV_OK)
      return tc_validation_status(parsed);
    if (!matched)
      return TC_CREDENTIAL_INVALID;
    checked |= bit;
  }
  return checked == lds->groups ? TC_CREDENTIAL_VALID : TC_CREDENTIAL_INVALID;
}

TC_credential_status TC_PIV_security_validate(const TC_PIV_security_validation_request* request,
                                              const TC_validation_context* context,
                                              const TC_PIV_security_validation_workspace* workspace,
                                              size_t* work, TC_PIV_security_result* out)
{
  credential_session session;
  if (request && request->count > TC_LDS_MAX_GROUPS)
    return TC_CREDENTIAL_LIMIT;
  if (!request || !request->encoded.data || !request->encoded.length || !request->card_expiration ||
      !request->objects || !request->count || !workspace || !workspace->content ||
      !workspace->content_capacity || !work || !out ||
      (request->encoding != TC_PIV_SECURITY_CONTENTS &&
       request->encoding != TC_PIV_SECURITY_CONTAINER) ||
      !credential_session_open(&session, context, request->profile) ||
      !chuid_result_bound(request->chuid, request->profile, context))
    return TC_CREDENTIAL_ERROR;
  if (request->count < 2)
    return TC_CREDENTIAL_INVALID;
  for (size_t i = 0; i < request->count; ++i) {
    if (!request->objects[i].parts || !request->objects[i].count)
      return TC_CREDENTIAL_ERROR;
    for (size_t j = 0; j < i; ++j)
      if (request->objects[i].container == request->objects[j].container)
        return TC_CREDENTIAL_INVALID;
  }
  const TC_bytes signer_bytes = request->chuid->signer;
  const TC_bytes inputs[] = {
      request->encoded,
      signer_bytes,
      {(const uint8_t*)request, sizeof *request},
      {(const uint8_t*)request->chuid, sizeof *request->chuid},
      {(const uint8_t*)workspace, sizeof *workspace},
      {(const uint8_t*)request->card_expiration, sizeof *request->card_expiration}};
  /* The content decoder writes only after every signature and inventory
   * input has been checked for overlap with its buffer. */
  const credential_storage storage = {inputs,
                                      sizeof inputs / sizeof *inputs,
                                      out,
                                      sizeof *out,
                                      workspace->content,
                                      workspace->content_capacity,
                                      request->objects,
                                      request->count};
  TC_TLV_result parsed = credential_session_bind(&session, context, &storage, work);
  if (parsed == TC_TLV_OK)
    parsed = credential_session_input(&session, request->encoded, work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  const TC_TLV_limits* limits = &session.policy.path.parsing;
  const TC_X509_path_workspace* scratch = credential_storage_of(context);

  TC_PIV_security_object container;
  TC_PIV_CMS_object object;
  TC_X509_certificate signer;
  parsed = TC_PIV_security_read(request->encoded, request->encoding, &container);
  if (parsed == TC_TLV_OK)
    parsed =
        TC_PIV_CMS_read(container.cms, TC_PIV_CMS_SECURITY, session.oids, session.policy.attributes,
                        limits, credential_frames(context), work, &object);
  if (parsed == TC_TLV_OK)
    parsed = tc_credential_signer_read(signer_bytes, limits, scratch, work, &signer);
  if (parsed == TC_TLV_OK)
    parsed =
        tc_credential_signer_policy(&signer, session.piv, !session.piv, request->card_expiration,
                                    &session.policy.path, scratch, work);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  const TC_CMS_validation_request cms = {container.cms, 0, object.envelope.content_type,
                                         NULL,          0, signer_bytes};
  TC_credential_status status = credential_session_verify(&session, context, &cms, &object, work);
  if (status != TC_CREDENTIAL_VALID)
    return status;
  TC_LDS_security_object lds;
  parsed = TC_LDS_read_content(object.envelope.content, limits, credential_frames(context), work,
                               workspace->content, workspace->content_capacity, &lds);
  if (parsed != TC_TLV_OK)
    return tc_validation_status(parsed);
  status = security_inventory_check(request, &container, &lds, context, limits, work);
  if (status == TC_CREDENTIAL_VALID) {
    const TC_PIV_security_result accepted = {request->objects, request->count, signer_bytes,
                                             request->profile, context->options->at};
    *out = accepted;
  }
  return status;
}

static TC_TLV_result security_object_equals(const TC_PIV_security_result* security,
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
  const TC_PIV_security_result* security = request->security;
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
      !request->security ||
      (request->profile != TC_TWIC_LEGACY_CARD && request->profile != TC_TWIC_NEXGEN_CARD) ||
      !context || !context->options || !work || !request->security->objects ||
      !request->security->count || request->security->count > TC_LDS_MAX_GROUPS ||
      !credential_result_current(request->security->profile, &request->security->at,
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

#if TC_ENABLE_PIV_CVC
TC_credential_status TC_PIV_CVC_validate(const TC_PIV_CVC_validation_request* request,
                                         const TC_validation_context* context,
                                         TC_EC_workspace* point, size_t* work, TC_PIV_CVC* out)
{
  credential_session session;
  if (!request || !request->card.data || !request->card.length ||
      !request->signer_certificate.data || !request->signer_certificate.length || !point || !work ||
      !out || !credential_session_open(&session, context, request->profile))
    return TC_CREDENTIAL_ERROR;
  const TC_bytes inputs[] = {request->card,
                             request->intermediate,
                             request->expected_uuid,
                             request->signer_certificate,
                             {(const uint8_t*)request, sizeof *request}};
  const credential_storage storage = {
      inputs, sizeof inputs / sizeof *inputs, out, sizeof *out, NULL, 0, NULL, 0};
  TC_TLV_result checked = credential_session_bind(&session, context, &storage, work);
  TC_X509_certificate parsed_signer;
  if (checked == TC_TLV_OK)
    checked = tc_credential_signer_read(request->signer_certificate, &session.policy.path.parsing,
                                        credential_storage_of(context), work, &parsed_signer);
  if (checked == TC_TLV_OK)
    checked =
        tc_credential_signer_policy(&parsed_signer, session.piv, !session.piv, NULL,
                                    &session.policy.path, credential_storage_of(context), work);
  if (checked != TC_TLV_OK)
    return tc_validation_status(checked);
  const TC_X509_path_options* path = &session.policy.path;
  TC_validation_options options = *context->options;
  options.certificate =
      (TC_validation_certificate_policy){path->initial_policies, path->initial_policy_count,
                                         path->anchor_names,     path->purpose,
                                         path->key_usage,        path->flags};
  TC_validation_context signer_context = *context;
  signer_context.options = &options;
  signer_context.trust.certificates = &session.source;
  TC_X509_validation_result signer;
  TC_credential_status status =
      TC_X509_validate(request->signer_certificate, &signer_context, work, &signer);
  if (status != TC_CREDENTIAL_VALID)
    return status;
  const TC_PIV_CVC_chain_request chain = {request->card, request->intermediate,
                                          request->expected_uuid, request->curve,
                                          &signer.certificate};
  return tc_credential_signature_status(
      TC_PIV_CVC_chain_verify(&chain, &options.parsing, &options.signatures, point, work, out));
}
#endif
#endif
