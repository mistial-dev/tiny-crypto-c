/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/common.h>
#if TC_ENABLE_X509_OCSP
#include <tiny_crypto/x509_ocsp.h>
#include "pki_internal.h"
#include "hash_dispatch_internal.h"
#include "x509_time_internal.h"
#include "internal.h"
#include <string.h>

static const TC_TLV_limits unbounded = {SIZE_MAX, SIZE_MAX, SIZE_MAX, SIZE_MAX};
static const uint8_t basic_oid[] = {0x2b, 6, 1, 5, 5, 7, 0x30, 1, 1};
static const uint8_t nonce_oid[] = {0x2b, 6, 1, 5, 5, 7, 0x30, 1, 2};
static const uint8_t ocsp_signing_oid[] = {0x2b, 6, 1, 5, 5, 7, 3, 9};
static const uint8_t eku_oid[] = {0x55, 0x1d, TC_PKI_EXT_EXTENDED_KEY_USAGE};
static const uint8_t ku_oid[] = {0x55, 0x1d, TC_PKI_EXT_KEY_USAGE};

typedef struct {
  TC_bytes tbs, signature, responder, embedded, nonce;
  TC_DER_algorithm algorithm;
  TC_OCSP_result result;
  int responder_by_key, matched, nonce_present;
} ocsp_response;

static TC_TLV_result sequence(TC_bytes encoded, TC_TLV_reader* reader)
{
  TC_bytes contents;
  if (TC_DER_sequence(encoded.data, encoded.length, &contents) != TC_TLV_OK)
    return TC_TLV_INVALID;
  return TC_TLV_reader_init(reader, contents.data, contents.length, TC_TLV_DER, &unbounded);
}

static TC_TLV_result contents_reader(TC_bytes contents, TC_TLV_reader* reader)
{
  return TC_TLV_reader_init(reader, contents.data, contents.length, TC_TLV_DER, &unbounded);
}

static TC_TLV_result time_value(const TC_TLV_element* element, TC_X509_time* out)
{
  return tc_pki_tag(element, 0x18) ? tc_x509_time_value(element, out) : TC_TLV_INVALID;
}

static TC_hash_algorithm hash_algorithm(TC_bytes oid)
{
  const TC_hash_algorithm supported[] = {TC_HASH_SHA1, TC_HASH_SHA256};
  for (size_t i = 0; i < sizeof supported / sizeof *supported; ++i) {
    tc_hash_info info;
    if (tc_hash_info_get(supported[i], &info) && tc_pki_equal(oid, info.oid))
      return supported[i];
  }
  return TC_HASH_UNKNOWN;
}

static TC_TLV_result digest(TC_hash_algorithm algorithm, TC_bytes bytes, uint8_t out[64],
                            size_t* work)
{
  tc_hash_info info;
  TC_hash_context context;
  if (!tc_hash_info_get(algorithm, &info) || !tc_hash_available(algorithm))
    return TC_TLV_UNSUPPORTED;
  if (bytes.length > *work)
    return TC_TLV_LIMIT;
  *work -= bytes.length;
  return tc_hash_digest_parts(algorithm, &bytes, 1, out, &context) == TC_OK ? TC_TLV_OK
                                                                            : TC_TLV_ARGUMENT;
}

static TC_TLV_result cert_id_matches(TC_bytes encoded, const TC_X509_certificate* certificate,
                                     const TC_X509_trust_anchor* issuer, size_t* work, int* matched)
{
  TC_TLV_reader reader;
  TC_TLV_element field;
  TC_DER_algorithm algorithm;
  TC_bytes name_hash, key_hash, serial;
  TC_hash_algorithm hash;
  tc_hash_info info;
  uint8_t computed[64];
  int negative;
  TC_TLV_result status = sequence(encoded, &reader);
  if (status != TC_TLV_OK || tc_pki_field(&reader, 0x30, &field) != TC_TLV_OK ||
      TC_DER_algorithm_identifier(field.encoded.data, field.encoded.length, &algorithm) !=
          TC_TLV_OK)
    return TC_TLV_INVALID;
  hash = hash_algorithm(algorithm.oid);
  if (hash == TC_HASH_UNKNOWN || !tc_hash_available(hash))
    return TC_TLV_UNSUPPORTED;
  if (algorithm.parameters.length &&
      TC_DER_null(algorithm.parameters.data, algorithm.parameters.length) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (tc_pki_field(&reader, 4, &field) != TC_TLV_OK)
    return TC_TLV_INVALID;
  name_hash = field.value;
  if (tc_pki_field(&reader, 4, &field) != TC_TLV_OK)
    return TC_TLV_INVALID;
  key_hash = field.value;
  if (tc_pki_field(&reader, 2, &field) != TC_TLV_OK ||
      TC_DER_integer(field.encoded.data, field.encoded.length, &serial, &negative) != TC_TLV_OK ||
      negative || !tc_pki_end(&reader) || !tc_hash_info_get(hash, &info) ||
      name_hash.length != info.digest_length || key_hash.length != info.digest_length)
    return TC_TLV_INVALID;
  *matched = 0;
  if (!tc_pki_equal(serial, certificate->serial))
    return TC_TLV_OK;
  status = digest(hash, issuer->name, computed, work);
  if (status != TC_TLV_OK)
    return status;
  if (memcmp(name_hash.data, computed, info.digest_length))
    return TC_TLV_OK;
  status = digest(hash, issuer->public_key.key, computed, work);
  if (status == TC_TLV_OK)
    *matched = !memcmp(key_hash.data, computed, info.digest_length);
  return status;
}

static TC_TLV_result extensions(TC_bytes wrapper, TC_bytes* nonce, int* nonce_present,
                                int allow_nonce, size_t max_extensions)
{
  TC_TLV_reader outer, list;
  TC_TLV_element element;
  TC_X509_extension extension;
  TC_TLV_result status = contents_reader(wrapper, &outer);
  if (status != TC_TLV_OK || tc_pki_field(&outer, 0x30, &element) != TC_TLV_OK ||
      !tc_pki_end(&outer) || contents_reader(element.value, &list) != TC_TLV_OK)
    return TC_TLV_INVALID;
  size_t count = 0;
  while ((status = TC_X509_extension_next(&list, &extension)) == TC_TLV_OK) {
    if (++count > max_extensions)
      return TC_TLV_LIMIT;
    if (extension.oid.length == sizeof nonce_oid &&
        !memcmp(extension.oid.data, nonce_oid, sizeof nonce_oid)) {
      if (!allow_nonce || *nonce_present || extension.critical)
        return TC_TLV_INVALID;
      TC_TLV_element value;
      if (TC_TLV_read(extension.value.data, extension.value.length, TC_TLV_DER, &unbounded,
                      &value) != TC_TLV_OK ||
          !tc_pki_tag(&value, 4) || value.encoded.length != extension.value.length ||
          !value.value.length || value.value.length > 128)
        return TC_TLV_INVALID;
      *nonce = value.value;
      *nonce_present = 1;
    } else if (extension.critical)
      return TC_TLV_UNSUPPORTED;
  }
  return status == TC_TLV_END ? TC_TLV_OK : status;
}

static TC_TLV_result single_response(TC_bytes encoded, const TC_X509_certificate* certificate,
                                     const TC_OCSP_verify_request* request,
                                     const TC_OCSP_workspace* workspace, size_t* work,
                                     ocsp_response* parsed)
{
  TC_TLV_reader reader;
  TC_TLV_element field;
  TC_OCSP_result result = {0};
  int matched, no_nonce = 0;
  TC_TLV_result status = sequence(encoded, &reader);
  if (status != TC_TLV_OK || tc_pki_field(&reader, 0x30, &field) != TC_TLV_OK)
    return TC_TLV_INVALID;
  status = cert_id_matches(field.encoded, certificate, request->issuer, work, &matched);
  if (status != TC_TLV_OK)
    return status;
  if (TC_TLV_next(&reader, &field) != TC_TLV_OK || field.header.tag_length != 1)
    return TC_TLV_INVALID;
  switch (field.header.tag[0]) {
  case 0x80:
    if (field.value.length)
      return TC_TLV_INVALID;
    result.status = TC_OCSP_GOOD;
    break;
  case 0x82:
    if (field.value.length)
      return TC_TLV_INVALID;
    result.status = TC_OCSP_UNKNOWN;
    break;
  case 0xa1: {
    TC_TLV_reader revoked;
    TC_TLV_element date;
    if (contents_reader(field.value, &revoked) != TC_TLV_OK ||
        tc_pki_field(&revoked, 0x18, &date) != TC_TLV_OK ||
        time_value(&date, &result.revocation_time) != TC_TLV_OK)
      return TC_TLV_INVALID;
    if (!tc_pki_end(&revoked)) {
      TC_TLV_reader reason;
      if (tc_pki_field(&revoked, 0xa0, &date) != TC_TLV_OK ||
          contents_reader(date.value, &reason) != TC_TLV_OK ||
          tc_pki_field(&reason, 0x0a, &date) != TC_TLV_OK || !tc_pki_end(&reason) ||
          date.value.length != 1 || date.value.data[0] > 10 || date.value.data[0] == 7)
        return TC_TLV_INVALID;
    }
    if (!tc_pki_end(&revoked))
      return TC_TLV_INVALID;
    result.has_revocation_time = 1;
    result.status = TC_OCSP_REVOKED;
    break;
  }
  default:
    return TC_TLV_UNSUPPORTED;
  }
  if (tc_pki_field(&reader, 0x18, &field) != TC_TLV_OK ||
      time_value(&field, &result.this_update) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (!tc_pki_end(&reader)) {
    TC_TLV_reader date;
    TC_TLV_reader probe = reader;
    if (TC_TLV_next(&probe, &field) != TC_TLV_OK)
      return TC_TLV_INVALID;
    if (tc_pki_tag(&field, 0xa0)) {
      reader = probe;
      if (contents_reader(field.value, &date) != TC_TLV_OK ||
          tc_pki_field(&date, 0x18, &field) != TC_TLV_OK || !tc_pki_end(&date) ||
          time_value(&field, &result.next_update) != TC_TLV_OK)
        return TC_TLV_INVALID;
      result.has_next_update = 1;
    }
  }
  if (!tc_pki_end(&reader)) {
    if (tc_pki_field(&reader, 0xa1, &field) != TC_TLV_OK)
      return TC_TLV_INVALID;
    TC_bytes ignored = {0};
    status = extensions(field.value, &ignored, &no_nonce, 0, workspace->extension_capacity);
    if (status != TC_TLV_OK)
      return status;
  }
  if (!tc_pki_end(&reader))
    return TC_TLV_INVALID;
  if (matched) {
    if (parsed->matched)
      return TC_TLV_INVALID;
    parsed->matched = 1;
    parsed->result.status = result.status;
    parsed->result.this_update = result.this_update;
    parsed->result.next_update = result.next_update;
    parsed->result.revocation_time = result.revocation_time;
    parsed->result.has_next_update = result.has_next_update;
    parsed->result.has_revocation_time = result.has_revocation_time;
  }
  return TC_TLV_OK;
}

static TC_TLV_result response_data(TC_bytes encoded, const TC_X509_certificate* certificate,
                                   const TC_OCSP_verify_request* request,
                                   const TC_OCSP_workspace* workspace, size_t* work,
                                   ocsp_response* parsed)
{
  TC_TLV_reader reader, responses;
  TC_TLV_element field;
  TC_TLV_result status = sequence(encoded, &reader);
  if (status != TC_TLV_OK)
    return status;
  TC_TLV_reader probe = reader;
  if (TC_TLV_next(&probe, &field) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (tc_pki_tag(&field, 0xa0)) {
    TC_TLV_reader version;
    if (contents_reader(field.value, &version) != TC_TLV_OK ||
        tc_pki_field(&version, 2, &field) != TC_TLV_OK || !tc_pki_end(&version) ||
        field.value.length != 1 || field.value.data[0] != 0)
      return TC_TLV_UNSUPPORTED;
    if (TC_TLV_next(&probe, &field) != TC_TLV_OK)
      return TC_TLV_INVALID;
  }
  reader = probe;
  if (field.header.tag_length != 1)
    return TC_TLV_INVALID;
  if (tc_pki_tag(&field, 0xa1)) {
    TC_TLV_reader name;
    TC_TLV_element value;
    if (contents_reader(field.value, &name) != TC_TLV_OK ||
        tc_pki_field(&name, 0x30, &value) != TC_TLV_OK || !tc_pki_end(&name))
      return TC_TLV_INVALID;
    parsed->responder = value.encoded;
    parsed->responder_by_key = 0;
  } else if (tc_pki_tag(&field, 0xa2)) {
    TC_TLV_reader key;
    TC_TLV_element value;
    if (contents_reader(field.value, &key) != TC_TLV_OK ||
        tc_pki_field(&key, 4, &value) != TC_TLV_OK || !tc_pki_end(&key) || value.value.length != 20)
      return TC_TLV_INVALID;
    parsed->responder = value.value;
    parsed->responder_by_key = 1;
  } else
    return TC_TLV_INVALID;
  if (tc_pki_field(&reader, 0x18, &field) != TC_TLV_OK ||
      time_value(&field, &parsed->result.produced_at) != TC_TLV_OK ||
      tc_pki_field(&reader, 0x30, &field) != TC_TLV_OK ||
      contents_reader(field.value, &responses) != TC_TLV_OK)
    return TC_TLV_INVALID;
  size_t count = 0;
  while ((status = TC_TLV_next(&responses, &field)) == TC_TLV_OK) {
    if (++count > request->max_responses)
      return TC_TLV_LIMIT;
    if (!tc_pki_tag(&field, 0x30))
      return TC_TLV_INVALID;
    status = single_response(field.encoded, certificate, request, workspace, work, parsed);
    if (status != TC_TLV_OK)
      return status;
  }
  if (status != TC_TLV_END || !count || !parsed->matched)
    return TC_TLV_INVALID;
  if (!tc_pki_end(&reader)) {
    if (tc_pki_field(&reader, 0xa1, &field) != TC_TLV_OK)
      return TC_TLV_INVALID;
    status = extensions(field.value, &parsed->nonce, &parsed->nonce_present, 1,
                        workspace->extension_capacity);
    if (status != TC_TLV_OK)
      return status;
  }
  return tc_pki_end(&reader) ? TC_TLV_OK : TC_TLV_INVALID;
}

static TC_TLV_result basic_response(TC_bytes encoded, const TC_X509_certificate* certificate,
                                    const TC_OCSP_verify_request* request,
                                    const TC_OCSP_workspace* workspace, size_t* work,
                                    ocsp_response* parsed)
{
  TC_TLV_reader reader;
  TC_TLV_element field;
  unsigned unused;
  TC_TLV_result status = sequence(encoded, &reader);
  if (status != TC_TLV_OK || tc_pki_field(&reader, 0x30, &field) != TC_TLV_OK)
    return TC_TLV_INVALID;
  parsed->tbs = field.encoded;
  status = response_data(field.encoded, certificate, request, workspace, work, parsed);
  if (status != TC_TLV_OK)
    return status;
  if (tc_pki_field(&reader, 0x30, &field) != TC_TLV_OK ||
      TC_DER_algorithm_identifier(field.encoded.data, field.encoded.length, &parsed->algorithm) !=
          TC_TLV_OK ||
      tc_pki_field(&reader, 3, &field) != TC_TLV_OK ||
      TC_DER_bit_string(field.encoded.data, field.encoded.length, &parsed->signature, &unused) !=
          TC_TLV_OK ||
      unused || !parsed->signature.length)
    return TC_TLV_INVALID;
  if (!tc_pki_end(&reader)) {
    TC_TLV_reader embedded;
    if (tc_pki_field(&reader, 0xa0, &field) != TC_TLV_OK ||
        contents_reader(field.value, &embedded) != TC_TLV_OK ||
        tc_pki_field(&embedded, 0x30, &field) != TC_TLV_OK || !tc_pki_end(&embedded))
      return TC_TLV_INVALID;
    parsed->embedded = field.value;
  }
  return tc_pki_end(&reader) ? TC_TLV_OK : TC_TLV_INVALID;
}

static TC_TLV_result parse_response(const TC_OCSP_verify_request* request,
                                    const TC_X509_certificate* certificate,
                                    const TC_OCSP_workspace* workspace, size_t* work,
                                    ocsp_response* parsed)
{
  TC_TLV_reader reader, bytes;
  TC_TLV_element field;
  TC_bytes oid;
  TC_TLV_result status = sequence(request->response, &reader);
  if (status != TC_TLV_OK || tc_pki_field(&reader, 0x0a, &field) != TC_TLV_OK ||
      field.value.length != 1)
    return TC_TLV_INVALID;
  if (field.value.data[0] != 0) {
    if (!tc_pki_end(&reader))
      return TC_TLV_INVALID;
    if (field.value.data[0] == 2 || field.value.data[0] == 3 || field.value.data[0] == 6) {
      parsed->result.status = TC_OCSP_UNAVAILABLE;
      return TC_TLV_OK;
    }
    return field.value.data[0] == 5 ? TC_TLV_UNSUPPORTED : TC_TLV_INVALID;
  }
  if (tc_pki_field(&reader, 0xa0, &field) != TC_TLV_OK || !tc_pki_end(&reader) ||
      contents_reader(field.value, &reader) != TC_TLV_OK ||
      tc_pki_field(&reader, 0x30, &field) != TC_TLV_OK || !tc_pki_end(&reader) ||
      contents_reader(field.value, &bytes) != TC_TLV_OK ||
      tc_pki_field(&bytes, 6, &field) != TC_TLV_OK ||
      TC_DER_oid(field.encoded.data, field.encoded.length, &oid) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (oid.length != sizeof basic_oid || memcmp(oid.data, basic_oid, sizeof basic_oid))
    return TC_TLV_UNSUPPORTED;
  if (tc_pki_field(&bytes, 4, &field) != TC_TLV_OK || !tc_pki_end(&bytes))
    return TC_TLV_INVALID;
  return basic_response(field.value, certificate, request, workspace, work, parsed);
}

static TC_TLV_result time_check(const TC_OCSP_verify_request* request, const TC_OCSP_result* result)
{
  int64_t now, produced, updated, next_time;
  if (TC_X509_time_to_unix(&request->at, &now) != TC_TLV_OK ||
      TC_X509_time_to_unix(&result->produced_at, &produced) != TC_TLV_OK ||
      TC_X509_time_to_unix(&result->this_update, &updated) != TC_TLV_OK ||
      request->clock_skew_seconds > INT64_MAX || request->max_age_seconds > INT64_MAX)
    return TC_TLV_ARGUMENT;
  const int64_t skew = (int64_t)request->clock_skew_seconds;
  const int64_t age = (int64_t)request->max_age_seconds;
  if (now > INT64_MAX - skew || now < INT64_MIN + skew)
    return TC_TLV_LIMIT;
  if (produced > now + skew || updated > now + skew ||
      (now - skew >= updated && (uint64_t)(now - skew) - (uint64_t)updated > (uint64_t)age))
    return TC_TLV_INVALID;
  if (result->has_next_update) {
    if (TC_X509_time_to_unix(&result->next_update, &next_time) != TC_TLV_OK ||
        next_time < updated || next_time < now - skew)
      return TC_TLV_INVALID;
  }
  return TC_TLV_OK;
}

static TC_TLV_result name_matches(TC_bytes left, TC_bytes right,
                                  const TC_OCSP_verify_request* request,
                                  const TC_OCSP_workspace* workspace, size_t* work, int* matched)
{
  return TC_X509_name_equal(left, right, request->parsing, &workspace->names, work, matched);
}

static TC_TLV_result responder_matches(const ocsp_response* response, TC_bytes name, TC_bytes key,
                                       const TC_OCSP_verify_request* request,
                                       const TC_OCSP_workspace* workspace, size_t* work,
                                       int* matched)
{
  if (!response->responder_by_key)
    return name_matches(response->responder, name, request, workspace, work, matched);
  uint8_t computed[64];
  TC_TLV_result status = digest(TC_HASH_SHA1, key, computed, work);
  if (status == TC_TLV_OK)
    *matched = !memcmp(response->responder.data, computed, 20);
  return status;
}

static TC_TLV_result delegated_usage(const TC_X509_certificate* signer,
                                     const TC_OCSP_workspace* workspace, int* permitted)
{
  TC_TLV_reader outer, extensions_reader;
  TC_TLV_element element;
  TC_X509_extension extension;
  TC_TLV_result status;
  int has_eku = 0, has_usage = 0, eku = 0, usage = 0;
  *permitted = 0;
  if (!signer->extensions.data || contents_reader(signer->extensions, &outer) != TC_TLV_OK ||
      tc_pki_field(&outer, 0x30, &element) != TC_TLV_OK || !tc_pki_end(&outer) ||
      contents_reader(element.value, &extensions_reader) != TC_TLV_OK)
    return TC_TLV_INVALID;
  while ((status = TC_X509_extension_next(&extensions_reader, &extension)) == TC_TLV_OK) {
    if (extension.oid.length == sizeof eku_oid &&
        !memcmp(extension.oid.data, eku_oid, sizeof eku_oid)) {
      size_t count;
      if (has_eku || TC_X509_extended_key_usage_read(
                         extension.value.data, extension.value.length, workspace->extension_oids,
                         workspace->extension_capacity, &count) != TC_TLV_OK)
        return TC_TLV_INVALID;
      has_eku = 1;
      for (size_t i = 0; i < count; ++i)
        if (workspace->extension_oids[i].length == sizeof ocsp_signing_oid &&
            !memcmp(workspace->extension_oids[i].data, ocsp_signing_oid, sizeof ocsp_signing_oid))
          eku = 1;
    } else if (extension.oid.length == sizeof ku_oid &&
               !memcmp(extension.oid.data, ku_oid, sizeof ku_oid)) {
      uint16_t bits;
      if (has_usage ||
          TC_X509_key_usage_read(extension.value.data, extension.value.length, &bits) != TC_TLV_OK)
        return TC_TLV_INVALID;
      has_usage = 1;
      usage = (bits & TC_KEY_USAGE_DIGITAL_SIGNATURE) != 0;
    } else if (extension.critical)
      return TC_TLV_UNSUPPORTED;
  }
  if (status != TC_TLV_END)
    return status;
  *permitted = has_eku && eku && (!has_usage || usage);
  return TC_TLV_OK;
}

static TC_TLV_result verify_signature(const ocsp_response* response,
                                      const TC_X509_public_key* signer,
                                      const TC_OCSP_verify_request* request, size_t* work,
                                      int* valid)
{
  const TC_bytes message = response->tbs;
  TC_X509_signature_result status = TC_X509_signature_verify_message(
      &message, 1, &response->algorithm, response->signature, signer, request->signatures, work);
  if (status == TC_X509_SIGNATURE_LIMIT)
    return TC_TLV_LIMIT;
  if (status == TC_X509_SIGNATURE_UNSUPPORTED)
    return TC_TLV_UNSUPPORTED;
  if (status == TC_X509_SIGNATURE_ERROR)
    return TC_TLV_ARGUMENT;
  *valid = status == TC_X509_SIGNATURE_VALID;
  return TC_TLV_OK;
}

static TC_TLV_result try_delegate(TC_bytes encoded, const ocsp_response* response,
                                  const TC_OCSP_verify_request* request,
                                  const TC_OCSP_workspace* workspace, size_t* work, int* valid)
{
  TC_X509_workspace scratch = {workspace->frames, workspace->frame_capacity,
                               workspace->extension_oids, workspace->extension_capacity};
  TC_X509_certificate signer;
  TC_TLV_result status =
      TC_X509_read(encoded.data, encoded.length, request->parsing, &scratch, &signer);
  if (status != TC_TLV_OK)
    return status;
  int matches;
  status = responder_matches(response, signer.subject, signer.public_key.key, request, workspace,
                             work, &matches);
  if (status != TC_TLV_OK || !matches)
    return status;
  status = name_matches(signer.issuer, request->issuer->name, request, workspace, work, &matches);
  if (status != TC_TLV_OK || !matches)
    return status;
  int current, permitted;
  status = TC_X509_valid_at(&signer, &request->at, &current);
  if (status != TC_TLV_OK || !current)
    return status;
  status = delegated_usage(&signer, workspace, &permitted);
  if (status != TC_TLV_OK || !permitted)
    return status;
  TC_X509_signature_result certificate_signature =
      TC_X509_signature_verify(&signer, &request->issuer->public_key, request->signatures, work);
  if (certificate_signature == TC_X509_SIGNATURE_LIMIT)
    return TC_TLV_LIMIT;
  if (certificate_signature == TC_X509_SIGNATURE_UNSUPPORTED)
    return TC_TLV_UNSUPPORTED;
  if (certificate_signature != TC_X509_SIGNATURE_VALID)
    return TC_TLV_OK;
  return verify_signature(response, &signer.public_key, request, work, valid);
}

static TC_TLV_result authorize_response(const ocsp_response* response,
                                        const TC_OCSP_verify_request* request,
                                        const TC_OCSP_workspace* workspace, size_t* work)
{
  int matches, valid = 0;
  TC_TLV_result status =
      responder_matches(response, request->issuer->name, request->issuer->public_key.key, request,
                        workspace, work, &matches);
  if (status != TC_TLV_OK)
    return status;
  if (matches) {
    status = verify_signature(response, &request->issuer->public_key, request, work, &valid);
    if (status != TC_TLV_OK || valid)
      return status;
  }
  if (response->embedded.data) {
    TC_TLV_reader embedded;
    TC_TLV_element element;
    status = contents_reader(response->embedded, &embedded);
    if (status != TC_TLV_OK)
      return status;
    size_t count = 0;
    while ((status = TC_TLV_next(&embedded, &element)) == TC_TLV_OK) {
      if (++count > request->max_certificates)
        return TC_TLV_LIMIT;
      if (!tc_pki_tag(&element, 0x30))
        return TC_TLV_INVALID;
      status = try_delegate(element.encoded, response, request, workspace, work, &valid);
      if (status == TC_TLV_LIMIT)
        return status;
      if (valid)
        return TC_TLV_OK;
    }
    if (status != TC_TLV_END)
      return status;
  }
  if (request->certificates) {
    if (request->certificates->candidate_count > request->max_certificates)
      return TC_TLV_LIMIT;
    for (size_t i = 0; i < request->certificates->candidate_count; ++i) {
      TC_bytes candidate;
      status =
          request->certificates->candidate(request->certificates->context, i, work, &candidate);
      if (status != TC_TLV_OK)
        return status;
      status = try_delegate(candidate, response, request, workspace, work, &valid);
      if (status == TC_TLV_LIMIT)
        return status;
      if (valid)
        return TC_TLV_OK;
    }
  }
  return TC_TLV_INVALID;
}

TC_TLV_result TC_OCSP_response_verify(const TC_OCSP_verify_request* request,
                                      const TC_OCSP_workspace* workspace, size_t* work,
                                      TC_OCSP_result* out)
{
  if (!request || !workspace || !work || !out || !request->response.data ||
      !request->certificate.data || !request->issuer || !request->parsing || !request->signatures ||
      !workspace->frames || !workspace->extension_oids || !request->max_responses ||
      !request->max_certificates ||
      (request->expected_nonce.length &&
       (!request->expected_nonce.data || request->expected_nonce.length < 32 ||
        request->expected_nonce.length > 128)))
    return TC_TLV_ARGUMENT;
  if (request->response.length > request->max_response_bytes)
    return TC_TLV_LIMIT;
  if (request->response.length > *work)
    return TC_TLV_LIMIT;
  *work -= request->response.length;
  TC_TLV_result status =
      TC_TLV_walk(request->response.data, request->response.length, TC_TLV_DER, request->parsing,
                  (TC_TLV_frames){workspace->frames, workspace->frame_capacity}, NULL, NULL);
  if (status != TC_TLV_OK)
    return status;
  TC_X509_workspace scratch = {workspace->frames, workspace->frame_capacity,
                               workspace->extension_oids, workspace->extension_capacity};
  TC_X509_certificate certificate;
  status = TC_X509_read(request->certificate.data, request->certificate.length, request->parsing,
                        &scratch, &certificate);
  if (status != TC_TLV_OK)
    return status;
  int matches;
  status =
      name_matches(certificate.issuer, request->issuer->name, request, workspace, work, &matches);
  if (status != TC_TLV_OK || !matches)
    return status == TC_TLV_OK ? TC_TLV_INVALID : status;
  ocsp_response parsed = {0};
  status = parse_response(request, &certificate, workspace, work, &parsed);
  if (status != TC_TLV_OK)
    return status;
  if (parsed.result.status == TC_OCSP_UNAVAILABLE) {
    *out = parsed.result;
    return TC_TLV_OK;
  }
  if (request->expected_nonce.length &&
      (!parsed.nonce_present || !tc_pki_equal(request->expected_nonce, parsed.nonce)))
    return TC_TLV_INVALID;
  status = time_check(request, &parsed.result);
  if (status != TC_TLV_OK)
    return status;
  status = authorize_response(&parsed, request, workspace, work);
  if (status == TC_TLV_OK)
    *out = parsed.result;
  return status;
}

static size_t der_size(size_t content)
{
  size_t length_octets = 1;
  if (content >= 128) {
    size_t value = content;
    length_octets = 1;
    do {
      ++length_octets;
      value >>= 8;
    } while (value);
  }
  return content <= SIZE_MAX - 1 - length_octets ? 1 + length_octets + content : 0;
}

static uint8_t* der_header(uint8_t* out, uint8_t tag, size_t content)
{
  *out++ = tag;
  if (content < 128) {
    *out++ = (uint8_t)content;
    return out;
  }
  size_t octets = 0, value = content;
  do {
    ++octets;
    value >>= 8;
  } while (value);
  *out++ = (uint8_t)(0x80 | octets);
  for (size_t i = octets; i; --i)
    *out++ = (uint8_t)(content >> (8 * (i - 1)));
  return out;
}

static uint8_t* der_bytes(uint8_t* out, uint8_t tag, TC_bytes bytes)
{
  out = der_header(out, tag, bytes.length);
  memcpy(out, bytes.data, bytes.length);
  return out + bytes.length;
}

TC_TLV_result TC_OCSP_request_encode(TC_bytes certificate, const TC_X509_trust_anchor* issuer,
                                     TC_hash_algorithm hash, TC_bytes nonce,
                                     const TC_TLV_limits* parsing,
                                     const TC_OCSP_workspace* workspace, size_t* work,
                                     TC_buffer encoded, size_t* length)
{
  tc_hash_info info;
  if (!certificate.data || !issuer || !issuer->name.data || !issuer->public_key.key.data ||
      !parsing || !workspace || !workspace->frames || !workspace->extension_oids || !work ||
      !length || (encoded.capacity && !encoded.data) ||
      (nonce.length && (!nonce.data || nonce.length < 32 || nonce.length > 128)))
    return TC_TLV_ARGUMENT;
  if (hash != TC_HASH_SHA1 && hash != TC_HASH_SHA256)
    return TC_TLV_UNSUPPORTED;
  if (!tc_hash_info_get(hash, &info) || !tc_hash_available(hash))
    return TC_TLV_UNSUPPORTED;
  if (!tc_internal_ranges_disjoint(encoded.data, encoded.capacity, certificate.data,
                                   certificate.length) ||
      !tc_internal_ranges_disjoint(encoded.data, encoded.capacity, issuer->name.data,
                                   issuer->name.length) ||
      !tc_internal_ranges_disjoint(encoded.data, encoded.capacity, issuer->public_key.key.data,
                                   issuer->public_key.key.length) ||
      !tc_internal_ranges_disjoint(encoded.data, encoded.capacity, nonce.data, nonce.length) ||
      !tc_internal_ranges_disjoint(encoded.data, encoded.capacity, length, sizeof *length) ||
      !tc_internal_ranges_disjoint(encoded.data, encoded.capacity, work, sizeof *work))
    return TC_TLV_ARGUMENT;
  TC_X509_workspace parser = {workspace->frames, workspace->frame_capacity,
                              workspace->extension_oids, workspace->extension_capacity};
  TC_X509_certificate target;
  TC_TLV_result status =
      TC_X509_read(certificate.data, certificate.length, parsing, &parser, &target);
  if (status != TC_TLV_OK)
    return status;
  int matched;
  status =
      TC_X509_name_equal(target.issuer, issuer->name, parsing, &workspace->names, work, &matched);
  if (status != TC_TLV_OK || !matched)
    return status == TC_TLV_OK ? TC_TLV_INVALID : status;
  if (target.serial.length > SIZE_MAX - 512)
    return TC_TLV_LIMIT;

  uint8_t name_hash[64], key_hash[64];
  if (info.digest_length > sizeof name_hash)
    return TC_TLV_UNSUPPORTED;
  status = digest(hash, issuer->name, name_hash, work);
  if (status == TC_TLV_OK)
    status = digest(hash, issuer->public_key.key, key_hash, work);
  if (status != TC_TLV_OK)
    return status;
  const size_t algorithm_content = der_size(info.oid.length) + 2;
  const size_t algorithm_size = der_size(algorithm_content);
  const size_t hash_field = der_size(info.digest_length);
  const size_t cert_id_content = algorithm_size + 2 * hash_field + der_size(target.serial.length);
  const size_t cert_id_size = der_size(cert_id_content);
  const size_t request_size = der_size(cert_id_size);
  const size_t request_list_size = der_size(request_size);
  const size_t nonce_inner_size = nonce.length ? der_size(nonce.length) : 0;
  const size_t extension_content =
      nonce.length ? der_size(sizeof nonce_oid) + der_size(nonce_inner_size) : 0;
  const size_t extension_size = nonce.length ? der_size(extension_content) : 0;
  const size_t extensions_size = nonce.length ? der_size(extension_size) : 0;
  const size_t extensions_wrapper = nonce.length ? der_size(extensions_size) : 0;
  const size_t tbs_content = request_list_size + extensions_wrapper;
  const size_t tbs_size = der_size(tbs_content);
  const size_t total = der_size(tbs_size);
  if (!total || total > encoded.capacity)
    return TC_TLV_LIMIT;

  uint8_t* cursor = der_header(encoded.data, 0x30, tbs_size);
  cursor = der_header(cursor, 0x30, tbs_content);
  cursor = der_header(cursor, 0x30, request_size);
  cursor = der_header(cursor, 0x30, cert_id_size);
  cursor = der_header(cursor, 0x30, cert_id_content);
  cursor = der_header(cursor, 0x30, algorithm_content);
  cursor = der_bytes(cursor, 6, info.oid);
  *cursor++ = 5;
  *cursor++ = 0;
  cursor = der_bytes(cursor, 4, (TC_bytes){name_hash, info.digest_length});
  cursor = der_bytes(cursor, 4, (TC_bytes){key_hash, info.digest_length});
  cursor = der_bytes(cursor, 2, target.serial);
  if (nonce.length) {
    cursor = der_header(cursor, 0xa2, extensions_size);
    cursor = der_header(cursor, 0x30, extension_size);
    cursor = der_header(cursor, 0x30, extension_content);
    cursor = der_bytes(cursor, 6, (TC_bytes){nonce_oid, sizeof nonce_oid});
    cursor = der_header(cursor, 4, nonce_inner_size);
    cursor = der_bytes(cursor, 4, nonce);
  }
  *length = (size_t)(cursor - encoded.data);
  return TC_TLV_OK;
}

#endif
