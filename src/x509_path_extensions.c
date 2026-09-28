/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Path-relevant certificate extensions: one summary per certificate and the
 * usage and critical-extension pass that reads it (RFC 5280 section 6.1). */
#include <tiny_crypto/x509.h>
#if TC_ENABLE_X509_PATH
#include "x509_path_internal.h"
#include "pki_extensions_internal.h"
#include "internal.h"

enum {
  EXTENSION_KEY_USAGE = 15,
  EXTENSION_SUBJECT_ALT_NAME = 17,
  EXTENSION_BASIC_CONSTRAINTS = 19,
  EXTENSION_NAME_CONSTRAINTS = 30,
  EXTENSION_POLICIES = 32,
  EXTENSION_POLICY_MAPPINGS = 33,
  EXTENSION_POLICY_CONSTRAINTS = 36,
  EXTENSION_EXTENDED_KEY_USAGE = 37,
  EXTENSION_INHIBIT_ANY = 54
};

/* Map an id-ce extension number to its summary slot. Extensions outside the
 * summary map to -1. */
static int summary_slot(unsigned id)
{
  switch (id) {
  case EXTENSION_KEY_USAGE:
    return TC_X509_SUMMARY_KEY_USAGE;
  case EXTENSION_SUBJECT_ALT_NAME:
    return TC_X509_SUMMARY_SUBJECT_ALT_NAME;
  case EXTENSION_BASIC_CONSTRAINTS:
    return TC_X509_SUMMARY_BASIC_CONSTRAINTS;
  case EXTENSION_NAME_CONSTRAINTS:
    return TC_X509_SUMMARY_NAME_CONSTRAINTS;
  case EXTENSION_POLICIES:
    return TC_X509_SUMMARY_POLICIES;
  case EXTENSION_POLICY_MAPPINGS:
    return TC_X509_SUMMARY_POLICY_MAPPINGS;
  case EXTENSION_POLICY_CONSTRAINTS:
    return TC_X509_SUMMARY_POLICY_CONSTRAINTS;
  case EXTENSION_EXTENDED_KEY_USAGE:
    return TC_X509_SUMMARY_EXTENDED_KEY_USAGE;
  case EXTENSION_INHIBIT_ANY:
    return TC_X509_SUMMARY_INHIBIT_ANY;
  default:
    return -1;
  }
}

/* Decode the fixed-form values every pass needs. Other values stay as spans. */
static TC_TLV_result summary_decode(TC_X509_extension_summary* summary, int slot, TC_bytes value)
{
  switch (slot) {
  case TC_X509_SUMMARY_BASIC_CONSTRAINTS:
    return TC_X509_basic_constraints_read(value.data, value.length, &summary->basic);
  case TC_X509_SUMMARY_KEY_USAGE:
    return TC_X509_key_usage_read(value.data, value.length, &summary->key_usage);
  case TC_X509_SUMMARY_POLICY_CONSTRAINTS:
    return TC_X509_policy_constraints_read(value.data, value.length, &summary->policy_constraints);
  case TC_X509_SUMMARY_INHIBIT_ANY:
    return TC_DER_uint32(value.data, value.length, &summary->inhibit_any);
  default:
    return TC_TLV_OK;
  }
}

TC_TLV_result tc_x509_extensions_summarize(const TC_X509_certificate* certificate,
                                           const TC_TLV_limits* limits, size_t* work,
                                           TC_X509_extension_summary* out)
{
  TC_X509_extension_summary summary;
  TC_TLV_reader reader;
  TC_X509_extension extension;
  TC_TLV_result result;
  memset(&summary, 0, sizeof summary);
  result = tc_pki_extensions_init(&reader, certificate, limits, work);
  if (result != TC_TLV_OK)
    return result;
  while ((result = tc_pki_extension_next(&reader, work, &extension)) == TC_TLV_OK) {
    const int slot = summary_slot(tc_pki_extension_id(&extension));
    if (slot < 0) {
      if (extension.critical)
        summary.unknown_critical = 1;
      continue;
    }
    if (tc_x509_summary_has(&summary, (unsigned)slot))
      return TC_TLV_INVALID;
    summary.present |= (uint16_t)(1u << slot);
    if (extension.critical)
      summary.critical |= (uint16_t)(1u << slot);
    summary.values[slot] = extension.value;
    result = summary_decode(&summary, slot, extension.value);
    if (result != TC_TLV_OK)
      return result;
  }
  if (result != TC_TLV_END)
    return result;
  summary.ready = 1;
  *out = summary;
  return TC_TLV_OK;
}

/* Structural DER check over every recorded value, charged by length. */
static TC_TLV_result summary_values_check(const TC_X509_extension_summary* extensions,
                                          const TC_TLV_limits* limits,
                                          const TC_X509_constraint_workspace* names, size_t* work)
{
  unsigned slot;
  for (slot = 0; slot < TC_X509_EXTENSION_SUMMARY_SLOTS; ++slot) {
    const TC_bytes value = extensions->values[slot];
    TC_TLV_result result;
    if (!tc_x509_summary_has(extensions, slot))
      continue;
    if (tc_pki_work_charge(work, value.length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    result = TC_TLV_walk(value.data, value.length, TC_TLV_DER, limits, names->frames,
                         names->frame_capacity, NULL, NULL);
    if (result != TC_TLV_OK)
      return result;
  }
  return TC_TLV_OK;
}

/* An EKU permits the requested purpose, or anyExtendedKeyUsage unless inhibited. */
static TC_TLV_result extended_key_usage_permits(TC_bytes value, const tc_x509_path_usage* usage,
                                                const tc_x509_extension_workspace* workspace,
                                                const TC_TLV_limits* limits, size_t* work,
                                                int* permitted)
{
  static const uint8_t any_eku[] = {0x55, 0x1d, 0x25, 0};
  size_t i, count;
  TC_TLV_result result;
  *permitted = !usage->purpose.length;
  if (tc_pki_work_charge(work, value.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  result = TC_X509_extended_key_usage_read(value.data, value.length, workspace->oids,
                                           workspace->oid_capacity, &count);
  if (result != TC_TLV_OK)
    return result;
  if (count > limits->max_elements)
    return TC_TLV_LIMIT;
  for (i = 0; i < count; ++i) {
    const TC_bytes oid = workspace->oids[i];
    if (tc_pki_work_charge(work, oid.length) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    if ((!usage->inhibit_any_purpose && oid.length == sizeof any_eku &&
         !memcmp(oid.data, any_eku, sizeof any_eku)) ||
        tc_pki_equal(oid, usage->purpose))
      *permitted = 1;
  }
  return TC_TLV_OK;
}

TC_TLV_result tc_x509_path_extensions(const tc_x509_path_input* input,
                                      const tc_x509_path_usage* usage,
                                      const tc_x509_extension_workspace* workspace, size_t* work,
                                      int* accepted)
{
  const TC_X509_name_constraints unrestricted = {{NULL, 0}, {NULL, 0}};
  size_t i;
  if (!tc_x509_path_source_valid(input) || !usage || !workspace || !work || !accepted ||
      !input->limits || !input->count || (usage->purpose.length && !usage->purpose.data) ||
      (usage->require_extended_key_usage && !usage->purpose.length) ||
      (usage->key_usage & ~(unsigned)TC_KEY_USAGE_ALL) ||
      (workspace->oid_capacity && !workspace->oids))
    return TC_TLV_ARGUMENT;
  if (input->count > input->max_certificates)
    return TC_TLV_LIMIT;
  for (i = 0; i < input->count; ++i) {
    TC_X509_extension_summary storage = {0};
    const TC_X509_extension_summary* extensions;
    const TC_X509_certificate* certificate;
    TC_TLV_result result;
    int valid, has_usage, has_eku, has_constraints;
    result = tc_x509_path_certificate(input, i, work, &certificate);
    if (result != TC_TLV_OK)
      return result;
    /* Subject names are checked on every path, including unconstrained ones. */
    result = TC_X509_certificate_names_check(certificate, &unrestricted, input->limits,
                                             &workspace->names, work, &valid);
    if (result != TC_TLV_OK)
      return result;
    if (!valid) {
      *accepted = 0;
      return TC_TLV_OK;
    }
    result = tc_x509_path_summary(input, i, work, &storage, &extensions);
    if (result != TC_TLV_OK)
      return result;
    result = summary_values_check(extensions, input->limits, &workspace->names, work);
    if (result != TC_TLV_OK)
      return result;
    if (extensions->unknown_critical)
      return TC_TLV_UNSUPPORTED;
    has_usage = tc_x509_summary_has(extensions, TC_X509_SUMMARY_KEY_USAGE);
    has_eku = tc_x509_summary_has(extensions, TC_X509_SUMMARY_EXTENDED_KEY_USAGE);
    has_constraints = tc_x509_summary_has(extensions, TC_X509_SUMMARY_NAME_CONSTRAINTS);
    if (has_eku) {
      int permitted;
      result = extended_key_usage_permits(extensions->values[TC_X509_SUMMARY_EXTENDED_KEY_USAGE],
                                          usage, workspace, input->limits, work, &permitted);
      if (result != TC_TLV_OK)
        return result;
      if (!permitted) {
        *accepted = 0;
        return TC_TLV_OK;
      }
    }
    if (has_constraints) {
      const TC_bytes value = extensions->values[TC_X509_SUMMARY_NAME_CONSTRAINTS];
      TC_X509_name_constraints constraints;
      result = TC_X509_name_constraints_read(value.data, value.length, input->limits, &constraints);
      if (result != TC_TLV_OK)
        return result;
      result =
          tc_x509_path_constraint_distances(&constraints, input->limits, &workspace->names, work);
      if (result != TC_TLV_OK)
        return result;
    }
    /* nameConstraints and keyCertSign are CA-only (RFC 5280 4.2.1.9, 4.2.1.3). */
    if ((has_constraints || (has_usage && (extensions->key_usage & TC_KEY_USAGE_CERT_SIGN))) &&
        !extensions->basic.ca)
      return TC_TLV_INVALID;
    if (i + 1 == input->count &&
        ((usage->require_key_usage && !has_usage) ||
         (usage->require_extended_key_usage && !has_eku) ||
         (has_usage && (extensions->key_usage & usage->key_usage) != usage->key_usage))) {
      *accepted = 0;
      return TC_TLV_OK;
    }
  }
  *accepted = 1;
  return TC_TLV_OK;
}
#endif
