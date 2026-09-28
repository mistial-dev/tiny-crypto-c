/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/common.h>
#if TC_ENABLE_TRUST_ANCHOR_FORMAT
#include <tiny_crypto/x509_trust_anchor.h>
#include <tiny_crypto/x509_path.h>
#include "pki_internal.h"
#include "string_internal.h"
#include "x509_time_internal.h"
#include "der_bits_internal.h"
#include <string.h>

static TC_TLV_result field(TC_TLV_reader* reader, unsigned tag, TC_TLV_element* out)
{
  TC_TLV_result result = TC_TLV_next(reader, out);
  if (result != TC_TLV_OK)
    return result == TC_TLV_END ? TC_TLV_INVALID : result;
  return tc_pki_tag(out, tag) ? TC_TLV_OK : TC_TLV_INVALID;
}

static TC_TLV_result contents_reader(TC_TLV_reader* reader, TC_bytes bytes,
                                     const TC_TLV_limits* limits)
{
  return TC_TLV_reader_init(reader, bytes.data, bytes.length, TC_TLV_DER, limits);
}

static TC_TLV_result utf8_string(TC_bytes value, size_t max_characters)
{
  size_t offset = 0, count = 0;
  uint32_t point;
  TC_TLV_result result;
  while ((result = tc_asn1_string_next(0x0c, value, &offset, &point)) == TC_TLV_OK) {
    if (++count > max_characters)
      return TC_TLV_LIMIT;
  }
  return result == TC_TLV_END && count ? TC_TLV_OK : TC_TLV_INVALID;
}

static TC_TLV_result encoded_name(TC_bytes name, const TC_TLV_limits* limits)
{
  TC_TLV_reader reader;
  TC_bytes rdn;
  TC_TLV_result result = TC_X509_name_init(&reader, name, limits);
  if (result != TC_TLV_OK)
    return result;
  result = TC_X509_rdn_next(&reader, &rdn);
  if (result != TC_TLV_OK)
    return result == TC_TLV_END ? TC_TLV_INVALID : result;
  while ((result = TC_X509_rdn_next(&reader, &rdn)) == TC_TLV_OK) {
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

static TC_TLV_result policy_set(TC_bytes contents, const TC_TLV_limits* limits)
{
  TC_TLV_reader policies, fields;
  TC_TLV_element item, oid;
  TC_TLV_result result = contents_reader(&policies, contents, limits);
  if (result != TC_TLV_OK)
    return result;
  if (!contents.length)
    return TC_TLV_INVALID;
  while ((result = TC_TLV_next(&policies, &item)) == TC_TLV_OK) {
    if (!tc_pki_tag(&item, 0x30))
      return TC_TLV_INVALID;
    result = contents_reader(&fields, item.value, limits);
    if (result != TC_TLV_OK)
      return result;
    result = field(&fields, 6, &oid);
    if (result != TC_TLV_OK)
      return result;
    result = TC_DER_oid_contents(oid.value.data, oid.value.length);
    if (result != TC_TLV_OK || !tc_pki_end(&fields))
      return TC_TLV_INVALID;
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

static TC_TLV_result policy_flags(TC_bytes contents, unsigned* flags)
{
  unsigned value;
  if (!flags || !contents.length || contents.length > 2 || contents.data[0] > 7)
    return TC_TLV_INVALID;
  if (contents.length == 1) {
    if (contents.data[0] != 0)
      return TC_TLV_INVALID;
    *flags = 0;
    return TC_TLV_OK;
  }
  value = contents.data[1];
  if ((value & 0x1fu) || !value || (contents.data[0] == 7 && value != 0x80u) ||
      (contents.data[0] == 6 && (value & 0x40u) == 0) ||
      (contents.data[0] == 5 && (value & 0x20u) == 0) || contents.data[0] < 5 ||
      contents.data[0] > 7)
    return TC_TLV_INVALID;
  *flags = ((value & 0x80u) ? TC_X509_PATH_INHIBIT_MAPPING : 0u) |
           ((value & 0x40u) ? TC_X509_PATH_REQUIRE_EXPLICIT_POLICY : 0u) |
           ((value & 0x20u) ? TC_X509_PATH_INHIBIT_ANY_POLICY : 0u);
  return TC_TLV_OK;
}

static TC_TLV_result validate_subtrees(const TC_X509_name_constraints* names,
                                       const TC_TLV_limits* limits, TC_X509_workspace* workspace)
{
  const TC_bytes lists[] = {names->permitted, names->excluded};
  for (size_t i = 0; i < 2; ++i) {
    TC_TLV_reader reader;
    TC_X509_general_subtree subtree;
    TC_TLV_result result;
    if (!lists[i].data)
      continue;
    result = contents_reader(&reader, lists[i], limits);
    if (result != TC_TLV_OK)
      return result;
    while ((result = TC_X509_general_subtree_next(
                &reader, workspace->frames, workspace->frame_capacity, &subtree)) == TC_TLV_OK) {
    }
    if (result != TC_TLV_END)
      return result;
  }
  return TC_TLV_OK;
}

static TC_TLV_result name_constraints(TC_bytes contents, const TC_TLV_limits* limits,
                                      TC_X509_workspace* workspace, TC_X509_name_constraints* out)
{
  TC_TLV_reader reader;
  TC_TLV_element element;
  TC_X509_name_constraints names = {{NULL, 0}, {NULL, 0}};
  unsigned last = 0;
  int seen = 0;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  if (result != TC_TLV_OK)
    return result;
  if (tc_pki_end(&reader))
    return TC_TLV_INVALID;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    unsigned tag = element.header.tag_length == 1 ? element.header.tag[0] : 0;
    unsigned number = tag & 0x1fu;
    if (!tag || (seen && number <= last))
      return TC_TLV_INVALID;
    last = number;
    seen = 1;
    if (tc_pki_tag(&element, 0xa0) && !names.permitted.data && element.value.length)
      names.permitted = element.value;
    else if (tc_pki_tag(&element, 0xa1) && !names.excluded.data && element.value.length)
      names.excluded = element.value;
    else
      return TC_TLV_INVALID;
  }
  if (result != TC_TLV_END)
    return result;
  result = validate_subtrees(&names, limits, workspace);
  if (result != TC_TLV_OK)
    return result;
  *out = names;
  return TC_TLV_OK;
}

static TC_TLV_result extensions(TC_bytes encoded, const TC_TLV_limits* limits,
                                TC_X509_workspace* workspace, int tai_ext,
                                TC_X509_store_anchor* out)
{
  TC_TLV_reader reader;
  TC_X509_extension extension;
  TC_TLV_result result;
  size_t count = 0;
  result = TC_X509_extensions_init(&reader, encoded.data, encoded.length, limits);
  if (result != TC_TLV_OK)
    return result;
  while ((result = TC_X509_extension_next(&reader, &extension)) == TC_TLV_OK) {
    TC_bytes oid = extension.oid;
    if (count == workspace->extension_capacity)
      return TC_TLV_LIMIT;
    for (size_t i = 0; i < count; ++i)
      if (workspace->extension_oids[i].length == oid.length &&
          !memcmp(workspace->extension_oids[i].data, oid.data, oid.length))
        return TC_TLV_INVALID;
    workspace->extension_oids[count++] = oid;
    if (oid.length != 3 || oid.data[0] != 0x55 || oid.data[1] != 0x1d)
      continue;
    if (tai_ext &&
        (oid.data[2] == 30 || oid.data[2] == 32 || oid.data[2] == 36 || oid.data[2] == 54))
      continue;
    switch (oid.data[2]) {
    case 32: {
      TC_TLV_element value;
      result =
          TC_TLV_read(extension.value.data, extension.value.length, TC_TLV_DER, limits, &value);
      if (result != TC_TLV_OK || !tc_pki_tag(&value, 0x30) ||
          value.encoded.length != extension.value.length || !value.value.length)
        return TC_TLV_INVALID;
      out->policy_set = value.value;
      break;
    }
    case 30:
      result = TC_X509_name_constraints_read(extension.value.data, extension.value.length, limits,
                                             &out->names);
      if (result != TC_TLV_OK)
        return result;
      result = validate_subtrees(&out->names, limits, workspace);
      if (result != TC_TLV_OK)
        return result;
      break;
    case 36: {
      TC_X509_policy_constraints constraints;
      result = TC_X509_policy_constraints_read(extension.value.data, extension.value.length,
                                               &constraints);
      if (result != TC_TLV_OK)
        return result;
      if (constraints.has_require_explicit_policy)
        out->policy_flags |= TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
      if (constraints.has_inhibit_policy_mapping)
        out->policy_flags |= TC_X509_PATH_INHIBIT_MAPPING;
      break;
    }
    case 54: {
      uint32_t skip;
      result = TC_DER_uint32(extension.value.data, extension.value.length, &skip);
      if (result != TC_TLV_OK)
        return result;
      out->policy_flags |= TC_X509_PATH_INHIBIT_ANY_POLICY;
      break;
    }
    case 19: {
      TC_X509_basic_constraints basic;
      result = TC_X509_basic_constraints_read(extension.value.data, extension.value.length, &basic);
      if (result != TC_TLV_OK)
        return result;
      if (basic.has_path_length) {
        out->has_path_len = 1;
        out->path_len = basic.path_length;
      }
      break;
    }
    case 14:
      result = TC_X509_subject_key_identifier_read(extension.value.data, extension.value.length,
                                                   limits, &out->key_id);
      if (result != TC_TLV_OK)
        return result;
      break;
    case 15: {
      uint16_t usage;
      result = TC_X509_key_usage_read(extension.value.data, extension.value.length, &usage);
      if (result != TC_TLV_OK)
        return result;
      if (!(usage & TC_KEY_USAGE_CERT_SIGN))
        return TC_TLV_INVALID;
      break;
    }
    default:
      break;
    }
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

static TC_TLV_result tbs_certificate(TC_bytes contents, const TC_TLV_limits* limits,
                                     TC_X509_workspace* workspace, TC_X509_store_anchor* out,
                                     TC_bytes* spki, TC_bytes* algorithm)
{
  TC_TLV_reader reader;
  TC_TLV_element element;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  uint32_t version = 0;
  unsigned last = 0;
  if (result != TC_TLV_OK)
    return result;
  result = TC_TLV_next(&reader, &element);
  if (result != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (tc_pki_tag(&element, 0xa0)) {
    result = TC_DER_uint32(element.value.data, element.value.length, &version);
    if (result != TC_TLV_OK || version > 2 || version == 0)
      return TC_TLV_INVALID;
    result = TC_TLV_next(&reader, &element);
    if (result != TC_TLV_OK)
      return TC_TLV_INVALID;
  }
  if (!tc_pki_tag(&element, 2) ||
      TC_DER_integer_contents(element.value.data, element.value.length) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (field(&reader, 0x30, &element) != TC_TLV_OK ||
      TC_DER_algorithm_identifier(element.encoded.data, element.encoded.length,
                                  &(TC_DER_algorithm){{NULL, 0}, {NULL, 0}}) != TC_TLV_OK)
    return TC_TLV_INVALID;
  *algorithm = element.encoded;
  if (field(&reader, 0x30, &element) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (encoded_name(element.encoded, limits) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (field(&reader, 0x30, &element) != TC_TLV_OK)
    return TC_TLV_INVALID;
  {
    TC_TLV_reader validity;
    TC_TLV_element before, after;
    TC_X509_time start, end;
    int order;
    result = contents_reader(&validity, element.value, limits);
    if (result != TC_TLV_OK || TC_TLV_next(&validity, &before) != TC_TLV_OK ||
        TC_TLV_next(&validity, &after) != TC_TLV_OK || !tc_pki_end(&validity) ||
        tc_x509_time_value(&before, &start) != TC_TLV_OK ||
        tc_x509_time_value(&after, &end) != TC_TLV_OK ||
        TC_X509_time_compare(&start, &end, &order) != TC_TLV_OK || order > 0)
      return TC_TLV_INVALID;
  }
  if (field(&reader, 0x30, &element) != TC_TLV_OK)
    return TC_TLV_INVALID;
  out->trust.name = element.encoded;
  if (encoded_name(element.encoded, limits) != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (field(&reader, 0x30, &element) != TC_TLV_OK)
    return TC_TLV_INVALID;
  *spki = element.encoded;
  result = TC_X509_subject_public_key(spki->data, spki->length, &out->trust.public_key);
  if (result != TC_TLV_OK)
    return result;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    TC_bytes bits;
    unsigned unused;
    if (element.header.tag_length != 1 || element.header.tag[0] <= last)
      return TC_TLV_INVALID;
    last = element.header.tag[0];
    if (last == 0xa3 && version == 2) {
      TC_TLV_element sequence;
      result = TC_TLV_read(element.value.data, element.value.length, TC_TLV_DER, limits, &sequence);
      if (result != TC_TLV_OK || !tc_pki_tag(&sequence, 0x30) ||
          sequence.encoded.length != element.value.length)
        return TC_TLV_INVALID;
      out->certificate_extensions = sequence.value;
      result = extensions(element.value, limits, workspace, 0, out);
      if (result != TC_TLV_OK)
        return result;
    } else if (last == 0x81 || last == 0x82) {
      if (version == 0 || tc_der_bit_string_contents(element.value, &bits, &unused) != TC_TLV_OK)
        return TC_TLV_INVALID;
    } else
      return TC_TLV_INVALID;
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

static TC_TLV_result certificate_contents(TC_bytes contents, const TC_TLV_limits* limits,
                                          TC_X509_workspace* workspace, TC_X509_store_anchor* out,
                                          TC_bytes* spki)
{
  TC_TLV_reader reader;
  TC_TLV_element tbs, signature_algorithm, signature;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  unsigned unused;
  TC_bytes bits, spki_algorithm;
  if (result != TC_TLV_OK)
    return result;
  result = field(&reader, 0x30, &tbs);
  if (result != TC_TLV_OK)
    return result;
  result = tbs_certificate(tbs.value, limits, workspace, out, spki, &spki_algorithm);
  if (result != TC_TLV_OK)
    return result;
  result = field(&reader, 0x30, &signature_algorithm);
  if (result != TC_TLV_OK)
    return result;
  if (signature_algorithm.encoded.length != spki_algorithm.length ||
      memcmp(signature_algorithm.encoded.data, spki_algorithm.data, spki_algorithm.length))
    return TC_TLV_INVALID;
  result = TC_DER_algorithm_identifier(signature_algorithm.encoded.data,
                                       signature_algorithm.encoded.length,
                                       &(TC_DER_algorithm){{NULL, 0}, {NULL, 0}});
  if (result != TC_TLV_OK)
    return result;
  result = field(&reader, 3, &signature);
  if (result != TC_TLV_OK || !tc_pki_end(&reader))
    return TC_TLV_INVALID;
  result = TC_DER_bit_string(signature.encoded.data, signature.encoded.length, &bits, &unused);
  return result == TC_TLV_OK && !unused && bits.length ? TC_TLV_OK : TC_TLV_INVALID;
}

static TC_TLV_result cert_path_controls(TC_bytes contents, const TC_TLV_limits* limits,
                                        TC_X509_workspace* workspace, TC_X509_store_anchor* out,
                                        TC_bytes pubkey, TC_bytes key_id)
{
  TC_TLV_reader reader;
  TC_TLV_element element;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  unsigned last = 0;
  int seen = 0;
  if (result != TC_TLV_OK)
    return result;
  result = field(&reader, 0x30, &element);
  if (result != TC_TLV_OK || !element.value.length ||
      encoded_name(element.encoded, limits) != TC_TLV_OK)
    return TC_TLV_INVALID;
  out->trust.name = element.encoded;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    unsigned tag = element.header.tag_length == 1 ? element.header.tag[0] : 0;
    unsigned number = tag & 0x1fu;
    if (!tag || (seen && number <= last))
      return TC_TLV_INVALID;
    last = number;
    seen = 1;
    switch (tag) {
    case 0xa0: {
      TC_X509_store_anchor embedded = {0};
      TC_bytes embedded_spki;
      result = certificate_contents(element.value, limits, workspace, &embedded, &embedded_spki);
      if (result != TC_TLV_OK)
        return result;
      if (embedded.trust.name.length != out->trust.name.length ||
          memcmp(embedded.trust.name.data, out->trust.name.data, out->trust.name.length) ||
          embedded_spki.length != pubkey.length ||
          memcmp(embedded_spki.data, pubkey.data, pubkey.length) ||
          (embedded.key_id.data && (embedded.key_id.length != key_id.length ||
                                    memcmp(embedded.key_id.data, key_id.data, key_id.length))))
        return TC_TLV_INVALID;
      out->policy_set = embedded.policy_set;
      out->policy_flags = embedded.policy_flags;
      out->names = embedded.names;
      out->path_len = embedded.path_len;
      out->has_path_len = embedded.has_path_len;
      out->certificate_extensions = embedded.certificate_extensions;
      break;
    }
    case 0xa1:
      result = policy_set(element.value, limits);
      if (result != TC_TLV_OK)
        return result;
      out->policy_set = element.value;
      break;
    case 0x82:
      result = policy_flags(element.value, &out->policy_flags);
      if (result != TC_TLV_OK)
        return result;
      if (!out->policy_set.data && (out->policy_flags & TC_X509_PATH_REQUIRE_EXPLICIT_POLICY))
        return TC_TLV_INVALID;
      break;
    case 0xa3:
      result = name_constraints(element.value, limits, workspace, &out->names);
      if (result != TC_TLV_OK)
        return result;
      break;
    case 0x84: {
      uint32_t length;
      result = TC_DER_uint32_contents(element.value.data, element.value.length, &length);
      if (result != TC_TLV_OK)
        return result;
      out->path_len = length;
      out->has_path_len = 1;
      break;
    }
    default:
      return TC_TLV_INVALID;
    }
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

static TC_TLV_result trust_anchor_info(TC_bytes contents, const TC_TLV_limits* limits,
                                       TC_X509_workspace* workspace, TC_X509_store_anchor* out)
{
  TC_TLV_reader reader;
  TC_TLV_element element;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  TC_bytes spki;
  unsigned last = 0;
  if (result != TC_TLV_OK)
    return result;
  result = TC_TLV_next(&reader, &element);
  if (result != TC_TLV_OK)
    return TC_TLV_INVALID;
  if (tc_pki_tag(&element, 2)) {
    uint32_t version;
    result = TC_DER_uint32(element.encoded.data, element.encoded.length, &version);
    if (result != TC_TLV_OK)
      return result;
    if (version == 1)
      return TC_TLV_INVALID; /* DEFAULT v1 is omitted in DER. */
    return TC_TLV_UNSUPPORTED;
  }
  if (!tc_pki_tag(&element, 0x30))
    return TC_TLV_INVALID;
  spki = element.encoded;
  result = TC_X509_subject_public_key(spki.data, spki.length, &out->trust.public_key);
  if (result != TC_TLV_OK)
    return result;
  result = field(&reader, 4, &element);
  if (result != TC_TLV_OK)
    return result;
  out->key_id = element.value;
  out->x509_unusable = 1;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    unsigned tag = element.header.tag_length == 1 ? element.header.tag[0] : 0;
    if (tag == 0x0c && last < 1) {
      result = utf8_string(element.value, 64);
      if (result != TC_TLV_OK)
        return result;
      out->title = element.value;
      last = 1;
    } else if (tag == 0x30 && last < 2) {
      result = cert_path_controls(element.value, limits, workspace, out, spki, out->key_id);
      if (result != TC_TLV_OK)
        return result;
      out->x509_unusable = 0;
      last = 2;
    } else if (tag == 0xa1 && last < 3) {
      TC_TLV_element inner;
      result = TC_TLV_read(element.value.data, element.value.length, TC_TLV_DER, limits, &inner);
      if (result != TC_TLV_OK || !tc_pki_tag(&inner, 0x30) ||
          inner.encoded.length != element.value.length)
        return TC_TLV_INVALID;
      out->extensions = inner.value;
      TC_X509_store_anchor overrides = {0};
      result = extensions(inner.encoded, limits, workspace, 1, &overrides);
      if (result != TC_TLV_OK)
        return result;
      if (overrides.policy_set.data)
        out->policy_set = overrides.policy_set;
      if (overrides.names.permitted.data || overrides.names.excluded.data)
        out->names = overrides.names;
      if (overrides.has_path_len) {
        out->path_len = overrides.path_len;
        out->has_path_len = 1;
      }
      out->policy_flags |= overrides.policy_flags;
      last = 3;
    } else if (tag == 0x82 && last < 4) {
      result = utf8_string(element.value, SIZE_MAX);
      if (result != TC_TLV_OK)
        return result;
      out->title_language = element.value;
      last = 4;
    } else
      return TC_TLV_INVALID;
  }
  return result == TC_TLV_END ? TC_TLV_OK : result;
}

TC_TLV_result TC_X509_trust_anchor_list_init(TC_TLV_reader* reader, const uint8_t* data,
                                             size_t length, const TC_TLV_limits* limits,
                                             TC_X509_workspace* workspace)
{
  TC_TLV_element list;
  TC_TLV_reader parsed;
  TC_TLV_result result;
  if (!reader || !limits || !workspace || (!workspace->frames && workspace->frame_capacity) ||
      (!workspace->extension_oids && workspace->extension_capacity))
    return TC_TLV_ARGUMENT;
  result = TC_TLV_read(data, length, TC_TLV_DER, limits, &list);
  if (result != TC_TLV_OK)
    return result;
  if (!tc_pki_tag(&list, 0x30) || list.encoded.length != length || !list.value.length)
    return TC_TLV_INVALID;
  result = TC_TLV_walk(data, length, TC_TLV_DER, limits, workspace->frames,
                       workspace->frame_capacity, NULL, NULL);
  if (result != TC_TLV_OK)
    return result;
  result = contents_reader(&parsed, list.value, limits);
  if (result != TC_TLV_OK)
    return result;
  *reader = parsed;
  return TC_TLV_OK;
}

TC_TLV_result TC_X509_trust_anchor_next(TC_TLV_reader* reader, const TC_TLV_limits* limits,
                                        TC_X509_workspace* workspace, TC_X509_store_anchor* out)
{
  TC_TLV_reader next;
  TC_TLV_element choice;
  TC_X509_store_anchor parsed = {0};
  TC_TLV_result result;
  TC_bytes spki;
  if (!reader || !limits || !workspace || !out || reader->profile != TC_TLV_DER)
    return TC_TLV_ARGUMENT;
  next = *reader;
  result = TC_TLV_next(&next, &choice);
  if (result != TC_TLV_OK)
    return result;
  if (tc_pki_tag(&choice, 0x30)) {
#if TC_TAF_ENABLE_CERTIFICATE
    TC_X509_certificate certificate;
    result =
        TC_X509_read(choice.encoded.data, choice.encoded.length, limits, workspace, &certificate);
    if (result != TC_TLV_OK)
      return result;
    parsed.trust.name = certificate.subject;
    parsed.trust.public_key = certificate.public_key;
    if (certificate.extensions.data) {
      TC_TLV_element sequence;
      result = TC_TLV_read(certificate.extensions.data, certificate.extensions.length, TC_TLV_DER,
                           limits, &sequence);
      if (result != TC_TLV_OK || !tc_pki_tag(&sequence, 0x30))
        return TC_TLV_INVALID;
      parsed.certificate_extensions = sequence.value;
    }
    if (certificate.extensions.data) {
      result = extensions(certificate.extensions, limits, workspace, 0, &parsed);
      if (result != TC_TLV_OK)
        return result;
    }
#else
    return TC_TLV_UNSUPPORTED;
#endif
  } else if (tc_pki_tag(&choice, 0xa1)) {
#if TC_TAF_ENABLE_TBS_CERTIFICATE
    TC_TLV_element tbs;
    result = TC_TLV_read(choice.value.data, choice.value.length, TC_TLV_DER, limits, &tbs);
    if (result != TC_TLV_OK || !tc_pki_tag(&tbs, 0x30) || tbs.encoded.length != choice.value.length)
      return TC_TLV_INVALID;
    TC_bytes algorithm;
    result = tbs_certificate(tbs.value, limits, workspace, &parsed, &spki, &algorithm);
    if (result != TC_TLV_OK)
      return result;
#else
    return TC_TLV_UNSUPPORTED;
#endif
  } else if (tc_pki_tag(&choice, 0xa2)) {
#if TC_TAF_ENABLE_TRUST_ANCHOR_INFO
    TC_TLV_element info;
    result = TC_TLV_read(choice.value.data, choice.value.length, TC_TLV_DER, limits, &info);
    if (result != TC_TLV_OK || !tc_pki_tag(&info, 0x30) ||
        info.encoded.length != choice.value.length)
      return TC_TLV_INVALID;
    result = trust_anchor_info(info.value, limits, workspace, &parsed);
    if (result != TC_TLV_OK)
      return result;
#else
    return TC_TLV_UNSUPPORTED;
#endif
  } else
    return TC_TLV_INVALID;
  *reader = next;
  *out = parsed;
  return TC_TLV_OK;
}
#endif
