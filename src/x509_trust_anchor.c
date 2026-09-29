/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/common.h>
#if TC_ENABLE_TRUST_ANCHOR_FORMAT
#include <tiny_crypto/x509_trust_anchor.h>
#include <tiny_crypto/x509_path.h>
#include "pki_internal.h"
#include "pki_extensions_internal.h"
#include "string_internal.h"
#include "x509_time_internal.h"
#include "der_bits_internal.h"
#include <string.h>

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

/* CertificatePolicies contents with unique identifiers. RFC 5914 section 2.5
 * forbids policyQualifiers in a TrustAnchorInfo policySet. An anchor
 * certificate's extension may carry them. Uses the extension OID scratch. */
static TC_TLV_result policy_set(TC_bytes contents, const TC_TLV_limits* limits,
                                TC_X509_workspace* workspace, int qualifiers_allowed)
{
  TC_TLV_reader policies;
  TC_TLV_element item;
  TC_X509_policy policy;
  size_t count = 0;
  TC_TLV_result result = contents_reader(&policies, contents, limits);
  if (result != TC_TLV_OK)
    return result;
  if (!contents.length)
    return TC_TLV_INVALID;
  while ((result = TC_TLV_next(&policies, &item)) == TC_TLV_OK) {
    if (count == workspace->extension_capacity)
      return TC_TLV_LIMIT;
    result = tc_x509_policy_information_read(item.encoded, &policy);
    if (result != TC_TLV_OK)
      return result;
    if (policy.qualifiers.data && !qualifiers_allowed)
      return TC_TLV_INVALID;
    workspace->extension_oids[count++] = policy.oid;
  }
  if (result != TC_TLV_END)
    return result;
  return tc_pki_spans_unique(workspace->extension_oids, count, NULL);
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
                &reader, (TC_TLV_frames){workspace->frames, workspace->frame_capacity},
                &subtree)) == TC_TLV_OK) {
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
  static const uint8_t subtree_tags[] = {0xa0, 0xa1}; /* permitted, excluded */
  size_t previous = 0, index;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  if (result != TC_TLV_OK)
    return result;
  if (tc_pki_end(&reader))
    return TC_TLV_INVALID;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    if (tc_pki_context_order(&element, subtree_tags, sizeof subtree_tags, &previous, &index) !=
            TC_TLV_OK ||
        !element.value.length)
      return TC_TLV_INVALID;
    if (index == 0)
      names.permitted = element.value;
    else
      names.excluded = element.value;
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
    if (count == workspace->extension_capacity)
      return TC_TLV_LIMIT;
    workspace->extension_oids[count++] = extension.oid;
    const unsigned id = tc_pki_extension_id(&extension);
    if (!id)
      continue;
    /* RFC 5914 section 2.6: these duplicate CertPathControls and must not
     * appear in TrustAnchorInfo exts. Reject them so a constraint is never
     * silently dropped. */
    if (tai_ext && tc_pki_extension_path_control(id))
      return TC_TLV_INVALID;
    switch (id) {
    case TC_PKI_EXT_CERTIFICATE_POLICIES: {
      TC_TLV_element value;
      result =
          TC_TLV_read(extension.value.data, extension.value.length, TC_TLV_DER, limits, &value);
      if (result != TC_TLV_OK || !tc_pki_tag(&value, 0x30) ||
          value.encoded.length != extension.value.length)
        return TC_TLV_INVALID;
      /* Checked after the loop, which owns the OID scratch until then. */
      out->policy_set = value.value;
      break;
    }
    case TC_PKI_EXT_NAME_CONSTRAINTS:
      result = TC_X509_name_constraints_read(extension.value.data, extension.value.length, limits,
                                             &out->names);
      if (result != TC_TLV_OK)
        return result;
      result = validate_subtrees(&out->names, limits, workspace);
      if (result != TC_TLV_OK)
        return result;
      break;
    /* RFC 5937 section 2: the presence of these fields sets the Boolean
     * path inputs. Their SkipCerts counts do not apply to the anchor. */
    case TC_PKI_EXT_POLICY_CONSTRAINTS: {
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
    case TC_PKI_EXT_INHIBIT_ANY_POLICY: {
      uint32_t skip;
      result = TC_DER_uint32(extension.value.data, extension.value.length, &skip);
      if (result != TC_TLV_OK)
        return result;
      out->policy_flags |= TC_X509_PATH_INHIBIT_ANY_POLICY;
      break;
    }
    case TC_PKI_EXT_BASIC_CONSTRAINTS: {
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
    case TC_PKI_EXT_SUBJECT_KEY_IDENTIFIER:
      result = TC_X509_subject_key_identifier_read(extension.value.data, extension.value.length,
                                                   limits, &out->key_id);
      if (result != TC_TLV_OK)
        return result;
      break;
    case TC_PKI_EXT_KEY_USAGE: {
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
  if (result != TC_TLV_END)
    return result;
  result = tc_pki_spans_unique(workspace->extension_oids, count, NULL);
  if (result != TC_TLV_OK || !out->policy_set.data)
    return result;
  return policy_set(out->policy_set, limits, workspace, 1);
}

/* Anchor fields from a parsed Certificate or TBSCertificate. An anchor
 * issues certificates, so its subject is non-empty (RFC 5280 section
 * 4.1.2.6). A reversed validity period is malformed. */
static TC_TLV_result certificate_anchor(const TC_X509_certificate* certificate,
                                        const TC_TLV_limits* limits, TC_X509_workspace* workspace,
                                        TC_X509_store_anchor* out)
{
  TC_bytes contents;
  int order;
  if (certificate->subject.length == 2 ||
      TC_X509_time_compare(&certificate->not_before, &certificate->not_after, &order) !=
          TC_TLV_OK ||
      order > 0)
    return TC_TLV_INVALID;
  out->trust.name = certificate->subject;
  out->trust.public_key = certificate->public_key;
  if (!certificate->extensions.data)
    return TC_TLV_OK;
  if (TC_DER_sequence(certificate->extensions.data, certificate->extensions.length, &contents) !=
      TC_TLV_OK)
    return TC_TLV_INVALID;
  out->certificate_extensions = contents;
  return extensions(certificate->extensions, limits, workspace, 0, out);
}

static TC_TLV_result cert_path_controls(TC_bytes contents, const TC_TLV_limits* limits,
                                        TC_X509_workspace* workspace, TC_X509_store_anchor* out,
                                        TC_bytes pubkey, TC_bytes key_id)
{
  TC_TLV_reader reader;
  TC_TLV_element element;
  /* RFC 5914 CertPathControls after taName: certificate [0], policySet [1],
   * policyFlags [2], nameConstr [3], pathLenConstraint [4]. */
  static const uint8_t control_tags[] = {0xa0, 0xa1, 0x82, 0xa3, 0x84};
  size_t previous = 0, index;
  TC_TLV_result result = contents_reader(&reader, contents, limits);
  if (result != TC_TLV_OK)
    return result;
  result = tc_pki_field(&reader, 0x30, &element);
  if (result != TC_TLV_OK || !element.value.length ||
      encoded_name(element.encoded, limits) != TC_TLV_OK)
    return TC_TLV_INVALID;
  out->trust.name = element.encoded;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    if (tc_pki_context_order(&element, control_tags, sizeof control_tags, &previous, &index) !=
        TC_TLV_OK)
      return TC_TLV_INVALID;
    switch (index) {
    case 0: {
      /* certificate [0] IMPLICIT Certificate must match taName, pubKey and keyId. */
      TC_X509_store_anchor embedded = {0};
      TC_X509_certificate certificate;
      result = tc_x509_certificate_read(element.encoded, 0xa0, limits, workspace, &certificate);
      if (result == TC_TLV_OK)
        result = certificate_anchor(&certificate, limits, workspace, &embedded);
      if (result != TC_TLV_OK)
        return result;
      if (!tc_pki_equal(embedded.trust.name, out->trust.name) ||
          !tc_pki_equal(certificate.spki, pubkey) ||
          (embedded.key_id.data && !tc_pki_equal(embedded.key_id, key_id)))
        return TC_TLV_INVALID;
      out->policy_set = embedded.policy_set;
      out->policy_flags = embedded.policy_flags;
      out->names = embedded.names;
      out->path_len = embedded.path_len;
      out->has_path_len = embedded.has_path_len;
      out->certificate_extensions = embedded.certificate_extensions;
      break;
    }
    case 1:
      result = policy_set(element.value, limits, workspace, 0);
      if (result != TC_TLV_OK)
        return result;
      out->policy_set = element.value;
      break;
    case 2:
      result = policy_flags(element.value, &out->policy_flags);
      if (result != TC_TLV_OK)
        return result;
      if (!out->policy_set.data && (out->policy_flags & TC_X509_PATH_REQUIRE_EXPLICIT_POLICY))
        return TC_TLV_INVALID;
      break;
    case 3:
      result = name_constraints(element.value, limits, workspace, &out->names);
      if (result != TC_TLV_OK)
        return result;
      break;
    default: {
      uint32_t length;
      result = TC_DER_uint32_contents(element.value.data, element.value.length, &length);
      if (result != TC_TLV_OK)
        return result;
      out->path_len = length;
      out->has_path_len = 1;
      break;
    }
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
  /* RFC 5914 TrustAnchorInfo after keyId: taTitle, certPath, exts [1],
   * taTitleLangTag [2]. */
  static const uint8_t optional_tags[] = {0x0c, 0x30, 0xa1, 0x82};
  size_t previous = 0, index;
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
  result = tc_pki_field(&reader, 4, &element);
  if (result != TC_TLV_OK)
    return result;
  out->key_id = element.value;
  out->x509_unusable = 1;
  while ((result = TC_TLV_next(&reader, &element)) == TC_TLV_OK) {
    if (tc_pki_context_order(&element, optional_tags, sizeof optional_tags, &previous, &index) !=
        TC_TLV_OK)
      return TC_TLV_INVALID;
    if (index == 0) {
      result = utf8_string(element.value, 64);
      if (result != TC_TLV_OK)
        return result;
      out->title = element.value;
    } else if (index == 1) {
      result = cert_path_controls(element.value, limits, workspace, out, spki, out->key_id);
      if (result != TC_TLV_OK)
        return result;
      out->x509_unusable = 0;
    } else if (index == 2) {
      TC_TLV_element inner;
      result = TC_TLV_read(element.value.data, element.value.length, TC_TLV_DER, limits, &inner);
      if (result != TC_TLV_OK || !tc_pki_tag(&inner, 0x30) ||
          inner.encoded.length != element.value.length)
        return TC_TLV_INVALID;
      out->extensions = inner.value;
      /* Path-control extensions are rejected here, so only basicConstraints
       * can refine the anchor. */
      TC_X509_store_anchor overrides = {0};
      result = extensions(inner.encoded, limits, workspace, 1, &overrides);
      if (result != TC_TLV_OK)
        return result;
      if (overrides.has_path_len) {
        out->path_len = overrides.path_len;
        out->has_path_len = 1;
      }
    } else {
      result = utf8_string(element.value, SIZE_MAX);
      if (result != TC_TLV_OK)
        return result;
      out->title_language = element.value;
    }
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
  result = TC_TLV_walk(data, length, TC_TLV_DER, limits,
                       (TC_TLV_frames){workspace->frames, workspace->frame_capacity}, NULL, NULL);
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
  if (!reader || !limits || !workspace || !out || reader->profile != TC_TLV_DER)
    return TC_TLV_ARGUMENT;
  next = *reader;
  result = TC_TLV_next(&next, &choice);
  if (result != TC_TLV_OK)
    return result;
  if (tc_pki_tag(&choice, 0x30)) {
#if TC_TAF_ENABLE_CERTIFICATE
    TC_X509_certificate certificate;
    result = tc_x509_certificate_read(choice.encoded, 0x30, limits, workspace, &certificate);
    if (result == TC_TLV_OK)
      result = certificate_anchor(&certificate, limits, workspace, &parsed);
    if (result != TC_TLV_OK)
      return result;
#else
    return TC_TLV_UNSUPPORTED;
#endif
  } else if (tc_pki_tag(&choice, 0xa1)) {
#if TC_TAF_ENABLE_TBS_CERTIFICATE
    /* tbsCert [1] EXPLICIT TBSCertificate. */
    TC_X509_certificate certificate;
    result = tc_x509_tbs_read(choice.value, limits, workspace, &certificate);
    if (result == TC_TLV_OK)
      result = certificate_anchor(&certificate, limits, workspace, &parsed);
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
