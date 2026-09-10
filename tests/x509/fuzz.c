/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/x509_workspace.h"
#include "../../src/cms_internal.h"
#include "../../src/pki_distribution_internal.h"
#include "../../src/pki_tree_internal.h"
#include "../../src/string_internal.h"
#include "../../src/unicode_internal.h"
#include "../../src/x509_crl_internal.h"
#include "../../src/x509_path_internal.h"
#include <stdlib.h>
#include <string.h>
#include <tiny_crypto/eac_cvc.h>
#include <tiny_crypto/fascn.h>
#include <tiny_crypto/lds.h>
#include <tiny_crypto/piv_card.h>
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_chuid.h>
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_security.h>
#include <tiny_crypto/twic_uuid.h>
#include <tiny_crypto/x509.h>
#include <tiny_crypto/x509_path.h>

typedef struct {
  uint64_t hash;
  size_t count;
} scalar_digest;

static void check_borrowed_span(TC_bytes input, TC_bytes span) {
  if (!span.length)
    return;
  uintptr_t start = (uintptr_t)input.data, borrowed = (uintptr_t)span.data;
  if (borrowed < start || borrowed - start > input.length ||
      span.length > input.length - (size_t)(borrowed - start))
    abort();
}

static void fuzz_certificate_container(const uint8_t *data, size_t length) {
  const TC_bytes input = {data, length};
  for (int profile = TC_PIV_CERTIFICATE_SLOT;
       profile <= TC_PIV_CERTIFICATE_SM_SIGNER; ++profile) {
    TC_PIV_certificate certificate, saved;
    memset(&certificate, 0xa5, sizeof certificate);
    memcpy(&saved, &certificate, sizeof saved);
    TC_TLV_result result = TC_PIV_certificate_read(
        input, (TC_PIV_certificate_profile)profile, &certificate);
    if (result != TC_TLV_OK) {
      if (memcmp(&certificate, &saved, sizeof certificate))
        abort();
      continue;
    }
    if (!certificate.certificate.length ||
        (certificate.compression != TC_PIV_CERTIFICATE_PLAIN &&
         certificate.compression != TC_PIV_CERTIFICATE_GZIP))
      abort();
    check_borrowed_span(input, certificate.certificate);
    check_borrowed_span(input, certificate.intermediate_cvc);
    if (profile != TC_PIV_CERTIFICATE_SM_SIGNER &&
        certificate.intermediate_cvc.length)
      abort();
  }
}

static void fuzz_card_identifiers(const uint8_t *data, size_t length) {
  enum { FRAMES = 8, MAX_BYTES = 32768, MAX_ELEMENTS = 512, WORK = 200000 };
  const TC_TLV_limits limits = {MAX_BYTES, MAX_BYTES, MAX_ELEMENTS, FRAMES};
  const TC_bytes input = {data, length};
  TC_TLV_frame frames[FRAMES];
  TC_PIV_card_identifiers out, saved;
  memset(&saved, 0xa5, sizeof saved);
  for (int profile = TC_PIV_CARD; profile <= TC_TWIC_NEXGEN_CARD; ++profile) {
    const size_t budgets[] = {WORK, length ? data[0] : 0};
    for (size_t i = 0; i < sizeof budgets / sizeof *budgets; ++i) {
      size_t work = budgets[i];
      memcpy(&out, &saved, sizeof out);
      TC_TLV_result result =
          TC_PIV_card_identifiers_read(input, (TC_PIV_card_profile)profile,
                                       &limits, frames, FRAMES, &work, &out);
      if (work > budgets[i])
        abort();
      if (result != TC_TLV_OK) {
        if (memcmp(&out, &saved, sizeof out))
          abort();
        continue;
      }
      check_borrowed_span(input, out.fascn);
      check_borrowed_span(input, out.fascn_oid);
      check_borrowed_span(input, out.uuid_urn);
      if (out.cardholder_uuid_urn.data || out.cardholder_uuid_urn.length)
        abort();
      if (out.fascn.length != 25 ||
          (out.uuid_urn.length && out.uuid_urn.length != 45))
        abort();
      uint8_t nil[16] = {0};
      int matched = -1;
      work = WORK;
      if (TC_PIV_card_identifiers_match(&out, out.fascn,
                                        (TC_bytes){nil, sizeof nil}, &work,
                                        &matched) != TC_TLV_OK)
        abort();
      if (matched != (profile == TC_TWIC_LEGACY_CARD))
        abort();
    }
  }
  uint8_t expected_guid[16] = {0};
  if (length >= sizeof expected_guid)
    memcpy(expected_guid, data, sizeof expected_guid);
  typedef TC_TLV_result (*authentication_reader)(
      TC_bytes, TC_bytes, const TC_TLV_limits *, TC_TLV_frame *, size_t,
      size_t *, TC_PIV_card_identifiers *);
  static const authentication_reader readers[] = {
      TC_PIV_authentication_identifiers_read,
      TC_TWIC_authentication_identifiers_read};
  const size_t authentication_budgets[] = {WORK, length ? data[0] : 0};
  for (size_t reader = 0; reader < sizeof readers / sizeof *readers; ++reader) {
    for (size_t i = 0;
         i < sizeof authentication_budgets / sizeof *authentication_budgets;
         ++i) {
      size_t work = authentication_budgets[i];
      memcpy(&out, &saved, sizeof out);
      const TC_TLV_result result = readers[reader](
          input, (TC_bytes){expected_guid, sizeof expected_guid}, &limits,
          frames, FRAMES, &work, &out);
      if (work > authentication_budgets[i])
        abort();
      if (result != TC_TLV_OK) {
        if (memcmp(&out, &saved, sizeof out))
          abort();
        continue;
      }
      check_borrowed_span(input, out.fascn);
      check_borrowed_span(input, out.fascn_oid);
      check_borrowed_span(input, out.uuid_urn);
      check_borrowed_span(input, out.cardholder_uuid_urn);
    }
  }
}

static void fuzz_identity_codecs(TC_bytes input) {
  TC_FASCN decoded, saved;
  memset(&saved, 0xa5, sizeof saved);
  memcpy(&decoded, &saved, sizeof decoded);
  TC_TLV_result result = TC_FASCN_read(input, &decoded);
  if (result == TC_TLV_OK) {
    uint8_t encoded[TC_FASCN_BYTES];
    if (TC_FASCN_write(&decoded, encoded, sizeof encoded) != TC_TLV_OK ||
        input.length != sizeof encoded ||
        memcmp(input.data, encoded, sizeof encoded))
      abort();
  } else if (memcmp(&decoded, &saved, sizeof decoded))
    abort();

  uint64_t number = UINT64_MAX;
  result = TC_TWIC_uuid_read(input, &number);
  if (result == TC_TLV_OK) {
    uint8_t encoded[TC_TWIC_UUID_BYTES];
    if (TC_TWIC_uuid_write(number, encoded, sizeof encoded) != TC_TLV_OK ||
        input.length != sizeof encoded ||
        memcmp(input.data, encoded, sizeof encoded))
      abort();
  } else if (number != UINT64_MAX)
    abort();
}

static void fuzz_security_container(TC_bytes input) {
  for (int encoding = TC_PIV_SECURITY_CONTENTS;
       encoding <= TC_PIV_SECURITY_CONTAINER; ++encoding) {
    TC_PIV_security_object object, saved;
    memset(&saved, 0xa5, sizeof saved);
    memcpy(&object, &saved, sizeof object);
    TC_TLV_result result = TC_PIV_security_read(
        input, (TC_PIV_security_encoding)encoding, &object);
    if (result != TC_TLV_OK) {
      if (memcmp(&object, &saved, sizeof object))
        abort();
      continue;
    }
    check_borrowed_span(input, object.mapping);
    check_borrowed_span(input, object.cms);
    if (!object.mapping.length || object.mapping.length % 3 ||
        !object.cms.length)
      abort();
    uint16_t groups = 0;
    for (size_t i = 0; i < object.mapping.length; i += 3) {
      const unsigned expected = object.mapping.data[i];
      const uint16_t container =
          (uint16_t)((unsigned)object.mapping.data[i + 1] << 8 |
                     object.mapping.data[i + 2]);
      unsigned number = 0;
      if (expected < 1 || expected > TC_LDS_MAX_GROUPS ||
          TC_PIV_security_group_find(&object, container, &number) !=
              TC_TLV_OK ||
          number != expected)
        abort();
      const uint16_t bit = (uint16_t)(1u << (expected - 1));
      if (groups & bit)
        abort();
      groups |= bit;
    }
    if (groups != object.groups)
      abort();
  }
}

static void fuzz_lds(TC_bytes input) {
  enum {
    FRAMES = 16,
    MAX_BYTES = 32768,
    MAX_ELEMENTS = 512,
    WORK = 200000,
    CONTENT_BYTES = 2048
  };
  const TC_TLV_limits limits = {MAX_BYTES, MAX_BYTES, MAX_ELEMENTS, FRAMES};
  TC_TLV_frame frames[FRAMES];
  uint8_t content[CONTENT_BYTES];
  TC_LDS_security_object object, saved;
  memset(&saved, 0xa5, sizeof saved);
  const size_t budgets[] = {WORK, input.length ? input.data[0] : 0};
  for (unsigned wrapped = 0; wrapped < 2; ++wrapped) {
    for (size_t i = 0; i < sizeof budgets / sizeof *budgets; ++i) {
      size_t work = budgets[i];
      memcpy(&object, &saved, sizeof object);
      TC_TLV_result result =
          wrapped ? TC_LDS_read_content(input, &limits, frames, FRAMES, &work,
                                        content, sizeof content, &object)
                  : TC_LDS_read(input, &limits, frames, FRAMES, &work, &object);
      if (work > budgets[i])
        abort();
      if (result != TC_TLV_OK) {
        if (memcmp(&object, &saved, sizeof object))
          abort();
        continue;
      }
      const TC_bytes backing = wrapped && object.encoded.data == content
                                   ? (TC_bytes){content, sizeof content}
                                   : input;
      check_borrowed_span(backing, object.encoded);
      check_borrowed_span(object.encoded, object.hashes);
      check_borrowed_span(object.encoded, object.lds_version);
      check_borrowed_span(object.encoded, object.unicode_version);
      for (unsigned number = 1; number <= TC_LDS_MAX_GROUPS; ++number) {
        TC_bytes hash = {NULL, 99};
        work = WORK;
        result = TC_LDS_hash_find(&object, number, &limits, frames, FRAMES,
                                  &work, &hash);
        if (work > WORK)
          abort();
        if (object.groups & (1u << (number - 1))) {
          if (result != TC_TLV_OK || !hash.length)
            abort();
          check_borrowed_span(object.encoded, hash);
        } else if (result != TC_TLV_END || hash.data || hash.length != 99)
          abort();
      }
    }
  }
}

static TC_TLV_result digest_scalar(void *context, uint32_t point) {
  scalar_digest *digest = context;
  /* Order-sensitive checksum for comparing the two decoder entry points. */
  digest->hash = digest->hash * UINT64_C(65599) + point;
  ++digest->count;
  return TC_TLV_OK;
}

static void fuzz_string_chunks(unsigned tag, TC_bytes input) {
  tc_asn1_string_state decoder = {tag, {0}, 0};
  scalar_digest contiguous = {0, 0}, chunked = {0, 0};
  TC_TLV_result complete, partial;
  uint32_t point;
  size_t offset = 0;
  const size_t split = input.length ? input.data[0] % (input.length + 1) : 0;
  if (tag == 0x14)
    return;
  while ((complete = tc_asn1_string_next(tag, input, &offset, &point)) ==
         TC_TLV_OK)
    digest_scalar(&contiguous, point);
  partial = tc_asn1_string_feed(&decoder, (TC_bytes){input.data, split},
                                digest_scalar, &chunked);
  if (partial == TC_TLV_OK)
    partial = tc_asn1_string_feed(
        &decoder, (TC_bytes){input.data + split, input.length - split},
        digest_scalar, &chunked);
  if (partial == TC_TLV_OK && decoder.used)
    partial = TC_TLV_INVALID;
  if (complete == TC_TLV_END) {
    if (partial != TC_TLV_OK || contiguous.count != chunked.count ||
        contiguous.hash != chunked.hash)
      abort();
  } else if (partial == TC_TLV_OK)
    abort();
}

/* Bypass cryptography here so DER mutations reach the path's structural checks.
 */
static TC_X509_signature_result
structural_signature(void *context, const TC_bytes *message, size_t count,
                     const TC_DER_algorithm *algorithm, TC_bytes signature,
                     const TC_X509_public_key *issuer_key, size_t *work) {
  (void)context;
  (void)message;
  (void)count;
  (void)algorithm;
  (void)signature;
  (void)issuer_key;
  if (!*work)
    return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return TC_X509_SIGNATURE_VALID;
}

static void fuzz_path(const uint8_t *data, size_t length,
                      const TC_X509_certificate *certificate) {
  static const uint8_t any_policy[] = {0x55, 0x1d, 0x20, 0};
  const TC_bytes initial = {any_policy, sizeof any_policy},
                 chain = {data, length};
  TC_TLV_frame frames[16];
  TC_bytes oids[16], policies[16];
  uint32_t left[64], right[64];
  uint8_t matched[8];
  TC_X509_policy_node nodes[32];
  TC_X509_policy_edge edges[64];
  TC_X509_policy_expected expected[64];
  TC_X509_policy_mapping mappings[16];
  TC_X509_path_workspace workspace =
      TC_X509_PATH_WORKSPACE_INIT(frames, oids, left, right, matched, nodes,
                                  edges, expected, mappings, policies);
  TC_X509_path_options options = {0};
  TC_X509_trust_anchor anchor = {0};
  TC_X509_path_result output, saved;
  TC_X509_path_status status;
  options.at.year = 2026;
  options.at.month = 1;
  options.at.day = 1;
  options.parsing = (TC_TLV_limits){32768, 32768, 2048, 16};
  options.max_certificates = 1;
  options.max_input = 32768;
  options.max_work = 200000;
  options.signatures.verify = structural_signature;
  options.initial_policies = &initial;
  options.initial_policy_count = 1;
  if (certificate) {
    anchor.name = certificate->issuer;
    anchor.public_key = certificate->public_key;
    options.at = certificate->not_before;
  }
  memset(&output, 0xa5, sizeof output);
  memcpy(&saved, &output, sizeof saved);
  status =
      TC_X509_path_validate(&chain, 1, &anchor, &options, &workspace, &output);
  if (status == TC_X509_PATH_VALID) {
    if (!certificate ||
        output.public_key.key.data != certificate->public_key.key.data ||
        output.public_key.key.length != certificate->public_key.key.length ||
        output.policies != policies || output.policy_count > 16 ||
        output.work_used > options.max_work)
      abort();
  } else if (memcmp(&output, &saved, sizeof output))
    abort();
  /* Exercise exhausted budgets with the same borrowed DER and scratch arrays.
   */
  options.max_work = length ? data[length - 1] : 0;
  memcpy(&output, &saved, sizeof output);
  status =
      TC_X509_path_validate(&chain, 1, &anchor, &options, &workspace, &output);
  if (status != TC_X509_PATH_VALID && memcmp(&output, &saved, sizeof output))
    abort();
  {
    TC_TLV_reader objects;
    TC_TLV_element element;
    TC_bytes candidates[4], path[4];
    tc_x509_search_frame search_frames[4];
    tc_x509_search_workspace search = {path, search_frames, 4};
    tc_x509_search_result found, unchanged;
    TC_X509_workspace parser = {frames, 16, oids, 16};
    TC_X509_certificate selected;
    size_t count = 0, work;
    options.max_certificates = 4;
    options.max_work = 200000;
    if (TC_TLV_reader_init(&objects, data, length, TC_TLV_DER,
                           &options.parsing) != TC_TLV_OK)
      return;
    while (count < 4 && TC_TLV_next(&objects, &element) == TC_TLV_OK)
      candidates[count++] = element.encoded;
    if (!count)
      return;
    if (TC_X509_read(candidates[0].data, candidates[0].length, &options.parsing,
                     &parser, &selected) != TC_TLV_OK)
      return;
    options.at = selected.not_before;
    if (TC_X509_read(candidates[count - 1].data, candidates[count - 1].length,
                     &options.parsing, &parser, &selected) != TC_TLV_OK)
      return;
    /* The final record supplies the test's trust anchor. */
    anchor.name = selected.subject;
    anchor.public_key = selected.public_key;
    memset(&found, 0xa5, sizeof found);
    memcpy(&unchanged, &found, sizeof found);
    work = options.max_work;
    status = tc_x509_path_search(candidates[0], candidates, count, &anchor, 1,
                                 &options, &workspace, &search, &work, &found);
    if (status == TC_X509_PATH_VALID) {
      size_t i, j;
      if (!found.count || found.count > 4 ||
          found.path != path + 4 - found.count || found.anchor_index ||
          found.validation.work_used != options.max_work - work ||
          found.path[found.count - 1].data != candidates[0].data)
        abort();
      for (i = 0; i < found.count; ++i) {
        for (j = 0; j < count; ++j)
          if (found.path[i].data == candidates[j].data &&
              found.path[i].length == candidates[j].length)
            break;
        if (j == count)
          abort();
      }
    } else if (memcmp(&found, &unchanged, sizeof found))
      abort();
    memcpy(&found, &unchanged, sizeof found);
    work = data[length - 1];
    status = tc_x509_path_search(candidates[0], candidates, count, &anchor, 1,
                                 &options, &workspace, &search, &work, &found);
    if (status != TC_X509_PATH_VALID &&
        memcmp(&found, &unchanged, sizeof found))
      abort();
  }
}

static void fuzz_cms_path(const uint8_t *data, size_t length) {
  enum {
    MAX_BYTES = 32768,
    MAX_ELEMENTS = 2048,
    WORK_BUDGET = 200000,
    CERTIFICATES = 8
  };
  static const uint8_t data_type[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 1,    7,    1};
  ExampleX509SearchWorkspace storage;
  TC_bytes certificates[CERTIFICATES];
  TC_CMS_path_workspace workspace = {
      example_x509_workspace(&storage.validation),
      example_x509_search_workspace(&storage),
      certificates,
      CERTIFICATES,
      NULL,
      0};
  TC_CMS_path_options options = {0};
  const TC_X509_store_source source = {0};
  TC_X509_search_result found, saved;
  options.path.parsing = (TC_TLV_limits){MAX_BYTES, MAX_BYTES, MAX_ELEMENTS,
                                         workspace.validation.frame_capacity};
  options.path.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  options.path.max_certificates = workspace.search.capacity;
  options.path.max_input = MAX_BYTES;
  options.max_candidates = CERTIFICATES;
  options.max_candidate_bytes = MAX_BYTES;
  const size_t budgets[] = {WORK_BUDGET, length ? data[0] : 0};
  memset(&saved, 0xa5, sizeof saved);
  for (size_t i = 0; i < sizeof budgets / sizeof *budgets; ++i) {
    size_t work = budgets[i];
    memcpy(&found, &saved, sizeof found);
    options.attributes =
        i ? TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER : TC_CMS_ATTRIBUTES_DER;
    TC_X509_path_status status = TC_CMS_signed_data_path_build(
        (TC_bytes){data, length}, 0, (TC_bytes){data_type, sizeof data_type},
        (TC_bytes){NULL, 0}, &source, &options, &workspace, &work, &found);
    /* No anchor was supplied, even if embedded certificates parse successfully.
     */
    if (status == TC_X509_PATH_VALID || work > budgets[i] ||
        memcmp(&found, &saved, sizeof found))
      abort();
  }
}

static void fuzz_cms(const uint8_t *data, size_t length) {
  enum {
    MAX_BYTES = 32768,
    MAX_ELEMENTS = 2048,
    FRAME_CAPACITY = 16,
    WORK_BUDGET = 200000
  };
  const TC_TLV_limits limits = {MAX_BYTES, MAX_BYTES, MAX_ELEMENTS,
                                FRAME_CAPACITY};
  const TC_TLV_profile profiles[] = {TC_TLV_DER, TC_TLV_BER};
  TC_TLV_frame frames[FRAME_CAPACITY];
  tc_cms_signer_info signer, saved;
  tc_cms_signed_data container, saved_container;
  TC_TLV_result result;
  size_t work = WORK_BUDGET;
  fuzz_cms_path(data, length);
  memset(&container, 0xa5, sizeof container);
  memcpy(&saved_container, &container, sizeof container);
  result = tc_cms_signed_data_read((TC_bytes){data, length}, &limits, frames,
                                   FRAME_CAPACITY, &work, &container);
  if (result != TC_TLV_OK &&
      memcmp(&container, &saved_container, sizeof container))
    abort();
  if (result == TC_TLV_OK) {
    const tc_pki_tree_workspace tree = {frames, FRAME_CAPACITY, &work};
    work = WORK_BUDGET;
    result = tc_cms_signed_data_version_check(&container, &limits, &tree);
    if (work > WORK_BUDGET)
      abort();
    if (result == TC_TLV_OK && container.version != 1 &&
        container.version != 3 && container.version != 4 &&
        container.version != 5)
      abort();
    work = length ? data[0] : 0;
    const size_t budget = work;
    (void)tc_cms_signed_data_version_check(&container, &limits, &tree);
    if (work > budget)
      abort();
  }
  for (unsigned kind = TC_CMS_OTHER_CERTIFICATE;
       kind <= TC_CMS_OTHER_REVOCATION; ++kind) {
    const size_t budgets[] = {WORK_BUDGET, length ? data[0] : 0};
    for (size_t j = 0; j < sizeof budgets / sizeof budgets[0]; ++j) {
      tc_cms_other_format other, previous;
      const tc_pki_tree_workspace tree = {frames, FRAME_CAPACITY, &work};
      memset(&other, 0xa5, sizeof other);
      memcpy(&previous, &other, sizeof previous);
      work = budgets[j];
      result = tc_cms_other_format_read((TC_bytes){data, length},
                                        (tc_cms_other_kind)kind, &limits, &tree,
                                        &other);
      if (work > budgets[j])
        abort();
      if (result != TC_TLV_OK && memcmp(&other, &previous, sizeof other))
        abort();
      if (result == TC_TLV_OK && (!other.format.length || !other.value.length))
        abort();
    }
  }
  for (size_t i = 0; i < sizeof profiles / sizeof *profiles; ++i) {
    const size_t budgets[] = {WORK_BUDGET, length ? data[0] : 0};
    for (size_t j = 0; j < sizeof budgets / sizeof *budgets; ++j) {
      work = budgets[j];
      memset(&signer, 0xa5, sizeof signer);
      memcpy(&saved, &signer, sizeof signer);
      result = tc_cms_signer_info_read((TC_bytes){data, length}, profiles[i],
                                       &limits, frames, FRAME_CAPACITY, &work,
                                       &signer);
      if (work > budgets[j])
        abort();
      if (result != TC_TLV_OK && memcmp(&signer, &saved, sizeof signer))
        abort();
      if (result == TC_TLV_OK && (signer.version != 1 && signer.version != 3))
        abort();
      {
        tc_pki_pss_parameters parameters, previous;
        const tc_pki_tree_workspace tree = {frames, FRAME_CAPACITY, &work};
        memset(&parameters, 0xa5, sizeof parameters);
        memcpy(&previous, &parameters, sizeof previous);
        work = budgets[j];
        result = tc_pki_pss_read_profile((TC_bytes){data, length}, profiles[i],
                                         &limits, &tree, &parameters);
        if (work > budgets[j])
          abort();
        if (result != TC_TLV_OK &&
            memcmp(&parameters, &previous, sizeof parameters))
          abort();
        if (result == TC_TLV_OK &&
            (!parameters.salt_length.length || !parameters.hash.oid.length ||
             !parameters.mgf_hash.oid.length))
          abort();
      }
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length) {
  TC_TLV_frame frames[16];
  TC_bytes oids[64];
  TC_X509_workspace workspace = {frames, 16, oids, 64};
  TC_TLV_limits limits = {32768, 32768, 2048, 16};
  TC_X509_certificate certificate, saved;
  TC_X509_public_key key;
  TC_X509_basic_constraints constraints;
  TC_PIV_CHUID chuid, old_chuid;
  TC_PIV_CVC cvc, old_cvc;
  TC_TLV_reader reader;
  TC_X509_extension extension;
  uint16_t usage;
  TC_TLV_result result;
  int encoding, profile;
  if (length > limits.max_input)
    return 0;
  fuzz_certificate_container(data, length);
  fuzz_card_identifiers(data, length);
  fuzz_identity_codecs((TC_bytes){data, length});
  fuzz_security_container((TC_bytes){data, length});
  fuzz_lds((TC_bytes){data, length});
  {
    TC_bytes number = {NULL, 99};
    TC_X509_time date, previous;
    unsigned reason = 99;
    const TC_bytes input = {data, length};
    result = tc_x509_crl_number_read(input, &number);
    if (result == TC_TLV_OK) {
      if (!number.length || (number.data[0] & 0x80))
        abort();
    } else if (number.data || number.length != 99)
      abort();
    result = tc_x509_crl_reason_read(input, &reason);
    if (result == TC_TLV_OK) {
      if (reason > 10 || reason == 7)
        abort();
    } else if (reason != 99)
      abort();
    memset(&date, 0xa5, sizeof date);
    memcpy(&previous, &date, sizeof previous);
    result = tc_x509_crl_invalidity_date_read(input, &date);
    if (result != TC_TLV_OK && memcmp(&date, &previous, sizeof date))
      abort();
  }
  {
    tc_x509_crl crl, previous;
    size_t work;
    const tc_pki_tree_workspace tree = {
        frames, sizeof frames / sizeof frames[0], &work};
    const size_t budgets[] = {200000, length ? data[0] : 0};
    for (size_t i = 0; i < sizeof budgets / sizeof budgets[0]; ++i) {
      work = budgets[i];
      memset(&crl, 0xa5, sizeof crl);
      memcpy(&previous, &crl, sizeof previous);
      result = tc_x509_crl_read((TC_bytes){data, length}, &limits, &tree, &crl);
      if (work > budgets[i])
        abort();
      if (result != TC_TLV_OK && memcmp(&crl, &previous, sizeof crl))
        abort();
      if (result == TC_TLV_OK &&
          (crl.version < 1 || crl.version > 2 || !crl.tbs.length ||
           !crl.issuer.length || !crl.signature.length))
        abort();
      if (result == TC_TLV_OK) {
        work = budgets[i];
        (void)tc_x509_crl_extensions_check(&crl, &limits, &tree, oids,
                                           sizeof oids / sizeof oids[0]);
        if (work > budgets[i])
          abort();
      }
      tc_x509_crl_distribution distribution, saved_distribution;
      memset(&distribution, 0xa5, sizeof distribution);
      saved_distribution = distribution;
      work = budgets[i];
      result = tc_x509_crl_distribution_read((TC_bytes){data, length}, &limits,
                                             &tree, &distribution);
      if (work > budgets[i])
        abort();
      if (result != TC_TLV_OK &&
          memcmp(&distribution, &saved_distribution, sizeof distribution))
        abort();
      if (result == TC_TLV_OK && distribution.user_only + distribution.ca_only +
                                         distribution.attribute_only >
                                     1)
        abort();
      tc_x509_crl_extension_info info, saved_info;
      memset(&info, 0xa5, sizeof info);
      saved_info = info;
      work = budgets[i];
      result = tc_x509_crl_extension_info_read(
          (TC_bytes){data, length}, &limits, &tree, oids,
          sizeof oids / sizeof oids[0], &info);
      if (work > budgets[i])
        abort();
      if (result != TC_TLV_OK && memcmp(&info, &saved_info, sizeof info))
        abort();
      if (result == TC_TLV_OK && (info.critical & ~info.present))
        abort();
      TC_TLV_reader points;
      work = budgets[i];
      result = tc_pki_distribution_points_init((TC_bytes){data, length},
                                               &limits, &tree, &points);
      if (work > budgets[i])
        abort();
      if (result == TC_TLV_OK) {
        do {
          const TC_TLV_reader saved_points = points;
          tc_pki_distribution_point point, saved_point;
          memset(&point, 0xa5, sizeof point);
          saved_point = point;
          result = tc_pki_distribution_point_next(&points, &tree, &point);
          if (work > budgets[i])
            abort();
          if (result != TC_TLV_OK &&
              (memcmp(&points, &saved_points, sizeof points) ||
               memcmp(&point, &saved_point, sizeof point)))
            abort();
          if (result == TC_TLV_OK &&
              (!point.name.encoded.length && !point.issuer.length))
            abort();
          if (result == TC_TLV_OK && points.offset <= saved_points.offset)
            abort();
        } while (result == TC_TLV_OK);
      }
    }
  }
  fuzz_cms(data, length);
  {
    TC_bytes input = {data, length}, rdn = {NULL, 0}, old_rdn;
    TC_TLV_reader names, old_names;
    uint32_t left[128], right[128];
    uint8_t matched_attributes[8];
    TC_X509_name_workspace comparison = {left, right, 128, matched_attributes,
                                         8};
    size_t work = 200000;
    int equal = 99;
    {
      static const uint8_t root_name[] = {0x30, 0};
      const TC_bytes root = {root_name, sizeof root_name};
      const tc_pki_tree_workspace tree = {
          frames, sizeof frames / sizeof frames[0], &work};
      result = tc_pki_name_appended_equal(root, input, root, input, &limits,
                                          &comparison, &tree, &equal);
      if (result == TC_TLV_OK) {
        if (equal != 1)
          abort();
      } else if (equal != 99)
        abort();
      if (work > 200000)
        abort();
      work = 200000;
      equal = 99;
    }
    result =
        TC_X509_name_equal(input, input, &limits, &comparison, &work, &equal);
    if (result == TC_TLV_OK) {
      if (equal != 1)
        abort();
    } else if (equal != 99)
      abort();
    work = 200000;
    equal = 99;
    result =
        TC_X509_name_within(input, input, &limits, &comparison, &work, &equal);
    if (result == TC_TLV_OK) {
      if (equal != 1)
        abort();
    } else if (equal != 99)
      abort();
    {
      enum { NAME_WORK_BUDGET = 200000 };
      const size_t budgets[] = {NAME_WORK_BUDGET, length ? data[0] : 0};
      const tc_pki_tree_workspace tree = {
          frames, sizeof frames / sizeof frames[0], &work};
      for (size_t i = 0; i < sizeof budgets / sizeof budgets[0]; ++i) {
        work = budgets[i];
        equal = 99;
        result = tc_pki_name_equal(input, TC_TLV_BER, input, TC_TLV_BER,
                                   &limits, &comparison, &tree, &equal);
        if (work > budgets[i])
          abort();
        if (result == TC_TLV_OK) {
          if (equal != 1)
            abort();
        } else if (equal != 99)
          abort();
      }
    }
    if (TC_X509_name_init(&names, input, &limits) == TC_TLV_OK) {
      do {
        old_names = names;
        old_rdn = rdn;
        result = TC_X509_rdn_next(&names, &rdn);
        if (result == TC_TLV_OK) {
          TC_TLV_reader attributes;
          TC_X509_name_attribute attribute;
          TC_TLV_result inner;
          if (names.offset <= old_names.offset ||
              names.elements > limits.max_elements)
            abort();
          if (TC_TLV_reader_init(&attributes, rdn.data, rdn.length, TC_TLV_DER,
                                 &limits) != TC_TLV_OK)
            abort();
          while ((inner = TC_X509_attribute_next(&attributes, &attribute)) ==
                 TC_TLV_OK) {
          }
          if (inner != TC_TLV_END)
            abort();
        } else if (memcmp(&names, &old_names, sizeof names) ||
                   rdn.data != old_rdn.data || rdn.length != old_rdn.length)
          abort();
      } while (result == TC_TLV_OK);
    }
  }
  {
    static const unsigned tags[] = {0x0c, 0x13, 0x16, 0x1c, 0x1e, 0x14};
    TC_bytes text = {data, length};
    uint32_t prepared[128], point = 99;
    size_t written = 999, work = 2000, offset = 0, steps = 0;
    const unsigned tag = tags[length ? data[0] % 6 : 0];
    fuzz_string_chunks(tag, text);
    result = tc_unicode_prepare(tag, text, prepared, 128, &written, &work);
    if (result == TC_TLV_OK) {
      size_t i;
      if (written < 2 || written > 128 || prepared[0] != 0x20 ||
          prepared[written - 1] != 0x20)
        abort();
      for (i = 0; i < written; ++i)
        if (!tc_unicode_allowed(prepared[i]))
          abort();
    } else if (written != 999)
      abort();
    do {
      size_t old_offset = offset;
      uint32_t old_point = point;
      result = tc_asn1_string_next(tag, text, &offset, &point);
      if (result == TC_TLV_OK) {
        if (offset <= old_offset || offset > length || point > 0x10ffff ||
            (point >= 0xd800 && point <= 0xdfff))
          abort();
      } else if (offset != old_offset || point != old_point)
        abort();
    } while (result == TC_TLV_OK && ++steps < 128);
  }
  {
    uint32_t points[64], normalized[128], again[256];
    size_t count = length / 3, i, written = 999, repeated = 999;
    size_t work = length ? (size_t)data[0] * 32 : 0;
    size_t capacity = length > 1 ? data[1] % 129 : 128;
    if (count > 64)
      count = 64;
    for (i = 0; i < count; ++i) {
      uint32_t mapped[4];
      points[i] = ((uint32_t)data[3 * i] << 16 |
                   (uint32_t)data[3 * i + 1] << 8 | data[3 * i + 2]) %
                  0x110100;
      if (tc_unicode_map(points[i], mapped) > 4)
        abort();
      (void)tc_unicode_allowed(points[i]);
      (void)tc_unicode_mark(points[i]);
    }
    result =
        tc_unicode_nfkc(points, count, normalized, capacity, &written, &work);
    if (result == TC_TLV_OK) {
      if (written > capacity)
        abort();
      work = 100000;
      result =
          tc_unicode_nfkc(normalized, written, again, 256, &repeated, &work);
      if (result != TC_TLV_OK || repeated != written ||
          memcmp(normalized, again, written * sizeof(*normalized)))
        abort();
      work = 100000;
      repeated = 999;
      result =
          tc_unicode_finish_name(normalized, written, 128, &repeated, &work);
      if (result == TC_TLV_OK) {
        if (repeated < 2 || repeated > 128 || normalized[0] != 0x20 ||
            normalized[repeated - 1] != 0x20)
          abort();
        for (i = 0; i < repeated; ++i)
          if (!tc_unicode_allowed(normalized[i]))
            abort();
      } else if (repeated != 999)
        abort();
    } else if (written != 999)
      abort();
  }
  memset(&certificate, 0xa5, sizeof certificate);
  saved = certificate;
  result = TC_X509_read(data, length, &limits, &workspace, &certificate);
  fuzz_path(data, length, result == TC_TLV_OK ? &certificate : NULL);
  if (result == TC_TLV_OK) {
    if (certificate.encoded.data != data ||
        certificate.encoded.length != length || certificate.version < 1 ||
        certificate.version > 3)
      abort();
    if (TC_X509_extensions_init(&reader, certificate.extensions.data,
                                certificate.extensions.length,
                                &limits) != TC_TLV_OK)
      abort();
    while ((result = TC_X509_extension_next(&reader, &extension)) ==
           TC_TLV_OK) {
    }
    if (result != TC_TLV_END)
      abort();
    {
      const TC_X509_name_constraints names = {{NULL, 0}, {NULL, 0}};
      TC_X509_constraint_workspace scratch = {frames, 16, NULL};
      size_t work = 200000;
      int permitted = 99;
      result = TC_X509_certificate_names_check(&certificate, &names, &limits,
                                               &scratch, &work, &permitted);
      if (result != TC_TLV_OK && permitted != 99)
        abort();
      if (result == TC_TLV_OK && permitted != 1)
        abort();
    }
  } else if (memcmp(&certificate, &saved, sizeof certificate))
    abort();
  (void)TC_X509_subject_public_key(data, length, &key);
  (void)TC_X509_basic_constraints_read(data, length, &constraints);
  (void)TC_X509_key_usage_read(data, length, &usage);
  {
    TC_X509_authority_key_identifier identifier, old_identifier;
    TC_bytes subject, old_subject;
    memset(&identifier, 0xa5, sizeof identifier);
    memcpy(&old_identifier, &identifier, sizeof identifier);
    memset(&subject, 0xa5, sizeof subject);
    memcpy(&old_subject, &subject, sizeof subject);
    result = TC_X509_authority_key_identifier_read(data, length, &limits,
                                                   &identifier);
    if (result != TC_TLV_OK &&
        memcmp(&identifier, &old_identifier, sizeof identifier))
      abort();
    result =
        TC_X509_subject_key_identifier_read(data, length, &limits, &subject);
    if (result != TC_TLV_OK && memcmp(&subject, &old_subject, sizeof subject))
      abort();
    (void)TC_DER_integer_contents(data, length);
  }
  {
    TC_X509_policy_constraints policy, old_policy;
    uint32_t number = 99;
    memset(&old_policy, 0xa5, sizeof old_policy);
    memcpy(&policy, &old_policy, sizeof policy);
    result = TC_X509_policy_constraints_read(data, length, &policy);
    if (result != TC_TLV_OK && memcmp(&policy, &old_policy, sizeof policy))
      abort();
    result = TC_DER_uint32_contents(data, length, &number);
    if (result != TC_TLV_OK && number != 99)
      abort();
  }
  {
    TC_bytes purposes[8], old_purposes[8];
    size_t count = 99;
    memset(old_purposes, 0xa5, sizeof old_purposes);
    memcpy(purposes, old_purposes, sizeof purposes);
    result = TC_X509_extended_key_usage_read(data, length, purposes, 8, &count);
    if (result == TC_TLV_OK) {
      if (!count || count > 8)
        abort();
    } else if (count != 99 || memcmp(purposes, old_purposes, sizeof purposes))
      abort();
  }
  if (TC_X509_extensions_init(&reader, data, length, &limits) == TC_TLV_OK)
    while (TC_X509_extension_next(&reader, &extension) == TC_TLV_OK) {
    }
  if (TC_X509_general_names_init(&reader, data, length, &limits) == TC_TLV_OK) {
    TC_X509_general_name general, old_general;
    TC_TLV_reader old_reader;
    memset(&general, 0xa5, sizeof general);
    do {
      memcpy(&old_reader, &reader, sizeof reader);
      memcpy(&old_general, &general, sizeof general);
      result = TC_X509_general_name_next(&reader, frames, 16, &general);
      if (result == TC_TLV_OK) {
        if (reader.offset <= old_reader.offset ||
            reader.elements <= old_reader.elements ||
            reader.elements > limits.max_elements || general.type > 8)
          abort();
      } else if (memcmp(&old_reader, &reader, sizeof reader) ||
                 memcmp(&old_general, &general, sizeof general))
        abort();
    } while (result == TC_TLV_OK);
  }
  {
    TC_X509_name_constraints constraints, old_constraints;
    TC_X509_general_subtree subtree, old_subtree;
    TC_TLV_reader old_reader;
    memset(&constraints, 0xa5, sizeof constraints);
    memcpy(&old_constraints, &constraints, sizeof constraints);
    result = TC_X509_name_constraints_read(data, length, &limits, &constraints);
    if (result != TC_TLV_OK &&
        memcmp(&old_constraints, &constraints, sizeof constraints))
      abort();
    memset(&subtree, 0xa5, sizeof subtree);
    if (TC_TLV_reader_init(&reader, data, length, TC_TLV_DER, &limits) ==
        TC_TLV_OK) {
      do {
        memcpy(&old_reader, &reader, sizeof reader);
        memcpy(&old_subtree, &subtree, sizeof subtree);
        result = TC_X509_general_subtree_next(&reader, frames, 16, &subtree);
        if (result == TC_TLV_OK) {
          if (reader.offset <= old_reader.offset ||
              reader.elements <= old_reader.elements ||
              reader.elements > limits.max_elements || subtree.base.type > 8)
            abort();
        } else if (memcmp(&old_reader, &reader, sizeof reader) ||
                   memcmp(&old_subtree, &subtree, sizeof subtree))
          abort();
      } while (result == TC_TLV_OK);
    }
  }
  if (TC_X509_policy_mappings_init(&reader, data, length, &limits) ==
      TC_TLV_OK) {
    TC_X509_policy_mapping mapping, old_mapping;
    TC_TLV_reader old_reader;
    memset(&mapping, 0xa5, sizeof mapping);
    do {
      memcpy(&old_reader, &reader, sizeof reader);
      memcpy(&old_mapping, &mapping, sizeof mapping);
      result = TC_X509_policy_mapping_next(&reader, &mapping);
      if (result == TC_TLV_OK) {
        if (reader.offset <= old_reader.offset ||
            !mapping.issuer_policy.length || !mapping.subject_policy.length)
          abort();
      } else if (memcmp(&reader, &old_reader, sizeof reader) ||
                 memcmp(&mapping, &old_mapping, sizeof mapping))
        abort();
    } while (result == TC_TLV_OK);
  }
  {
    TC_X509_policy_reader policies, old_policies;
    TC_X509_policy policy, old_policy;
    TC_X509_policy_qualifier qualifier;
    TC_bytes seen[8], old_seen[8];
    memset(seen, 0xa5, sizeof seen);
    memset(&policy, 0xa5, sizeof policy);
    if (TC_X509_policies_init(&policies, data, length, &limits, seen, 8) ==
        TC_TLV_OK) {
      do {
        memcpy(&old_policies, &policies, sizeof policies);
        memcpy(&old_policy, &policy, sizeof policy);
        memcpy(old_seen, seen, sizeof seen);
        result = TC_X509_policy_next(&policies, &policy);
        if (result == TC_TLV_OK) {
          if (policies.count != old_policies.count + 1 || policies.count > 8 ||
              policies.reader.offset <= old_policies.reader.offset)
            abort();
          if (TC_X509_policy_qualifiers_init(&reader, policy.qualifiers,
                                             &limits) != TC_TLV_OK)
            abort();
          while (TC_X509_policy_qualifier_next(&reader, &qualifier) ==
                 TC_TLV_OK) {
          }
        } else if (memcmp(&old_policies, &policies, sizeof policies) ||
                   memcmp(&old_policy, &policy, sizeof policy) ||
                   memcmp(old_seen, seen, sizeof seen))
          abort();
      } while (result == TC_TLV_OK);
    }
  }
  if (length) {
    const unsigned types[] = {0, 1, 2, 6, 7};
    size_t split = data[0] % length, kind;
    for (kind = 0; kind < sizeof types / sizeof types[0]; ++kind) {
      TC_X509_general_name name = {0};
      TC_X509_general_subtree base = {0};
      size_t work = 100000, small = data[0];
      int matched = 99, limited = 99;
      TC_TLV_result retry;
      name.type = base.base.type = types[kind];
      if (!name.type)
        base.base.type = 1;
      name.value.data = data;
      name.value.length = split;
      base.base.value.data = data + split;
      base.base.value.length = length - split;
      result = TC_X509_general_name_within(&name, &base, &limits, NULL, &work,
                                           &matched);
      if (result != TC_TLV_OK && matched != 99)
        abort();
      if (result == TC_TLV_OK && matched != 0 && matched != 1)
        abort();
      retry = TC_X509_general_name_within(&name, &base, &limits, NULL, &small,
                                          &limited);
      if (retry != TC_TLV_OK && limited != 99)
        abort();
      if (retry == TC_TLV_OK && (result != TC_TLV_OK || limited != matched))
        abort();
      {
        TC_X509_name_constraints constraints = {base.base.value, {NULL, 0}};
        TC_X509_constraint_workspace workspace = {frames, 16, NULL};
        work = 100000;
        matched = 99;
        result = TC_X509_name_constraints_check(&name, &constraints, &limits,
                                                &workspace, &work, &matched);
        if (result != TC_TLV_OK && matched != 99)
          abort();
        if (result == TC_TLV_OK && matched != 0 && matched != 1)
          abort();
      }
    }
  }
  memset(&cvc, 0xa5, sizeof cvc);
  old_cvc = cvc;
  result = TC_PIV_CVC_read(data, length, &cvc);
  if (result != TC_TLV_OK && memcmp(&cvc, &old_cvc, sizeof cvc))
    abort();
  for (profile = TC_CHUID_PROFILE_PIV;
       profile <= TC_CHUID_PROFILE_TWIC_UNSIGNED; ++profile)
    for (encoding = TC_PIV_CHUID_CONTENTS; encoding <= TC_PIV_CHUID_CONTAINER;
         ++encoding) {
      memset(&chuid, 0xa5, sizeof chuid);
      old_chuid = chuid;
      result = TC_PIV_CHUID_read_profile(data, length,
                                         (TC_PIV_CHUID_encoding)encoding,
                                         (TC_PIV_CHUID_profile)profile, &chuid);
      if (result != TC_TLV_OK && memcmp(&chuid, &old_chuid, sizeof chuid))
        abort();
    }
  {
    TC_EAC_CVC eac, old_eac;
    TC_EAC_CVC_public_key eac_key, old_key;
    TC_EAC_CVC_extension ext;
    TC_EAC_CVC_workspace work = {frames, 16};
    memset(&eac, 0xa5, sizeof eac);
    old_eac = eac;
    result = TC_EAC_CVC_read(data, length, &limits, &work, &eac);
    if (result == TC_TLV_OK) {
      (void)TC_EAC_CVC_check_encoding(&eac, &eac.public_key, &eac.public_key);
      if (TC_EAC_CVC_extensions_init(&reader, eac.extensions, &limits) !=
          TC_TLV_OK)
        abort();
      while ((result = TC_EAC_CVC_extension_next(&reader, &ext)) == TC_TLV_OK) {
      }
      if (result != TC_TLV_END)
        abort();
    } else if (memcmp(&eac, &old_eac, sizeof eac))
      abort();
    memset(&eac_key, 0xa5, sizeof eac_key);
    old_key = eac_key;
    result = TC_EAC_CVC_public_key_read(data, length, &limits, &eac_key);
    if (result != TC_TLV_OK && memcmp(&eac_key, &old_key, sizeof eac_key))
      abort();
  }
  return 0;
}
