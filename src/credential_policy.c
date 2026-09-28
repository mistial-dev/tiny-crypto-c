/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Content-signer and card-profile policy shared by the PIV and TWIC credential
 * validators. These helpers turn the card profile and the signer certificate
 * into path options: the content-signing EKU (PIV or TWIC OID, per the TWIC
 * part 2 section 6 pairs), id-fpki-common-piv-contentSigning
 * (2.16.840.1.101.3.2.1.3.39) as an explicit policy for PIV cards, and the
 * card-expiration bound on the signer. Signature and path checks run
 * afterwards in the validators. */
#include "internal.h"
#include "pki_source_internal.h"
#include "validation_internal.h"
#include "cms_internal.h"
#include "credential_status_internal.h"
#include "credential_policy_internal.h"
#include "credential_text_internal.h"
#include <string.h>
#include <tiny_crypto/credential.h>
#include <tiny_crypto/piv_biometric.h>
#include <tiny_crypto/piv_cms.h>

#if TC_ENABLE_CREDENTIAL

static TC_TLV_result signing_policy_present(TC_bytes encoded_extensions, TC_bytes required,
                                            const TC_TLV_limits* limits,
                                            const TC_X509_path_workspace* storage)
{
  static const uint8_t policies_oid[] = {0x55, 0x1d, TC_PKI_EXT_CERTIFICATE_POLICIES};
  TC_TLV_reader extensions;
  TC_X509_extension extension;
  TC_TLV_result status = TC_X509_extensions_init(&extensions, encoded_extensions.data,
                                                 encoded_extensions.length, limits);
  if (status != TC_TLV_OK)
    return status;
  int found = 0;
  while ((status = TC_X509_extension_next(&extensions, &extension)) == TC_TLV_OK) {
    if (extension.oid.length != sizeof policies_oid ||
        memcmp(extension.oid.data, policies_oid, sizeof policies_oid))
      continue;
    TC_X509_policy_reader policies;
    TC_X509_policy policy;
    status = TC_X509_policies_init(&policies, extension.value.data, extension.value.length, limits,
                                   storage->oids, storage->oid_capacity);
    if (status != TC_TLV_OK)
      return status;
    while ((status = TC_X509_policy_next(&policies, &policy)) == TC_TLV_OK) {
      if (policy.oid.length == required.length &&
          !memcmp(policy.oid.data, required.data, required.length))
        found = 1;
    }
    if (status != TC_TLV_END)
      return status;
  }
  return status == TC_TLV_END ? (found ? TC_TLV_OK : TC_TLV_INVALID) : status;
}

static TC_TLV_result content_signing_purpose(TC_bytes extensions, int twic_compatible,
                                             TC_X509_path_options* policy,
                                             const TC_X509_path_workspace* storage)
{
  static const uint8_t eku_oid[] = {0x55, 0x1d, TC_PKI_EXT_EXTENDED_KEY_USAGE};
  TC_TLV_reader reader;
  TC_TLV_result status =
      TC_X509_extensions_init(&reader, extensions.data, extensions.length, &policy->parsing);
  if (status != TC_TLV_OK)
    return status;
  TC_X509_extension extension;
  while ((status = TC_X509_extension_next(&reader, &extension)) == TC_TLV_OK) {
    if (extension.oid.length != sizeof eku_oid ||
        memcmp(extension.oid.data, eku_oid, sizeof eku_oid))
      continue;
    size_t count;
    status = TC_X509_extended_key_usage_read(extension.value.data, extension.value.length,
                                             storage->oids, storage->oid_capacity, &count);
    if (status != TC_TLV_OK)
      return status;
    for (size_t i = 0; i < count; ++i) {
      if (TC_PIV_oid_identify(storage->oids[i],
                              twic_compatible ? TC_PIV_OIDS_TWIC_COMPATIBLE : TC_PIV_OIDS_ONLY) !=
          TC_PIV_OID_CONTENT_SIGNING)
        continue;
      if (!policy->purpose.length)
        policy->purpose = storage->oids[i];
    }
  }
  if (status != TC_TLV_END)
    return status;
  return policy->purpose.length ? TC_TLV_OK : TC_TLV_INVALID;
}

static TC_TLV_result piv_content_signer_policy(const TC_X509_certificate* signer,
                                               const TC_X509_time* card_expiration,
                                               TC_X509_path_options* policy,
                                               const TC_X509_path_workspace* storage)
{
  static const uint8_t signing_policy[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 2, 1, 3, 39};
  static const TC_bytes required_policy = {signing_policy, sizeof signing_policy};
  TC_TLV_result status =
      signing_policy_present(signer->extensions, required_policy, &policy->parsing, storage);
  if (status != TC_TLV_OK)
    return status;
  if (card_expiration) {
    int order;
    status = TC_X509_time_compare(&signer->not_after, card_expiration, &order);
    if (status != TC_TLV_OK)
      return status;
    if (order < 0)
      return TC_TLV_INVALID;
  }
  policy->initial_policies = &required_policy;
  policy->initial_policy_count = 1;
  policy->flags |= TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
  return TC_TLV_OK;
}

TC_TLV_result tc_credential_signer_policy(TC_bytes certificate, int piv, int twic_compatible,
                                          const TC_X509_time* card_expiration,
                                          TC_X509_path_options* policy,
                                          const TC_X509_path_workspace* storage, size_t* work)
{
  if (!piv && policy->purpose.length)
    policy->purpose = (TC_bytes){NULL, 0};
  if (piv || !policy->purpose.length) {
    if (certificate.length > *work / 3)
      return TC_TLV_LIMIT;
    *work -= certificate.length * 3;
    TC_X509_workspace parser = {storage->frames, storage->frame_capacity, storage->oids,
                                storage->oid_capacity};
    TC_X509_certificate signer;
    TC_TLV_result status =
        TC_X509_read(certificate.data, certificate.length, &policy->parsing, &parser, &signer);
    if (status != TC_TLV_OK)
      return status;
    if (!policy->purpose.length) {
      status = content_signing_purpose(signer.extensions, twic_compatible, policy, storage);
      if (status != TC_TLV_OK)
        return status;
    }
    if (piv) {
      status = piv_content_signer_policy(&signer, card_expiration, policy, storage);
      if (status != TC_TLV_OK)
        return status;
    }
  }
  policy->key_usage |= TC_KEY_USAGE_DIGITAL_SIGNATURE;
  policy->flags |= TC_X509_PATH_REQUIRE_KEY_USAGE | TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE |
                   TC_X509_PATH_INHIBIT_ANY_PURPOSE;
  return TC_TLV_OK;
}

TC_TLV_result tc_credential_chuid_expiration_check(TC_bytes expiration, const TC_X509_time* at,
                                                   int* valid)
{
  if (!at || !valid || !expiration.data || expiration.length != 8)
    return TC_TLV_ARGUMENT;
  unsigned year, month, day;
  if (!tc_credential_yyyymmdd(expiration.data, expiration.length, &year, &month, &day))
    return TC_TLV_INVALID;
  /* The card remains valid through the last second of its expiration day. */
  const TC_X509_time expires = {year, (uint8_t)month, (uint8_t)day, 23, 59, 59};
  int order;
  TC_TLV_result result = TC_X509_time_compare(at, &expires, &order);
  if (result == TC_TLV_OK)
    *valid = order <= 0;
  return result;
}

int tc_credential_profile(TC_PIV_card_profile profile, const TC_validation_options* options,
                          int* piv, TC_PIV_oid_profile* oids)
{
  if (!options || !piv || !oids ||
      (profile != TC_PIV_CARD && profile != TC_TWIC_LEGACY_CARD && profile != TC_TWIC_NEXGEN_CARD))
    return 0;
  *piv = profile == TC_PIV_CARD;
  *oids = *piv ? TC_PIV_OIDS_ONLY : TC_PIV_OIDS_TWIC_COMPATIBLE;
  return (!options->certificate.purpose.data && !options->certificate.purpose.length) ||
         TC_PIV_oid_identify(options->certificate.purpose, *oids) == TC_PIV_OID_CONTENT_SIGNING;
}

#endif
