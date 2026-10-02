/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Revocation evidence policy of TC_validation_options (RFC 5280 section
 * 6.3.3) over NIST PKITS paths: Trust Anchor -> Good CA -> end entity. The
 * Trust Anchor CRL covers Good CA and the Good CA CRL covers the end
 * entities. InvalidRevokedEETest3EE is listed on the Good CA CRL. */
#include "validation_fixture.h"
#include "test_util.h"

#ifndef TC_PKITS_DIR
#error "TC_PKITS_DIR must name the vendored PKITS directory"
#endif

static validation_fixture fixture;
static uint8_t anchor_bytes[FIXTURE_FILE_BYTES], ca_bytes[FIXTURE_FILE_BYTES];
static uint8_t good_bytes[FIXTURE_FILE_BYTES], revoked_bytes[FIXTURE_FILE_BYTES];
static uint8_t crl_bytes[2][FIXTURE_FILE_BYTES];

static const TC_X509_time at = {2026, 9, 29, 18, 0, 0};

enum { ROOT_CRL = 1u << 0, CA_CRL = 1u << 1 };
enum { GOOD, REVOKED };

static TC_bytes pkits(const char* name, uint8_t bytes[FIXTURE_FILE_BYTES])
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", TC_PKITS_DIR, name), >, 0);
  return fixture_read(path, bytes);
}

/* Index the CRLs named by crls and build the context under policy. */
static void pkits_init(unsigned crls, TC_validation_revocation policy)
{
  const TC_bytes anchor = pkits("certs/TrustAnchorRootCertificate.crt", anchor_bytes);
  const TC_bytes ca = pkits("certs/GoodCACert.crt", ca_bytes);
  TC_bytes indexed[2];
  size_t count = 0;
  if (crls & ROOT_CRL)
    indexed[count++] = pkits("crls/TrustAnchorRootCRL.crl", crl_bytes[0]);
  if (crls & CA_CRL)
    indexed[count++] = pkits("crls/GoodCACRL.crl", crl_bytes[1]);
  /* CRL signer searches read candidates, so the anchor is one too. */
  const TC_bytes candidates[] = {ca, anchor};
  validation_fixture_init(&fixture, anchor, candidates, 2, indexed, count, at, policy);
}

static TC_bytes end_entity(int which)
{
  return which == GOOD ? pkits("certs/ValidCertificatePathTest1EE.crt", good_bytes)
                       : pkits("certs/InvalidRevokedEETest3EE.crt", revoked_bytes);
}

/* Validate one end entity. A failure leaves the 0xa5 result unchanged. */
static TC_credential_status validate(int which, TC_X509_validation_report* out)
{
  const TC_bytes encoded = end_entity(which);
  size_t work = FIXTURE_WORK;
  memset(out, 0xa5, sizeof *out);
  const TC_credential_status status = TC_X509_validate(encoded, &fixture.context, &work, out);
  if (status != TC_CREDENTIAL_VALID)
    munit_assert_true(tc_test_all_value(out, sizeof *out, 0xa5));
  else
    munit_assert_ptr_equal(out->certificate.encoded.data, encoded.data);
  return status;
}

/* REQUIRED: every path member needs CRL evidence. A missing CRL for either
 * member is UNAVAILABLE, and a revoked member outranks a missing CRL. */
TC_TEST(required)
{
  TC_X509_validation_report result;
  pkits_init(ROOT_CRL | CA_CRL, TC_VALIDATION_REVOCATION_REQUIRED);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.revocation_checked, ==, 1);
  munit_assert_int(validate(REVOKED, &result), ==, TC_CREDENTIAL_REVOKED);

  pkits_init(0, TC_VALIDATION_REVOCATION_REQUIRED);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_UNAVAILABLE);
  munit_assert_int(validate(REVOKED, &result), ==, TC_CREDENTIAL_UNAVAILABLE);

  pkits_init(ROOT_CRL, TC_VALIDATION_REVOCATION_REQUIRED);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_UNAVAILABLE);

  pkits_init(CA_CRL, TC_VALIDATION_REVOCATION_REQUIRED);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_UNAVAILABLE);
  munit_assert_int(validate(REVOKED, &result), ==, TC_CREDENTIAL_REVOKED);
  return MUNIT_OK;
}

/* WHEN_AVAILABLE: missing evidence is accepted and reported. Covering CRLs
 * are still checked, so the revoked end entity stays REVOKED. */
TC_TEST(when_available)
{
  TC_X509_validation_report result;
  pkits_init(0, TC_VALIDATION_REVOCATION_WHEN_AVAILABLE);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.revocation_checked, ==, 0);
  munit_assert_int(validate(REVOKED, &result), ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.revocation_checked, ==, 0);

  pkits_init(ROOT_CRL | CA_CRL, TC_VALIDATION_REVOCATION_WHEN_AVAILABLE);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.revocation_checked, ==, 1);
  munit_assert_int(validate(REVOKED, &result), ==, TC_CREDENTIAL_REVOKED);

  /* Good CA has no CRL here. The end entity CRL still applies. */
  pkits_init(CA_CRL, TC_VALIDATION_REVOCATION_WHEN_AVAILABLE);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.revocation_checked, ==, 0);
  munit_assert_int(validate(REVOKED, &result), ==, TC_CREDENTIAL_REVOKED);

  pkits_init(ROOT_CRL, TC_VALIDATION_REVOCATION_WHEN_AVAILABLE);
  munit_assert_int(validate(GOOD, &result), ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.revocation_checked, ==, 0);
  return MUNIT_OK;
}

/* PKITS Invalid Unknown CRL Extension Test10: a CRL with an unknown critical
 * extension cannot establish status. It stays UNSUPPORTED under both policies, so an unusable CRL never
 * reads as missing evidence. */
TC_TEST(unsupported_crl)
{
  const TC_validation_revocation policies[] = {TC_VALIDATION_REVOCATION_REQUIRED,
                                               TC_VALIDATION_REVOCATION_WHEN_AVAILABLE};
  for (size_t i = 0; i < sizeof policies / sizeof *policies; ++i) {
    const TC_bytes anchor = pkits("certs/TrustAnchorRootCertificate.crt", anchor_bytes);
    const TC_bytes ca = pkits("certs/UnknownCRLExtensionCACert.crt", ca_bytes);
    const TC_bytes crls[] = {pkits("crls/TrustAnchorRootCRL.crl", crl_bytes[0]),
                             pkits("crls/UnknownCRLExtensionCACRL.crl", crl_bytes[1])};
    validation_fixture_init(&fixture, anchor, &ca, 1, crls, 2, at, policies[i]);
    const TC_bytes encoded = pkits("certs/InvalidUnknownCRLExtensionTest10EE.crt", good_bytes);
    TC_X509_validation_report result;
    size_t work = FIXTURE_WORK;
    memset(&result, 0xa5, sizeof result);
    munit_assert_int(TC_X509_validate(encoded, &fixture.context, &work, &result), ==,
                     TC_CREDENTIAL_UNSUPPORTED);
    munit_assert_true(tc_test_all_value(&result, sizeof result, 0xa5));
  }
  return MUNIT_OK;
}

/* Index the Trust Anchor CRL and one CA CRL, then validate end_entity under
 * both policies. A changed byte at offset flip, when nonzero, alters the CA
 * CRL. results[0] is the REQUIRED status and results[1] the WHEN_AVAILABLE
 * status. */
static void crl_case(const char* ca_name, const char* crl_name, const char* end_entity_name,
                     size_t flip, TC_credential_status results[2], uint8_t* checked)
{
  for (int when_available = 0; when_available < 2; ++when_available) {
    const TC_bytes anchor = pkits("certs/TrustAnchorRootCertificate.crt", anchor_bytes);
    const TC_bytes ca = pkits(ca_name, ca_bytes);
    const TC_bytes crls[] = {pkits("crls/TrustAnchorRootCRL.crl", crl_bytes[0]),
                             pkits(crl_name, crl_bytes[1])};
    if (flip)
      crl_bytes[1][crls[1].length - flip] ^= 1;
    const TC_bytes candidates[] = {ca, anchor};
    validation_fixture_init(&fixture, anchor, candidates, 2, crls, 2, at,
                            when_available ? TC_VALIDATION_REVOCATION_WHEN_AVAILABLE
                                           : TC_VALIDATION_REVOCATION_REQUIRED);
    const TC_bytes encoded = pkits(end_entity_name, good_bytes);
    TC_X509_validation_report result;
    size_t work = FIXTURE_WORK;
    memset(&result, 0xa5, sizeof result);
    results[when_available] = TC_X509_validate(encoded, &fixture.context, &work, &result);
    if (results[when_available] == TC_CREDENTIAL_VALID)
      *checked = result.revocation_checked;
    else
      munit_assert_true(tc_test_all_value(&result, sizeof result, 0xa5));
  }
}

/* PKITS Invalid Old CRL nextUpdate Test11: the only CRL for the end entity
 * is past its nextUpdate, so it is no evidence (RFC 5280 section 6.3.3 (a)).
 * REQUIRED returns UNAVAILABLE and WHEN_AVAILABLE accepts the path with
 * revocation_checked 0. This is the state of held CRLs after they expire. */
TC_TEST(expired_crl)
{
  TC_credential_status results[2];
  uint8_t checked = 0xa5;
  crl_case("certs/OldCRLnextUpdateCACert.crt", "crls/OldCRLnextUpdateCACRL.crl",
           "certs/InvalidOldCRLnextUpdateTest11EE.crt", 0, results, &checked);
  munit_assert_int(results[0], ==, TC_CREDENTIAL_UNAVAILABLE);
  munit_assert_int(results[1], ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(checked, ==, 0);
  return MUNIT_OK;
}

/* A covering CRL whose signature fails is INVALID under both policies, so a
 * damaged or substituted CRL never reads as missing evidence. */
TC_TEST(bad_crl_signature)
{
  TC_credential_status results[2];
  uint8_t checked = 0xa5;
  crl_case("certs/GoodCACert.crt", "crls/GoodCACRL.crl", "certs/ValidCertificatePathTest1EE.crt", 1,
           results, &checked);
  munit_assert_int(results[0], ==, TC_CREDENTIAL_INVALID);
  munit_assert_int(results[1], ==, TC_CREDENTIAL_INVALID);
  munit_assert_uint8(checked, ==, 0xa5);
  return MUNIT_OK;
}

/* The policy is validated at the context entry and again by each operation
 * for a context filled by hand. */
TC_TEST(policy_value)
{
  pkits_init(ROOT_CRL | CA_CRL, TC_VALIDATION_REVOCATION_REQUIRED);
  TC_validation_options options = fixture.options;
  options.revocation = (TC_validation_revocation)2;
  const TC_validation_trust trust = {&fixture.source, &fixture.index};
  TC_validation_context context;
  memset(&context, 0x5a, sizeof context);
  munit_assert_int(
      TC_validation_context_init(&trust, &options, &fixture.workspace.credential, &context), ==,
      TC_RESULT_ARGUMENT);
  munit_assert_true(tc_test_all_value(&context, sizeof context, 0x5a));

  context = fixture.context;
  context.options = &options;
  const TC_bytes encoded = end_entity(GOOD);
  TC_X509_validation_report result;
  size_t work = FIXTURE_WORK;
  memset(&result, 0xa5, sizeof result);
  munit_assert_int(TC_X509_validate(encoded, &context, &work, &result), ==, TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, FIXTURE_WORK);
  munit_assert_true(tc_test_all_value(&result, sizeof result, 0xa5));
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/required", required, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/when-available", when_available, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/unsupported-crl", unsupported_crl, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/expired-crl", expired_crl, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/bad-crl-signature", bad_crl_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/policy-value", policy_value, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/credential/revocation-policy", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
