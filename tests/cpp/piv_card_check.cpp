/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
#include <tiny_crypto/piv_card_check.hpp>
#include <cstring>

TEST_CASE("PIV card report find and acceptance")
{
  static tiny_crypto::piv_card_report report;
  std::memset(&report, 0, sizeof report);
  report.checks[0] = {TC_CREDENTIAL_VALID, 0x0500, 0, TC_PIV_CHECK_KEY_PROOF, TC_PIV_CHECK_PASSED,
                      TC_PIV_REASON_NONE,  0x9e};
  report.checks[1] = {
      TC_CREDENTIAL_UNAVAILABLE, 0x3000, 0, TC_PIV_CHECK_CHUID, TC_PIV_CHECK_NOT_CHECKABLE,
      TC_PIV_REASON_NO_EVIDENCE, 0};
  report.count = 2;
  const tiny_crypto::piv_check_requirement card_auth[] = {{TC_PIV_CHECK_KEY_PROOF, 0x9e, 0}};
  const tiny_crypto::piv_check_requirement chuid[] = {{TC_PIV_CHECK_CHUID, 0, 0}};
  CHECK(tiny_crypto::piv_card_report_accepts(report, card_auth));
  CHECK_FALSE(tiny_crypto::piv_card_report_accepts(report, chuid));
  CHECK_FALSE(tiny_crypto::piv_card_report_accepts(report, card_auth, 0));
  const tiny_crypto::piv_check* found = tiny_crypto::piv_card_report_find(report, chuid[0]);
  REQUIRE(found != nullptr);
  CHECK(found->reason == TC_PIV_REASON_NO_EVIDENCE);
}

TEST_CASE("PIV card check argument errors")
{
  static tiny_crypto::piv_card_report report;
  static tiny_crypto::piv_card_check_workspace workspace;
  std::memset(&report, 0xa5, sizeof report);
  const tiny_crypto::piv_card_check_request request = {};
  size_t work = 1000;
  CHECK(tiny_crypto::piv_card_check(request, workspace, work, report) == TC_PIV_ARGUMENT);
  CHECK(work == 1000);
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&report);
  size_t changed = 0;
  for (size_t i = 0; i < sizeof report; ++i)
    changed += bytes[i] != 0xa5;
  CHECK(changed == 0);

  const tiny_crypto::piv_card_certificate_request certificate = {};
  const TC_validation_context context = {};
  tiny_crypto::piv_card_certificate_result result;
  CHECK(tiny_crypto::piv_card_certificate_validate(certificate, context, work, result) ==
        TC_CREDENTIAL_ERROR);
}
