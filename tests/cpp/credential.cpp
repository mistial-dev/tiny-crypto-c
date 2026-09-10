/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
#include <tiny_crypto/tiny_crypto.hpp>
#include <type_traits>

static_assert(std::is_standard_layout<TC_PIV_CHUID_validation_request>::value,
              "Credential requests remain ordinary C++ aggregate data");
static_assert(std::is_standard_layout<TC_PIV_biometric_validation_request>::value,
              "Biometric requests remain ordinary C++ aggregate data");
static_assert(std::is_standard_layout<TC_PIV_security_validation_request>::value,
              "Security requests remain ordinary C++ aggregate data");

TEST_CASE("CHUID validation rejects incomplete requests atomically") {
  size_t work = 100;
  CHECK(TC_PIV_CHUID_validate(nullptr,nullptr,&work,nullptr) ==
        TC_CREDENTIAL_ERROR);
  CHECK(work == 100);
}

TEST_CASE("Credential object validation rejects incomplete requests atomically") {
  size_t work = 100;
  CHECK(TC_PIV_biometric_validate(nullptr,nullptr,&work) == TC_CREDENTIAL_ERROR);
  CHECK(work == 100);
  CHECK(TC_PIV_security_validate(nullptr,nullptr,nullptr,&work,nullptr) ==
        TC_CREDENTIAL_ERROR);
  CHECK(work == 100);
  CHECK(TC_TWIC_unsigned_CHUID_validate(nullptr,nullptr,nullptr,&work) ==
        TC_CREDENTIAL_ERROR);
  CHECK(work == 100);
}

TEST_CASE("Validation context retains caller-owned views") {
  TC_X509_store_source source{};
  TC_validation_options options{};
  options.at = {2026,1,1,0,0,0};
  options.max_certificates = 4;
  options.max_candidates = 8;
  options.max_input = options.max_candidate_bytes = 65536;
  TC_X509_crl_index index{};
  TC_validation_trust trust{&source,&index};
  TC_CMS_path_workspace path{};
  TC_CMS_credential_workspace workspace{};
  workspace.path = &path;
  TC_validation_context context{};

  REQUIRE(TC_validation_context_init(&trust,&options,
      &workspace,&context) == TC_RESULT_OK);
  CHECK(context.trust.certificates == &source);
  CHECK(context.options == &options);
  CHECK(context.trust.crls == &index);
  CHECK(context.workspace == &workspace);
}
