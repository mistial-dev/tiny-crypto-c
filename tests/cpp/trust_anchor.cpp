/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The RFC 5914 reader and constrained-anchor path validation from C++, over
 * the vendored synthetic TWIC Legacy fixture. */
#include "doctest.h"
#include <tiny_crypto/tiny_crypto.hpp>
#include <tiny_crypto/validation.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_trust_anchor.h>
#include <cstdio>
#include <type_traits>

#ifndef TC_TWIC_SYNTHETIC_ROOT
#error "TC_TWIC_SYNTHETIC_ROOT must name the vendored fixture directory"
#endif

static_assert(std::is_standard_layout<TC_X509_store_anchor>::value,
              "Anchor records remain ordinary C++ aggregate data");

namespace {
const size_t capacity = 20000;
uint8_t anchors_der[capacity], issuer_der[capacity], card_der[capacity];
TC_validation_storage arena[40000];
TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
TC_ECDSA_workspace ec;

TC_bytes fixture(const char* name, uint8_t* buffer)
{
  char path[512];
  std::snprintf(path, sizeof path, "%s/legacy/%s", TC_TWIC_SYNTHETIC_ROOT, name);
  std::FILE* file = std::fopen(path, "rb");
  REQUIRE(file != nullptr);
  const size_t length = std::fread(buffer, 1, capacity, file);
  std::fclose(file);
  REQUIRE(length > 0);
  return TC_bytes{buffer, length};
}
} // namespace

TEST_CASE("Constrained trust anchor from C++")
{
  const TC_TLV_limits limits = {capacity, capacity, 512, 16};
  TC_TLV_frame frames[32];
  TC_bytes oids[32];
  TC_X509_workspace parser = {{frames, 32}, oids, 32};
  const TC_bytes list = fixture("trust-anchors.der", anchors_der);
  const TC_bytes chain[] = {fixture("issuer.der", issuer_der), fixture("card.der", card_der)};
  TC_X509_trust_anchor_reader reader;
  TC_X509_store_anchor anchor = {};
  REQUIRE(TC_X509_trust_anchor_list_init(&reader, list, &limits, &parser) == TC_TLV_OK);
  REQUIRE(TC_X509_trust_anchor_next(&reader, &anchor) == TC_TLV_OK);
  CHECK(TC_X509_trust_anchor_next(&reader, &anchor) == TC_TLV_END);

  TC_validation_capacity sizes;
  TC_validation_workspace storage;
  size_t bytes = 0;
  REQUIRE(TC_validation_capacity_init(TC_VALIDATION_DESKTOP, &sizes) == TC_RESULT_OK);
  REQUIRE(TC_validation_workspace_size(&sizes, &bytes) == TC_RESULT_OK);
  REQUIRE(bytes <= sizeof arena);
  REQUIRE(TC_validation_workspace_init(&sizes,
                                       TC_buffer{reinterpret_cast<uint8_t*>(arena), sizeof arena},
                                       &storage) == TC_RESULT_OK);
  TC_RSA_workspace rsa = {rsa_words, sizeof rsa_words / sizeof *rsa_words};
  TC_X509_native_workspace native = {&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_path_options options = {};
  options.at = TC_X509_time{2026, 1, 1, 0, 0, 0};
  options.parsing = limits;
  options.max_certificates = 4;
  options.max_input = capacity;
  options.max_work = 2000000;
  options.signatures = TC_X509_native_provider(&native);
  TC_X509_path_report result;
  CHECK(TC_X509_path_validate_with_anchor(chain, 2, &anchor, &options, &storage.path.validation,
                                          &result) == TC_X509_PATH_VALID);

  // A path length of 0 from the anchor forbids the issuing CA.
  TC_X509_store_anchor constrained = anchor;
  constrained.has_path_len = 1;
  constrained.path_len = 0;
  CHECK(TC_X509_path_validate_with_anchor(chain, 2, &constrained, &options,
                                          &storage.path.validation,
                                          &result) == TC_X509_PATH_INVALID);
}
