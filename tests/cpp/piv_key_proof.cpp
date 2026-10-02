/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "doctest.h"
/* The test support is C. */
extern "C" {
#include "card_simulator.h"
}
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_key_proof.hpp>
#include <tiny_crypto/x509_crypto.h>
#include <cstdio>
#include <cstring>

namespace {
tc_card_fixture fixture;
tc_card_simulator card;
uint8_t certificate_bytes[4096];
const uint8_t* signed_digest;

/* Returns the digest SD 33 card 4 signed with 9E in the capture. */
TC_status recorded_digest(void*, uint8_t* output, size_t length)
{
  std::memcpy(output, signed_digest, length);
  return TC_OK;
}

/* The card 4 certificate of container 5FC101. */
bool card_certificate(TC_X509_certificate& out)
{
  static TC_GZIP_workspace gzip;
  static TC_TLV_frame frames[16];
  static TC_bytes oids[32];
  const TC_TLV_limits limits = {sizeof certificate_bytes, sizeof certificate_bytes, 512, 16};
  TC_X509_workspace parser = {{frames, 16}, oids, 32};
  TC_PIV_certificate container;
  size_t work = 1000000;
  const tc_card_object* object = tc_card_fixture_object(&fixture, 0x5fc101);
  return object &&
         TC_PIV_certificate_decode(object->data, TC_PIV_CERTIFICATE_SLOT, sizeof certificate_bytes,
                                   &gzip, &work, {certificate_bytes, sizeof certificate_bytes},
                                   &container) == TC_TLV_OK &&
         TC_X509_read(container.certificate, &limits, &parser, &out) == TC_TLV_OK;
}
} // namespace

TEST_CASE("PIV key proof on a PIVLink")
{
  char path[512];
  std::snprintf(path, sizeof path, "%s/sd33_card4.txt", TC_CARD_FIXTURE_DIR);
  REQUIRE(tc_card_fixture_load(&fixture, path) == 0);
  for (size_t i = 0; i < fixture.authentication_count; ++i)
    if (fixture.authentications[i].key == TC_PIV_KEY_CARD_AUTHENTICATION)
      signed_digest = fixture.authentications[i].input.data;
  REQUIRE(signed_digest != nullptr);
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  TC_X509_certificate certificate;
  REQUIRE(card_certificate(certificate));

  const tiny_crypto::piv_key_policy policy = {
      TC_PIV_CARD, {2026, 9, 29, 18, 0, 0}, TC_PIV_RSA_PKCS1_V15, 0};
  tiny_crypto::piv_key_parameters parameters;
  REQUIRE(tiny_crypto::piv_key_parameters_select(certificate, policy, parameters) == TC_PIV_OK);
  CHECK(parameters.algorithm == TC_PIV_ALGORITHM_ECC_P256);

  static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES], response[512];
  static tiny_crypto::piv_key_proof_workspace workspace;
  static TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {&ec, nullptr, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const tiny_crypto::piv_link_options options = {{TC_APDU_SHORT, 0, 16, 0, 0}, TC_PIV_CONTACT, 0};
  tiny_crypto::PIVLink link;
  tiny_crypto::piv_application application;
  REQUIRE(link.init(tc_card_simulator_transport(&card), options, {scratch, sizeof scratch}) ==
          TC_PIV_OK);
  REQUIRE(link.select(TC_PIV_APPLICATION_PIV, 0, {response, sizeof response}, application) ==
          TC_PIV_OK);
  tiny_crypto::piv_key_proof_request request = {&certificate, policy,
                                                TC_PIV_KEY_CARD_AUTHENTICATION};
  TC_work_budget work = {1000000};
  CHECK(tiny_crypto::piv_key_prove(link, request, {recorded_digest, nullptr}, provider, workspace,
                                   work) == TC_PIV_OK);
  /* 9A needs the PIN, and the card answers 6982. */
  request.key_reference = TC_PIV_KEY_PIV_AUTHENTICATION;
  CHECK(tiny_crypto::piv_key_prove(link, request, {recorded_digest, nullptr}, provider, workspace,
                                   work) == TC_PIV_CARD_STATUS);
  CHECK(link.status() == 0x6982);
  request.key_reference = 0x9d;
  CHECK(tiny_crypto::piv_key_prove(link, request, {recorded_digest, nullptr}, provider, workspace,
                                   work) == TC_PIV_ARGUMENT);
  CHECK(card.violations == 0);
}
