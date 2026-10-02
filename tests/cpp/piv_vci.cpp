/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* piv_vci.hpp over the tests/support/sm_card.c card model with the
 * tools/sm_fixtures.py CS2 handshake. */
#include "doctest.h"
#include <tiny_crypto/piv_sm_apdu.hpp>
#include <tiny_crypto/piv_vci.hpp>
#include <cstring>
#if TC_TEST_SM_FIXTURES
extern "C" {
#include "sm_card.h"
}
#include "sm_fixtures.h"

namespace {
TC_status scalar_one(void*, uint8_t* output, size_t length)
{
  std::memset(output, 0, length);
  output[length - 1] = 1;
  return TC_OK;
}

/* SD 33 card 2 application property template announcing CS2. */
const uint8_t template_answer[] = {
    0x61, 0x2a, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x50, 0x0a, 0x49, 0x44, 0x2d, 0x4f,
    0x6e, 0x65, 0x20, 0x50, 0x49, 0x56, 0xac, 0x06, 0x80, 0x01, 0x27, 0x06, 0x01, 0x00, 0x7f,
    0x66, 0x08, 0x02, 0x02, 0x03, 0xf8, 0x02, 0x02, 0x7f, 0xff, 0x90, 0x00};

/* 7E 12 {4F 0B PIV AID} {5F2F 02 48 00}: PIV PIN and VCI with pairing. */
const uint8_t discovery_object[] = {0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00,
                                    0x00, 0x10, 0x00, 0x01, 0x00, 0x5f, 0x2f, 0x02, 0x48, 0x00};

/* SP 800-73-5 Part 2 Table 25 example pairing code. */
const uint8_t pairing_code[] = {'6', '5', '1', '3', '5', '2', '7', '5'};
} // namespace

TEST_CASE("PIV virtual contact interface on a link")
{
  const tc_sm_fixture& fixture = sm_fixtures[0];
  if (!TC_PIV_SM_ENABLE_CS2 || fixture.suite != TC_PIV_SM_CS2)
    return;
  static tc_sm_card card;
  static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES], sm_scratch[128], response[512],
      key_answer[400];
  tc_sm_card_init(&card);
  card.select_answer = {template_answer, sizeof template_answer};
  std::memcpy(key_answer, fixture.response.data, fixture.response.length);
  key_answer[fixture.response.length] = 0x90;
  key_answer[fixture.response.length + 1] = 0x00;
  card.key_command = fixture.request;
  card.key_answer = {key_answer, fixture.response.length + 2};
  const uint8_t host_id[8] = {};
  const tiny_crypto::piv_link_options options = {
      {TC_APDU_SHORT, 0, 16, 0, 0}, TC_PIV_CONTACTLESS, 0};
  // Declare the session first: the link borrows it and is destroyed first.
  tiny_crypto::PIVSM session;
  tiny_crypto::piv_sm_workspace workspace{};
  tiny_crypto::PIVLink link;
  REQUIRE(link.init(tc_sm_card_transport(&card), options, {scratch, sizeof scratch}) == TC_PIV_OK);
  tiny_crypto::piv_application application{};
  REQUIRE(link.select(TC_PIV_APPLICATION_PIV, 0, {response, sizeof response}, application) ==
          TC_PIV_OK);
  tiny_crypto::piv_sm_peer peer{};
  REQUIRE(tiny_crypto::piv_sm_key_request(link, session, TC_PIV_SM_CS2, host_id,
                                          {scalar_one, nullptr}, {response, sizeof response}, peer,
                                          workspace) == TC_PIV_OK);
  REQUIRE(session.finish(peer, fixture.public_key, workspace) == TC_OK);
  tc_sm_card_keys(&card, fixture.material);
  REQUIRE(tiny_crypto::piv_link_secure(link, workspace, {sm_scratch, sizeof sm_scratch}) ==
          TC_PIV_OK);

  std::memcpy(card.answer, discovery_object, sizeof discovery_object);
  card.answer_length = sizeof discovery_object;
  tiny_crypto::piv_discovery discovery{};
  REQUIRE(tiny_crypto::piv_discovery_get(link, TC_PIV_DISCOVERY_PIV, {response, sizeof response},
                                         discovery) == TC_PIV_OK);
  CHECK(discovery.secured == 1);
  CHECK(discovery.policy == (TC_PIV_POLICY_PIV_PIN | TC_PIV_POLICY_VCI));

  card.answer_length = 0;
  tiny_crypto::piv_vci_mode mode = TC_PIV_VCI_WITHOUT_PAIRING;
  REQUIRE(tiny_crypto::piv_vci_establish(link, discovery, {pairing_code, sizeof pairing_code},
                                         mode) == TC_PIV_OK);
  CHECK(mode == TC_PIV_VCI_PAIRED);
  CHECK(link.info().vci == 1);
  CHECK(card.mac_valid);
  CHECK(card.plain_commands == 0);
  tiny_crypto::piv_link_unsecure(link);
  CHECK(link.info().vci == 0);
}
#endif
