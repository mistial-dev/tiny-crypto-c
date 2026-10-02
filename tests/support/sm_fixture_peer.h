/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Split a tools/sm_fixtures.py key establishment answer 7C {82 {CB_ICC ||
 * N_ICC || AuthCryptogram_ICC || C_ICC}} into session peer fields, for tests
 * of the session API below the APDU layer (SP 800-73-5 Part 2 4.1.8).
 * TC_PIV_SM_key_request decodes real answers. */
#ifndef TC_TEST_SM_FIXTURE_PEER_H
#define TC_TEST_SM_FIXTURE_PEER_H

#include <tiny_crypto/piv_sm.h>
#include <tiny_crypto/tlv.h>

/* Returns 1 and fills *peer when response has that layout. */
static inline int tc_sm_fixture_peer(TC_PIV_SM_suite suite, TC_bytes response, TC_PIV_SM_peer* peer)
{
  const size_t nonce = suite == TC_PIV_SM_CS2 ? 16u : 24u;
  const TC_TLV_limits limits = {response.length, response.length, 2, 1};
  TC_TLV_element outer, inner;
  if (TC_TLV_read(response, TC_TLV_ISO7816, &limits, &outer) != TC_TLV_OK ||
      TC_TLV_read(outer.value, TC_TLV_ISO7816, &limits, &inner) != TC_TLV_OK ||
      inner.value.length <= 1 + nonce + 16)
    return 0;
  peer->card_control = inner.value.data[0];
  peer->nonce.data = inner.value.data + 1;
  peer->nonce.length = nonce;
  peer->cryptogram.data = inner.value.data + 1 + nonce;
  peer->cryptogram.length = 16;
  peer->certificate.data = inner.value.data + 1 + nonce + 16;
  peer->certificate.length = inner.value.length - 1 - nonce - 16;
  return 1;
}

#endif
