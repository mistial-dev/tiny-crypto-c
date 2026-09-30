/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Link state and the command dispatch shared by the PIV command sources. */
#ifndef TC_PIV_LINK_INTERNAL_H_
#define TC_PIV_LINK_INTERNAL_H_
#include <tiny_crypto/piv_command.h>

/* TC_PIV_link.flags bits. */
enum {
  TC_PIV_LINK_SECURED = 1u << 0,
  TC_PIV_LINK_SM_LOST = 1u << 1,
  TC_PIV_LINK_VCI = 1u << 2,
  TC_PIV_LINK_PIN_VERIFIED = 1u << 3
};

enum {
  TC_PIV_SW_SUCCESS_VALUE = 0x9000,
  TC_PIV_SW_END_OF_OBJECT_VALUE = 0x6282,
  TC_PIV_PLAIN_CLA = 0x00
};

/* The PIV AID prefix (SP 800-73-5 Part 1 2.2) and the TWIC AID prefix (TWIC
 * Part 2 v5 4.1), each followed by two version bytes in a complete AID. */
#define TC_PIV_AID_PREFIX_BYTES 9u
#define TC_PIV_AID_BYTES (TC_PIV_AID_PREFIX_BYTES + 2u)
extern const uint8_t tc_piv_aid_prefixes[2][TC_PIV_AID_PREFIX_BYTES];
/* The complete PIV AID with version 01 00. */
extern const uint8_t tc_piv_aid[TC_PIV_AID_BYTES];
/* Prefix for application PIV or TWIC, NULL for another value. */
const uint8_t* tc_piv_aid_prefix(TC_PIV_application_id application);

/* 1 when link holds an initialized channel. */
int tc_piv_link_ready(const TC_PIV_link* link);
/* 1 when length bytes at data are disjoint from *link and its command
 * scratch, which the channel wipes after every transmit. */
int tc_piv_link_disjoint(const TC_PIV_link* link, const void* data, size_t length);
/* 1 when response can receive an answer for link and out: data present, at
 * least SW1 SW2, disjoint from *link, its command scratch and out_length bytes
 * at out. */
int tc_piv_response_valid(const TC_PIV_link* link, TC_buffer response, const void* out,
                          size_t out_length);

/* Send command for the command kind and collect the answer in response.
 * Records the kind, and the final SW as the link status on TC_PIV_OK. Every
 * other result sets the link status to 0 and has the channel wipe response.
 * TC_PIV_OK means the card answered with any status. The callers checked
 * their arguments. */
TC_PIV_result tc_piv_link_transceive(TC_PIV_link* link, TC_PIV_command kind,
                                     const TC_APDU_command* command, TC_buffer response,
                                     TC_APDU_response* out);

/* End a command that failed after transmit: wipe response, set the link
 * status to status and return result. */
TC_PIV_result tc_piv_link_fail(TC_PIV_link* link, TC_buffer response, uint16_t status,
                               TC_PIV_result result);
#endif
