/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_PIV_UUID_INTERNAL_H_
#define TC_PIV_UUID_INTERNAL_H_
#include <stdint.h>

/* Bit for one RFC 4122 version in a tc_piv_uuid_valid mask. */
#define TC_PIV_UUID_VERSION(version) (1u << (version))
/* Card UUID versions (SP 800-73-5 Part 1 3.4.1). */
#define TC_PIV_CARD_UUID_VERSIONS                                                                  \
  (TC_PIV_UUID_VERSION(1) | TC_PIV_UUID_VERSION(4) | TC_PIV_UUID_VERSION(5))
/* Cardholder UUID version (SP 800-73-5 Part 1 3.4.2). */
#define TC_PIV_CARDHOLDER_UUID_VERSIONS TC_PIV_UUID_VERSION(4)

/* 1 when the 16-byte uuid has the RFC 4122 variant 10x (section 4.1.1) and a
 * version listed in versions (section 4.1.3). */
static inline int tc_piv_uuid_valid(const uint8_t* uuid, unsigned versions)
{
  return (uuid[8] & 0xc0) == 0x80 && ((versions >> (uuid[6] >> 4)) & 1u);
}
#endif
