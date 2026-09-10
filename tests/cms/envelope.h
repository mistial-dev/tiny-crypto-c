/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TEST_CMS_ENVELOPE_H_
#define TEST_CMS_ENVELOPE_H_
#include <tiny_crypto/cms.h>
#include "munit.h"
#include <string.h>

/* Reframe an envelope without changing the signed content or attributes. */
static inline size_t test_cms_encode_envelope(const TC_CMS_signed_data* data,
    TC_bytes algorithms, TC_bytes signers, uint8_t* out, size_t capacity)
{
  const uint8_t header[] = {0x30,0x80,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2,
    0xa0,0x80,0x30,0x80,2,1,(uint8_t)data->version};
  const uint8_t encap[] = {0x30,0x80,6,(uint8_t)data->content_type.length};
  static const uint8_t content_header[] = {0xa0,0x80}, end[] = {0,0}, finish[] = {0,0,0,0,0,0};
  munit_assert_size(data->content_type.length, <, 128);
  const TC_bytes parts[] = {
    {header,sizeof header},algorithms,{encap,sizeof encap},data->content_type,
    {content_header,data->has_content ? sizeof content_header : 0},data->content,
    {end,data->has_content ? sizeof end : 0},{end,sizeof end},data->certificates,
    data->revocations,signers,{finish,sizeof finish}
  };
  size_t used = 0;
  for (size_t i = 0; i < sizeof parts / sizeof *parts; ++i) {
    munit_assert_size(parts[i].length, <=, capacity - used);
    if (parts[i].length) memcpy(out + used,parts[i].data,parts[i].length);
    used += parts[i].length;
  }
  return used;
}
#endif
