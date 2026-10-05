/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC application rules for GET DATA (TWIC Part 2 v5 3.3.6, 4.5 and 5.2). */
#include <tiny_crypto/piv_command.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_COMMAND
#include "twic_command_internal.h"
#include "piv_link_internal.h"
#include "tlv_internal.h"
#include <string.h>

enum { CONTAINER = 0x53, CONSTRUCTED = 0x20 };

/* 1 when every byte after the object is an ISO/IEC 7816-4:2020 8.1.3 padding
 * byte. 00 and FF both pad when no data coding byte says otherwise. */
static int padding_only(TC_bytes data, size_t used)
{
  for (size_t i = used; i < data.length; ++i)
    if (!tc_tlv_padding(TC_TLV_ISO7816_PAD_ZERO_FF, data.data[i]))
      return 0;
  return 1;
}

TC_TLV_result tc_twic_object_frame(TC_bytes data, uint16_t sw, TC_bytes tag,
                                   const TC_TLV_limits* limits, TC_PIV_data_object* out)
{
  static const uint8_t empty_template[] = {0x80, 0x00};
  if (!data.length) {
    if (sw != TC_PIV_SW_SUCCESS_VALUE)
      return TC_TLV_INVALID;
    out->encoded = (TC_bytes){NULL, 0};
    out->value = (TC_bytes){NULL, 0};
    out->form = TC_PIV_FORM_NONE;
    return TC_TLV_OK;
  }
  TC_TLV_element element;
  const TC_TLV_result result = TC_TLV_read(data, TC_TLV_ISO7816, limits, &element);
  if (result != TC_TLV_OK)
    return result;
  const int container = tc_tlv_tag_is(&element, CONTAINER);
  const int framed = sw == TC_PIV_SW_END_OF_OBJECT_VALUE
                         ? padding_only(data, element.encoded.length)
                         : element.encoded.length == data.length;
  if ((!container && !tc_tlv_tag_matches(&element, tag)) || !framed)
    return TC_TLV_INVALID;
  out->encoded = element.encoded;
  out->value = element.value;
  out->form = container ? TC_PIV_FORM_CONTAINER : TC_PIV_FORM_TEMPLATE;
  if (!container && (tag.data[0] & CONSTRUCTED) && element.value.length == sizeof empty_template &&
      !memcmp(element.value.data, empty_template, sizeof empty_template))
    out->value.length = 0;
  return TC_TLV_OK;
}
#endif
