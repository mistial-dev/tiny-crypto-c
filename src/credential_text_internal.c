/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "credential_text_internal.h"
#include "pki_internal.h"
#include <tiny_crypto/config.h>

#if TC_ENABLE_PIV_OBJECTS || TC_ENABLE_PIV_CHUID || TC_ENABLE_TWIC_CCL || TC_ENABLE_TWIC_TPK
#if defined(__AVR__) && TC_AVR_PROGMEM
#include <avr/pgmspace.h>
#define TC_TEXT_STORAGE PROGMEM
#define TC_TEXT_READ(value) pgm_read_byte(value)
#else
#define TC_TEXT_STORAGE
#define TC_TEXT_READ(value) (*(value))
#endif

int tc_credential_hex_digit(uint8_t value)
{
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'A' && value <= 'F')
    return value - 'A' + 10;
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  return -1;
}

unsigned tc_credential_month3(const uint8_t value[3], int title_case)
{
  static const uint8_t names[] TC_TEXT_STORAGE = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";
  for (unsigned month = 0; month < 12; ++month) {
    unsigned character;
    for (character = 0; character < 3; ++character) {
      uint8_t expected = TC_TEXT_READ(names + 3 * month + character);
      if (title_case && character != 0)
        expected += 'a' - 'A';
      if (value[character] != expected)
        break;
    }
    if (character == 3)
      return month + 1;
  }
  return 0;
}

int tc_credential_yyyymmdd(const uint8_t* value, size_t length, unsigned* year, unsigned* month,
                           unsigned* day)
{
  unsigned y = 0, m, d;
  if (!value || length != 8)
    return 0;
  for (size_t i = 0; i < 8; ++i)
    if (value[i] < '0' || value[i] > '9')
      return 0;
  for (size_t i = 0; i < 4; ++i)
    y = 10 * y + (unsigned)(value[i] - '0');
  m = 10 * (unsigned)(value[4] - '0') + (unsigned)(value[5] - '0');
  d = 10 * (unsigned)(value[6] - '0') + (unsigned)(value[7] - '0');
  if (!tc_pki_date(y, m, d))
    return 0;
  if (year)
    *year = y;
  if (month)
    *month = m;
  if (day)
    *day = d;
  return 1;
}
#endif
