/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "cavp.h"

#include <stdio.h>
#include <string.h>

int tc_cavp_hex_nibble(int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

long tc_cavp_parse_hex(const char* text, uint8_t* output, size_t capacity)
{
  size_t length = 0;

  while (text[0] != '\0' && text[0] != '\r' && text[0] != '\n' &&
         text[0] != ' ')
  {
    const int high = tc_cavp_hex_nibble((unsigned char)text[0]);
    const int low = tc_cavp_hex_nibble((unsigned char)text[1]);
    if (high < 0 || low < 0 || length >= capacity)
      return -1;
    output[length++] = (uint8_t)((high << 4) | low);
    text += 2;
  }
  return (long)length;
}

const char* tc_cavp_field_value(const char* line, const char* name)
{
  const size_t name_length = strlen(name);
  const char* value = line;

  if (strncmp(value, name, name_length) != 0)
    return NULL;
  value += name_length;
  if (*value != ' ' && *value != '\t' && *value != '=')
    return NULL;
  while (*value == ' ' || *value == '\t')
    ++value;
  if (*value != '=')
    return NULL;
  ++value;
  while (*value == ' ' || *value == '\t')
    ++value;
  return value;
}

void tc_cavp_print_bytes(const char* label, const uint8_t* data, size_t length)
{
  size_t i;

  fprintf(stderr, "  %s = ", label);
  for (i = 0; i < length; ++i)
    fprintf(stderr, "%02x", data[i]);
  fputc('\n', stderr);
}
