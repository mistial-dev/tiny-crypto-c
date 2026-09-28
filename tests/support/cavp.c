/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev */

#include "cavp.h"
#include "test_io.h"

#include <string.h>

static int is_space(char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Trim both ends in place and return the first significant character. */
static char* trim(char* start, char* end)
{
  while (start < end && is_space(*start))
    ++start;
  while (end > start && is_space(end[-1]))
    --end;
  *end = '\0';
  return start;
}

int tc_cavp_open(tc_cavp_reader* reader, const char* directory, const char* relative, char* line,
                 size_t capacity)
{
  char path[1024];

  memset(reader, 0, sizeof *reader);
  if (line == NULL || capacity < 2 ||
      snprintf(path, sizeof path, "%s/%s", directory, relative) >= (int)sizeof path)
    return 0;
  reader->file = tc_test_fopen(path, "rb");
  reader->line = line;
  reader->capacity = capacity;
  return reader->file != NULL;
}

static void record_header(tc_cavp_reader* reader, const char* text)
{
  if (!reader->in_header_group)
    reader->header_count = 0;
  reader->in_header_group = 1;
  if (reader->header_count < TC_CAVP_MAX_HEADERS) {
    char* slot = reader->headers[reader->header_count++];
    strncpy(slot, text, TC_CAVP_HEADER_BYTES - 1);
    slot[TC_CAVP_HEADER_BYTES - 1] = '\0';
  }
}

tc_cavp_event tc_cavp_next(tc_cavp_reader* reader)
{
  if (reader->file == NULL)
    return TC_CAVP_FAILURE;
  while (fgets(reader->line, (int)reader->capacity, reader->file) != NULL) {
    char* line = reader->line;
    size_t length = strlen(line);
    char* equals;

    ++reader->line_number;
    /* A full buffer without a line ending means the line was cut. */
    if (length == reader->capacity - 1 && line[length - 1] != '\n' && !feof(reader->file))
      return TC_CAVP_FAILURE;
    line = trim(line, line + length);
    if (*line == '#')
      continue;
    if (*line == '\0') {
      if (!reader->record_open)
        continue;
      reader->record_open = 0;
      reader->name = "";
      reader->value = "";
      return TC_CAVP_RECORD_END;
    }
    if (*line == '[') {
      char* close = strchr(line, ']');
      if (close == NULL)
        return TC_CAVP_FAILURE;
      reader->name = trim(line + 1, close);
      reader->value = "";
      record_header(reader, reader->name);
      return TC_CAVP_HEADER;
    }
    reader->in_header_group = 0;
    reader->record_open = 1;
    equals = strchr(line, '=');
    if (equals == NULL) {
      reader->name = line;
      reader->value = "";
    } else {
      reader->value = trim(equals + 1, line + strlen(line));
      reader->name = trim(line, equals);
    }
    return TC_CAVP_FIELD;
  }
  if (ferror(reader->file))
    return TC_CAVP_FAILURE;
  if (reader->record_open) {
    reader->record_open = 0;
    reader->name = "";
    reader->value = "";
    return TC_CAVP_RECORD_END;
  }
  return TC_CAVP_END;
}

int tc_cavp_is(const tc_cavp_reader* reader, const char* name)
{
  return reader->name != NULL && strcmp(reader->name, name) == 0;
}

const char* tc_cavp_header_value(const tc_cavp_reader* reader, const char* name, char* value,
                                 size_t capacity)
{
  const size_t name_length = strlen(name);
  size_t i;

  for (i = 0; i < reader->header_count; ++i) {
    const char* parameter = reader->headers[i];
    /* Walk the comma-separated NAME = VALUE parameters of one header. */
    while (*parameter != '\0') {
      const char* end = strchr(parameter, ',');
      const char* cursor;
      size_t length;
      if (end == NULL)
        end = parameter + strlen(parameter);
      while (parameter < end && (*parameter == ' ' || *parameter == '\t'))
        ++parameter;
      cursor = parameter + name_length;
      if (end - parameter > (ptrdiff_t)name_length && strncmp(parameter, name, name_length) == 0) {
        while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
          ++cursor;
        if (cursor < end && *cursor == '=') {
          ++cursor;
          while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
            ++cursor;
          while (end > cursor && (end[-1] == ' ' || end[-1] == '\t'))
            --end;
          length = (size_t)(end - cursor);
          if (length >= capacity)
            return NULL;
          memcpy(value, cursor, length);
          value[length] = '\0';
          return value;
        }
      }
      parameter = *end == ',' ? end + 1 : end;
    }
  }
  return NULL;
}

int tc_cavp_header_has(const tc_cavp_reader* reader, const char* label)
{
  size_t i;

  for (i = 0; i < reader->header_count; ++i)
    if (strcmp(reader->headers[i], label) == 0)
      return 1;
  return 0;
}

void tc_cavp_close(tc_cavp_reader* reader)
{
  if (reader->file != NULL)
    fclose(reader->file);
  reader->file = NULL;
}

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

  while (text[0] != '\0' && text[0] != '\r' && text[0] != '\n' && text[0] != ' ') {
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
