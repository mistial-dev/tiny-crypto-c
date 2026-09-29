/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * Shared reader for NIST CAVP response files (.rsp) and their companion
 * .txt files. A file is a sequence of bracketed headers such as [SHA-256],
 * [ENCRYPT] or [PredictionResistance = True], fields such as
 * "COUNT = 0" or "Key = 00ff", bare markers such as "FAIL", comments that
 * start with '#', and blank lines between records. A header may hold several
 * comma-separated parameters, as in [Alen = 0, Plen = 0, Nlen = 7].
 *
 * Usage:
 *   tc_cavp_reader reader;
 *   static char line[4096];
 *   if (!tc_cavp_open(&reader, DIR, "HMAC.rsp", line, sizeof line)) fail;
 *   while ((event = tc_cavp_next(&reader)) != TC_CAVP_END) {
 *     if (event == TC_CAVP_FAILURE) fail;
 *     if (event == TC_CAVP_FIELD && tc_cavp_is(&reader, "Key")) ...
 *   }
 *   tc_cavp_close(&reader);
 */
#ifndef TINY_CRYPTO_TEST_CAVP_H
#define TINY_CRYPTO_TEST_CAVP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum {
  TC_CAVP_MAX_HEADERS = 8,  /* headers kept for the current group */
  TC_CAVP_HEADER_BYTES = 96 /* longest header text, without brackets */
};

typedef enum {
  TC_CAVP_FIELD,      /* name and value are set, and value is "" for a bare marker */
  TC_CAVP_HEADER,     /* name is the header text without brackets */
  TC_CAVP_RECORD_END, /* a blank line or the end of file closed a record */
  TC_CAVP_END,        /* end of file */
  TC_CAVP_FAILURE     /* unreadable file or a line longer than the buffer */
} tc_cavp_event;

typedef struct {
  FILE* file;
  char* line; /* caller buffer, reused for every line */
  size_t capacity;
  unsigned long line_number;
  const char* name;  /* borrowed from line until the next call */
  const char* value; /* borrowed from line until the next call */
  char headers[TC_CAVP_MAX_HEADERS][TC_CAVP_HEADER_BYTES];
  size_t header_count;
  int in_header_group; /* the previous significant line was a header */
  int record_open;     /* a field arrived since the last record end */
} tc_cavp_reader;

/* Open DIRECTORY/RELATIVE. The line buffer must hold the longest line plus
 * its line ending and terminator. Returns 1 on success and 0 on failure. */
int tc_cavp_open(tc_cavp_reader* reader, const char* directory, const char* relative, char* line,
                 size_t capacity);

/* Read the next field, header or record end. Comments are skipped. A blank
 * line after one or more fields ends a record, and the end of file ends the
 * final record when it has no trailing blank line. Headers that follow a
 * field start a new group and replace the previous group. Field names and
 * values have surrounding whitespace removed. */
tc_cavp_event tc_cavp_next(tc_cavp_reader* reader);

/* True when the current field or header name equals name exactly. */
int tc_cavp_is(const tc_cavp_reader* reader, const char* name);

/* Copy the value of NAME in the current header group into value and return
 * value, or return NULL when NAME is absent or its value is too long. Each
 * header is searched as a comma-separated list of NAME = VALUE parameters,
 * and the value runs to the next comma or the end of the header. */
const char* tc_cavp_header_value(const tc_cavp_reader* reader, const char* name, char* value,
                                 size_t capacity);

/* True when the current group contains the bare header [label]. */
int tc_cavp_header_has(const tc_cavp_reader* reader, const char* label);

void tc_cavp_close(tc_cavp_reader* reader);

typedef enum {
  /* One field value. The digits may be followed by spaces, tabs, CR or LF
   * and end at NUL or a closing '"'. Any other text after them fails. */
  TC_TEST_HEX_FIELD,
  /* Hex bytes with any non-hex separators between them, such as "00 01:02".
   * Decoding ends at NUL. */
  TC_TEST_HEX_SEPARATED
} tc_test_hex_format;

/* The one hex decoder of the test suite. Decode text into output and store
 * the byte count in *length. Returns 1 on success. Returns 0 with *length
 * unchanged for an odd digit count, a non-hex character inside a byte, a
 * non-hex character in TC_TEST_HEX_FIELD format, or more bytes than capacity.
 * output may change on failure. */
int tc_test_hex_decode(const char* text, tc_test_hex_format format, uint8_t* output,
                       size_t capacity, size_t* length);
/* Decode a fixture known to be well formed in TC_TEST_HEX_FIELD format and
 * return its byte count. Malformed text or too little capacity fails the
 * current munit test. Readers of external files that must report malformed
 * values call tc_test_hex_decode instead. */
size_t tc_test_hex(const char* text, uint8_t* output, size_t capacity);
/* Match "NAME = value" in a raw line and return the value, or NULL. */
const char* tc_cavp_field_value(const char* line, const char* name);
void tc_cavp_print_bytes(const char* label, const uint8_t* data, size_t length);

#endif
