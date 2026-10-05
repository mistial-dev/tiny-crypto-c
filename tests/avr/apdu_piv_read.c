/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* APDU lengths and a plain PIV read with a 16-bit size_t, run on an emulated
 * ATmega328P. The result is written to USART0 as APDU-OK or APDU-BAD n, where
 * n names the first failed check.
 *
 * Checks: Ne 65536 encodes extended 0000 and Ne 256 short 00 (ISO/IEC 7816-4
 * 5.2), an EXTENDED size above SIZE_MAX reports LIMIT, and a scripted card
 * answers SELECT, GET DATA and a VERIFY query (SP 800-73-5 Part 2 3.1.1,
 * 3.1.2 and 3.2.1). The script uses the SD 33 card 2 SELECT answer. */
#include <avr/io.h>
#include <stdint.h>
#include <string.h>
#include <tiny_crypto/piv_command.h>

static void put_string(const char* text)
{
  while (*text) {
    while (!(UCSR0A & (1 << UDRE0))) {
    }
    UDR0 = (uint8_t)*text++;
  }
}

/* One scripted card exchange: the expected command and the answer. */
typedef struct {
  const uint8_t* command;
  uint8_t command_length;
  const uint8_t* answer;
  uint8_t answer_length;
} Step;

typedef struct {
  const Step* steps;
  uint8_t count, next, mismatch;
} Script;

static TC_status script_transmit(void* context, TC_bytes command, TC_buffer response,
                                 size_t* length)
{
  Script* script = (Script*)context;
  if (script->next >= script->count) {
    script->mismatch = 1;
    return TC_ERROR;
  }
  const Step* step = &script->steps[script->next++];
  if (command.length != step->command_length ||
      memcmp(command.data, step->command, command.length) != 0 ||
      response.capacity < step->answer_length) {
    script->mismatch = 1;
    return TC_ERROR;
  }
  memcpy(response.data, step->answer, step->answer_length);
  *length = step->answer_length;
  return TC_OK;
}

static const uint8_t select_command[] = {0x00, 0xa4, 0x04, 0x00, 0x0b, 0xa0, 0x00, 0x00, 0x03,
                                         0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00};
/* SD 33 card 2: 61 {4F AID 01 00, 79 {4F RID}, 50 label, AC {80 2E, 06 01 00}}
 * and 7F66 {02 03F8, 02 7FFF}. */
static const uint8_t select_answer[] = {
    0x61, 0x2a, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x50, 0x0a, 0x49, 0x44, 0x2d, 0x4f,
    0x6e, 0x65, 0x20, 0x50, 0x49, 0x56, 0xac, 0x06, 0x80, 0x01, 0x2e, 0x06, 0x01, 0x00, 0x7f,
    0x66, 0x08, 0x02, 0x02, 0x03, 0xf8, 0x02, 0x02, 0x7f, 0xff, 0x90, 0x00};
/* GET DATA 5FC102 (CHUID) with Le 00. */
static const uint8_t get_data_command[] = {0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c,
                                           0x03, 0x5f, 0xc1, 0x02, 0x00};
static const uint8_t get_data_answer[] = {0x53, 0x04, 0x30, 0x02, 0x11, 0x22, 0x90, 0x00};
/* VERIFY query of the PIV PIN: 63C3 reports three tries. */
static const uint8_t verify_command[] = {0x00, 0x20, 0x00, 0x80};
static const uint8_t verify_answer[] = {0x63, 0xc3};

static int encode_check(uint32_t ne, TC_APDU_length_format format, const uint8_t* expected,
                        size_t expected_length)
{
  const TC_APDU_command command = {{NULL, 0}, ne, 0x00, 0xcb, 0x3f, 0xff};
  uint8_t encoded[8];
  size_t written = 0;
  /* A fill byte shows any Le byte that was never written. */
  memset(encoded, 0xee, sizeof encoded);
  return TC_APDU_command_encode(&command, format, (TC_buffer){encoded, sizeof encoded}, &written) ==
             TC_APDU_OK &&
         written == expected_length && memcmp(encoded, expected, expected_length) == 0;
}

/* Size of an EXTENDED case 4 command with nc data bytes, or 0 on failure.
 * Sizing never reads the data. Spans must not wrap the 16-bit address space,
 * so a span near SIZE_MAX bytes starts at address 1. */
static size_t extended_size(size_t nc, uint32_t ne, TC_APDU_result expected)
{
  const TC_APDU_command command = {{(const uint8_t*)1, nc}, ne, 0x00, 0xcb, 0x3f, 0xff};
  size_t size = 1;
  if (TC_APDU_command_size(&command, TC_APDU_EXTENDED, &size) != expected) {
    return 0;
  }
  return size;
}

static int length_checks(void)
{
  static const uint8_t extended[] = {0x00, 0xcb, 0x3f, 0xff, 0x00, 0x00, 0x00};
  static const uint8_t short_le[] = {0x00, 0xcb, 0x3f, 0xff, 0x00};
  if (sizeof(size_t) != 2) {
    return 1;
  }
  if (!encode_check(65536ul, TC_APDU_EXTENDED, extended, sizeof extended)) {
    return 2;
  }
  if (!encode_check(256, TC_APDU_SHORT, short_le, sizeof short_le) ||
      !encode_check(256, TC_APDU_EXTENDED, short_le, sizeof short_le)) {
    return 3;
  }
  /* Header, 3-byte Lc, 2-byte Le: nc = SIZE_MAX - 9 is the largest that fits. */
  if (extended_size(SIZE_MAX - 9u, 65536ul, TC_APDU_OK) != SIZE_MAX) {
    return 4;
  }
  /* Without Le, header and 3-byte Lc overflow with the largest span that fits. */
  if (extended_size(SIZE_MAX - 8u, 65536ul, TC_APDU_LIMIT) != 1 ||
      extended_size(TC_APDU_MAX_NC - 1u, 0, TC_APDU_LIMIT) != 1) {
    return 5;
  }
  return 0;
}

static int piv_read(void)
{
  static const Step steps[] = {
      {select_command, sizeof select_command, select_answer, sizeof select_answer},
      {get_data_command, sizeof get_data_command, get_data_answer, sizeof get_data_answer},
      {verify_command, sizeof verify_command, verify_answer, sizeof verify_answer}};
  static const uint8_t chuid_tag[] = {0x5f, 0xc1, 0x02};
  Script script = {steps, 3, 0, 0};
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 8, 0, 0}, TC_PIV_CONTACT, 0};
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  uint8_t response[64];
  TC_PIV_link link;
  TC_PIV_application application;
  TC_PIV_data_object object;
  TC_PIV_reference_status status;
  int failed = 0;
  if (TC_PIV_link_init(&link, (TC_APDU_transport){script_transmit, &script}, &options,
                       (TC_buffer){scratch, sizeof scratch}) != TC_PIV_OK) {
    return 10;
  }
  if (TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, (TC_buffer){response, sizeof response},
                    &application) != TC_PIV_OK ||
      application.max_command_bytes != 1016 || application.max_response_bytes != 32767 ||
      application.sm_suite != 0x2e) {
    failed = 11;
  } else if (TC_PIV_get_data(&link, (TC_bytes){chuid_tag, sizeof chuid_tag},
                             (TC_buffer){response, sizeof response}, &object) != TC_PIV_OK ||
             object.value.length != 4 || object.value.data != response + 2 ||
             object.form != TC_PIV_FORM_CONTAINER) {
    failed = 12;
  } else if (TC_PIV_verify_status(&link, 0x80, &status) != TC_PIV_OK || status.verified ||
             !status.retries_known || status.retries != 3 || TC_PIV_link_status(&link) != 0x63c3) {
    failed = 13;
  } else if (script.mismatch || script.next != 3 ||
             TC_APDU_channel_exchanges_left(&link.channel) != 5) {
    failed = 14;
  }
  TC_PIV_link_clear(&link);
  return failed;
}

int main(void)
{
  UCSR0B = 1 << TXEN0;
  UCSR0C = 3 << UCSZ00;
  int failed = length_checks();
  if (!failed) {
    failed = piv_read();
  }
  if (failed) {
    char text[] = "APDU-BAD 00\n";
    text[9] = (char)('0' + failed / 10);
    text[10] = (char)('0' + failed % 10);
    put_string(text);
  } else {
    put_string("APDU-OK\n");
  }
  for (;;) {
  }
}
