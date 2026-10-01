/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* libFuzzer target for the PIV card stack on arbitrary card answers. Every
 * input runs through each stage:
 * - ISO/IEC 7816-4 response reading and exchanges: chaining, GET RESPONSE
 *   and 6CXX correction (5.3.3, 5.3.4, 5.6).
 * - PIV and TWIC SELECT and GET DATA framing (SP 800-73-5 Part 2 3.1.1 and
 *   3.1.2, TWIC Part 2 v5 5.1 and 5.2).
 * - The card object readers and certificate decoding (Part 1 3.1.1, 3.3 and
 *   Tables 9, 10, 19, 20, 42 and 44).
 * - Secure messaging answers, raw and authenticated with the fixture keys,
 *   and the session-loss rule (Part 2 4.2.5 to 4.3, footnote 25).
 * - The Discovery Object read under secure messaging and the VCI (Part 1
 *   5.5), the inventory and the key proof answer (Part 2 3.2.4, A.4).
 *
 * The input is a card answer in one of three forms: the bytes as sent,
 * the bytes followed by 90 00, or a script of answers. A script record is a
 * 2-byte big-endian length (low 13 bits) and that many answer bytes, and the
 * transport fails once the script ends.
 *
 * Checked invariants: card data never produces ARGUMENT or REFUSED, outputs
 * change only on success, failures wipe the documented buffers, success
 * returns spans inside the caller's buffers, and a failed secure messaging
 * exchange ends the session. AddressSanitizer checks that no read leaves the
 * input or the buffers. */
#include <tiny_crypto/piv_card_objects.h>
#include <tiny_crypto/piv_catalog.h>
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_key_proof.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_vci.h>
#include <tiny_crypto/x509_crypto.h>
#include "piv_link_internal.h"
#include "sm_card.h"
#include "sm_fixtures.h"
#include <stdlib.h>
#include <string.h>

#define DER_BYTES 4096u
#define SENTINEL 0xa5u
#define UNWRITTEN 0x5au

enum {
  SCRATCH_BYTES = 1024,
  SM_SCRATCH_BYTES = 1024,
  /* Enough for two SM commands whose answers arrive in 256-byte chunks,
   * plus the key establishment. */
  EXCHANGES = 64,
  CHANNEL_EXCHANGES = 8,
  SCRIPT_CAPACITY = 600,
  SUITES = 2,
  /* Plaintext bounds for authenticated answers. 1 KiB still spans five
   * GET RESPONSE chunks, and the Discovery Object needs 20 bytes. Larger
   * answers add AES work without new paths. */
  SM_PLAIN_MAX = 1024,
  VCI_PLAIN_MAX = 64,
  WORK = 1 << 24,
  /* The response buffer holds at least this many answer bytes, enough for
   * the setup SELECT and key establishment answers of every input. */
  SETUP_ANSWER_BYTES = 8192
};

static void require(int condition)
{
  if (!condition)
    abort();
}

static int all_value(const void* pointer, size_t length, uint8_t value)
{
  const uint8_t* bytes = pointer;
  for (size_t i = 0; i < length; ++i)
    if (bytes[i] != value)
      return 0;
  return 1;
}

/* An empty span may point anywhere. */
static int span_within(TC_bytes inner, const uint8_t* outer, size_t length)
{
  return !inner.length || (inner.data >= outer && inner.length <= length &&
                           (size_t)(inner.data - outer) <= length - inner.length);
}

/* Fuzz card */

typedef enum { ANSWER_REPEAT, ANSWER_SCRIPT } answer_mode;

/* A transport that answers from fixed prefix answers first, then from the
 * SM card model when sm is set, else from source. It records the highest
 * byte written into the tracked buffer, so the checks can tell received
 * bytes from untouched ones. */
typedef struct {
  const TC_bytes* prefix;
  size_t prefix_count, prefix_sent;
  answer_mode mode;
  TC_bytes source;
  size_t offset;
  tc_sm_card* sm;
  size_t transmits;
  const uint8_t* tracked;
  size_t tracked_capacity, high_water;
} fuzz_card;

static fuzz_card card;

static void card_setup(const TC_bytes* prefix, size_t prefix_count, answer_mode mode,
                       TC_bytes source, tc_sm_card* sm)
{
  memset(&card, 0, sizeof card);
  card.prefix = prefix;
  card.prefix_count = prefix_count;
  card.mode = mode;
  card.source = source;
  card.sm = sm;
}

static void card_track(const uint8_t* buffer, size_t capacity)
{
  card.tracked = buffer;
  card.tracked_capacity = capacity;
  card.high_water = 0;
}

static void card_mark(TC_buffer response, size_t length)
{
  if (!card.tracked || response.data < card.tracked ||
      response.data >= card.tracked + card.tracked_capacity)
    return;
  const size_t end = (size_t)(response.data - card.tracked) + length;
  if (end > card.high_water)
    card.high_water = end;
}

static int script_next(TC_bytes* answer)
{
  const TC_bytes script = card.source;
  if (script.length - card.offset < 2)
    return 0;
  size_t length = (size_t)(script.data[card.offset] & 0x1f) << 8 | script.data[card.offset + 1];
  card.offset += 2;
  if (length > script.length - card.offset)
    length = script.length - card.offset;
  *answer = (TC_bytes){script.data + card.offset, length};
  card.offset += length;
  return 1;
}

static TC_status card_transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  TC_bytes answer;
  (void)context;
  ++card.transmits;
  if (card.prefix_sent < card.prefix_count)
    answer = card.prefix[card.prefix_sent++];
  else if (card.sm) {
    const TC_status status =
        tc_sm_card_transport(card.sm).transmit(card.sm, command, response, length);
    if (status == TC_OK)
      card_mark(response, *length);
    return status;
  } else if (card.mode == ANSWER_REPEAT)
    answer = card.source;
  else if (!script_next(&answer))
    return TC_ERROR;
  if (answer.length > response.capacity)
    return TC_ERROR;
  if (answer.length)
    memcpy(response.data, answer.data, answer.length);
  *length = answer.length;
  card_mark(response, answer.length);
  return TC_OK;
}

static const TC_APDU_transport transport = {card_transmit, &card};

/* Fixed answers and buffers */

/* Synthetic SELECT answers: 61 {4F PIV AID, 79 {4F RID}, AC {80 suite,
 * 06 01 00}} 7F66 {02 03F8, 02 7FFF} 90 00, and the TWIC NEXGEN answer
 * 61 {4F AID 01 03, 79 {4F RID}} 7F66 {02 0400, 02 0800} 90 00. */
#define PIV_APT(suite)                                                                             \
  {0x61, 0x1e, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01,  0x00,      \
   0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0xac, 0x06, 0x80, 0x01, suite, 0x06,      \
   0x01, 0x00, 0x7f, 0x66, 0x08, 0x02, 0x02, 0x03, 0xf8, 0x02, 0x02, 0x7f, 0xff, 0x90,  0x00}
static const uint8_t piv_apt_cs2[] = PIV_APT(0x27);
static const uint8_t piv_apt_cs7[] = PIV_APT(0x2e);
static const uint8_t twic_apt[] = {0x61, 0x14, 0x4f, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x67,
                                   0x20, 0x00, 0x00, 0x01, 0x01, 0x03, 0x79, 0x05, 0x4f,
                                   0x03, 0xa0, 0x00, 0x00, 0x7f, 0x66, 0x08, 0x02, 0x02,
                                   0x04, 0x00, 0x02, 0x02, 0x08, 0x00, 0x90, 0x00};
static const TC_bytes piv_select = {piv_apt_cs2, sizeof piv_apt_cs2};
static const TC_bytes twic_select = {twic_apt, sizeof twic_apt};

static const uint8_t tag_chuid[] = {0x5f, 0xc1, 0x02};
static const uint8_t tag_discovery[] = {0x7e};
static const uint8_t tag_bit_group[] = {0x7f, 0x61};
static const uint8_t tag_twic_privacy[] = {0xdf, 0xc1, 0x01};
/* A synthetic pairing code. */
static const uint8_t pairing_code[] = "31415926";

static uint8_t scratch[SCRATCH_BYTES], sm_scratch[SM_SCRATCH_BYTES];
/* Sized for the whole input as one answer, so the library sees every input.
 * A smaller configured buffer or limit must give LIMIT. */
static uint8_t* response;
static size_t response_bytes;

/* Size the response buffer for an answer of answer_bytes, and at least for
 * the setup answers. */
static void response_prepare(size_t answer_bytes)
{
  const size_t bytes =
      TC_PIV_RESPONSE_BYTES(answer_bytes > SETUP_ANSWER_BYTES ? answer_bytes : SETUP_ANSWER_BYTES);
  if (bytes > response_bytes) {
    response = realloc(response, bytes);
    require(response != NULL);
    response_bytes = bytes;
  }
}

static TC_buffer response_reset(size_t capacity)
{
  memset(response, SENTINEL, response_bytes);
  card_track(response, capacity);
  return (TC_buffer){response, capacity};
}

/* Open a plain link and select application from the card prefix. */
static void link_open(TC_PIV_link* link, TC_APDU_length_format format,
                      TC_PIV_application_id application)
{
  const TC_PIV_link_options options = {
      {format, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, format == TC_APDU_EXTENDED ? 65536u : 0u};
  TC_PIV_application selected;
  require(TC_PIV_link_init(link, transport, &options, (TC_buffer){scratch, sizeof scratch}) ==
          TC_PIV_OK);
  if (application != TC_PIV_APPLICATION_NONE)
    require(TC_PIV_select(link, application, 0, response_reset(response_bytes), &selected) ==
            TC_PIV_OK);
}

/* Link information after a call. */
static TC_PIV_link_info link_info(const TC_PIV_link* link)
{
  TC_PIV_link_info info;
  TC_PIV_link_info_get(link, &info);
  return info;
}

/* ISO/IEC 7816-4 */

static void response_read_check(TC_bytes input)
{
  TC_APDU_response out;
  memset(&out, UNWRITTEN, sizeof out);
  const TC_APDU_result result = TC_APDU_response_read(input, &out);
  if (result == TC_APDU_OK) {
    require(input.length >= 2 && out.data.length == input.length - 2);
    require(span_within(out.data, input.data, input.length));
    require(out.sw == (uint16_t)(input.data[input.length - 2] << 8 | input.data[input.length - 1]));
    (void)TC_APDU_status_classify(out.sw);
  } else
    require(result == TC_APDU_INVALID && all_value(&out, sizeof out, UNWRITTEN));
}

static const uint8_t command_data[300] = {0x5c, 0x03, 0x5f, 0xc1, 0x02};

/* One exchange on a new channel. OK wipes the received status bytes after
 * the data and leaves bytes past the last received one untouched. Card
 * failures wipe the whole response buffer, and a transport failure stops
 * the channel. */
static void exchange_check(TC_APDU_length_format format, const TC_APDU_command* command,
                           answer_mode mode, TC_bytes source, size_t capacity)
{
  const TC_APDU_channel_options options = {
      format,
      format == TC_APDU_SHORT ? TC_APDU_GET_RESPONSE_PLAIN_CLA | TC_APDU_GET_RESPONSE_LE_FF : 0,
      CHANNEL_EXCHANGES, 0, 0};
  TC_APDU_channel channel;
  TC_APDU_response out;
  card_setup(NULL, 0, mode, source, NULL);
  require(TC_APDU_channel_init(&channel, transport, &options,
                               (TC_buffer){scratch, sizeof scratch}) == TC_APDU_OK);
  const TC_buffer buffer = response_reset(capacity);
  memset(&out, UNWRITTEN, sizeof out);
  const TC_APDU_result result = TC_APDU_transceive(&channel, command, buffer, &out);
  require(all_value(scratch, sizeof scratch, 0));
  require(card.transmits == CHANNEL_EXCHANGES - TC_APDU_channel_exchanges_left(&channel));
  if (result == TC_APDU_OK) {
    require(span_within(out.data, response, capacity));
    const size_t end = out.data.length ? (size_t)(out.data.data - response) + out.data.length : 0;
    const size_t received = card.high_water > end ? card.high_water : end;
    require(all_value(response + end, received - end, 0));
    require(all_value(response + received, capacity - received, SENTINEL));
  } else {
    require(result == TC_APDU_INVALID || result == TC_APDU_LIMIT || result == TC_APDU_ERROR);
    require(all_value(response, capacity, 0) && all_value(&out, sizeof out, UNWRITTEN));
    if (result == TC_APDU_ERROR) {
      const size_t sent = card.transmits;
      memset(response, SENTINEL, capacity);
      require(TC_APDU_transceive(&channel, command, buffer, &out) == TC_APDU_ERROR);
      require(card.transmits == sent && all_value(response, capacity, SENTINEL));
    }
  }
  TC_APDU_channel_clear(&channel);
}

static void apdu_check(TC_bytes input, TC_bytes with_status)
{
  static const TC_APDU_length_format formats[] = {TC_APDU_SHORT, TC_APDU_EXTENDED};
  response_read_check(input);
  response_read_check(with_status);
  for (size_t f = 0; f < sizeof formats / sizeof *formats; ++f) {
    const uint32_t ne = formats[f] == TC_APDU_SHORT ? 256u : 65536u;
    /* Case 2 GET DATA, case 4 with a data field that SHORT chains, and
     * case 3 VERIFY without Le. */
    const TC_APDU_command commands[] = {
        {{command_data, 5}, ne, 0x00, 0xcb, 0x3f, 0xff},
        {{command_data, sizeof command_data}, ne, 0x00, 0x87, 0x07, 0x9e},
        {{command_data, 8}, 0, 0x00, 0x20, 0x00, 0x80}};
    for (size_t c = 0; c < sizeof commands / sizeof *commands; ++c) {
      exchange_check(formats[f], &commands[c], ANSWER_REPEAT, input, response_bytes);
      exchange_check(formats[f], &commands[c], ANSWER_REPEAT, with_status, response_bytes);
      exchange_check(formats[f], &commands[c], ANSWER_SCRIPT, input, SCRIPT_CAPACITY);
    }
  }
}

/* SELECT and GET DATA */

static void application_read_check(TC_bytes input)
{
  static const TC_PIV_application_id applications[] = {TC_PIV_APPLICATION_PIV,
                                                       TC_PIV_APPLICATION_TWIC};
  static const unsigned flags[] = {0, TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE};
  for (size_t a = 0; a < 2; ++a)
    for (size_t f = 0; f < 2; ++f) {
      TC_PIV_application out;
      memset(&out, UNWRITTEN, sizeof out);
      const TC_TLV_result result = TC_PIV_application_read(input, applications[a], flags[f], &out);
      if (result == TC_TLV_OK)
        require(span_within(out.aid, input.data, input.length) && out.aid.length == 11 &&
                span_within(out.label, input.data, input.length) &&
                span_within(out.url, input.data, input.length) &&
                span_within(out.algorithms, input.data, input.length));
      else
        require(
            (result == TC_TLV_INVALID || result == TC_TLV_LIMIT || result == TC_TLV_UNSUPPORTED) &&
            all_value(&out, sizeof out, UNWRITTEN));
    }
}

static void select_check(TC_PIV_application_id application, TC_bytes answer)
{
  TC_PIV_link link;
  TC_PIV_application out;
  card_setup(NULL, 0, ANSWER_REPEAT, answer, NULL);
  link_open(&link, TC_APDU_SHORT, TC_PIV_APPLICATION_NONE);
  const TC_buffer buffer = response_reset(response_bytes);
  memset(&out, UNWRITTEN, sizeof out);
  const TC_PIV_result result = TC_PIV_select(&link, application, 0, buffer, &out);
  const TC_PIV_link_info info = link_info(&link);
  if (result == TC_PIV_OK)
    require(info.application == application && span_within(out.aid, response, response_bytes) &&
            span_within(out.label, response, response_bytes) &&
            span_within(out.url, response, response_bytes) &&
            span_within(out.algorithms, response, response_bytes));
  else
    require(result != TC_PIV_ARGUMENT && result != TC_PIV_REFUSED &&
            info.application == TC_PIV_APPLICATION_NONE && all_value(response, response_bytes, 0) &&
            all_value(&out, sizeof out, UNWRITTEN));
  TC_PIV_link_clear(&link);
}

/* A data object borrows the response. FORM_NONE has no spans. */
static void object_within(const TC_PIV_data_object* object)
{
  require(span_within(object->encoded, response, response_bytes));
  require(span_within(object->value, object->encoded.data, object->encoded.length));
  require(object->status == 0x9000 || object->status == 0x6282);
  require(object->form <= TC_PIV_FORM_NONE);
  if (object->form == TC_PIV_FORM_NONE)
    require(!object->encoded.length && !object->value.length);
}

/* Card failures of GET DATA wipe the response and leave out unchanged. */
static void get_data_failed(TC_PIV_result result, const TC_PIV_data_object* out)
{
  require(result != TC_PIV_ARGUMENT && result != TC_PIV_REFUSED && result != TC_PIV_UNSUPPORTED);
  require(all_value(response, response_bytes, 0) && all_value(out, sizeof *out, UNWRITTEN));
}

static void get_data_check(TC_PIV_application_id application, TC_APDU_length_format format,
                           answer_mode mode, TC_bytes source, TC_bytes tag)
{
  TC_PIV_link link;
  TC_PIV_data_object out;
  card_setup(application == TC_PIV_APPLICATION_PIV ? &piv_select : &twic_select, 1, mode, source,
             NULL);
  link_open(&link, format, application);
  const TC_buffer buffer = response_reset(response_bytes);
  memset(&out, UNWRITTEN, sizeof out);
  const TC_PIV_result result = TC_PIV_get_data(&link, tag, buffer, &out);
  if (result == TC_PIV_OK)
    object_within(&out);
  else
    get_data_failed(result, &out);
  TC_PIV_link_clear(&link);
}

static void command_check(TC_bytes input, TC_bytes with_status)
{
  const TC_bytes chuid = {tag_chuid, sizeof tag_chuid};
  const TC_bytes discovery = {tag_discovery, sizeof tag_discovery};
  const TC_bytes bit_group = {tag_bit_group, sizeof tag_bit_group};
  const TC_bytes privacy = {tag_twic_privacy, sizeof tag_twic_privacy};
  application_read_check(input);
  select_check(TC_PIV_APPLICATION_PIV, with_status);
  select_check(TC_PIV_APPLICATION_TWIC, with_status);
  select_check(TC_PIV_APPLICATION_PIV, input);
  get_data_check(TC_PIV_APPLICATION_PIV, TC_APDU_SHORT, ANSWER_REPEAT, with_status, chuid);
  get_data_check(TC_PIV_APPLICATION_PIV, TC_APDU_SHORT, ANSWER_REPEAT, with_status, discovery);
  get_data_check(TC_PIV_APPLICATION_PIV, TC_APDU_SHORT, ANSWER_REPEAT, with_status, bit_group);
  get_data_check(TC_PIV_APPLICATION_PIV, TC_APDU_SHORT, ANSWER_REPEAT, input, chuid);
  get_data_check(TC_PIV_APPLICATION_PIV, TC_APDU_SHORT, ANSWER_SCRIPT, input, chuid);
  get_data_check(TC_PIV_APPLICATION_PIV, TC_APDU_EXTENDED, ANSWER_REPEAT, with_status, chuid);
  get_data_check(TC_PIV_APPLICATION_TWIC, TC_APDU_SHORT, ANSWER_REPEAT, with_status, chuid);
  get_data_check(TC_PIV_APPLICATION_TWIC, TC_APDU_SHORT, ANSWER_REPEAT, with_status, privacy);
  get_data_check(TC_PIV_APPLICATION_TWIC, TC_APDU_SHORT, ANSWER_SCRIPT, input, privacy);
}

/* Card object readers */

/* Reader failures on card data leave out unchanged. */
static void reader_result(TC_TLV_result result, const void* out, size_t size)
{
  require(result != TC_TLV_ARGUMENT);
  if (result != TC_TLV_OK)
    require(all_value(out, size, UNWRITTEN));
}

static void container_readers_check(TC_bytes input, TC_PIV_container_encoding encoding)
{
  TC_PIV_CCC ccc;
  TC_PIV_key_history history;
  TC_bytes code;
  memset(&ccc, UNWRITTEN, sizeof ccc);
  TC_TLV_result result = TC_PIV_CCC_read(input, encoding, &ccc);
  reader_result(result, &ccc, sizeof ccc);
  if (result == TC_TLV_OK)
    require(span_within(ccc.card_identifier, input.data, input.length) &&
            span_within(ccc.card_url, input.data, input.length) &&
            span_within(ccc.access_control_rules, input.data, input.length));
  memset(&history, UNWRITTEN, sizeof history);
  result = TC_PIV_key_history_read(input, encoding, &history);
  reader_result(result, &history, sizeof history);
  if (result == TC_TLV_OK)
    require(span_within(history.url, input.data, input.length) &&
            history.url.length <= TC_PIV_KEY_HISTORY_URL_MAX_BYTES &&
            history.on_card + history.off_card <= TC_PIV_KEY_HISTORY_MAX_KEYS);
  memset(&code, UNWRITTEN, sizeof code);
  result = TC_PIV_pairing_code_read(input, encoding, &code);
  reader_result(result, &code, sizeof code);
  if (result == TC_TLV_OK)
    require(span_within(code, input.data, input.length) &&
            code.length == TC_PIV_PAIRING_CODE_BYTES);
}

static void object_readers_check(TC_bytes input)
{
  static const TC_PIV_discovery_profile profiles[] = {TC_PIV_DISCOVERY_PIV, TC_PIV_DISCOVERY_TWIC};
  TC_PIV_bit_group group;
  container_readers_check(input, TC_PIV_CONTENTS);
  container_readers_check(input, TC_PIV_CONTAINER);
  memset(&group, UNWRITTEN, sizeof group);
  const TC_TLV_result result = TC_PIV_bit_group_read(input, &group);
  reader_result(result, &group, sizeof group);
  if (result == TC_TLV_OK) {
    require(group.fingers <= 2);
    for (size_t i = 0; i < 2; ++i)
      require(span_within(group.templates[i], input.data, input.length) &&
              group.templates[i].length <= TC_PIV_BIT_MAX_BYTES);
  }
  for (size_t p = 0; p < 2; ++p) {
    TC_PIV_discovery discovery;
    memset(&discovery, UNWRITTEN, sizeof discovery);
    const TC_TLV_result read = TC_PIV_discovery_read(input, profiles[p], &discovery);
    reader_result(read, &discovery, sizeof discovery);
    if (read == TC_TLV_OK)
      require(span_within(discovery.aid, input.data, input.length) && discovery.aid.length == 11 &&
              discovery.profile == profiles[p] && !discovery.secured);
  }
}

/* A decoded certificate is one DER SEQUENCE in the container (PLAIN) or in
 * der (GZIP). Every failure wipes der. */
static void certificate_check(TC_bytes input)
{
  static const TC_PIV_certificate_profile profiles[] = {
      TC_PIV_CERTIFICATE_SLOT, TC_PIV_CERTIFICATE_TWIC, TC_PIV_CERTIFICATE_SM_SIGNER};
  static TC_GZIP_workspace gzip;
  static uint8_t der[DER_BYTES];
  for (size_t p = 0; p < sizeof profiles / sizeof *profiles; ++p) {
    TC_PIV_certificate out;
    size_t work = WORK;
    memset(der, SENTINEL, sizeof der);
    memset(&out, UNWRITTEN, sizeof out);
    const TC_TLV_result result =
        TC_PIV_certificate_decode(input, profiles[p], TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip,
                                  &work, (TC_buffer){der, sizeof der}, &out);
    require(result != TC_TLV_ARGUMENT);
    if (result != TC_TLV_OK) {
      require(all_value(der, sizeof der, 0) && all_value(&out, sizeof out, UNWRITTEN));
      continue;
    }
    require(out.certificate.length >= 2 && out.certificate.data[0] == 0x30);
    require(span_within(out.intermediate_cvc, input.data, input.length) &&
            span_within(out.mscuid, input.data, input.length));
    if (out.compression == TC_PIV_CERTIFICATE_GZIP)
      require(out.certificate.data == der && out.certificate.length <= sizeof der);
    else
      require(span_within(out.certificate, input.data, input.length) && work == WORK &&
              all_value(der, sizeof der, SENTINEL));
  }
}

/* Secure messaging */

/* A secured link for each suite, established once with the fixture
 * handshake of tools/sm_fixtures.py. Each stage restores the saved link,
 * session and card model at their original addresses, which repeats the
 * same session counter against the same card state. The fixture keys
 * protect nothing, so this reuse is confined to the harness. */
static TC_PIV_link secured;
static TC_PIV_SM session;
static TC_PIV_SM_workspace sm_workspace;
static tc_sm_card sm_card;
static struct {
  TC_PIV_link link;
  TC_PIV_SM session;
  tc_sm_card card;
} saved[SUITES];
static uint8_t key_answers[SUITES][512];
static size_t suite_count;

static TC_status scalar_one(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memset(output, 0, length);
  output[length - 1] = 1;
  return TC_OK;
}

static void secured_save(const struct tc_sm_fixture* fixture)
{
  static const uint8_t host_id[8] = {0};
  const TC_bytes select = fixture->suite == TC_PIV_SM_CS2
                              ? (TC_bytes){piv_apt_cs2, sizeof piv_apt_cs2}
                              : (TC_bytes){piv_apt_cs7, sizeof piv_apt_cs7};
  uint8_t* key_answer = key_answers[suite_count];
  TC_PIV_SM_peer peer;
  require(fixture->response.length + 2 <= sizeof key_answers[0]);
  memcpy(key_answer, fixture->response.data, fixture->response.length);
  key_answer[fixture->response.length] = 0x90;
  key_answer[fixture->response.length + 1] = 0x00;
  tc_sm_card_init(&sm_card);
  sm_card.key_command = fixture->request;
  sm_card.key_answer = (TC_bytes){key_answer, fixture->response.length + 2};
  card_setup(&select, 1, ANSWER_REPEAT, (TC_bytes){NULL, 0}, &sm_card);
  link_open(&secured, TC_APDU_SHORT, TC_PIV_APPLICATION_PIV);
  memset(&session, 0, sizeof session);
  require(TC_PIV_SM_key_request(&secured, &session, fixture->suite, host_id,
                                (TC_random_source){scalar_one, NULL},
                                response_reset(response_bytes), &peer, &sm_workspace) == TC_PIV_OK);
  require(TC_PIV_SM_finish(&session, &peer, fixture->public_key, &sm_workspace) == TC_OK);
  tc_sm_card_keys(&sm_card, fixture->material);
  require(TC_PIV_link_secure(&secured, &sm_workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}) ==
          TC_PIV_OK);
  require(!sm_card.broken);
  saved[suite_count].link = secured;
  saved[suite_count].session = session;
  saved[suite_count].card = sm_card;
  ++suite_count;
}

/* Restore suite s and let the SM card model answer when model is set. */
static void secured_restore(size_t s, int model)
{
  secured = saved[s].link;
  session = saved[s].session;
  sm_card = saved[s].card;
  memset(&sm_workspace, 0, sizeof sm_workspace);
  memset(sm_scratch, 0, sizeof sm_scratch);
  card_setup(NULL, 0, ANSWER_REPEAT, (TC_bytes){NULL, 0}, model ? &sm_card : NULL);
}

static int session_live(void)
{
  const TC_PIV_link_info info = link_info(&secured);
  return info.secured && !info.sm_lost && TC_PIV_SM_get_state(&session) == TC_PIV_SM_READY;
}

/* A session loss clears the session, the VCI and PIN status, wipes the
 * response and the SM scratch, and later protected commands are refused
 * without transmit. */
static void session_lost_check(TC_PIV_result result)
{
  const TC_PIV_link_info info = link_info(&secured);
  const TC_bytes chuid = {tag_chuid, sizeof tag_chuid};
  TC_PIV_data_object out;
  require(result == TC_PIV_CARD_STATUS || result == TC_PIV_INVALID || result == TC_PIV_LIMIT ||
          result == TC_PIV_ERROR);
  require(info.sm_lost && !info.secured && !info.vci && !info.pin_verified);
  require(all_value(&session, sizeof session, 0) && all_value(sm_scratch, sizeof sm_scratch, 0));
  require(all_value(response, response_bytes, 0));
  const size_t sent = card.transmits;
  require(TC_PIV_get_data(&secured, chuid, response_reset(response_bytes), &out) == TC_PIV_REFUSED);
  require(card.transmits == sent);
}

/* A raw answer carries no valid response MAC, so any failure ends the
 * session. */
static void sm_raw_check(size_t s, answer_mode mode, TC_bytes source)
{
  const TC_bytes chuid = {tag_chuid, sizeof tag_chuid};
  TC_PIV_data_object out;
  secured_restore(s, 0);
  card.mode = mode;
  card.source = source;
  const TC_buffer buffer = response_reset(response_bytes);
  memset(&out, UNWRITTEN, sizeof out);
  const TC_PIV_result result = TC_PIV_get_data(&secured, chuid, buffer, &out);
  if (result == TC_PIV_OK) {
    require(session_live());
    object_within(&out);
  } else {
    require(all_value(&out, sizeof out, UNWRITTEN));
    session_lost_check(result);
  }
}

static const TC_APDU_command get_chuid = {{command_data, 5}, 256, 0x00, 0xcb, 0x3f, 0xff};

/* An authenticated answer decrypts in place to plaintext with inner_sw,
 * and the session stays READY. GET DATA then frames the plaintext, and its
 * failures keep the session. */
static void sm_answer_check(size_t s, TC_bytes plaintext, uint16_t inner_sw)
{
  const TC_bytes chuid = {tag_chuid, sizeof tag_chuid};
  TC_APDU_response answer;
  TC_PIV_data_object out;
  if (plaintext.length > SM_PLAIN_MAX)
    return;
  secured_restore(s, 1);
  if (plaintext.length)
    memcpy(sm_card.answer, plaintext.data, plaintext.length);
  sm_card.answer_length = plaintext.length;
  sm_card.inner_sw = inner_sw;
  TC_buffer buffer = response_reset(response_bytes);
  require(tc_piv_link_transceive(&secured, TC_PIV_COMMAND_GET_DATA, &get_chuid, buffer, &answer) ==
          TC_PIV_OK);
  require(answer.sw == inner_sw && answer.data.length == plaintext.length &&
          span_within(answer.data, response, response_bytes));
  require(!plaintext.length || !memcmp(answer.data.data, plaintext.data, plaintext.length));
  require(session_live() && !sm_card.broken);
  buffer = response_reset(response_bytes);
  memset(&out, UNWRITTEN, sizeof out);
  const TC_PIV_result result = TC_PIV_get_data(&secured, chuid, buffer, &out);
  require(session_live());
  if (result == TC_PIV_OK)
    object_within(&out);
  else
    get_data_failed(result, &out);
}

/* The card model damages an authenticated answer, and the session ends. A
 * padding fault needs plaintext whose last byte is neither 00 nor 80,
 * since the host strips zero padding up to the last 80 (Part 2 4.2.5). */
static void sm_fault_check(size_t s, TC_bytes plaintext, uint8_t selector, uint16_t outer_sw)
{
  static const tc_sm_card_fault faults[] = {
      TC_SM_CARD_BAD_MAC,       TC_SM_CARD_NO_MAC,        TC_SM_CARD_NO_STATUS,
      TC_SM_CARD_MAC_LENGTH,    TC_SM_CARD_TRAILING,      TC_SM_CARD_OUTER_STATUS,
      TC_SM_CARD_BAD_INDICATOR, TC_SM_CARD_PARTIAL_BLOCK, TC_SM_CARD_BAD_PADDING};
  const TC_bytes chuid = {tag_chuid, sizeof tag_chuid};
  TC_PIV_data_object out;
  tc_sm_card_fault fault = faults[selector % (sizeof faults / sizeof *faults)];
  const uint8_t last = plaintext.length ? plaintext.data[plaintext.length - 1] : 0;
  if (plaintext.length > SM_PLAIN_MAX)
    return;
  if ((fault == TC_SM_CARD_BAD_INDICATOR || fault == TC_SM_CARD_PARTIAL_BLOCK ||
       fault == TC_SM_CARD_BAD_PADDING) &&
      (!plaintext.length || (fault == TC_SM_CARD_BAD_PADDING && (last == 0 || last == 0x80))))
    fault = TC_SM_CARD_BAD_MAC;
  secured_restore(s, 1);
  if (plaintext.length)
    memcpy(sm_card.answer, plaintext.data, plaintext.length);
  sm_card.answer_length = plaintext.length;
  sm_card.fault = fault;
  sm_card.outer_sw = outer_sw;
  const TC_buffer buffer = response_reset(response_bytes);
  memset(&out, UNWRITTEN, sizeof out);
  const TC_PIV_result result = TC_PIV_get_data(&secured, chuid, buffer, &out);
  require(result != TC_PIV_OK && all_value(&out, sizeof out, UNWRITTEN));
  session_lost_check(result);
}

/* Read the Discovery Object from an authenticated answer, then establish
 * the VCI with a VERIFY 98 answered verify_sw. */
static void vci_check(size_t s, TC_bytes plaintext, uint16_t verify_sw)
{
  const TC_bytes code = {pairing_code, TC_PIV_PAIRING_CODE_DIGITS};
  TC_PIV_discovery discovery;
  TC_PIV_vci_mode mode;
  if (plaintext.length > VCI_PLAIN_MAX)
    return;
  secured_restore(s, 1);
  if (plaintext.length)
    memcpy(sm_card.answer, plaintext.data, plaintext.length);
  sm_card.answer_length = plaintext.length;
  memset(&discovery, UNWRITTEN, sizeof discovery);
  const TC_PIV_result read = TC_PIV_discovery_get(&secured, TC_PIV_DISCOVERY_PIV,
                                                  response_reset(response_bytes), &discovery);
  require(session_live());
  if (read != TC_PIV_OK) {
    require((read == TC_PIV_INVALID || read == TC_PIV_UNSUPPORTED) &&
            all_value(response, response_bytes, 0) &&
            all_value(&discovery, sizeof discovery, UNWRITTEN));
    return;
  }
  require(discovery.secured && span_within(discovery.aid, response, response_bytes));
  sm_card.answer_length = 0;
  sm_card.inner_sw = verify_sw;
  const size_t sent = sm_card.protected_commands;
  memset(&mode, UNWRITTEN, sizeof mode);
  const TC_PIV_result result = TC_PIV_vci_establish(&secured, &discovery, code, &mode);
  const TC_PIV_link_info info = link_info(&secured);
  require(session_live());
  if (result == TC_PIV_OK) {
    require(info.vci && (discovery.policy & TC_PIV_POLICY_VCI));
    if (mode == TC_PIV_VCI_WITHOUT_PAIRING)
      require((discovery.policy & TC_PIV_POLICY_VCI_WITHOUT_PAIRING) &&
              sm_card.protected_commands == sent);
    else
      require(mode == TC_PIV_VCI_PAIRED && verify_sw == 0x9000 &&
              sm_card.protected_commands == sent + 1);
  } else if (result == TC_PIV_CARD_STATUS)
    require(!info.vci && verify_sw != 0x9000 && (discovery.policy & TC_PIV_POLICY_VCI) &&
            !(discovery.policy & TC_PIV_POLICY_VCI_WITHOUT_PAIRING) &&
            sm_card.protected_commands == sent + 1 && all_value(&mode, sizeof mode, UNWRITTEN));
  else
    require(result == TC_PIV_UNSUPPORTED && !(discovery.policy & TC_PIV_POLICY_VCI) &&
            sm_card.protected_commands == sent && all_value(&mode, sizeof mode, UNWRITTEN));
}

static void secure_messaging_check(TC_bytes input, TC_bytes with_status)
{
  const uint16_t leading = input.length >= 2 ? (uint16_t)(input.data[0] << 8 | input.data[1]) : 0;
  const uint16_t trailing =
      input.length >= 2
          ? (uint16_t)(input.data[input.length - 2] << 8 | input.data[input.length - 1])
          : 0x6300;
  /* The input length picks the suite, which halves the AES work per input
   * and still reaches both suites. */
  {
    const size_t s = input.length % suite_count;
    sm_raw_check(s, ANSWER_REPEAT, input);
    sm_raw_check(s, ANSWER_REPEAT, with_status);
    sm_raw_check(s, ANSWER_SCRIPT, input);
    sm_answer_check(s, input, 0x9000);
    sm_answer_check(s, input, leading);
    sm_fault_check(s, input, input.length ? input.data[0] : 0, trailing);
    vci_check(s, input, 0x9000);
    vci_check(s, input, trailing);
  }
}

/* Inventory */

static void inventory_check(answer_mode mode, TC_bytes source)
{
  static TC_PIV_object objects[TC_PIV_CATALOG_PIV_OBJECTS];
  static uint8_t pool[TC_PIV_INVENTORY_POOL_BYTES];
  TC_PIV_inventory inventory = {objects, TC_PIV_CATALOG_PIV_OBJECTS, 0, NULL, 0, {0}};
  TC_PIV_link link;
  size_t work = WORK;
  card_setup(&piv_select, 1, mode, source, NULL);
  link_open(&link, TC_APDU_SHORT, TC_PIV_APPLICATION_PIV);
  card_track(pool, sizeof pool);
  const TC_PIV_result result =
      TC_PIV_inventory_read(&link, NULL, (TC_buffer){pool, sizeof pool}, &work, &inventory);
  const size_t received = card.high_water;
  if (result == TC_PIV_OK) {
    require(inventory.count == TC_PIV_catalog_count(TC_PIV_APPLICATION_PIV, TC_PIV_CARD));
    require(inventory.pool == pool && inventory.pool_used <= sizeof pool);
    for (size_t i = 0; i < inventory.count; ++i) {
      const TC_PIV_object* object = &objects[i];
      require(object->info && object->state <= TC_PIV_OBJECT_SKIPPED);
      require(span_within(object->encoded, pool, inventory.pool_used) &&
              span_within(object->value, pool, inventory.pool_used));
    }
    if (received > inventory.pool_used)
      require(all_value(pool + inventory.pool_used, received - inventory.pool_used, 0));
    TC_PIV_inventory_clear(&inventory);
  } else
    require(result != TC_PIV_ARGUMENT && result != TC_PIV_REFUSED && result != TC_PIV_UNSUPPORTED &&
            !inventory.count && !inventory.pool_used && !inventory.pool &&
            all_value(objects, sizeof objects, 0));
  /* Clear and abort leave the pool zero for the next input. */
  require(all_value(pool, received, 0));
  TC_PIV_link_clear(&link);
}

/* Key proof */

/* Certificate views with only the fields the key policy and verification
 * read: RSA-2048 with exponent 65537 and a P-256 point, each with keyUsage
 * digitalSignature (RFC 5280 4.2.1.3). The keys are synthetic and the
 * challenge is fixed, so mutation cannot find a valid proof. */
static TC_X509_certificate rsa_certificate, ec_certificate;
static uint8_t certificate_extensions[18], rsa_modulus[256], ec_point[65];
static const uint8_t rsa_exponent[] = {0x01, 0x00, 0x01};

static void certificates_init(void)
{
  static const uint8_t extensions[] = {0x30, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
                                       0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
  memcpy(certificate_extensions, extensions, sizeof extensions);
  memset(rsa_modulus, 0xc3, sizeof rsa_modulus);
  ec_point[0] = 0x04;
  memset(ec_point + 1, 0x11, sizeof ec_point - 1);
  rsa_certificate.version = 3;
  rsa_certificate.extensions = (TC_bytes){certificate_extensions, sizeof certificate_extensions};
  ec_certificate = rsa_certificate;
  rsa_certificate.public_key.type = TC_KEY_RSA;
  rsa_certificate.public_key.bits = 2048;
  rsa_certificate.public_key.modulus = (TC_bytes){rsa_modulus, sizeof rsa_modulus};
  rsa_certificate.public_key.exponent = (TC_bytes){rsa_exponent, sizeof rsa_exponent};
  ec_certificate.public_key.type = TC_KEY_EC;
  ec_certificate.public_key.curve = TC_EC_P256;
  ec_certificate.public_key.bits = 256;
  ec_certificate.public_key.key = (TC_bytes){ec_point, sizeof ec_point};
}

static TC_status fixed_random(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memset(output, 0x42, length);
  return TC_OK;
}

/* Every return after the entry checks wipes the workspace, and REFUSED or
 * ARGUMENT never follow from card data. */
static void key_proof_check(TC_APDU_length_format format, answer_mode mode, TC_bytes source,
                            const TC_X509_certificate* certificate)
{
  static TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(2048)];
  static TC_ECDSA_workspace ec_workspace;
  static TC_PIV_key_proof_workspace workspace;
  const TC_RSA_workspace rsa = {rsa_words, sizeof rsa_words / sizeof *rsa_words};
  const TC_X509_native_workspace native = {&ec_workspace, &rsa,
                                           TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  TC_PIV_key_proof_request request;
  TC_work_budget work = {WORK};
  TC_PIV_link link;
  memset(&request, 0, sizeof request);
  request.certificate = certificate;
  request.policy.profile = TC_PIV_CARD;
  request.policy.at = (TC_X509_time){2026, 9, 29, 18, 0, 0};
  request.policy.rsa_padding = TC_PIV_RSA_PKCS1_V15;
  request.key_reference = TC_PIV_KEY_CARD_AUTHENTICATION;
  card_setup(&piv_select, 1, mode, source, NULL);
  link_open(&link, format, TC_PIV_APPLICATION_PIV);
  memset(&workspace, SENTINEL, sizeof workspace);
  const TC_PIV_result result = TC_PIV_key_prove(
      &link, &request, (TC_random_source){fixed_random, NULL}, &provider, &workspace, &work);
  require(result != TC_PIV_OK && result != TC_PIV_ARGUMENT && result != TC_PIV_REFUSED);
  require(all_value(&workspace, sizeof workspace, 0));
  TC_PIV_link_clear(&link);
}

static void card_stack_check(TC_bytes input, TC_bytes with_status)
{
  inventory_check(ANSWER_REPEAT, with_status);
  inventory_check(ANSWER_REPEAT, input);
  inventory_check(ANSWER_SCRIPT, input);
  key_proof_check(TC_APDU_EXTENDED, ANSWER_REPEAT, with_status, &rsa_certificate);
  key_proof_check(TC_APDU_EXTENDED, ANSWER_REPEAT, with_status, &ec_certificate);
  key_proof_check(TC_APDU_SHORT, ANSWER_SCRIPT, input, &rsa_certificate);
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  response_prepare(0);
  for (size_t i = 0; i < sizeof sm_fixtures / sizeof *sm_fixtures; ++i)
    if (!sm_fixtures[i].intermediate.length && suite_count < SUITES)
      secured_save(&sm_fixtures[i]);
  require(suite_count == SUITES);
  certificates_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t length)
{
  const TC_bytes input = {data, length};
  response_prepare(length);
  /* An exact-size copy lets AddressSanitizer catch reads past the answer. */
  uint8_t* appended = malloc(length + TC_APDU_STATUS_BYTES);
  require(appended != NULL);
  if (length)
    memcpy(appended, data, length);
  appended[length] = 0x90;
  appended[length + 1] = 0x00;
  const TC_bytes with_status = {appended, length + TC_APDU_STATUS_BYTES};
  apdu_check(input, with_status);
  command_check(input, with_status);
  object_readers_check(input);
  certificate_check(input);
  secure_messaging_check(input, with_status);
  card_stack_check(input, with_status);
  free(appended);
  return 0;
}
