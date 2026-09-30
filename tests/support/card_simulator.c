/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "card_simulator.h"
#include <tiny_crypto/tlv.h>
#include <string.h>

enum {
  CHUNK = 256,
  SW_SUCCESS = 0x9000,
  SW_WARNING_NO_COUNTER = 0x6300,
  SW_WRONG_LENGTH = 0x6700,
  SW_LAST_COMMAND_EXPECTED = 0x6883,
  SW_SECURITY_STATUS = 0x6982,
  SW_BLOCKED = 0x6983,
  SW_CONDITIONS = 0x6985,
  SW_SM_INCORRECT = 0x6988,
  SW_WRONG_DATA = 0x6a80,
  SW_NOT_FOUND = 0x6a82,
  SW_WRONG_P1P2 = 0x6a86,
  SW_REFERENCE_NOT_FOUND = 0x6a88,
  SW_INS_UNSUPPORTED = 0x6d00,
  SW_CLA_UNSUPPORTED = 0x6e00
};

/* Discovery Object PIN usage policy, first byte (Part 1 3.3.2). */
enum { POLICY_GLOBAL_PIN = 0x20, POLICY_VCI = 0x08, POLICY_VCI_WITHOUT_PAIRING = 0x04 };

static const uint8_t piv_aid[] = {0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
/* The right-truncated AID omits the 2-byte version (Part 2 3.1.1). */
#define PIV_AID_TRUNCATED_BYTES 9u

/* One command APDU in any case of ISO/IEC 7816-4 5.2. ne is 0 without Le. */
typedef struct {
  uint8_t cla, ins, p1, p2;
  TC_bytes data;
  uint32_t ne;
  uint8_t extended;
} apdu;

/* One command after chaining and secure messaging. */
typedef struct {
  uint8_t ins, p1, p2, secured, has_le;
  TC_bytes data;
} card_command;

typedef struct {
  TC_bytes data;
  uint16_t sw;
} card_answer;

/* Part 1 Table 2 read rules. PIN or OCC reads as PIN: the simulator has no
 * OCC. */
typedef enum {
  READ_ALWAYS,         /* Always on both interfaces */
  READ_CONTACT_OR_VCI, /* Always on contact, VCI on contactless */
  READ_PIN             /* PIN on contact, VCI and PIN on contactless */
} read_rule;

static void violation(tc_card_simulator* card, const char* reason)
{
  if (!card->violations)
    card->violation = reason;
  ++card->violations;
}

static int apdu_parse(TC_bytes raw, apdu* out)
{
  const uint8_t* c = raw.data;
  const size_t length = raw.length;
  if (length < 4)
    return 0;
  *out = (apdu){c[0], c[1], c[2], c[3], {NULL, 0}, 0, 0};
  if (length == 4)
    return 1;
  if (length == 5) {
    out->ne = c[4] ? c[4] : 256u;
    return 1;
  }
  if (c[4]) {
    const size_t lc = c[4];
    if (length != 5 + lc && length != 6 + lc)
      return 0;
    out->data = (TC_bytes){c + 5, lc};
    if (length == 6 + lc)
      out->ne = c[5 + lc] ? c[5 + lc] : 256u;
    return 1;
  }
  out->extended = 1;
  if (length == 7) {
    const uint32_t le = (uint32_t)c[5] << 8 | c[6];
    out->ne = le ? le : 65536u;
    return 1;
  }
  const size_t lc = (size_t)c[5] << 8 | c[6];
  if (!lc || (length != 7 + lc && length != 9 + lc))
    return 0;
  out->data = (TC_bytes){c + 7, lc};
  if (length == 9 + lc) {
    const uint32_t le = (uint32_t)c[7 + lc] << 8 | c[8 + lc];
    out->ne = le ? le : 65536u;
  }
  return 1;
}

/* Answer delivery. */

static TC_status status_write(uint16_t sw, const uint8_t* data, size_t count, TC_buffer response,
                              size_t* length)
{
  if (count + 2 > response.capacity)
    return TC_ERROR;
  if (count)
    memcpy(response.data, data, count);
  response.data[count] = (uint8_t)(sw >> 8);
  response.data[count + 1] = (uint8_t)sw;
  *length = count + 2;
  return TC_OK;
}

static TC_status status_only(uint16_t sw, TC_buffer response, size_t* length)
{
  return status_write(sw, NULL, 0, response, length);
}

/* Send up to limit pending bytes, with 61XX while more remain (ISO/IEC
 * 7816-4 5.3.4). */
static TC_status pending_deliver(tc_card_simulator* card, size_t limit, TC_buffer response,
                                 size_t* length)
{
  const size_t remaining = card->pending_length - card->pending_offset;
  const size_t count = remaining < limit ? remaining : limit;
  const size_t after = remaining - count;
  const uint16_t sw = after ? (uint16_t)(0x6100 | (after >= CHUNK ? 0 : after)) : card->pending_sw;
  const TC_status status =
      status_write(sw, card->pending + card->pending_offset, count, response, length);
  card->pending_offset += count;
  if (!after)
    card->pending_length = card->pending_offset = 0;
  return status;
}

static TC_status pending_start(tc_card_simulator* card, TC_bytes data, uint16_t sw,
                               TC_buffer response, size_t* length)
{
  if (data.length > sizeof card->pending)
    return TC_ERROR;
  memmove(card->pending, data.data, data.length);
  card->pending_length = data.length;
  card->pending_offset = 0;
  card->pending_sw = sw;
  return pending_deliver(card, CHUNK, response, length);
}

/* A plaintext answer: Le 00 gets 256-byte chunks, a short Le below the size
 * gets the first Le bytes with the final status, an extended Le gets the
 * complete answer (SD 33 card 2 answered 264 bytes to Ne 256). */
static TC_status plain_answer(tc_card_simulator* card, const apdu* command, card_answer answer,
                              TC_buffer response, size_t* length)
{
  if (!answer.data.length)
    return status_only(answer.sw, response, length);
  if (command->extended)
    return status_write(answer.sw, answer.data.data, answer.data.length, response, length);
  if (command->ne < CHUNK) {
    const size_t count = answer.data.length < command->ne ? answer.data.length : command->ne;
    return status_write(answer.sw, answer.data.data, count, response, length);
  }
  return pending_start(card, answer.data, answer.sw, response, length);
}

/* Security conditions. */

static int pin_verified(const tc_card_simulator* card)
{
  for (size_t i = 0; i < card->fixture->reference_count; ++i)
    if (card->fixture->references[i].reference != 0x98 && card->verified[i])
      return 1;
  return 0;
}

/* The card's answer for container tag: a test override, the fixture data,
 * or 6A82 (Part 2 3.1.2). */
static card_answer container_answer(const tc_card_simulator* card, uint32_t tag)
{
  for (size_t i = 0; i < card->override_count; ++i)
    if (card->overrides[i].tag == tag)
      return (card_answer){card->overrides[i].sw == SW_SUCCESS ? card->overrides[i].data
                                                               : (TC_bytes){NULL, 0},
                           card->overrides[i].sw};
  const tc_card_object* object = tc_card_fixture_object(card->fixture, tag);
  if (!object)
    return (card_answer){{NULL, 0}, SW_NOT_FOUND};
  return (card_answer){object->data, SW_SUCCESS};
}

/* First byte of the PIN usage policy of the Discovery Object the card
 * answers, overrides included. Returns 0 without a Discovery Object
 * (7E 12 {4F 0B AID, 5F2F 02 policy}). */
static int discovery_policy(const tc_card_simulator* card, uint8_t* policy)
{
  const card_answer object = container_answer(card, 0x7e);
  if (object.sw != SW_SUCCESS || object.data.length < 5)
    return 0;
  const uint8_t* end = object.data.data + object.data.length;
  if (end[-5] != 0x5f || end[-4] != 0x2f || end[-3] != 2)
    return 0;
  *policy = end[-2];
  return 1;
}

/* Part 1 Table 2 footnote 9: SM, the Discovery Object present, bit 4, and
 * the pairing code verified or bit 3. */
static int vci(const tc_card_simulator* card, const card_command* command)
{
  uint8_t policy = 0;
  return command->secured && card->session_active && discovery_policy(card, &policy) &&
         (policy & POLICY_VCI) && (card->pairing_verified || (policy & POLICY_VCI_WITHOUT_PAIRING));
}

static read_rule read_rule_of(uint32_t tag)
{
  switch (tag) {
  case 0x5fc102: /* CHUID */
  case 0x5fc101: /* Card Authentication certificate */
  case 0x7e:     /* Discovery Object */
  case 0x7f61:   /* BIT group template */
  case 0x5fc122: /* SM certificate signer */
    return READ_ALWAYS;
  case 0x5fc103: /* fingerprints */
  case 0x5fc108: /* facial image */
  case 0x5fc121: /* iris */
  case 0x5fc109: /* printed information, PIN or OCC */
  case 0x5fc123: /* pairing code, PIN or OCC */
    return READ_PIN;
  default:
    return READ_CONTACT_OR_VCI;
  }
}

static int read_allowed(const tc_card_simulator* card, const card_command* command, read_rule rule)
{
  const int contact = card->interface == TC_PIV_CONTACT;
  switch (rule) {
  case READ_ALWAYS:
    return 1;
  case READ_CONTACT_OR_VCI:
    return contact || vci(card, command);
  case READ_PIN:
    return (contact || vci(card, command)) && pin_verified(card);
  }
  return 0;
}

/* SELECT (Part 2 3.1.1). An unknown AID keeps the selection and the
 * security status. */
static card_answer select_command(tc_card_simulator* card, const card_command* command)
{
  const TC_bytes aid = command->data;
  if (command->p1 != 0x04 || command->p2 != 0x00)
    return (card_answer){{NULL, 0}, SW_WRONG_P1P2};
  if ((aid.length != sizeof piv_aid && aid.length != PIV_AID_TRUNCATED_BYTES) ||
      memcmp(aid.data, piv_aid, aid.length))
    return (card_answer){{NULL, 0}, SW_NOT_FOUND};
  card->selected = 1;
  return (card_answer){card->fixture->select, SW_SUCCESS};
}

/* GET DATA (Part 2 3.1.2): 5C L tag, then the Table 2 read rule, the test
 * overrides and the fixture. */
static card_answer get_data_command(tc_card_simulator* card, const card_command* command,
                                    uint32_t* logged_tag)
{
  const TC_bytes field = command->data;
  if (command->p1 != 0x3f || command->p2 != 0xff)
    return (card_answer){{NULL, 0}, SW_WRONG_P1P2};
  if (field.length < 3 || field.length > 5 || field.data[0] != 0x5c ||
      field.data[1] != field.length - 2)
    return (card_answer){{NULL, 0}, SW_WRONG_DATA};
  uint32_t tag = 0;
  for (size_t i = 2; i < field.length; ++i)
    tag = tag << 8 | field.data[i];
  *logged_tag = tag;
  if (!command->has_le)
    return (card_answer){{NULL, 0}, SW_WRONG_LENGTH};
  if (!read_allowed(card, command, read_rule_of(tag)))
    return (card_answer){{NULL, 0}, SW_SECURITY_STATUS};
  return container_answer(card, tag);
}

/* The fixture index of a verifiable reference, or -1. 00 needs policy bit
 * 6 and 98 needs bit 4 (Part 2 3.2.1). */
static int reference_index(const tc_card_simulator* card, uint8_t reference)
{
  uint8_t policy = 0;
  const int discovery = discovery_policy(card, &policy);
  if ((reference == 0x00 && !(discovery && (policy & POLICY_GLOBAL_PIN))) ||
      (reference == 0x98 && !(discovery && (policy & POLICY_VCI))))
    return -1;
  for (size_t i = 0; i < card->fixture->reference_count; ++i)
    if (card->fixture->references[i].reference == reference)
      return (int)i;
  return -1;
}

/* Part 2 2.4.3: 6 to 8 ASCII digits padded with FF to 8 bytes. */
static int pin_format_valid(TC_bytes pin)
{
  size_t digits = 0;
  if (pin.length != 8)
    return 0;
  while (digits < 8 && pin.data[digits] >= 0x30 && pin.data[digits] <= 0x39)
    ++digits;
  for (size_t i = digits; i < 8; ++i)
    if (pin.data[i] != 0xff)
      return 0;
  return digits >= 6;
}

/* PIN comparison of Part 2 3.2.1.1 with the retry counter. */
static uint16_t pin_submit(tc_card_simulator* card, size_t index, TC_bytes pin)
{
  const tc_card_reference* reference = &card->fixture->references[index];
  if (!card->retries[index])
    return SW_BLOCKED;
  if (!pin_format_valid(pin))
    return SW_WRONG_DATA;
  if (!reference->value_known || memcmp(pin.data, reference->value, 8)) {
    card->verified[index] = 0;
    --card->retries[index];
    return (uint16_t)(0x63c0 | card->retries[index]);
  }
  card->verified[index] = 1;
  card->retries[index] = reference->retries;
  card->pin_always = 1;
  return SW_SUCCESS;
}

/* Pairing code comparison of Part 2 3.2.1.3. No retry counter (footnote 7). */
static uint16_t pairing_submit(tc_card_simulator* card, size_t index, TC_bytes code)
{
  const tc_card_reference* reference = &card->fixture->references[index];
  if (code.length != 8)
    return SW_WRONG_DATA;
  card->pairing_verified = reference->value_known && !memcmp(code.data, reference->value, 8);
  card->verified[index] = card->pairing_verified;
  return card->pairing_verified ? SW_SUCCESS : SW_WARNING_NO_COUNTER;
}

/* VERIFY (Part 2 3.2.1; Part 1 Table 4 for the interface rules). */
static card_answer verify_command(tc_card_simulator* card, const card_command* command)
{
  const uint8_t reference = command->p2;
  const TC_bytes data = command->data;
  const int pairing = reference == 0x98;
  if (data.length) {
    if (pairing)
      ++card->pairing_submissions;
    else if (reference == 0x80 || reference == 0x00)
      ++card->pin_submissions;
  }
  if (command->p1 != 0x00 && command->p1 != 0xff)
    return (card_answer){{NULL, 0}, SW_WRONG_P1P2};
  const int index = reference_index(card, reference);
  if (index < 0)
    return (card_answer){{NULL, 0}, SW_REFERENCE_NOT_FOUND};
  if (card->interface == TC_PIV_CONTACTLESS && !(pairing ? command->secured : vci(card, command))) {
    if (data.length && !command->secured)
      violation(card, "plaintext reference data on the contactless interface");
    return (card_answer){{NULL, 0}, SW_SECURITY_STATUS};
  }
  if (command->p1 == 0xff) {
    if (data.length)
      return (card_answer){{NULL, 0}, SW_WRONG_DATA};
    card->verified[index] = 0;
    if (pairing)
      card->pairing_verified = 0;
    return (card_answer){{NULL, 0}, SW_SUCCESS};
  }
  if (!data.length) {
    if (card->verified[index])
      return (card_answer){{NULL, 0}, SW_SUCCESS};
    if (pairing)
      return (card_answer){{NULL, 0}, SW_WARNING_NO_COUNTER};
    if (!card->retries[index])
      return (card_answer){{NULL, 0}, SW_BLOCKED};
    return (card_answer){{NULL, 0}, (uint16_t)(0x63c0 | card->retries[index])};
  }
  const uint16_t sw =
      pairing ? pairing_submit(card, (size_t)index, data) : pin_submit(card, (size_t)index, data);
  return (card_answer){{NULL, 0}, sw};
}

static void session_end(tc_card_simulator* card)
{
  card->session_active = 0;
  card->pairing_verified = 0;
  memset(&card->session, 0, sizeof card->session);
}

/* An SM error status to a protected APDU: any status other than 9000 or
 * 61XX zeroizes the session keys (Part 2 4.3 footnote 25). */
static TC_status sm_error(tc_card_simulator* card, uint16_t sw, TC_buffer response, size_t* length)
{
  session_end(card);
  return status_only(sw, response, length);
}

/* Key establishment (Part 2 4.1.8): the command must equal a recorded one,
 * which starts that session with its recorded keys. Any request zeroizes the
 * current session keys first (4.3). */
static card_answer key_establishment(tc_card_simulator* card, const card_command* command)
{
  if (command->secured) {
    violation(card, "key establishment under secure messaging");
    return (card_answer){{NULL, 0}, SW_SECURITY_STATUS};
  }
  session_end(card);
  for (size_t i = 0; i < card->fixture->session_count; ++i) {
    const tc_card_session* session = &card->fixture->sessions[i];
    apdu recorded;
    if (!apdu_parse(session->command, &recorded) || recorded.p1 != command->p1 ||
        recorded.data.length != command->data.length ||
        memcmp(recorded.data.data, command->data.data, command->data.length))
      continue;
    tc_sm_card_session_keys(&card->session, session->material);
    card->session_active = 1;
    return (card_answer){session->answer, SW_SUCCESS};
  }
  return (card_answer){{NULL, 0}, SW_WRONG_DATA};
}

/* Part 1 Table 5. pin_always is a PIN submission as the preceding command. */
static int key_allowed(const tc_card_simulator* card, const card_command* command, int pin_always)
{
  const uint8_t key = command->p2;
  const int contact = card->interface == TC_PIV_CONTACT;
  if (key == 0x9e)
    return 1;
  if (!contact && !vci(card, command))
    return 0;
  return key == 0x9c ? pin_always : pin_verified(card);
}

static int key_supported(uint8_t key)
{
  return key == 0x9a || key == 0x9c || key == 0x9d || key == 0x9e || (key >= 0x82 && key <= 0x95);
}

/* The input DO (81 challenge or 85 exponentiation) of 7C {82 00, input}
 * in either order. Returns 0 for any other template. */
static int template_input(TC_bytes data, uint8_t* tag, TC_bytes* input)
{
  static const TC_TLV_limits limits = {4096, 4096, 8, 2};
  TC_TLV_element element;
  TC_TLV_reader reader;
  int response = 0, inputs = 0;
  if (TC_TLV_read(data, TC_TLV_ISO7816, &limits, &element) != TC_TLV_OK ||
      element.encoded.length != data.length || element.header.tag_length != 1 ||
      element.header.tag[0] != 0x7c ||
      TC_TLV_reader_init(&reader, element.value, TC_TLV_ISO7816, &limits) != TC_TLV_OK)
    return 0;
  for (TC_TLV_result result; (result = TC_TLV_next(&reader, &element)) != TC_TLV_END;) {
    if (result != TC_TLV_OK || element.header.tag_length != 1)
      return 0;
    const uint8_t t = element.header.tag[0];
    if (t == 0x82 && !element.value.length && !response) {
      response = 1;
    } else if ((t == 0x81 || t == 0x85) && element.value.length && !inputs) {
      inputs = 1;
      *tag = t;
      *input = element.value;
    } else {
      return 0;
    }
  }
  return response && inputs;
}

/* GENERAL AUTHENTICATE (Part 2 3.2.4) with the recorded input and answer
 * pairs. */
static card_answer authenticate_command(tc_card_simulator* card, const card_command* command,
                                        int pin_always)
{
  if (command->p2 == 0x04)
    return key_establishment(card, command);
  int recorded = 0;
  for (size_t i = 0; i < card->fixture->authentication_count; ++i)
    recorded |= card->fixture->authentications[i].algorithm == command->p1 &&
                card->fixture->authentications[i].key == command->p2;
  if (!key_supported(command->p2) || !recorded)
    return (card_answer){{NULL, 0}, SW_WRONG_P1P2};
  if (!key_allowed(card, command, pin_always))
    return (card_answer){{NULL, 0}, SW_SECURITY_STATUS};
  uint8_t tag = 0;
  TC_bytes input = {NULL, 0};
  if (!template_input(command->data, &tag, &input))
    return (card_answer){{NULL, 0}, SW_WRONG_DATA};
  for (size_t i = 0; i < card->fixture->authentication_count; ++i) {
    const tc_card_authentication* entry = &card->fixture->authentications[i];
    if (entry->algorithm == command->p1 && entry->key == command->p2 && entry->tag == tag &&
        entry->input.length == input.length && !memcmp(entry->input.data, input.data, input.length))
      return (card_answer){entry->answer, SW_SUCCESS};
  }
  return (card_answer){{NULL, 0}, SW_WRONG_DATA};
}

static void command_log(tc_card_simulator* card, const card_command* command, uint32_t tag,
                        uint16_t sw)
{
  if (card->log_count == TC_CARD_SIMULATOR_LOG) {
    violation(card, "command log full");
    return;
  }
  card->log[card->log_count++] = (tc_card_command){
      command->ins, command->p1, command->p2, command->secured, tag, command->data.length, sw};
}

/* Run one complete command. A PIN Always status lasts for one command. */
static card_answer command_run(tc_card_simulator* card, const card_command* command)
{
  const int pin_always = card->pin_always;
  uint32_t tag = 0;
  card_answer answer = {{NULL, 0}, SW_INS_UNSUPPORTED};
  card->pin_always = 0;
  if (command->ins == 0xa4)
    answer = select_command(card, command);
  else if (!card->selected)
    answer.sw = SW_CONDITIONS;
  else if (command->ins == 0xcb)
    answer = get_data_command(card, command, &tag);
  else if (command->ins == 0x20)
    answer = verify_command(card, command);
  else if (command->ins == 0x87)
    answer = authenticate_command(card, command, pin_always);
  command_log(card, command, tag, answer.sw);
  return answer;
}

/* The final 0C command of a protected command: C-MAC check, the command,
 * and the protected answer in 256-byte chunks (Part 2 4.2.3 to 4.2.6). */
static TC_status protected_run(tc_card_simulator* card, const apdu* command, TC_bytes field,
                               TC_buffer response, size_t* length)
{
  const uint8_t header[3] = {command->ins, command->p1, command->p2};
  tc_sm_card_plain plain = {card->plain, sizeof card->plain, 0, 0, 0};
  ++card->protected_commands;
  if (!tc_sm_card_session_open(&card->session, header, field, &plain)) {
    violation(card, "bad C-MAC or SM data field");
    return sm_error(card, SW_SM_INCORRECT, response, length);
  }
  const card_command logical = {
      command->ins, command->p1, command->p2, 1, (uint8_t)plain.has_le, {plain.data, plain.length}};
  const card_answer answer = command_run(card, &logical);
  if (answer.data.length + TC_SM_CARD_ANSWER_OVERHEAD > sizeof card->pending)
    return TC_ERROR;
  const size_t written = tc_sm_card_session_answer(&card->session, answer.data, answer.sw,
                                                   TC_SM_CARD_ANSWER, card->pending);
  tc_sm_card_session_next(&card->session);
  card->pending_length = written;
  card->pending_offset = 0;
  card->pending_sw = SW_SUCCESS;
  return pending_deliver(card, CHUNK, response, length);
}

/* Collect one fragment of a chained command (ISO/IEC 7816-4 5.3.3). The
 * chain header and SM state must stay equal. Returns 0 for a broken chain. */
static int chain_append(tc_card_simulator* card, const apdu* command, int secured)
{
  const uint8_t header[4] = {(uint8_t)(command->cla & ~0x10u), command->ins, command->p1,
                             command->p2};
  if (card->chaining && (memcmp(card->chain_header, header, 4) || card->chain_secured != secured))
    return 0;
  if (card->chain_length + command->data.length > sizeof card->chain)
    return 0;
  if (!card->chaining) {
    memcpy(card->chain_header, header, 4);
    card->chain_secured = (uint8_t)secured;
    card->chaining = 1;
    card->chain_length = 0;
  }
  memcpy(card->chain + card->chain_length, command->data.data, command->data.length);
  card->chain_length += command->data.length;
  return 1;
}

static void chain_reset(tc_card_simulator* card)
{
  card->chaining = 0;
  card->chain_length = 0;
}

/* GET RESPONSE continues only the pending answer (ISO/IEC 7816-4 5.3.4)
 * and is always plain (Part 2 4.2.6). */
static TC_status get_response(tc_card_simulator* card, const apdu* command, TC_buffer response,
                              size_t* length)
{
  ++card->get_responses;
  if (command->cla != 0x00 || command->data.length || command->extended || !command->ne ||
      !card->pending_length) {
    violation(card, "GET RESPONSE without pending data or with a CLA other than 00");
    card->pending_length = card->pending_offset = 0;
    return status_only(SW_CONDITIONS, response, length);
  }
  return pending_deliver(card, command->ne, response, length);
}

/* A broken chain answers 6883. It is an SM error when the fragment or the
 * chain it breaks is protected. */
static TC_status chain_broken(tc_card_simulator* card, int secured, TC_buffer response,
                              size_t* length)
{
  const int protected_chain = secured || (card->chaining && card->chain_secured);
  violation(card, "broken command chain");
  chain_reset(card);
  if (protected_chain)
    return sm_error(card, SW_LAST_COMMAND_EXPECTED, response, length);
  return status_only(SW_LAST_COMMAND_EXPECTED, response, length);
}

static TC_status transmit(void* context, TC_bytes raw, TC_buffer response, size_t* length)
{
  tc_card_simulator* card = context;
  apdu command;
  ++card->transmits;
  if (!apdu_parse(raw, &command)) {
    violation(card, "malformed APDU");
    chain_reset(card);
    return status_only(SW_WRONG_LENGTH, response, length);
  }
  if (command.ins == 0xc0)
    return get_response(card, &command, response, length);
  /* Any other command ends a pending answer. */
  card->pending_length = card->pending_offset = 0;
  const uint8_t cla = command.cla;
  const int secured = cla == 0x0c || cla == 0x1c;
  const int chained = cla == 0x10 || cla == 0x1c;
  if (cla != 0x00 && cla != 0x10 && !secured) {
    violation(card, "unknown CLA");
    chain_reset(card);
    return status_only(SW_CLA_UNSUPPORTED, response, length);
  }
  if (secured && (command.extended || (!chained && command.ne != CHUNK))) {
    violation(card, command.extended ? "extended length secure messaging"
                                     : "protected command without the outer Le 00");
    chain_reset(card);
    return sm_error(card, SW_WRONG_LENGTH, response, length);
  }
  if (secured && !card->session_active) {
    chain_reset(card);
    return status_only(SW_SECURITY_STATUS, response, length);
  }
  if (chained) {
    ++card->fragments;
    if (!command.data.length || command.ne || !chain_append(card, &command, secured))
      return chain_broken(card, secured, response, length);
    return status_only(SW_SUCCESS, response, length);
  }
  TC_bytes data = command.data;
  if (card->chaining) {
    if (!chain_append(card, &command, secured))
      return chain_broken(card, secured, response, length);
    data = (TC_bytes){card->chain, card->chain_length};
    card->chaining = 0;
  }
  if (secured)
    return protected_run(card, &command, data, response, length);
  const card_command logical = {command.ins, command.p1, command.p2, 0, command.ne != 0, data};
  return plain_answer(card, &command, command_run(card, &logical), response, length);
}

void tc_card_simulator_init(tc_card_simulator* card, const tc_card_fixture* fixture,
                            TC_PIV_interface interface)
{
  memset(card, 0, sizeof *card);
  card->fixture = fixture;
  card->interface = interface;
  for (size_t i = 0; i < fixture->reference_count; ++i)
    card->retries[i] = fixture->references[i].retries;
}

void tc_card_simulator_reset(tc_card_simulator* card)
{
  session_end(card);
  card->selected = 0;
  card->pin_always = 0;
  memset(card->verified, 0, sizeof card->verified);
  chain_reset(card);
  card->pending_length = card->pending_offset = 0;
}

int tc_card_simulator_override(tc_card_simulator* card, uint32_t tag, uint16_t sw, TC_bytes data)
{
  if (card->override_count == TC_CARD_SIMULATOR_OVERRIDES)
    return 0;
  card->overrides[card->override_count++] = (tc_card_override){tag, sw, data};
  return 1;
}

size_t tc_card_simulator_sent(const tc_card_simulator* card, uint8_t ins, uint32_t tag)
{
  size_t count = 0;
  for (size_t i = 0; i < card->log_count; ++i)
    count += card->log[i].ins == ins && (!tag || card->log[i].tag == tag);
  return count;
}

TC_APDU_transport tc_card_simulator_transport(tc_card_simulator* card)
{
  TC_APDU_transport transport = {transmit, card};
  return transport;
}
