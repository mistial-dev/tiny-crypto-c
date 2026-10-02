/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The PIV hardware transmit guard. guard.h lists its rules. */
#include "guard.h"
#include <string.h>

enum {
  CLA_CHAINING = 0x10,
  CLA_SECURE = 0x0c,
  INS_SELECT = 0xa4,
  INS_GET_DATA = 0xcb,
  INS_GET_RESPONSE = 0xc0,
  INS_VERIFY = 0x20,
  INS_GENERAL_AUTHENTICATE = 0x87,
  REFERENCE_GLOBAL_PIN = 0x00,
  REFERENCE_PIN = 0x80,
  REFERENCE_PAIRING_CODE = 0x98,
  KEY_ESTABLISHMENT = 0x04,
  KEY_DIGITAL_SIGNATURE = 0x9c,
  SW_SUCCESS = 0x9000,
  SW1_MORE = 0x61,
  RETRIES_FLOOR = 2,
  RETRIES_MAXIMUM = 15
};

/* What the command passed last is, for its answer. */
enum { KIND_OTHER, KIND_SELECT, KIND_PIN_QUERY, KIND_PIN_SUBMISSION, KIND_PAIRING_SUBMISSION };

/* ISO/IEC 7816-4 5.1 command structure: data field and Le presence. */
typedef struct {
  TC_bytes data;
  int has_le;
} Body;

static int body_parse(TC_bytes command, Body* out)
{
  const uint8_t* bytes = command.data;
  const size_t length = command.length;
  out->data = (TC_bytes){NULL, 0};
  out->has_le = 0;
  if (!bytes || length < 4)
    return 0;
  if (length == 4)
    return 1; /* case 1 */
  if (length == 5) {
    out->has_le = 1; /* case 2 short */
    return 1;
  }
  if (bytes[4]) {
    const size_t nc = bytes[4];
    if (length != 5 + nc && length != 6 + nc)
      return 0;
    out->data = (TC_bytes){bytes + 5, nc};
    out->has_le = length == 6 + nc;
    return 1;
  }
  if (length < 7)
    return 0; /* an extended length field cut short */
  if (length == 7) {
    out->has_le = 1; /* case 2 extended */
    return 1;
  }
  const size_t nc = (size_t)bytes[5] << 8 | bytes[6];
  if (!nc || (length != 7 + nc && length != 9 + nc))
    return 0;
  out->data = (TC_bytes){bytes + 7, nc};
  out->has_le = length == 9 + nc;
  return 1;
}

static int bytes_equal(TC_bytes value, const uint8_t* expected, size_t length)
{
  return value.length == length && !memcmp(value.data, expected, length);
}

/* The PIV AID, its 9-byte prefix and the TWIC AID prefix (SP 800-73-5 Part 1
 * 2.2, Part 2 3.1.1, TWIC Part 2 v5 4.1). */
static int aid_allowed(TC_bytes aid)
{
  static const uint8_t piv[] = {0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
  static const uint8_t twic[] = {0xa0, 0x00, 0x00, 0x03, 0x67, 0x20, 0x00, 0x00, 0x01};
  return bytes_equal(aid, piv, sizeof piv) || bytes_equal(aid, piv, 9) ||
         bytes_equal(aid, twic, sizeof twic);
}

/* 1 when an SM data field carries DO 87 at its top level, 0 when it holds
 * only DO 97 and DO 8E (Part 2 4.2.1, 4.2.4). The field is a sequence of one-byte
 * tags with BER lengths of up to three octets. A malformed field, or a DO
 * outside 87, 97 and 8E such as a plain value DO 81, returns -1. */
static int sm_has_cryptogram(TC_bytes field)
{
  size_t offset = 0;
  int cryptogram = 0;
  while (offset < field.length) {
    const uint8_t tag = field.data[offset++];
    if (offset >= field.length)
      return -1;
    size_t length = field.data[offset++];
    if (length > 0x82 || length == 0x80)
      return -1;
    if (length & 0x80) {
      const size_t octets = length & 0x7f;
      if (field.length - offset < octets)
        return -1;
      length = 0;
      for (size_t i = 0; i < octets; ++i)
        length = length << 8 | field.data[offset++];
    }
    if (field.length - offset < length)
      return -1;
    if (tag == 0x87)
      cryptogram = 1;
    else if (tag != 0x97 && tag != 0x8e)
      return -1;
    offset += length;
  }
  return cryptogram;
}

/* The card status of a VERIFY answer: SW1 SW2, or under secure messaging
 * the status in DO 99 of an answer with outer 9000 (Part 2 4.2.6). 0 when
 * the answer shows none. */
static uint16_t verify_status(int secured, TC_bytes answer)
{
  if (answer.length < 2)
    return 0;
  const uint16_t sw =
      (uint16_t)(answer.data[answer.length - 2] << 8 | answer.data[answer.length - 1]);
  if (!secured)
    return sw;
  if (sw != SW_SUCCESS || answer.length < 6 || answer.data[0] != 0x99 || answer.data[1] != 0x02)
    return 0;
  return (uint16_t)(answer.data[2] << 8 | answer.data[3]);
}

static int refuse(tc_piv_guard* guard, const char* reason)
{
  ++guard->counts.refusals;
  if (!guard->counts.refusal)
    guard->counts.refusal = reason;
  guard->capture_index = -1;
  return 0;
}

int tc_piv_guard_init(tc_piv_guard* guard, const tc_piv_guard_policy* policy)
{
  if (!guard || !policy || policy->minimum_retries < RETRIES_FLOOR ||
      policy->minimum_retries > RETRIES_MAXIMUM ||
      policy->pin_submissions > TC_PIV_GUARD_MAX_PIN_SUBMISSIONS ||
      policy->pairing_submissions > 1 || policy->signatures > 1)
    return 0;
  memset(guard, 0, sizeof *guard);
  guard->policy = *policy;
  guard->interface = TC_PIV_CONTACTLESS;
  guard->capture_index = -1;
  return 1;
}

void tc_piv_guard_connected(void* context, TC_PIV_interface interface)
{
  tc_piv_guard* guard = context;
  guard->interface = interface == TC_PIV_CONTACT ? TC_PIV_CONTACT : TC_PIV_CONTACTLESS;
}

int tc_piv_guard_identity_bound(const tc_piv_guard* guard)
{
  return guard->identity_bound && !guard->identity_conflict;
}

/* Start collecting a plain GET DATA answer of a watched identity. */
static void capture_start(tc_piv_guard* guard, TC_bytes data)
{
  static const uint8_t tags[TC_PIV_GUARD_IDENTITIES][5] = {{0x5c, 0x03, 0x5f, 0xc1, 0x02},
                                                           {0x5c, 0x03, 0x5f, 0xc1, 0x01}};
  for (int i = 0; i < TC_PIV_GUARD_IDENTITIES; ++i)
    if (guard->policy.identity[i].length && bytes_equal(data, tags[i], sizeof tags[i])) {
      guard->capture_index = i;
      guard->capture_length = 0;
    }
}

static int select_check(tc_piv_guard* guard, const uint8_t* header, const Body* body)
{
  if (header[0] || header[2] != 0x04 || header[3] != 0x00 || !aid_allowed(body->data))
    return refuse(guard, "SELECT outside the PIV and TWIC AIDs");
  guard->pending_kind = KIND_SELECT;
  return 1;
}

static int get_data_check(tc_piv_guard* guard, const uint8_t* header, const Body* body)
{
  if ((header[0] != 0x00 && header[0] != CLA_SECURE) || header[2] != 0x3f || header[3] != 0xff ||
      !body->data.length)
    return refuse(guard, "GET DATA outside 3F FF");
  if (!header[0])
    capture_start(guard, body->data);
  return 1;
}

static int pin_submission_check(tc_piv_guard* guard, uint8_t reference)
{
  uint8_t* ready = &guard->query_ready[reference == REFERENCE_PIN ? 0 : 1];
  if (guard->counts.pin_submissions >= guard->policy.pin_submissions)
    return refuse(guard, "PIN budget spent");
  if (guard->pin_failed)
    return refuse(guard, "PIN submission after a failed one");
  if (!tc_piv_guard_identity_bound(guard))
    return refuse(guard, "PIN before the card identity matched");
  if (!*ready)
    return refuse(guard, "PIN without a retry query at the floor");
  *ready = 0;
  guard->pin_outcome_pending = 1;
  guard->pending_kind = KIND_PIN_SUBMISSION;
  ++guard->counts.pin_submissions;
  return 1;
}

static int pairing_submission_check(tc_piv_guard* guard)
{
  if (guard->counts.pairing_submissions >= guard->policy.pairing_submissions)
    return refuse(guard, "pairing code budget spent");
  if (guard->pairing_failed)
    return refuse(guard, "pairing code after a failed one");
  if (!tc_piv_guard_identity_bound(guard))
    return refuse(guard, "pairing code before the card identity matched");
  guard->pairing_outcome_pending = 1;
  guard->pending_kind = KIND_PAIRING_SUBMISSION;
  ++guard->counts.pairing_submissions;
  return 1;
}

static int verify_check(tc_piv_guard* guard, const uint8_t* header, const Body* body)
{
  const uint8_t reference = header[3];
  const int secured = header[0] == CLA_SECURE;
  if ((header[0] != 0x00 && !secured) || header[2] != 0x00 ||
      (reference != REFERENCE_PIN && reference != REFERENCE_GLOBAL_PIN &&
       reference != REFERENCE_PAIRING_CODE))
    return refuse(guard, "VERIFY outside P1 00 and references 80, 00, 98");
  int submission = body->data.length != 0;
  if (secured) {
    submission = sm_has_cryptogram(body->data);
    if (submission < 0)
      return refuse(guard, "malformed secure messaging VERIFY");
  } else if (submission && guard->interface == TC_PIV_CONTACTLESS) {
    return refuse(guard, "plaintext reference data on contactless");
  }
  guard->pending_reference = reference;
  if (!submission) {
    if (reference != REFERENCE_PAIRING_CODE) {
      guard->pending_kind = KIND_PIN_QUERY;
      ++guard->counts.pin_queries;
    }
    return 1;
  }
  if (reference == REFERENCE_PAIRING_CODE)
    return pairing_submission_check(guard);
  if (!secured && body->data.length != 8)
    return refuse(guard, "PIN submission of another length");
  return pin_submission_check(guard, reference);
}

static int authenticate_check(tc_piv_guard* guard, const uint8_t* header, int previous_verified)
{
  const uint8_t algorithm = header[2], key = header[3];
  const int secured = (header[0] & CLA_SECURE) != 0;
  if (key == KEY_ESTABLISHMENT) {
    if (secured || (algorithm != 0x27 && algorithm != 0x2e))
      return refuse(guard, "key establishment outside plain CLA and suites 27, 2E");
    return 1;
  }
  if ((key != 0x9a && key != KEY_DIGITAL_SIGNATURE && key != 0x9e) ||
      (algorithm != 0x05 && algorithm != 0x06 && algorithm != 0x07 && algorithm != 0x11 &&
       algorithm != 0x14))
    return refuse(guard, "GENERAL AUTHENTICATE outside 9A, 9C, 9E and the PIV algorithms");
  if (key != KEY_DIGITAL_SIGNATURE)
    return 1;
  if (guard->counts.signatures >= guard->policy.signatures)
    return refuse(guard, "signature budget spent");
  if (!tc_piv_guard_identity_bound(guard))
    return refuse(guard, "9C before the card identity matched");
  if (!previous_verified)
    return refuse(guard, "9C without a PIN submission directly before it");
  ++guard->counts.signatures;
  return 1;
}

/* Check a command that opens an exchange (anything but GET RESPONSE and a
 * later chain fragment). */
static int command_check(tc_piv_guard* guard, const uint8_t* header, const Body* body,
                         int previous_verified)
{
  if (header[0] & CLA_CHAINING && header[1] != INS_GENERAL_AUTHENTICATE)
    return refuse(guard, "chaining outside GENERAL AUTHENTICATE");
  switch (header[1]) {
  case INS_SELECT:
    return select_check(guard, header, body);
  case INS_GET_DATA:
    return get_data_check(guard, header, body);
  case INS_VERIFY:
    return verify_check(guard, header, body);
  case INS_GENERAL_AUTHENTICATE:
    return authenticate_check(guard, header, previous_verified);
  default:
    return refuse(guard, "instruction outside the allowed set");
  }
}

static int get_response_check(tc_piv_guard* guard, const uint8_t* header, const Body* body,
                              TC_bytes command)
{
  if (header[0] || header[2] || header[3] || body->data.length || !body->has_le)
    return refuse(guard, "GET RESPONSE other than 00 C0 00 00 Le");
  if (!guard->answer_pending)
    return refuse(guard, "GET RESPONSE without 61XX");
  const uint8_t le = command.data[command.length - 1];
  guard->counts.get_response_le_mismatches += le != guard->last_sw2;
  ++guard->counts.get_responses;
  return 1;
}

int tc_piv_guard_check(void* context, TC_bytes command)
{
  tc_piv_guard* guard = context;
  Body body;
  if (!body_parse(command, &body))
    return refuse(guard, "malformed command APDU");
  const uint8_t* header = command.data;
  const uint8_t cla = header[0];
  if (cla != 0x00 && cla != CLA_CHAINING && cla != CLA_SECURE && cla != (CLA_CHAINING | CLA_SECURE))
    return refuse(guard, "CLA outside 00, 10, 0C and 1C");
  /* An unanswered submission counts as failed. */
  if (guard->pin_outcome_pending) {
    guard->pin_outcome_pending = 0;
    guard->pin_failed = 1;
  }
  if (guard->pairing_outcome_pending) {
    guard->pairing_outcome_pending = 0;
    guard->pairing_failed = 1;
  }
  const int previous_verified = guard->pin_just_verified;
  guard->pin_just_verified = 0;
  const int continuation = header[1] == INS_GET_RESPONSE;
  if (continuation) {
    if (!get_response_check(guard, header, &body, command))
      return 0;
  } else {
    guard->answer_pending = 0;
    guard->capture_index = -1;
    guard->pending_kind = KIND_OTHER;
    const int secured = (cla & CLA_SECURE) != 0;
    if (guard->chain_open) {
      if (memcmp(guard->chain_header, header + 1, 3) || guard->chain_secured != secured)
        return refuse(guard, "command inside an open chain");
    } else if (!command_check(guard, header, &body, previous_verified)) {
      return 0;
    }
    guard->pending_secured = (uint8_t)secured;
    guard->pending_chained = (cla & CLA_CHAINING) != 0;
    memcpy(guard->pending_header, header + 1, 3);
    guard->counts.fragments += guard->pending_chained;
    guard->counts.protected_commands += secured;
  }
  ++guard->counts.exchanges;
  if (command.length > guard->counts.max_command_bytes)
    guard->counts.max_command_bytes = command.length;
  return 1;
}

/* Collect answer data of a watched identity and compare it when complete. */
static void capture_answer(tc_piv_guard* guard, TC_bytes data, uint16_t sw)
{
  if (guard->capture_index < 0)
    return;
  if (data.length > sizeof guard->capture - guard->capture_length) {
    guard->capture_index = -1;
    return;
  }
  if (data.length)
    memcpy(guard->capture + guard->capture_length, data.data, data.length);
  guard->capture_length += data.length;
  if (sw >> 8 == SW1_MORE)
    return;
  if (sw == SW_SUCCESS) {
    const TC_bytes expected = guard->policy.identity[guard->capture_index];
    if (bytes_equal(expected, guard->capture, guard->capture_length))
      guard->identity_bound = 1;
    else
      guard->identity_conflict = 1;
  }
  guard->capture_index = -1;
}

static void verify_answer(tc_piv_guard* guard, TC_bytes answer)
{
  const uint16_t status = verify_status(guard->pending_secured, answer);
  const uint8_t reference = guard->pending_reference;
  switch (guard->pending_kind) {
  case KIND_PIN_QUERY:
    guard->query_ready[reference == REFERENCE_PIN ? 0 : 1] =
        (status & 0xfff0) == 0x63c0 && (unsigned)(status & 0x0f) >= guard->policy.minimum_retries;
    break;
  case KIND_PIN_SUBMISSION:
    guard->pin_outcome_pending = 0;
    if (status == SW_SUCCESS)
      guard->pin_just_verified = 1;
    else
      guard->pin_failed = 1;
    break;
  case KIND_PAIRING_SUBMISSION:
    guard->pairing_outcome_pending = 0;
    guard->pairing_failed = status != SW_SUCCESS;
    break;
  default:
    break;
  }
}

void tc_piv_guard_observe(void* context, TC_bytes command, TC_bytes answer)
{
  tc_piv_guard* guard = context;
  (void)command;
  if (answer.length < 2)
    return;
  if (answer.length > guard->counts.max_answer_bytes)
    guard->counts.max_answer_bytes = answer.length;
  const uint16_t sw =
      (uint16_t)(answer.data[answer.length - 2] << 8 | answer.data[answer.length - 1]);
  const TC_bytes data = {answer.data, answer.length - 2};
  guard->answer_pending = sw >> 8 == SW1_MORE;
  guard->last_sw2 = (uint8_t)sw;
  capture_answer(guard, data, sw);
  if (guard->pending_kind == KIND_SELECT) {
    /* Another application sets the security status FALSE (Part 2 3.1.1). */
    guard->query_ready[0] = guard->query_ready[1] = 0;
  }
  verify_answer(guard, answer);
  if (!command.length || command.data[1] != INS_GET_RESPONSE) {
    guard->chain_open = guard->pending_chained && sw == SW_SUCCESS;
    memcpy(guard->chain_header, guard->pending_header, 3);
    guard->chain_secured = guard->pending_secured;
  }
  guard->pending_kind = KIND_OTHER;
}

static TC_status guarded_transmit(void* context, TC_bytes command, TC_buffer response,
                                  size_t* length)
{
  tc_piv_guarded_transport* wrapper = context;
  if (wrapper->stopped || !tc_piv_guard_check(wrapper->guard, command)) {
    wrapper->stopped = 1;
    if (response.data)
      TC_secure_zero(response.data, response.capacity);
    return TC_ERROR;
  }
  const TC_status status =
      wrapper->inner.transmit(wrapper->inner.context, command, response, length);
  if (status != TC_OK) {
    wrapper->stopped = 1;
    return status;
  }
  tc_piv_guard_observe(wrapper->guard, command, (TC_bytes){response.data, *length});
  return TC_OK;
}

TC_APDU_transport tc_piv_guarded_transport_init(tc_piv_guarded_transport* wrapper,
                                                tc_piv_guard* guard, TC_APDU_transport inner)
{
  wrapper->guard = guard;
  wrapper->inner = inner;
  wrapper->stopped = 0;
  return (TC_APDU_transport){guarded_transmit, wrapper};
}
