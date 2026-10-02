/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Rules of the PIV hardware transmit guard (tests/piv/hardware/guard.h) on
 * synthetic commands and answers. The PIN digits are arbitrary. */
#include "hardware/guard.h"
#include "cavp.h"
#include "test_util.h"
#include <string.h>

enum { BYTES = 512 };

static tc_piv_guard guard;

/* Expected identity answers: a short CHUID-shaped 53 container and a Card
 * Authentication certificate container. */
static const uint8_t chuid[] = {0x53, 0x04, 0x01, 0x02, 0x03, 0x04};
static const uint8_t card_certificate[] = {0x53, 0x02, 0x70, 0x00};

static TC_bytes hex(const char* text, uint8_t* storage)
{
  size_t length = 0;
  munit_assert_true(tc_test_hex_decode(text, TC_TEST_HEX_SEPARATED, storage, BYTES, &length));
  return (TC_bytes){storage, length};
}

static int check(const char* command)
{
  uint8_t storage[BYTES];
  return tc_piv_guard_check(&guard, hex(command, storage));
}

/* Pass command and deliver answer. Returns 0 when the guard refused. */
static int exchange(const char* command, const char* answer)
{
  uint8_t command_bytes[BYTES], answer_bytes[BYTES];
  const TC_bytes sent = hex(command, command_bytes);
  if (!tc_piv_guard_check(&guard, sent))
    return 0;
  tc_piv_guard_observe(&guard, sent, hex(answer, answer_bytes));
  return 1;
}

static tc_piv_guard_policy policy(unsigned pins, unsigned pairings, unsigned signatures)
{
  tc_piv_guard_policy value;
  memset(&value, 0, sizeof value);
  value.identity[TC_PIV_GUARD_CHUID] = (TC_bytes){chuid, sizeof chuid};
  value.identity[TC_PIV_GUARD_CARD_CERTIFICATE] =
      (TC_bytes){card_certificate, sizeof card_certificate};
  value.minimum_retries = 3;
  value.pin_submissions = pins;
  value.pairing_submissions = pairings;
  value.signatures = signatures;
  return value;
}

static void start(unsigned pins, unsigned pairings, unsigned signatures, TC_PIV_interface interface)
{
  const tc_piv_guard_policy value = policy(pins, pairings, signatures);
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 1);
  tc_piv_guard_connected(&guard, interface);
}

#define SELECT_PIV "00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00 00"
#define GET_CHUID "00 CB 3F FF 05 5C 03 5F C1 02 00"
#define GET_CARD_CERTIFICATE "00 CB 3F FF 05 5C 03 5F C1 01 00"
#define QUERY_PIN "00 20 00 80"
#define SUBMIT_PIN "00 20 00 80 08 31 31 31 31 31 31 FF FF"
#define SM_QUERY_PIN "0C 20 00 80 0A 8E 08 01 02 03 04 05 06 07 08 00"
#define SM_SUBMIT_PIN                                                                              \
  "0C 20 00 80 1D 87 11 01 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 8E 08 01 02 03 04 05 "  \
  "06 07 08 00"
#define SM_ANSWER(sw) "99 02 " sw " 8E 08 01 02 03 04 05 06 07 08 90 00"
#define SIGN_9C "00 87 07 9C 06 7C 04 82 00 81 00 00"

static void bind_identity(void)
{
  munit_assert_int(exchange(SELECT_PIV, "61 2A 90 00"), ==, 1);
  munit_assert_int(exchange(GET_CHUID, "53 04 01 02 03 04 90 00"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 1);
}

TC_TEST(policy_ranges)
{
  tc_piv_guard_policy value = policy(2, 1, 1);
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 1);
  munit_assert_int(tc_piv_guard_init(NULL, &value), ==, 0);
  munit_assert_int(tc_piv_guard_init(&guard, NULL), ==, 0);
  value.minimum_retries = 1;
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 0);
  value = policy(3, 1, 1);
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 0);
  value = policy(2, 2, 1);
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 0);
  value = policy(2, 1, 2);
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 0);
  return MUNIT_OK;
}

/* The allowed command set, and refusals of everything around it. */
TC_TEST(commands)
{
  start(0, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange(SELECT_PIV, "90 00"), ==, 1);
  munit_assert_int(exchange("00 A4 04 00 09 A0 00 00 03 08 00 00 10 00 00", "90 00"), ==, 1);
  munit_assert_int(exchange("00 A4 04 00 09 A0 00 00 03 67 20 00 00 01 00", "6A 82"), ==, 1);
  munit_assert_int(exchange(GET_CHUID, "6A 82"), ==, 1);
  munit_assert_int(exchange("0C CB 3F FF 0B 87 09 01 00 11 22 33 44 55 66 77 00", "90 00"), ==, 1);
  munit_assert_int(exchange("00 CB 3F FF 00 00 05 5C 03 5F C1 02 00 00", "6A 82"), ==, 1);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange("00 20 00 98", "63 C5"), ==, 1);
  munit_assert_int(exchange("00 87 2E 04 04 7C 02 81 00 00", "90 00"), ==, 1);
  munit_assert_int(exchange("0C 87 07 9E 04 7C 02 82 00 00", "90 00"), ==, 1);
  munit_assert_int(exchange("00 87 11 9A 04 7C 02 82 00 00", "90 00"), ==, 1);
  munit_assert_size(guard.counts.refusals, ==, 0);
  munit_assert_size(guard.counts.exchanges, ==, 11);
  munit_assert_size(guard.counts.protected_commands, ==, 2);

  static const char* const refused[] = {
      "00 A4 04 00 05 A0 00 00 03 97 00",                   /* another AID */
      "00 A4 04 0C 0B A0 00 00 03 08 00 00 10 00 01 00 00", /* SELECT P2 0C */
      "00 CB 3F FE 05 5C 03 5F C1 02 00",                   /* GET DATA P2 */
      "00 C0 00 00 00",                                     /* GET RESPONSE without 61XX */
      "00 24 00 80 10 31 31 31 31 31 31 FF FF 32 32 32 32 32 32 FF FF",
      "00 2C 00 80 00",
      "00 DB 3F FF 03 5C 01 7E",
      "00 47 00 9A 05 AC 03 80 01 07",
      "00 20 FF 80",                      /* VERIFY P1 FF */
      "00 20 00 81",                      /* another reference */
      "00 87 07 9B 04 7C 02 82 00 00",    /* 9B */
      "00 87 07 9D 04 7C 02 82 00 00",    /* 9D */
      "00 87 07 82 04 7C 02 82 00 00",    /* retired key */
      "00 87 08 9E 04 7C 02 82 00 00",    /* unknown algorithm */
      "0C 87 2E 04 04 7C 02 81 00 00",    /* key establishment under SM */
      "10 CB 3F FF 05 5C 03 5F C1 02",    /* chained GET DATA */
      "01 CB 3F FF 05 5C 03 5F C1 02 00", /* logical channel */
      "80 CB 3F FF 05 5C 03 5F C1 02 00", /* proprietary class */
      "00 CB 3F FF 05 5C 03 5F C1",       /* Lc beyond the data */
      "00 CB 3F",                         /* short header */
      "00 CB 3F FF 00 00 05 5C 03",       /* extended Lc beyond the data */
      "00 CB 3F FF 00 00"};               /* extended Lc cut short */
  for (size_t i = 0; i < sizeof refused / sizeof *refused; ++i) {
    const size_t before = guard.counts.refusals;
    munit_assert_int(check(refused[i]), ==, 0);
    munit_assert_size(guard.counts.refusals, ==, before + 1);
  }
  munit_assert_not_null(guard.counts.refusal);
  munit_assert_size(guard.counts.exchanges, ==, 11);
  return MUNIT_OK;
}

/* GET RESPONSE follows 61XX, and chained fragments keep one header. */
TC_TEST(continuations)
{
  start(0, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange(SELECT_PIV, "61 10"), ==, 1);
  munit_assert_int(exchange("00 C0 00 00 10", "61 00"), ==, 1);
  munit_assert_int(exchange("00 C0 00 00 00", "90 00"), ==, 1);
  munit_assert_size(guard.counts.get_responses, ==, 2);
  munit_assert_size(guard.counts.get_response_le_mismatches, ==, 0);
  munit_assert_int(exchange(SELECT_PIV, "61 10"), ==, 1);
  munit_assert_int(exchange("00 C0 00 00 00", "90 00"), ==, 1);
  munit_assert_size(guard.counts.get_response_le_mismatches, ==, 1);
  munit_assert_int(check("0C C0 00 00 00"), ==, 0);

  start(0, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange("10 87 07 9E 02 7C 04", "90 00"), ==, 1);
  munit_assert_int(exchange("00 87 07 9E 04 82 00 81 00 00", "90 00"), ==, 1);
  munit_assert_size(guard.counts.fragments, ==, 1);
  munit_assert_int(exchange("10 87 07 9E 02 7C 04", "90 00"), ==, 1);
  munit_assert_int(check("00 87 07 9A 04 82 00 81 00 00"), ==, 0); /* another key */
  start(0, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange("1C 87 07 9E 02 7C 04", "90 00"), ==, 1);
  munit_assert_int(check(GET_CHUID), ==, 0); /* the chain is open */
  return MUNIT_OK;
}

/* The identity binds from a complete plain answer, collected over GET
 * RESPONSE, and a differing answer blocks it. */
TC_TEST(identity)
{
  start(1, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange(GET_CHUID, "53 04 01 61 03"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 0);
  munit_assert_int(exchange("00 C0 00 00 03", "02 03 04 90 00"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 1);

  /* An incomplete read binds nothing. */
  start(1, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange(GET_CARD_CERTIFICATE, "53 02 61 02"), ==, 1);
  munit_assert_int(exchange(SELECT_PIV, "90 00"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 0);
  munit_assert_int(exchange(GET_CARD_CERTIFICATE, "53 02 70 00 90 00"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 1);

  /* A differing CHUID blocks the binding, also after a matching one. */
  munit_assert_int(exchange(GET_CHUID, "53 04 01 02 03 05 90 00"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 0);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);
  munit_assert_int(exchange(GET_CHUID, "53 04 01 02 03 04 90 00"), ==, 1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 0);

  /* An SM read is never compared. */
  start(1, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(
      exchange("0C CB 3F FF 0B 87 09 01 00 11 22 33 44 55 66 77 00", "53 04 01 02 03 04 90 00"), ==,
      1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 0);
  return MUNIT_OK;
}

/* A PIN submission needs the binding, a query at or above the floor, budget
 * and no failed submission. */
TC_TEST(pin_budget)
{
  start(2, 0, 0, TC_PIV_CONTACT);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0); /* no identity */
  bind_identity();
  munit_assert_int(check(SUBMIT_PIN), ==, 0); /* SELECT cleared the query */
  munit_assert_int(exchange(QUERY_PIN, "63 C2"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0); /* below the floor */
  munit_assert_int(exchange(QUERY_PIN, "63 C3"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "90 00"), ==, 1);
  munit_assert_size(guard.counts.pin_submissions, ==, 1);
  /* A verified reference answers 9000 without a count. */
  munit_assert_int(exchange(QUERY_PIN, "90 00"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "90 00"), ==, 1);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0); /* budget spent */
  munit_assert_size(guard.counts.pin_submissions, ==, 2);
  munit_assert_size(guard.counts.pin_queries, ==, 6);

  /* A rejected submission ends PIN submissions. */
  start(2, 0, 0, TC_PIV_CONTACT);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "63 C4"), ==, 1);
  munit_assert_int(exchange(QUERY_PIN, "63 C4"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);

  /* A submission without an answer counts as failed. */
  start(2, 0, 0, TC_PIV_CONTACT);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 1);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);

  /* No budget, no submission. */
  start(0, 0, 0, TC_PIV_CONTACT);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);
  return MUNIT_OK;
}

/* Contactless refuses plain reference data, and SM VERIFY is classified by
 * DO 87. */
TC_TEST(contactless)
{
  start(1, 1, 0, TC_PIV_CONTACTLESS);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);
  munit_assert_int(check("00 20 00 98 08 30 30 30 30 30 30 30 30"), ==, 0);
  munit_assert_int(exchange(SM_QUERY_PIN, SM_ANSWER("63 C5")), ==, 1);
  munit_assert_size(guard.counts.pin_queries, ==, 2);
  munit_assert_int(exchange(SM_SUBMIT_PIN, SM_ANSWER("90 00")), ==, 1);
  munit_assert_size(guard.counts.pin_submissions, ==, 1);
  /* An SM field with a DO outside 87, 97 and 8E is refused, such as the
   * plain value DO 81, which would carry the PIN in plaintext. */
  static const char* const unknown[] = {
      "0C 20 00 80 16 81 08 31 31 31 31 31 31 FF FF 8E 08 01 02 03 04 05 06 07 08 00",
      "0C 20 00 98 16 85 08 30 30 30 30 30 30 30 32 8E 08 01 02 03 04 05 06 07 08 00",
      "0C 20 00 80 0C 8E 08 01 02 03 04 05 06 07 08 99 00 00"};
  for (size_t i = 0; i < sizeof unknown / sizeof *unknown; ++i) {
    const size_t queries = guard.counts.pin_queries;
    munit_assert_int(check(unknown[i]), ==, 0);
    munit_assert_size(guard.counts.pin_queries, ==, queries);
  }
  /* An SM error without DO 99 is a failed submission. */
  start(2, 0, 0, TC_PIV_CONTACTLESS);
  bind_identity();
  munit_assert_int(exchange(SM_QUERY_PIN, SM_ANSWER("63 C5")), ==, 1);
  munit_assert_int(exchange(SM_SUBMIT_PIN, "69 88"), ==, 1);
  munit_assert_int(exchange(SM_QUERY_PIN, SM_ANSWER("63 C5")), ==, 1);
  munit_assert_int(check(SM_SUBMIT_PIN), ==, 0);
  /* A guard that never learned the interface keeps contactless rules. */
  const tc_piv_guard_policy value = policy(1, 0, 0);
  munit_assert_int(tc_piv_guard_init(&guard, &value), ==, 1);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(check(SUBMIT_PIN), ==, 0);
  return MUNIT_OK;
}

TC_TEST(pairing)
{
  start(0, 1, 0, TC_PIV_CONTACTLESS);
  const char* submit =
      "0C 20 00 98 1D 87 11 01 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 8E 08 01 02 03 04 "
      "05 06 07 08 00";
  munit_assert_int(check(submit), ==, 0); /* no identity */
  bind_identity();
  munit_assert_int(exchange(submit, SM_ANSWER("90 00")), ==, 1);
  munit_assert_int(check(submit), ==, 0); /* budget spent */
  munit_assert_size(guard.counts.pairing_submissions, ==, 1);
  start(0, 0, 0, TC_PIV_CONTACTLESS);
  bind_identity();
  munit_assert_int(check(submit), ==, 0);
  return MUNIT_OK;
}

/* 9C follows a successful PIN submission directly. */
TC_TEST(signature)
{
  start(2, 0, 1, TC_PIV_CONTACT);
  bind_identity();
  munit_assert_int(check(SIGN_9C), ==, 0);
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "90 00"), ==, 1);
  munit_assert_int(exchange(QUERY_PIN, "90 00"), ==, 1);
  munit_assert_int(check(SIGN_9C), ==, 0); /* a command came between */
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "90 00"), ==, 1);
  munit_assert_int(exchange("10 87 07 9C 02 7C 04", "90 00"), ==, 1);
  munit_assert_int(exchange("00 87 07 9C 04 82 00 81 00 00", "61 10"), ==, 1);
  munit_assert_int(exchange("00 C0 00 00 10", "90 00"), ==, 1);
  munit_assert_size(guard.counts.signatures, ==, 1);
  munit_assert_int(check(SIGN_9C), ==, 0);

  /* No signature budget. */
  start(1, 0, 0, TC_PIV_CONTACT);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "90 00"), ==, 1);
  munit_assert_int(check(SIGN_9C), ==, 0);
  /* A failed submission allows no signature. */
  start(1, 0, 1, TC_PIV_CONTACT);
  bind_identity();
  munit_assert_int(exchange(QUERY_PIN, "63 C5"), ==, 1);
  munit_assert_int(exchange(SUBMIT_PIN, "63 C4"), ==, 1);
  munit_assert_int(check(SIGN_9C), ==, 0);
  return MUNIT_OK;
}

static struct {
  size_t calls;
} inner_state;

static TC_status inner_transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  (void)context;
  (void)command;
  ++inner_state.calls;
  response.data[0] = 0x90;
  response.data[1] = 0x00;
  *length = 2;
  return TC_OK;
}

/* The wrapper refuses before the inner transport, wipes the response and
 * stops. */
TC_TEST(transport)
{
  start(0, 0, 0, TC_PIV_CONTACT);
  tc_piv_guarded_transport wrapper;
  memset(&inner_state, 0, sizeof inner_state);
  const TC_APDU_transport transport =
      tc_piv_guarded_transport_init(&wrapper, &guard, (TC_APDU_transport){inner_transmit, NULL});
  uint8_t command[BYTES], response[8];
  size_t length = 0;
  munit_assert_int(transport.transmit(transport.context, hex(SELECT_PIV, command),
                                      (TC_buffer){response, sizeof response}, &length),
                   ==, TC_OK);
  munit_assert_size(length, ==, 2);
  munit_assert_size(inner_state.calls, ==, 1);
  memset(response, 0xa5, sizeof response);
  length = 7;
  munit_assert_int(transport.transmit(transport.context, hex("00 24 00 80 00", command),
                                      (TC_buffer){response, sizeof response}, &length),
                   ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(response, sizeof response));
  munit_assert_size(length, ==, 7);
  munit_assert_size(inner_state.calls, ==, 1);
  munit_assert_int(transport.transmit(transport.context, hex(SELECT_PIV, command),
                                      (TC_buffer){response, sizeof response}, &length),
                   ==, TC_ERROR);
  munit_assert_size(inner_state.calls, ==, 1);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/policy", policy_ranges, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/commands", commands, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/continuations", continuations, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/identity", identity, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/pin-budget", pin_budget, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/contactless", contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/pairing", pairing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/signature", signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/transport", transport, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/hardware-guard", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
