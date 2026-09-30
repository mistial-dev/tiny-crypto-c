/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * examples/piv_inspect.c on the SD 33 card 2 and card 4 simulators, with
 * the output compared to tests/vectors/piv/inspect. The PIN and pairing
 * code come from TC_PIV_PIN and TC_PIV_PAIRING_CODE, which CTest sets to the
 * published SD 33 test values. The random source replays the recorded key
 * establishment scalar and the recorded key proof challenges. The trust
 * inputs and the evaluation time follow tests/piv/card_check.c. The guarded
 * runs put the hardware transmit guard of tests/piv/hardware/guard.h
 * between the example and the card. */
#include "../../examples/piv_inspect.h"
#include "card_simulator.h"
#include "hardware/guard.h"
#include "test_io.h"
#include "test_util.h"
#include <stdlib.h>
#include <string.h>

#ifndef TC_CARD_FIXTURE_DIR
#error "TC_CARD_FIXTURE_DIR must name the capture fixture directory"
#endif
#ifndef TC_VECTOR_DIR
#error "TC_VECTOR_DIR must name tests/vectors"
#endif

enum { FILE_BYTES = 16384, OUTPUT_BYTES = 65536, QUEUE = 4 };

static const TC_X509_time at = {2026, 9, 29, 18, 0, 0};

static tc_card_fixture fixture;
static tc_card_simulator card;
static uint8_t files[8][FILE_BYTES];
static size_t file_count;
static char output[OUTPUT_BYTES], golden[OUTPUT_BYTES];
static TC_PIV_card_report report;

static void load(const char* name)
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, name), >, 0);
  munit_assert_long(tc_card_fixture_load(&fixture, path), ==, 0);
}

/* Read tests/vectors/name into the next file slot. */
static TC_bytes vector(const char* name)
{
  char path[512];
  munit_assert_size(file_count, <, sizeof files / sizeof *files);
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", TC_VECTOR_DIR, name), >, 0);
  FILE* file = tc_test_fopen(path, "rb");
  munit_assert_not_null(file);
  const size_t length = fread(files[file_count], 1, FILE_BYTES, file);
  munit_assert_true(feof(file));
  munit_assert_int(fclose(file), ==, 0);
  return (TC_bytes){files[file_count++], length};
}

/* ---- Random source ---- */

/* Byte strings the random source returns in order. */
static struct {
  TC_bytes entries[QUEUE];
  size_t count, calls;
} entropy;

static TC_status queued(void* context, uint8_t* out, size_t length)
{
  (void)context;
  munit_assert_size(entropy.calls, <, entropy.count);
  const TC_bytes entry = entropy.entries[entropy.calls++];
  munit_assert_size(length, ==, entry.length);
  memcpy(out, entry.data, length);
  return TC_OK;
}

static void entropy_push(TC_bytes entry)
{
  munit_assert_size(entropy.count, <, QUEUE);
  entropy.entries[entropy.count++] = entry;
}

static TC_bytes recorded_challenge(uint8_t key)
{
  const TC_bytes challenge = tc_card_fixture_challenge(&fixture, key);
  if (!challenge.length)
    munit_errorf("no recorded challenge for key %02x", key);
  return challenge;
}

/* ---- Runs ---- */

/* A secret from the environment, or empty. */
static TC_bytes secret(const char* name)
{
  const char* value = getenv(name);
  return value ? (TC_bytes){(const uint8_t*)value, strlen(value)} : (TC_bytes){NULL, 0};
}

static struct {
  size_t objects, secret;
} dumped;

static void dump(void* context, const TC_PIV_object* object)
{
  munit_assert_ptr_equal(context, &dumped);
  ++dumped.objects;
  dumped.secret += (object->info->flags & TC_PIV_OBJECT_SECRET) != 0;
}

/* Options for card 2 or card 4 with the pinned issuing CAs, their CRLs and
 * OCSP responses. */
static ExamplePIVInspectOptions options_for(int card4, TC_PIV_interface interface,
                                            TC_bytes anchors[2], TC_bytes crls[2])
{
  ExamplePIVInspectOptions options;
  memset(&options, 0, sizeof options);
  file_count = 0;
  const TC_bytes response =
      vector(card4 ? "x509/ocsp/sd33/card03_response.der" : "x509/ocsp/sd33/card01_response.der");
  if (card4) {
    anchors[0] = vector("x509/ocsp/sd33/card03_issuer.der");
    crls[0] = vector("x509/crl/sd33/ECCP256IssuingCA.crl");
  } else {
    anchors[0] = vector("x509/ocsp/sd33/card01_issuer.der");
    anchors[1] = vector("x509/ocsp/sd33/card04_issuer.der");
    crls[0] = vector("x509/crl/sd33/RSA3072IssuingCA.crl");
    crls[1] = vector("x509/crl/sd33/ECCP384IssuingCA.crl");
  }
  options.interface = interface;
  options.format = TC_APDU_SHORT;
  options.minimum_retries = 3;
  options.anchors = anchors;
  options.anchor_count = card4 ? 1 : 2;
  options.crls = crls;
  options.crl_count = card4 ? 1 : 2;
  options.ocsp[TC_PIV_CARD_SLOT_PIV_AUTHENTICATION] = response;
  options.ocsp[TC_PIV_CARD_SLOT_CARD_AUTHENTICATION] = response;
  options.revocation = TC_VALIDATION_REVOCATION_REQUIRED;
  options.at = at;
  options.random = (TC_random_source){queued, NULL};
  memcpy(options.host_id, fixture.sessions[0].host_id.data, 8);
  options.dump = dump;
  options.dump_context = &dumped;
  memset(&entropy, 0, sizeof entropy);
  memset(&dumped, 0, sizeof dumped);
  entropy_push(fixture.sessions[0].scalar);
  return options;
}

/* Run the example over transport into output and return its exit status. */
static int run_over(const ExamplePIVInspectOptions* options, TC_APDU_transport transport)
{
  FILE* stream = tmpfile();
  munit_assert_not_null(stream);
  memset(&report, 0xa5, sizeof report);
  const int status = example_piv_inspect_run(options, transport, stream, &report);
  const long length = ftell(stream);
  munit_assert_long(length, >=, 0);
  munit_assert_long(length, <, OUTPUT_BYTES);
  rewind(stream);
  munit_assert_size(fread(output, 1, (size_t)length, stream), ==, (size_t)length);
  output[length] = 0;
  munit_assert_int(fclose(stream), ==, 0);
  return status;
}

static int run(const ExamplePIVInspectOptions* options)
{
  return run_over(options, tc_card_simulator_transport(&card));
}

/* Compare output with tests/vectors/piv/inspect/name.txt. A mismatch writes
 * the output to name.actual in the working directory. */
static void expect_golden(const char* name)
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/piv/inspect/%s.txt", TC_VECTOR_DIR, name), >, 0);
  FILE* file = tc_test_fopen(path, "rb");
  size_t length = 0;
  if (file) {
    length = fread(golden, 1, sizeof golden - 1, file);
    munit_assert_int(fclose(file), ==, 0);
  }
  golden[length] = 0;
  if (!file || strcmp(golden, output)) {
    munit_assert_int(snprintf(path, sizeof path, "%s.actual", name), >, 0);
    FILE* actual = tc_test_fopen(path, "wb");
    munit_assert_not_null(actual);
    munit_assert_size(fwrite(output, 1, strlen(output), actual), ==, strlen(output));
    munit_assert_int(fclose(actual), ==, 0);
    munit_errorf("output differs from %s.txt, see %s", name, path);
  }
}

/* No FAILED entry, and the secrets never reach the output. */
static void expect_clean(TC_bytes pin, TC_bytes pairing)
{
  for (size_t i = 0; i < report.count; ++i)
    if (report.checks[i].outcome == TC_PIV_CHECK_FAILED)
      munit_errorf("check %zu kind %u container %04x failed", i, report.checks[i].kind,
                   report.checks[i].container);
  char text[16];
  if (pin.length && pin.length < sizeof text) {
    memcpy(text, pin.data, pin.length);
    text[pin.length] = 0;
    munit_assert_null(strstr(output, text));
  }
  if (pairing.length && pairing.length < sizeof text) {
    memcpy(text, pairing.data, pairing.length);
    text[pairing.length] = 0;
    munit_assert_null(strstr(output, text));
  }
  munit_assert_size(dumped.objects, >, 0);
  munit_assert_size(dumped.secret, ==, 0);
  munit_assert_size(card.violations, ==, 0);
  munit_assert_size(entropy.calls, ==, entropy.count);
}

static const TC_PIV_check* find(uint8_t kind, uint8_t key)
{
  const TC_PIV_check_requirement requirement = {kind, key, 0};
  return TC_PIV_card_report_find(&report, &requirement);
}

/* Card 2 on contactless: secure messaging, the paired VCI, the PIN, the
 * complete inventory and both proofs. */
TC_TEST(card2_contactless)
{
  const TC_bytes pin = secret("TC_PIV_PIN"), pairing = secret("TC_PIV_PAIRING_CODE");
  if (!pin.length || !pairing.length)
    return MUNIT_SKIP;
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACTLESS, anchors, crls);
  options.pin = pin;
  options.pairing_code = pairing;
  entropy_push(recorded_challenge(0x9a));
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 0);
  expect_golden("sd33_card2_contactless");
  expect_clean(pin, pairing);
  munit_assert_size(card.pin_submissions, ==, 1);
  munit_assert_size(card.pairing_submissions, ==, 1);
  munit_assert_uint8(find(TC_PIV_CHECK_SM_CVC, 0)->outcome, ==, TC_PIV_CHECK_PASSED);
  munit_assert_uint8(find(TC_PIV_CHECK_KEY_PROOF, 0x9a)->outcome, ==, TC_PIV_CHECK_PASSED);
  return MUNIT_OK;
}

/* Card 2 on contact: secure messaging without the VCI. */
TC_TEST(card2_contact)
{
  const TC_bytes pin = secret("TC_PIV_PIN");
  if (!pin.length)
    return MUNIT_SKIP;
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACT, anchors, crls);
  options.pin = pin;
  options.pairing_code = secret("TC_PIV_PAIRING_CODE");
  entropy_push(recorded_challenge(0x9a));
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 0);
  expect_golden("sd33_card2_contact");
  expect_clean(pin, options.pairing_code);
  munit_assert_size(card.pin_submissions, ==, 1);
  munit_assert_size(card.pairing_submissions, ==, 0);
  return MUNIT_OK;
}

/* Card 4 (CS2, P-256) on contactless. */
TC_TEST(card4_contactless)
{
  const TC_bytes pin = secret("TC_PIV_PIN"), pairing = secret("TC_PIV_PAIRING_CODE");
  if (!pin.length || !pairing.length)
    return MUNIT_SKIP;
  TC_bytes anchors[2], crls[2];
  load("sd33_card4");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  ExamplePIVInspectOptions options = options_for(1, TC_PIV_CONTACTLESS, anchors, crls);
  options.pin = pin;
  options.pairing_code = pairing;
  entropy_push(recorded_challenge(0x9a));
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 0);
  expect_golden("sd33_card4_contactless");
  expect_clean(pin, pairing);
  munit_assert_size(card.pairing_submissions, ==, 1);
  return MUNIT_OK;
}

/* Without a PIN or pairing code on contactless the run sends neither, reads
 * the objects its access allows and proves 9E. The baseline and secure
 * messaging requirements still accept the card. */
TC_TEST(card2_without_pin)
{
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  const ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACTLESS, anchors, crls);
  entropy_push(recorded_challenge(0x9e));
  const int status = run(&options);
  if (status)
    fputs(output, stderr);
  munit_assert_int(status, ==, 0);
  expect_clean((TC_bytes){NULL, 0}, (TC_bytes){NULL, 0});
  munit_assert_size(card.pin_submissions, ==, 0);
  munit_assert_size(card.pairing_submissions, ==, 0);
  munit_assert_null(strstr(output, "VCI: paired"));
  munit_assert_not_null(strstr(output, "VCI: no pairing code"));
  munit_assert_null(find(TC_PIV_CHECK_KEY_PROOF, 0x9a));
  munit_assert_uint8(find(TC_PIV_CHECK_KEY_PROOF, 0x9e)->outcome, ==, TC_PIV_CHECK_PASSED);
  return MUNIT_OK;
}

/* A changed CHUID byte fails the CHUID check, so the card is rejected. */
TC_TEST(card2_tampered)
{
  static uint8_t changed[FILE_BYTES];
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  const tc_card_object* chuid = tc_card_fixture_object(&fixture, 0x5fc102);
  munit_assert_not_null(chuid);
  memcpy(changed, chuid->data.data, chuid->data.length);
  changed[chuid->data.length - 3] ^= 1;
  munit_assert_int(
      tc_card_simulator_override(&card, 0x5fc102, 0x9000, (TC_bytes){changed, chuid->data.length}),
      ==, 1);
  const ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACT, anchors, crls);
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 1);
  munit_assert_uint8(find(TC_PIV_CHECK_CHUID, 0)->outcome, ==, TC_PIV_CHECK_FAILED);
  munit_assert_not_null(strstr(output, "Result: rejected"));
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* A supplied PIN that the card rejects is a failed step, so the card is
 * rejected. The value differs from the SD 33 test PIN. */
TC_TEST(card2_wrong_pin)
{
  const TC_bytes pairing = secret("TC_PIV_PAIRING_CODE");
  if (!pairing.length)
    return MUNIT_SKIP;
  static const uint8_t wrong[] = "999999";
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACTLESS, anchors, crls);
  options.pin = (TC_bytes){wrong, sizeof wrong - 1};
  options.pairing_code = pairing;
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 1);
  munit_assert_size(card.pin_submissions, ==, 1);
  munit_assert_not_null(strstr(output, "PIN 80: card status 63c"));
  munit_assert_not_null(strstr(output, "Result: rejected"));
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* A FAILED entry rejects the card even when no requirement names it: a
 * changed Key History fails its Security Object digest on contact without
 * a PIN. */
TC_TEST(card2_unrequired_failure)
{
  static uint8_t changed[FILE_BYTES];
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  const tc_card_object* history = tc_card_fixture_object(&fixture, 0x5fc10c);
  munit_assert_not_null(history);
  munit_assert_size(history->data.length, ==, 10);
  memcpy(changed, history->data.data, history->data.length);
  changed[4] = 0x02; /* keysWithOnCardCerts 1 -> 2 */
  munit_assert_int(tc_card_simulator_override(&card, 0x5fc10c, 0x9000,
                                              (TC_bytes){changed, history->data.length}),
                   ==, 1);
  const ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACT, anchors, crls);
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 1);
  const TC_PIV_check_requirement digest = {TC_PIV_CHECK_SECURITY_DIGEST, 0, 0x6060};
  munit_assert_uint8(TC_PIV_card_report_find(&report, &digest)->outcome, ==, TC_PIV_CHECK_FAILED);
  munit_assert_not_null(strstr(output, "Result: rejected"));
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* A card that offers secure messaging and refuses key establishment is
 * rejected, although the plain baseline passes. */
TC_TEST(card2_key_establishment_refused)
{
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACTLESS, anchors, crls);
  options.host_id[0] ^= 1; /* no recorded session answers this host */
  entropy_push(recorded_challenge(0x9e));
  munit_assert_int(run(&options), ==, 1);
  munit_assert_not_null(strstr(output, "Secure messaging: key establishment"));
  munit_assert_uint8(find(TC_PIV_CHECK_KEY_PROOF, 0x9e)->outcome, ==, TC_PIV_CHECK_PASSED);
  munit_assert_uint8(find(TC_PIV_CHECK_SM_CVC, 0)->outcome, ==, TC_PIV_CHECK_NOT_CHECKABLE);
  munit_assert_not_null(strstr(output, "Result: rejected"));
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* ---- Hardware guard ---- */

static tc_piv_guard guard;
static tc_piv_guarded_transport guarded;

/* The guard of test_piv_inspect_live over the card simulator: one PIN
 * submission, one pairing code and no 9C, with the identity of the
 * fixture. */
static TC_APDU_transport guard_start(TC_bytes chuid)
{
  const tc_card_object* certificate = tc_card_fixture_object(&fixture, 0x5fc101);
  munit_assert_not_null(certificate);
  tc_piv_guard_policy policy;
  memset(&policy, 0, sizeof policy);
  policy.identity[TC_PIV_GUARD_CHUID] = chuid;
  policy.identity[TC_PIV_GUARD_CARD_CERTIFICATE] = certificate->data;
  policy.minimum_retries = 3;
  policy.pin_submissions = 1;
  policy.pairing_submissions = 1;
  munit_assert_int(tc_piv_guard_init(&guard, &policy), ==, 1);
  tc_piv_guard_connected(&guard, card.interface);
  return tc_piv_guarded_transport_init(&guarded, &guard, tc_card_simulator_transport(&card));
}

/* The complete contactless run passes the guard: the plain CHUID binds the
 * identity before the pairing code and the PIN. */
TC_TEST(card2_guarded)
{
  const TC_bytes pin = secret("TC_PIV_PIN"), pairing = secret("TC_PIV_PAIRING_CODE");
  if (!pin.length || !pairing.length)
    return MUNIT_SKIP;
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACTLESS, anchors, crls);
  options.pin = pin;
  options.pairing_code = pairing;
  entropy_push(recorded_challenge(0x9a));
  entropy_push(recorded_challenge(0x9e));
  const tc_card_object* chuid = tc_card_fixture_object(&fixture, 0x5fc102);
  munit_assert_not_null(chuid);
  munit_assert_int(run_over(&options, guard_start(chuid->data)), ==, 0);
  expect_golden("sd33_card2_contactless");
  expect_clean(pin, pairing);
  munit_assert_size(guard.counts.refusals, ==, 0);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 1);
  munit_assert_size(guard.counts.pin_submissions, ==, 1);
  munit_assert_size(guard.counts.pairing_submissions, ==, 1);
  munit_assert_size(guard.counts.exchanges, ==, card.transmits);
  munit_assert_size(guard.counts.get_response_le_mismatches, ==, 0);
  return MUNIT_OK;
}

/* A CHUID that differs from the expected identity keeps the pairing code
 * and the PIN off the card. The first refused command stops the
 * transport. */
TC_TEST(card2_guard_identity)
{
  static uint8_t expected[FILE_BYTES];
  const TC_bytes pin = secret("TC_PIV_PIN"), pairing = secret("TC_PIV_PAIRING_CODE");
  if (!pin.length || !pairing.length)
    return MUNIT_SKIP;
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  ExamplePIVInspectOptions options = options_for(0, TC_PIV_CONTACTLESS, anchors, crls);
  options.pin = pin;
  options.pairing_code = pairing;
  const tc_card_object* chuid = tc_card_fixture_object(&fixture, 0x5fc102);
  munit_assert_not_null(chuid);
  memcpy(expected, chuid->data.data, chuid->data.length);
  expected[chuid->data.length - 3] ^= 1;
  munit_assert_int(run_over(&options, guard_start((TC_bytes){expected, chuid->data.length})), ==,
                   1);
  munit_assert_int(tc_piv_guard_identity_bound(&guard), ==, 0);
  munit_assert_size(guard.counts.refusals, ==, 1);
  munit_assert_string_equal(guard.counts.refusal, "pairing code before the card identity matched");
  munit_assert_size(card.pin_submissions, ==, 0);
  munit_assert_size(card.pairing_submissions, ==, 0);
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* Invalid options return 2 before any command. */
TC_TEST(arguments)
{
  TC_bytes anchors[2], crls[2];
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  const ExamplePIVInspectOptions valid = options_for(0, TC_PIV_CONTACT, anchors, crls);
  ExamplePIVInspectOptions options = valid;
  options.minimum_retries = 1;
  munit_assert_int(run(&options), ==, 2);
  options = valid;
  options.anchor_count = 0;
  munit_assert_int(run(&options), ==, 2);
  options = valid;
  options.anchor_count = EXAMPLE_PIV_INSPECT_ANCHORS + 1;
  munit_assert_int(run(&options), ==, 2);
  options = valid;
  options.interface = (TC_PIV_interface)2;
  munit_assert_int(run(&options), ==, 2);
  options = valid;
  options.random.fill = NULL;
  munit_assert_int(run(&options), ==, 2);
  munit_assert_int(run(NULL), ==, 2);
  munit_assert_size(card.transmits, ==, 0);
  /* A malformed anchor stops the run before any command. */
  options = valid;
  const uint8_t junk[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  const TC_bytes bad[] = {{junk, sizeof junk}};
  options.anchors = bad;
  options.anchor_count = 1;
  munit_assert_int(run(&options), ==, 1);
  munit_assert_size(card.transmits, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/card2-contactless", card2_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-contact", card2_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card4-contactless", card4_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-without-pin", card2_without_pin, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-tampered", card2_tampered, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-wrong-pin", card2_wrong_pin, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-unrequired-failure", card2_unrequired_failure, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {"/card2-key-establishment-refused", card2_key_establishment_refused, NULL, NULL,
       MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-guarded", card2_guarded, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-guard-identity", card2_guard_identity, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/arguments", arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/inspect", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
