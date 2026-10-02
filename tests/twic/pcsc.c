/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_pcsc.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

/* These entry points replace the platform service. Calls count in order:
 * establish, list, status, connect and begin on open, then end, disconnect
 * and release on close. fail_call makes that call fail. */
SCARD_IO_REQUEST g_rgSCardT0Pci, g_rgSCardT1Pci, g_rgSCardRawPci;
static unsigned calls, fail_call, released, disconnected, ended, transfers, status_reads, connects;
static uint32_t selected_protocol = SCARD_PROTOCOL_T1, disposition = SCARD_LEAVE_CARD;
static uint32_t card_state = SCARD_STATE_PRESENT;
static const char* reader_names;
static size_t reader_names_length;
static char connected_reader[64];
static const uint8_t* card_atr;
static size_t card_atr_length;

/* A contact ATR and the PC/SC contactless ATR of SD 33 card 2 on an ACS
 * ACR1552 PICC reader (PC/SC Part 3 section 3.1.3.2.3). */
static const uint8_t contact_atr[] = {0x3b, 0xf8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x00};
static const uint8_t contactless_atr[] = {0x3b, 0x86, 0x80, 0x01, 0x80, 0x31,
                                          0xc1, 0x52, 0x41, 0x1a, 0x7e};
/* The YubiKey 4 ATR spells "Yubikey4" in its historical bytes, and the NFC
 * form spells "YubiKey". */
static const uint8_t yubikey_atr[] = {0x3b, 0xf8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15,
                                      0x59, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x34, 0xd4};
static const uint8_t yubikey_nfc_atr[] = {0x3b, 0x8c, 0x80, 0x01, 0x59, 0x75, 0x62,
                                          0x69, 0x4b, 0x65, 0x79, 0x00, 0x00};

static int32_t outcome(void)
{
  return ++calls == fail_call ? -1 : SCARD_S_SUCCESS;
}
int32_t SCardEstablishContext(uint32_t scope, const void* a, const void* b, LPSCARDCONTEXT out)
{
  munit_assert_uint(scope, ==, SCARD_SCOPE_SYSTEM);
  munit_assert_null(a);
  munit_assert_null(b);
  *out = 1;
  return outcome();
}
int32_t SCardListReaders(SCARDCONTEXT context, const char* groups, char* names, uint32_t* length)
{
  munit_assert_int(context, ==, 1);
  munit_assert_null(groups);
  munit_assert_not_null(names);
  munit_assert_size(*length, >=, reader_names_length);
  memcpy(names, reader_names, reader_names_length);
  *length = (uint32_t)reader_names_length;
  return outcome();
}
int32_t SCardGetStatusChange(SCARDCONTEXT context, uint32_t timeout, LPSCARD_READERSTATE_A states,
                             uint32_t count)
{
  munit_assert_int(context, ==, 1);
  munit_assert_uint(timeout, ==, 0);
  munit_assert_uint(count, ==, 1);
  munit_assert_uint(states->dwCurrentState, ==, SCARD_STATE_UNAWARE);
  ++status_reads;
  states->dwEventState = card_state;
  states->cbAtr = (uint32_t)card_atr_length;
  memcpy(states->rgbAtr, card_atr, card_atr_length);
  return outcome();
}
int32_t SCardConnect(SCARDCONTEXT context, const char* reader, uint32_t sharing, uint32_t protocols,
                     LPSCARDHANDLE card, uint32_t* protocol)
{
  munit_assert_int(context, ==, 1);
  munit_assert_uint(sharing, ==, SCARD_SHARE_EXCLUSIVE);
  munit_assert_uint(protocols, ==, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);
  munit_assert_size(strlen(reader), <, sizeof connected_reader);
  strcpy(connected_reader, reader);
  ++connects;
  *card = 2;
  *protocol = selected_protocol;
  return outcome();
}
int32_t SCardBeginTransaction(SCARDHANDLE card)
{
  munit_assert_int(card, ==, 2);
  return outcome();
}
int32_t SCardEndTransaction(SCARDHANDLE card, uint32_t value)
{
  munit_assert_int(card, ==, 2);
  munit_assert_uint(value, ==, SCARD_LEAVE_CARD);
  ++ended;
  return outcome();
}
int32_t SCardDisconnect(SCARDHANDLE card, uint32_t value)
{
  munit_assert_int(card, ==, 2);
  disposition = value;
  ++disconnected;
  return outcome();
}
int32_t SCardReleaseContext(SCARDCONTEXT context)
{
  munit_assert_int(context, ==, 1);
  ++released;
  return outcome();
}
int32_t SCardTransmit(SCARDHANDLE card, LPCSCARD_IO_REQUEST protocol, const unsigned char* command,
                      uint32_t length, LPSCARD_IO_REQUEST receive_protocol, unsigned char* response,
                      uint32_t* capacity)
{
  munit_assert_int(card, ==, 2);
  munit_assert_ptr_equal(protocol,
                         selected_protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1);
  munit_assert_null(receive_protocol);
  munit_assert_not_null(command);
  munit_assert_uint(length, ==, 4);
  munit_assert_uint(*capacity, >=, 2);
  response[0] = 0x90;
  response[1] = 0;
  *capacity = 2;
  ++transfers;
  return outcome();
}

#define READERS(text) readers_set(text, sizeof text)
static void readers_set(const char* names, size_t length)
{
  reader_names = names;
  reader_names_length = length;
}
#define ATR(bytes) atr_set(bytes, sizeof bytes)
static void atr_set(const uint8_t* atr, size_t length)
{
  card_atr = atr;
  card_atr_length = length;
}
static void reset(void)
{
  calls = fail_call = released = disconnected = ended = transfers = status_reads = connects = 0;
  disposition = SCARD_LEAVE_CARD;
  card_state = SCARD_STATE_PRESENT;
  memset(connected_reader, 0, sizeof connected_reader);
  READERS("synthetic reader\0");
  ATR(contact_atr);
}
static ExampleCardPCSCOptions options_for(const char* reader, ExampleCardPCSCInterface interface)
{
  ExampleCardPCSCOptions options = {reader, interface, NULL};
  return options;
}

TC_TEST(lifecycle)
{
  /* Calls 1 to 5 fail during open, 6 to 8 during close. */
  for (unsigned failure = 0; failure <= 8; ++failure) {
    ExampleCardPCSC state = {0}, zero = {0};
    reset();
    fail_call = failure;
    const ExampleCardPCSCOptions options = options_for("synthetic", EXAMPLE_PCSC_DETECT);
    const ExampleCardPCSCResult opened = example_card_pcsc_open(&state, &options);
    const int expected = failure == 0 || failure > 5;
    munit_assert_int(opened, ==, expected ? EXAMPLE_PCSC_OPENED : EXAMPLE_PCSC_FAILED);
    if (expected) {
      munit_assert_string_equal(connected_reader, "synthetic reader");
      munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_FAILED);
      munit_assert_int(example_card_pcsc_close(&state), ==, failure == 0);
    }
    munit_assert_uint(ended, ==, expected ? 1 : 0);
    munit_assert_uint(disconnected, ==, failure >= 1 && failure <= 4 ? 0 : 1);
    munit_assert_uint(released, ==, failure == 1 ? 0 : 1);
    munit_assert_memory_equal(sizeof state, &state, &zero);
  }
  reset();
  selected_protocol = 99;
  ExampleCardPCSC state = {0};
  const ExampleCardPCSCOptions options = options_for("synthetic", EXAMPLE_PCSC_DETECT);
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_FAILED);
  munit_assert_uint(disconnected, ==, 1);
  munit_assert_uint(released, ==, 1);
  selected_protocol = SCARD_PROTOCOL_T1;
  munit_assert_int(example_card_pcsc_open(&state, NULL), ==, EXAMPLE_PCSC_FAILED);
  const ExampleCardPCSCOptions empty = options_for("", EXAMPLE_PCSC_DETECT);
  munit_assert_int(example_card_pcsc_open(&state, &empty), ==, EXAMPLE_PCSC_FAILED);
  munit_assert_int(example_card_pcsc_open(NULL, &options), ==, EXAMPLE_PCSC_FAILED);
  return MUNIT_OK;
}

/* The filter names exactly one reader by substring. No match and several
 * matches connect to nothing. */
TC_TEST(reader_filter)
{
  ExampleCardPCSC state = {0};
  reset();
  READERS("ACS ACR1552 1S CL Reader PICC\0ACS ACR1552 1S CL Reader SAM\0");
  ExampleCardPCSCOptions options = options_for("ACR1552", EXAMPLE_PCSC_DETECT);
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_AMBIGUOUS);
  options.reader = "Omnikey";
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_NO_READER);
  munit_assert_uint(connects, ==, 0);
  munit_assert_uint(status_reads, ==, 0);
  munit_assert_uint(released, ==, 2);
  options.reader = "PICC";
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_string_equal(connected_reader, "ACS ACR1552 1S CL Reader PICC");
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  /* No readers at all. */
  reset();
  READERS("\0");
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_NO_READER);
  munit_assert_uint(connects, ==, 0);
  /* A card-less reader connects to nothing. */
  reset();
  card_state = 0;
  options.reader = "synthetic";
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_NO_CARD);
  munit_assert_uint(connects, ==, 0);
  return MUNIT_OK;
}

/* Yubico readers and YubiKey ATRs are refused before any connect, in any
 * letter case. */
TC_TEST(yubico)
{
  static const char* const filters[] = {"Yubico", "yubikey", "U2F"};
  ExampleCardPCSC state = {0};
  for (size_t i = 0; i < sizeof filters / sizeof *filters; ++i) {
    reset();
    READERS("ACS ACR1552 1S CL Reader PICC\0Yubico Yubikey 4 U2F+CCID\0");
    const ExampleCardPCSCOptions options = options_for(filters[i], EXAMPLE_PCSC_DETECT);
    munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_REFUSED);
    munit_assert_uint(connects, ==, 0);
    munit_assert_uint(status_reads, ==, 0);
  }
  reset();
  READERS("Generic YUBIKEY reader\0");
  ExampleCardPCSCOptions options = options_for("Generic", EXAMPLE_PCSC_DETECT);
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_REFUSED);
  munit_assert_uint(connects, ==, 0);
  /* A reader with a neutral name holding a YubiKey. */
  const uint8_t* const atrs[] = {yubikey_atr, yubikey_nfc_atr};
  const size_t lengths[] = {sizeof yubikey_atr, sizeof yubikey_nfc_atr};
  for (size_t i = 0; i < 2; ++i) {
    reset();
    atr_set(atrs[i], lengths[i]);
    options.reader = "synthetic";
    munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_REFUSED);
    munit_assert_uint(status_reads, ==, 1);
    munit_assert_uint(connects, ==, 0);
    munit_assert_uint(released, ==, 1);
  }
  return MUNIT_OK;
}

/* A contactless ATR refuses a contact request, and detection reports the
 * interface the ATR shows. */
TC_TEST(interface)
{
  ExampleCardPCSC state = {0};
  reset();
  ATR(contactless_atr);
  ExampleCardPCSCOptions options = options_for("synthetic", EXAMPLE_PCSC_CONTACT);
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_INTERFACE);
  munit_assert_uint(connects, ==, 0);
  options.interface = EXAMPLE_PCSC_DETECT;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_int(example_card_pcsc_interface(&state), ==, TC_PIV_CONTACTLESS);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  options.interface = EXAMPLE_PCSC_CONTACTLESS;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_int(example_card_pcsc_interface(&state), ==, TC_PIV_CONTACTLESS);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  /* A contact ATR takes either request. Contactless keeps the stricter
   * library rules. */
  reset();
  options.interface = EXAMPLE_PCSC_DETECT;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_int(example_card_pcsc_interface(&state), ==, TC_PIV_CONTACT);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  options.interface = EXAMPLE_PCSC_CONTACTLESS;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_int(example_card_pcsc_interface(&state), ==, TC_PIV_CONTACTLESS);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  options.interface = (ExampleCardPCSCInterface)7;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_FAILED);
  return MUNIT_OK;
}

TC_TEST(transport)
{
  const uint8_t command[] = {0, 0x20, 0, 0x80};
  for (unsigned protocol = SCARD_PROTOCOL_T0; protocol <= SCARD_PROTOCOL_T1; ++protocol) {
    ExampleCardPCSC state = {0};
    uint8_t response[8], zero[8] = {0};
    size_t length = SIZE_MAX;
    reset();
    selected_protocol = protocol;
    const ExampleCardPCSCOptions options = options_for("synthetic", EXAMPLE_PCSC_DETECT);
    munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
    const TC_bytes wire = {command, sizeof command};
    const TC_buffer buffer = {response, sizeof response};
    munit_assert_int(example_card_pcsc_transmit(&state, wire, buffer, &length), ==, TC_OK);
    munit_assert_size(length, ==, 2);
    fail_call = calls + 1;
    length = SIZE_MAX;
    munit_assert_int(example_card_pcsc_transmit(&state, wire, buffer, &length), ==, TC_ERROR);
    munit_assert_size(length, ==, SIZE_MAX);
    munit_assert_memory_equal(sizeof response, response, zero);
    munit_assert_int(example_card_pcsc_transmit(&state, wire, buffer, &length), ==, TC_ERROR);
    munit_assert_uint(transfers, ==, 2);
    munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  }
  return MUNIT_OK;
}

/* The guard sees every command before transmission and every answer after
 * it. A refused command never reaches the reader and stops the connection. */
static struct {
  unsigned checks, observed, allow, connected;
  TC_PIV_interface interface;
  uint8_t last_answer[2];
} guard_log;
static int guard_check(void* context, TC_bytes command)
{
  munit_assert_ptr_equal(context, &guard_log);
  munit_assert_size(command.length, ==, 4);
  ++guard_log.checks;
  return guard_log.checks <= guard_log.allow;
}
static void guard_observe(void* context, TC_bytes command, TC_bytes answer)
{
  munit_assert_ptr_equal(context, &guard_log);
  munit_assert_size(command.length, ==, 4);
  munit_assert_size(answer.length, ==, 2);
  memcpy(guard_log.last_answer, answer.data, 2);
  ++guard_log.observed;
}

/* The guard learns the interface once the reader connected, before any
 * command. */
static void guard_connected(void* context, TC_PIV_interface interface)
{
  munit_assert_ptr_equal(context, &guard_log);
  munit_assert_uint(guard_log.checks, ==, 0);
  munit_assert_uint(connects, ==, 1);
  guard_log.interface = interface;
  ++guard_log.connected;
}

TC_TEST(guard)
{
  const uint8_t command[] = {0, 0x20, 0, 0x80};
  const ExampleCardPCSCGuard guard = {guard_check, guard_observe, &guard_log, NULL};
  ExampleCardPCSC state = {0};
  uint8_t response[8], zero[8] = {0};
  size_t length = SIZE_MAX;
  reset();
  memset(&guard_log, 0, sizeof guard_log);
  guard_log.allow = 1;
  ExampleCardPCSCOptions options = options_for("synthetic", EXAMPLE_PCSC_DETECT);
  options.guard = &guard;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  const TC_bytes wire = {command, sizeof command};
  const TC_buffer buffer = {response, sizeof response};
  munit_assert_int(example_card_pcsc_transmit(&state, wire, buffer, &length), ==, TC_OK);
  munit_assert_uint(guard_log.observed, ==, 1);
  munit_assert_uint8(guard_log.last_answer[0], ==, 0x90);
  memset(response, 0xa5, sizeof response);
  length = SIZE_MAX;
  munit_assert_int(example_card_pcsc_transmit(&state, wire, buffer, &length), ==, TC_ERROR);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof response, response, zero);
  munit_assert_uint(transfers, ==, 1);
  munit_assert_uint(guard_log.checks, ==, 2);
  /* The connection stays stopped, without asking the guard again. */
  munit_assert_int(example_card_pcsc_transmit(&state, wire, buffer, &length), ==, TC_ERROR);
  munit_assert_uint(guard_log.checks, ==, 2);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  munit_assert_uint(guard_log.connected, ==, 0);
  /* The connected callback reports the interface the ATR shows. */
  const ExampleCardPCSCGuard informed = {guard_check, guard_observe, &guard_log, guard_connected};
  reset();
  ATR(contactless_atr);
  memset(&guard_log, 0, sizeof guard_log);
  guard_log.interface = TC_PIV_CONTACT;
  options.guard = &informed;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_uint(guard_log.connected, ==, 1);
  munit_assert_int(guard_log.interface, ==, TC_PIV_CONTACTLESS);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  /* A refused open never reports a connection. */
  reset();
  memset(&guard_log, 0, sizeof guard_log);
  READERS("Yubico YubiKey 4\0");
  const ExampleCardPCSCOptions yubico = {"Yubi", EXAMPLE_PCSC_DETECT, &informed};
  munit_assert_int(example_card_pcsc_open(&state, &yubico), ==, EXAMPLE_PCSC_REFUSED);
  munit_assert_uint(guard_log.connected, ==, 0);
  /* A guard without its check is an argument error. */
  const ExampleCardPCSCGuard broken = {NULL, guard_observe, &guard_log, NULL};
  options.guard = &broken;
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_FAILED);
  munit_assert_uint(connects, ==, 0);
  return MUNIT_OK;
}

/* A connection marked for reset disconnects with SCARD_RESET_CARD, which
 * clears the card's PIN status. */
TC_TEST(reset_on_close)
{
  ExampleCardPCSC state = {0};
  reset();
  const ExampleCardPCSCOptions options = options_for("synthetic", EXAMPLE_PCSC_DETECT);
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  munit_assert_uint(disposition, ==, SCARD_LEAVE_CARD);
  munit_assert_int(example_card_pcsc_open(&state, &options), ==, EXAMPLE_PCSC_OPENED);
  example_card_pcsc_reset_on_close(&state);
  munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  munit_assert_uint(disposition, ==, SCARD_RESET_CARD);
  example_card_pcsc_reset_on_close(NULL);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/lifecycle", lifecycle, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/reader-filter", reader_filter, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/yubico", yubico, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/interface", interface, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/transport", transport, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/guard", guard, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/reset-on-close", reset_on_close, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/twic/pcsc", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
