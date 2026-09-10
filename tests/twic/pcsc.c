/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_pcsc.h"
#include "munit.h"
#include <string.h>

/* These entry points replace the platform service for lifecycle tests. */
SCARD_IO_REQUEST g_rgSCardT0Pci, g_rgSCardT1Pci, g_rgSCardRawPci;
static unsigned calls, fail_call, released, disconnected, ended, transfers;
static uint32_t selected_protocol = SCARD_PROTOCOL_T1;
static int32_t outcome(void) { return ++calls == fail_call ? -1 : SCARD_S_SUCCESS; }
int32_t SCardEstablishContext(uint32_t scope, const void* a, const void* b, LPSCARDCONTEXT out)
{
  munit_assert_uint(scope, ==, SCARD_SCOPE_SYSTEM);
  munit_assert_null(a); munit_assert_null(b);
  *out = 1; return outcome();
}
int32_t SCardConnect(SCARDCONTEXT context, const char* reader, uint32_t sharing,
    uint32_t protocols, LPSCARDHANDLE card, uint32_t* protocol)
{
  munit_assert_int(context, ==, 1); munit_assert_string_equal(reader,"synthetic reader");
  munit_assert_uint(sharing, ==, SCARD_SHARE_EXCLUSIVE);
  munit_assert_uint(protocols, ==, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);
  *card = 2; *protocol = selected_protocol; return outcome();
}
int32_t SCardBeginTransaction(SCARDHANDLE card)
{ munit_assert_int(card, ==, 2); return outcome(); }
int32_t SCardEndTransaction(SCARDHANDLE card, uint32_t disposition)
{
  munit_assert_int(card, ==, 2); munit_assert_uint(disposition, ==, SCARD_LEAVE_CARD);
  ++ended; return outcome();
}
int32_t SCardDisconnect(SCARDHANDLE card, uint32_t disposition)
{
  munit_assert_int(card, ==, 2); munit_assert_uint(disposition, ==, SCARD_LEAVE_CARD);
  ++disconnected; return outcome();
}
int32_t SCardReleaseContext(SCARDCONTEXT context)
{ munit_assert_int(context, ==, 1); ++released; return outcome(); }
int32_t SCardTransmit(SCARDHANDLE card, LPCSCARD_IO_REQUEST protocol,
    const unsigned char* command, uint32_t length, LPSCARD_IO_REQUEST receive_protocol,
    unsigned char* response, uint32_t* capacity)
{
  munit_assert_int(card, ==, 2);
  munit_assert_ptr_equal(protocol,selected_protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1);
  munit_assert_null(receive_protocol); munit_assert_not_null(command);
  munit_assert_uint(length, ==, 4); munit_assert_uint(*capacity, >=, 2);
  response[0] = 0x90; response[1] = 0; *capacity = 2;
  ++transfers; return outcome();
}
static void reset(void)
{ calls = fail_call = released = disconnected = ended = transfers = 0; }

static MunitResult lifecycle(const MunitParameter params[], void* context)
{
  for (unsigned failure = 0; failure <= 6; ++failure) {
    ExampleCardPCSC state = {0}, zero = {0};
    reset(); fail_call = failure;
    const int opened = example_card_pcsc_open(&state,"synthetic reader");
    munit_assert_int(opened, ==, failure == 0 || failure > 3);
    if (opened) {
      munit_assert_int(example_card_pcsc_open(&state,"synthetic reader"), ==, 0);
      munit_assert_int(example_card_pcsc_close(&state), ==, failure == 0);
    }
    munit_assert_uint(ended, ==, opened ? 1 : 0);
    munit_assert_uint(disconnected, ==, failure == 1 || failure == 2 ? 0 : 1);
    munit_assert_uint(released, ==, failure == 1 ? 0 : 1);
    munit_assert_memory_equal(sizeof state,&state,&zero);
  }
  reset(); selected_protocol = 99;
  ExampleCardPCSC state = {0};
  munit_assert_int(example_card_pcsc_open(&state,"synthetic reader"), ==, 0);
  munit_assert_uint(disconnected, ==, 1); munit_assert_uint(released, ==, 1);
  selected_protocol = SCARD_PROTOCOL_T1;
  (void)params; (void)context; return MUNIT_OK;
}
static MunitResult transport(const MunitParameter params[], void* context)
{
  const uint8_t command[] = {0,0x20,0,0x80};
  for (unsigned protocol = SCARD_PROTOCOL_T0; protocol <= SCARD_PROTOCOL_T1; ++protocol) {
    ExampleCardPCSC state = {0};
    uint8_t response[8], zero[8] = {0}; size_t length = SIZE_MAX;
    reset(); selected_protocol = protocol;
    munit_assert_int(example_card_pcsc_open(&state,"synthetic reader"), ==, 1);
    munit_assert_int(example_card_pcsc_transmit(&state,command,sizeof command,response,sizeof response,&length), ==, 1);
    munit_assert_size(length, ==, 2);
    fail_call = calls + 1; length = SIZE_MAX;
    munit_assert_int(example_card_pcsc_transmit(&state,command,sizeof command,response,sizeof response,&length), ==, 0);
    munit_assert_size(length, ==, SIZE_MAX);
    munit_assert_memory_equal(sizeof response,response,zero);
    munit_assert_int(example_card_pcsc_transmit(&state,command,sizeof command,response,sizeof response,&length), ==, 0);
    munit_assert_uint(transfers, ==, 2);
    munit_assert_int(example_card_pcsc_close(&state), ==, 1);
  }
  (void)params; (void)context; return MUNIT_OK;
}
int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/lifecycle",lifecycle,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/transport",transport,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/twic/pcsc",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
