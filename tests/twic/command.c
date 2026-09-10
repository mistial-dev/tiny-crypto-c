/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_pcsc.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>
#include <sys/resource.h>

int example_credential_main(int argc, char** argv);
static int protection_failure, open_failure, close_failure, bad_identity, bad_object;
static unsigned absent, absent_objects, fail_transfer, transfers, opens, closes, locks, unlocks;
static int protected_memory, selected, certificate_case, unsigned_option, unsigned_chuid;
static void* held_buffer;
static size_t held_capacity;

int example_test_setrlimit(int resource, const struct rlimit* limit)
{
  munit_assert_int(resource, ==, RLIMIT_CORE);
  munit_assert_uint(limit->rlim_cur, ==, 0); munit_assert_uint(limit->rlim_max, ==, 0);
  protected_memory = protection_failure != 1;
  return protected_memory ? 0 : -1;
}
int example_test_mlock(const void* buffer, size_t capacity)
{
  munit_assert_int(protected_memory, ==, 1);
  ++locks; held_buffer = (void*)buffer; held_capacity = capacity;
  return protection_failure == 2 ? -1 : 0;
}
int example_test_munlock(const void* buffer, size_t capacity)
{
  munit_assert_ptr_equal(buffer,held_buffer); munit_assert_size(capacity, ==, held_capacity);
  for (size_t i = 0; i < capacity; ++i) munit_assert_uint(((const uint8_t*)buffer)[i], ==, 0);
  ++unlocks; return 0;
}
int example_card_pcsc_open(ExampleCardPCSC* state, const char* reader)
{
  munit_assert_int(protected_memory, ==, 1); munit_assert_uint(locks, ==, 1);
  munit_assert_string_equal(reader,"synthetic reader");
  ++opens; state->transaction = !open_failure; return !open_failure;
}
int example_card_pcsc_close(ExampleCardPCSC* state)
{ ++closes; state->transaction = 0; return !close_failure; }
int example_card_pcsc_transmit(void* context, const uint8_t* command,
    size_t length, uint8_t* response, size_t capacity, size_t* out)
{
  ExampleCardPCSC* state = context;
  munit_assert_int(state->transaction, ==, 1);
  ++transfers;
  if (transfers == fail_transfer) return 0;
  munit_assert_size(capacity, >=, 17);
  if (command[1] == 0xa4) {
    munit_assert_size(length, ==, 15);
    selected = command[9] == 0x67 ? EXAMPLE_CARD_TWIC : EXAMPLE_CARD_PIV;
    if (absent & (1u << selected)) {
      response[0] = 0x6a; response[1] = 0x82; *out = 2; return 1;
    }
    response[0] = 0x61; response[1] = 13; response[2] = 0x4f; response[3] = 11;
    memcpy(response + 4,command + 5,9);
    response[13] = bad_identity ? 99 : 1;
    response[14] = selected == EXAMPLE_CARD_TWIC ? 3 : 0;
    response[15] = 0x90; response[16] = 0; *out = 17;
  } else {
    munit_assert_uint(command[1], ==, 0xcb); munit_assert_size(length, ==, 11);
    munit_assert_uint(command[7], ==, 0x5f); munit_assert_uint(command[8], ==, 0xc1);
    munit_assert_true(command[9] == 1 || command[9] == 2);
    if (absent_objects & (1u << (command[9] - 1))) {
      response[0] = 0x6a; response[1] = 0x88; *out = 2; return 1;
    }
    if (command[9] == 1) {
      /* tools/pki_fixtures.py certificate(); signature is a placeholder. */
      static const char plain[] =
        "308191307ca003020102020101300d06092a864886f70d01010b050030123110300e06035504030c074578616d706c65"
        "301e170d3234303130313030303030305a170d3330303130313030303030305a30123110300e06035504030c074578"
        "616d706c65301b300d06092a864886f70d0101010500030a00300702020ca1020111300d06092a864886f70d01010b050003020001";
      static const char compressed[] =
        "1f8b08000000000002ff33689c6850b380998991898991d180978d53abcda3ed3b2f2323372b838190a180011f1b73"
        "280b330fbb6b45626e414eaa819c38af918981211082419438afb1011217ab1e69648319591998b9180cd899987816"
        "32310aa2d9c9ccc4c0080028a0d93c94000000";
      uint8_t encoded[192];
      int gzip = certificate_case == 1 || certificate_case == 2;
      size_t encoded_length = tc_test_decode_hex(gzip ? compressed : plain,encoded,sizeof encoded);
      munit_assert_size(encoded_length, >, 0);
      if (certificate_case == 2) encoded[encoded_length - 8] ^= 1;
      if (certificate_case == 3) encoded[4] -= 1; /* Shorten TBSCertificate. */
      if (certificate_case == 5) { encoded[0] = 0x30; encoded[1] = 0; encoded_length = 2; }
      size_t bytes = 3;
      response[0] = 0x53; response[1] = 0x81;
      response[bytes++] = 0x70;
      if (encoded_length >= 128) response[bytes++] = 0x81;
      response[bytes++] = (uint8_t)encoded_length;
      memcpy(response + bytes,encoded,encoded_length); bytes += encoded_length;
      response[bytes++] = 0x71; response[bytes++] = 1;
      response[bytes++] = certificate_case == 4 ? 2 : (uint8_t)gzip;
      if (selected == EXAMPLE_CARD_PIV) { response[bytes++] = 0xfe; response[bytes++] = 0; }
      response[2] = (uint8_t)(bytes - 3);
      response[bytes] = 0x90; response[bytes + 1] = 0; *out = bytes + 2;
      return 1;
    }
    size_t bytes = 2;
    response[0] = bad_object ? 0x54 : 0x53;
    response[bytes++] = 0x30; response[bytes++] = 25;
    for (unsigned i = 0; i < 25; ++i) response[bytes++] = (uint8_t)i;
    response[bytes++] = 0x34; response[bytes++] = 16;
    for (unsigned i = 0; i < 16; ++i) response[bytes++] = (uint8_t)(i + 32);
    response[bytes++] = 0x35; response[bytes++] = 8;
    memcpy(response + bytes,"20300101",8); bytes += 8;
    if (!(unsigned_chuid & (1 << selected))) {
      response[bytes++] = 0x3e; response[bytes++] = 2;
      response[bytes++] = 0x30; response[bytes++] = 0; /* CMS placeholder. */
    }
    response[bytes++] = 0xfe; response[bytes++] = 0;
    response[1] = (uint8_t)(bytes - 2);
    response[bytes++] = 0x90; response[bytes++] = 0; *out = bytes;
  }
  return 1;
}
static void reset(void)
{
  protection_failure = open_failure = close_failure = bad_identity = bad_object = 0;
  absent = absent_objects = fail_transfer = transfers = opens = closes = locks = unlocks = 0;
  protected_memory = certificate_case = 0; held_buffer = NULL; held_capacity = 0;
  unsigned_option = unsigned_chuid = 0;
}
static int run(void)
{
  char program[] = "credential_check", option[] = "--reader", reader[] = "synthetic reader";
  char policy[] = "--twic-unsigned-chuid";
  char* args[] = {program,option,reader,policy,NULL};
  if (!unsigned_option) args[3] = NULL;
  return example_credential_main(unsigned_option ? 4 : 3,args);
}
static MunitResult workflow(const MunitParameter params[], void* context)
{
  for (unsigned mask = 0; mask < 4; ++mask) {
    reset(); absent = mask;
    munit_assert_int(run(), ==, mask == 3 ? 1 : 0);
    munit_assert_uint(transfers, ==, 6 - 2 * ((mask & 1) + ((mask >> 1) & 1)));
    munit_assert_uint(closes, ==, 1); munit_assert_uint(unlocks, ==, 1);
  }
  for (unsigned failure = 1; failure <= 6; ++failure) {
    reset(); fail_transfer = failure;
    munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, failure);
    munit_assert_uint(closes, ==, 1); munit_assert_uint(unlocks, ==, 1);
  }
  for (unsigned mask = 1; mask < 4; ++mask) {
    reset(); absent_objects = mask;
    munit_assert_int(run(), ==, 0); munit_assert_uint(transfers, ==, 6);
    munit_assert_uint(closes, ==, 1); munit_assert_uint(unlocks, ==, 1);
  }
  reset(); bad_identity = 1;
  munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, 1);
  reset(); bad_object = 1;
  munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, 2);
  reset(); close_failure = 1;
  munit_assert_int(run(), ==, 1); munit_assert_uint(unlocks, ==, 1);
  for (int fixture = 1; fixture <= 5; ++fixture) {
    reset(); certificate_case = fixture;
    munit_assert_int(run(), ==, fixture == 1 ? 0 : 1);
    munit_assert_uint(transfers, ==, fixture == 1 ? 6 : 3);
    munit_assert_uint(unlocks, ==, 1);
  }
  reset(); unsigned_chuid = 1 << EXAMPLE_CARD_TWIC;
  munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, 2);
  reset(); unsigned_chuid = 1 << EXAMPLE_CARD_TWIC; unsigned_option = 1;
  munit_assert_int(run(), ==, 0); munit_assert_uint(transfers, ==, 6);
  reset(); unsigned_option = 1;
  munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, 2);
  reset(); unsigned_chuid = (1 << EXAMPLE_CARD_PIV) | (1 << EXAMPLE_CARD_TWIC); unsigned_option = 1;
  munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, 5);
  (void)params; (void)context; return MUNIT_OK;
}
static MunitResult protection(const MunitParameter params[], void* context)
{
  for (int failure = 1; failure <= 2; ++failure) {
    reset(); protection_failure = failure;
    munit_assert_int(run(), ==, 1); munit_assert_uint(opens, ==, 0);
    munit_assert_uint(transfers, ==, 0); munit_assert_uint(unlocks, ==, 0);
  }
  reset(); open_failure = 1;
  munit_assert_int(run(), ==, 1); munit_assert_uint(transfers, ==, 0);
  munit_assert_uint(closes, ==, 1); munit_assert_uint(unlocks, ==, 1);
  (void)params; (void)context; return MUNIT_OK;
}
int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/workflow",workflow,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/protection",protection,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/twic/command",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
