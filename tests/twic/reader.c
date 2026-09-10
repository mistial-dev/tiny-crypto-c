/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_io.h"
#include "munit.h"
#include <string.h>

typedef struct {
  uint8_t command[16], response[16];
  size_t command_length, response_length;
  int success;
} Exchange;
typedef struct { const Exchange* steps; size_t count, next; } Script;
static int transmit(void* context, const uint8_t* command, size_t command_length,
    uint8_t* response, size_t capacity, size_t* length)
{
  Script* script = context;
  munit_assert_size(script->next, <, script->count);
  const Exchange* step = &script->steps[script->next++];
  munit_assert_size(command_length, ==, step->command_length);
  munit_assert_memory_equal(command_length,command,step->command);
  if (!step->success) return 0;
  if (step->response_length <= sizeof step->response) {
    munit_assert_size(step->response_length, <=, capacity);
    memcpy(response,step->response,step->response_length);
  }
  *length = step->response_length;
  return 1;
}

typedef struct {
  unsigned next, absent, failure;
  ExampleCardModel model;
  uint16_t status;
} InventoryScript;

static int inventory_transmit(void* context, const uint8_t* command, size_t length,
    uint8_t* response, size_t capacity, size_t* out)
{
  InventoryScript* script = context;
  const unsigned call = script->next++;
  if (call == script->failure) return 0;
  munit_assert_size(capacity, >=, 17);
  if (!call) {
    munit_assert_size(length, ==, 15);
    munit_assert_uint(command[1], ==, 0xa4);
    response[0] = 0x61; response[1] = 13; response[2] = 0x4f; response[3] = 11;
    memcpy(response + 4,command + 5,9);
    response[13] = 1;
    response[14] = script->model == EXAMPLE_CARD_MODEL_TWIC_LEGACY ? 1 : 3;
    response[15] = 0x90; response[16] = 0; *out = 17;
    return 1;
  }
  static const uint8_t tags[][3] = {
    {0x5f,0xc1,2},{0x5f,0xc1,4},{0xdf,0xc1,3},{0xdf,0xc1,8},
    {0xdf,0xc1,9},{0xdf,0xc1,0x21},{0xdf,0xc0,1},{0xdf,0xc0,2},{0xdf,0xc1,0x0f}
  };
  const unsigned index = script->model == EXAMPLE_CARD_MODEL_TWIC_LEGACY && call == 4 ? 8 : call - 1;
  munit_assert_uint(index, <, 9);
  munit_assert_size(length, ==, 11);
  munit_assert_uint(command[1], ==, 0xcb);
  munit_assert_memory_equal(3,command + 7,tags[index]);
  if (script->absent & (1u << index)) {
    response[0] = (uint8_t)(script->status >> 8); response[1] = (uint8_t)script->status;
    *out = 2; return 1;
  }
  const uint8_t bytes[] = {0x53,3,0xbc,1,(uint8_t)index,0x90,0};
  memcpy(response,bytes,sizeof bytes); *out = sizeof bytes;
  return 1;
}

static MunitResult inventory(const MunitParameter params[], void* context)
{
  uint8_t pool[2048];
  ExampleTWICInventory out, preserved;
  memset(&preserved,0xa5,sizeof preserved);
  for (unsigned model = 0; model < 2; ++model) {
    const ExampleCardModel selected = model ? EXAMPLE_CARD_MODEL_TWIC_NEXGEN : EXAMPLE_CARD_MODEL_TWIC_LEGACY;
    for (unsigned absent = 0; absent < 8; ++absent) {
      InventoryScript script = {0,absent << 5,99,selected,0x6a82};
      ExampleCardIO io = {inventory_transmit,&script,20,0};
      size_t work = 1000;
      munit_assert_int(example_twic_inventory_read(&io,selected,EXAMPLE_CARD_READ_SHORT,pool,sizeof pool,512,&work,&out), ==, EXAMPLE_CARD_OK);
      unsigned optional = 0;
      for (unsigned i = 0; i < 3; ++i) if (!(absent & (1u << i))) ++optional;
      munit_assert_size(out.count, ==, model ? 5 + optional : 3);
      munit_assert_uint(script.next, ==, model ? 10 : 5);
      munit_assert_int(io.stopped, ==, 0);
      munit_assert_size(out.security.length, ==, 5);
      for (size_t i = 0; i < out.count; ++i) {
        munit_assert_true(out.objects[i].contents.data >= pool);
        munit_assert_true(out.objects[i].contents.data + out.objects[i].contents.length <= pool + sizeof pool);
        munit_assert_size(out.objects[i].contents.length, ==, 3);
        munit_assert_uint(out.objects[i].contents.data[0], ==, 0xbc);
      }
    }
  }
  for (unsigned failure = 0; failure < 10; ++failure) {
    InventoryScript script = {0,0,failure,EXAMPLE_CARD_MODEL_TWIC_NEXGEN,0x6a82};
    ExampleCardIO io = {inventory_transmit,&script,20,0};
    size_t work = 1000; out = preserved; memset(pool,0xa5,sizeof pool);
    munit_assert_int(example_twic_inventory_read(&io,script.model,EXAMPLE_CARD_READ_SHORT,pool,sizeof pool,512,&work,&out), ==, EXAMPLE_CARD_TRANSPORT);
    munit_assert_memory_equal(sizeof out,&out,&preserved);
    for (size_t i = 0; i < sizeof pool; ++i) munit_assert_uint(pool[i], ==, 0);
    munit_assert_int(io.stopped, ==, 1);
  }
  /* 15 SELECT bytes plus nine five-byte object responses. */
  enum { REQUIRED_WORK = 15 + 9 * 5 };
  for (size_t budget = 0; budget <= REQUIRED_WORK; ++budget) {
    InventoryScript script = {0,0,99,EXAMPLE_CARD_MODEL_TWIC_NEXGEN,0x6a82};
    ExampleCardIO io = {inventory_transmit,&script,20,0};
    size_t work = budget; out = preserved;
    munit_assert_int(example_twic_inventory_read(&io,script.model,EXAMPLE_CARD_READ_SHORT,pool,sizeof pool,512,&work,&out), ==,
        budget == REQUIRED_WORK ? EXAMPLE_CARD_OK : EXAMPLE_CARD_LIMIT);
    if (budget < REQUIRED_WORK) {
      munit_assert_memory_equal(sizeof out,&out,&preserved);
      for (size_t i = 0; i < sizeof pool; ++i) munit_assert_uint(pool[i], ==, 0);
    }
  }
  for (unsigned optional = 0; optional < 2; ++optional) {
    InventoryScript script = {0,1u << (optional ? 5 : 0),99,EXAMPLE_CARD_MODEL_TWIC_NEXGEN,
      optional ? 0x6982 : 0x6a82};
    ExampleCardIO io = {inventory_transmit,&script,20,0};
    size_t work = 1000; out = preserved;
    munit_assert_int(example_twic_inventory_read(&io,script.model,EXAMPLE_CARD_READ_SHORT,pool,sizeof pool,512,&work,&out), ==, EXAMPLE_CARD_STATUS);
    munit_assert_memory_equal(sizeof out,&out,&preserved);
    munit_assert_int(io.stopped, ==, 1);
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult responses(const MunitParameter params[], void* context)
{
  static const Exchange steps[] = {
    {{0,0xcb,0x3f,0xff,5,0x5c,3,0x5f,0xc1,2,0xff},{0x6c,4},11,2,1},
    {{0,0xcb,0x3f,0xff,5,0x5c,3,0x5f,0xc1,2,4},{0x53,4,0x61,4},11,4,1},
    {{0,0xc0,0,0,4},{1,2,3,4,0x90,0},5,6,1}
  };
  Script script = {steps,3,0};
  ExampleCardIO io = {transmit,&script,3,0};
  uint8_t buffer[300];
  const uint8_t tag[] = {0x5f,0xc1,2}, expected[] = {0x53,4,1,2,3,4};
  ExampleCardResponse out = {SIZE_MAX,0};
  munit_assert_int(example_card_read(&io,tag,sizeof tag,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_OK);
  munit_assert_size(out.length, ==, sizeof expected);
  munit_assert_uint(out.status, ==, 0x9000);
  munit_assert_memory_equal(out.length,buffer,expected);
  munit_assert_uint(buffer[out.length], ==, 0);
  munit_assert_uint(buffer[out.length + 1], ==, 0);
  munit_assert_size(io.exchanges_left, ==, 0);
  munit_assert_int(io.stopped, ==, 0);
  munit_assert_size(script.next, ==, 3);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult extended_responses(const MunitParameter params[], void* context)
{
  static const Exchange steps[] = {
    {{0,0xcb,0x3f,0xff,0,0,5,0x5c,3,0x5f,0xc1,2,1,0x2a},
     {0x53,2,1,2,0x62,0x82},14,6,1},
    {{0,0xcb,0x3f,0xff,0,0,5,0x5c,3,0x5f,0xc1,2,1,0x2a},
     {0x53,2,0x61,2},14,4,1},
    {{0,0xc0,0,0,2},{0x6c,4},5,2,1},
    {{0,0xc0,0,0,4},{1,2,0x90,0},5,4,1}
  };
  Script script = {steps,4,0};
  ExampleCardIO io = {transmit,&script,4,0};
  uint8_t buffer[300];
  const uint8_t tag[] = {0x5f,0xc1,2}, expected[] = {0x53,2,1,2};
  ExampleCardResponse out = {SIZE_MAX,0};
  munit_assert_int(example_card_read_extended(&io,tag,sizeof tag,buffer,sizeof buffer,&out),
      ==, EXAMPLE_CARD_STATUS);
  munit_assert_uint(out.status, ==, 0x6282);
  munit_assert_size(out.length, ==, sizeof expected);
  munit_assert_memory_equal(out.length,buffer,expected);
  munit_assert_int(example_card_read_extended(&io,tag,sizeof tag,buffer,sizeof buffer,&out),
      ==, EXAMPLE_CARD_OK);
  munit_assert_size(out.length, ==, sizeof expected);
  munit_assert_memory_equal(out.length,buffer,expected);
  munit_assert_uint(buffer[out.length], ==, 0);
  munit_assert_uint(buffer[out.length + 1], ==, 0);
  munit_assert_size(script.next, ==, 4);
  munit_assert_int(io.stopped, ==, 0);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult extended_maximum(const MunitParameter params[], void* context)
{
  static const Exchange steps[] = {
    {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,0xff,0xff},{0x53,0,0x62,0x82},12,4,1}
  };
  static uint8_t buffer[UINT16_MAX + EXAMPLE_CARD_STATUS_BYTES + 1];
  const uint8_t tag = 0x53;
  Script script = {steps,1,0};
  ExampleCardIO io = {transmit,&script,1,0};
  ExampleCardResponse out;
  munit_assert_int(example_card_object_read(&io,EXAMPLE_CARD_READ_EXTENDED,&tag,1,
      buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_OK);
  munit_assert_size(out.length, ==, 2);
  munit_assert_uint(out.status, ==, 0x6282);
  munit_assert_size(script.next, ==, 1);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult extended_failures(const MunitParameter params[], void* context)
{
  static const Exchange steps[] = {
    {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,0,1},{0x6c,1},12,2,1},
    {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,0,1},{0x61,0},12,2,1},
    {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,0,1},{0},12,0,0},
    {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,0,1},{0},12,1000,1},
    {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,0,1},{0x90},12,1,1}
  };
  static const ExampleCardResult results[] = {EXAMPLE_CARD_PROTOCOL,EXAMPLE_CARD_LIMIT,
      EXAMPLE_CARD_TRANSPORT,EXAMPLE_CARD_PROTOCOL,EXAMPLE_CARD_PROTOCOL};
  const uint8_t tag = 0x53, zero[3] = {0};
  for (size_t i = 0; i < sizeof steps / sizeof *steps; ++i) {
    Script script = {steps + i,1,0};
    ExampleCardIO io = {transmit,&script,2,0};
    ExampleCardResponse out = {17,0x1234}, preserved = out;
    uint8_t buffer[3] = {1,2,3};
    munit_assert_int(example_card_read_extended(&io,&tag,1,buffer,sizeof buffer,&out),
        ==, results[i]);
    munit_assert_memory_equal(sizeof buffer,buffer,zero);
    munit_assert_memory_equal(sizeof out,&out,&preserved);
    munit_assert_int(io.stopped, ==, 1);
    munit_assert_size(script.next, ==, 1);
  }
  Script script = {NULL,0,0};
  ExampleCardIO io = {transmit,&script,1,0};
  uint8_t buffer[3] = {1,2,3};
  ExampleCardResponse out = {17,0x1234};
  munit_assert_int(example_card_read_extended(&io,&tag,1,buffer,2,&out),
      ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_int(example_card_read_extended(&io,&tag,0,buffer,3,&out),
      ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_int(example_card_read_extended(&io,&tag,1,NULL,3,&out),
      ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_size(script.next, ==, 0);
  munit_assert_int(io.stopped, ==, 0);
  munit_assert_uint(buffer[0], ==, 1);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult object_responses(const MunitParameter params[], void* context)
{
  static const uint8_t payloads[][8] = {
    {0x53,1,7,0x62,0x82}, {0x53,2,7,0x62,0x82},
    {0x53,1,7,0x90,0}, {0x53,2,7,0x90,0},
    {0x54,1,7,0x62,0x82}, {0x53,0,7,0x62,0x82},
    {0x69,0x82}
  };
  static const ExampleCardResult expected[] = {EXAMPLE_CARD_OK,EXAMPLE_CARD_PROTOCOL,
      EXAMPLE_CARD_OK,EXAMPLE_CARD_PROTOCOL,EXAMPLE_CARD_PROTOCOL,EXAMPLE_CARD_PROTOCOL,
      EXAMPLE_CARD_STATUS};
  const uint8_t tag = 0x53;
  for (size_t i = 0; i < sizeof expected / sizeof *expected; ++i) {
    Exchange step = {{0,0xcb,0x3f,0xff,0,0,3,0x5c,1,0x53,1,0x2a},{0},12,5,1};
    memcpy(step.response,payloads[i],sizeof payloads[i]);
    if (i == 6) step.response_length = 2;
    Script script = {&step,1,0};
    ExampleCardIO io = {transmit,&script,1,0};
    uint8_t buffer[300];
    memset(buffer,0xa5,sizeof buffer);
    ExampleCardResponse out = {17,0x1234}, preserved = out;
    munit_assert_int(example_card_object_read(&io,EXAMPLE_CARD_READ_EXTENDED,&tag,1,
        buffer,sizeof buffer,&out), ==, expected[i]);
    if (expected[i] == EXAMPLE_CARD_PROTOCOL) {
      munit_assert_int(io.stopped, ==, 1);
      munit_assert_memory_equal(sizeof out,&out,&preserved);
      for (size_t j = 0; j < sizeof buffer; ++j) munit_assert_uint(buffer[j], ==, 0);
    } else {
      munit_assert_int(io.stopped, ==, 0);
      munit_assert_uint(out.status, ==, i == 6 ? 0x6982 : i == 2 ? 0x9000 : 0x6282);
    }
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult selection(const MunitParameter params[], void* context)
{
  static const Exchange steps[] = {
    {{0,0xa4,4,0,9,0xa0,0,0,3,0x67,0x20,0,0,1,0xff},{0x6a,0x82},15,2,1},
    {{0,0xa4,4,0,9,0xa0,0,0,3,8,0,0,0x10,0,0},{0x90,0},15,2,1}
  };
  Script script = {steps,2,0};
  ExampleCardIO io = {transmit,&script,2,0};
  uint8_t buffer[300];
  ExampleCardResponse out;
  munit_assert_int(example_card_select(&io,EXAMPLE_CARD_TWIC,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_STATUS);
  munit_assert_uint(out.status, ==, 0x6a82);
  munit_assert_size(out.length, ==, 0);
  munit_assert_int(example_card_select(&io,EXAMPLE_CARD_PIV,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_OK);
  munit_assert_size(script.next, ==, 2);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult failures(const MunitParameter params[], void* context)
{
  const uint8_t tag = 0x7e;
  const Exchange cases[] = {
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{0},9,0,0},
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{0x90},9,1,1},
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{0},9,258,1},
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{1,0x6c,2},9,3,1},
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{0x61,0},9,2,1}
  };
  const ExampleCardResult expected[] = {EXAMPLE_CARD_TRANSPORT,EXAMPLE_CARD_PROTOCOL,
      EXAMPLE_CARD_PROTOCOL,EXAMPLE_CARD_PROTOCOL,EXAMPLE_CARD_LIMIT};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    Script script = {cases + i,1,0};
    ExampleCardIO io = {transmit,&script,1,0};
    ExampleCardResponse out = {SIZE_MAX,0x1234};
    uint8_t buffer[300], zeros[sizeof buffer] = {0};
    memset(buffer,0x5a,sizeof buffer);
    munit_assert_int(example_card_read(&io,&tag,1,buffer,sizeof buffer,&out), ==, expected[i]);
    munit_assert_size(out.length, ==, SIZE_MAX);
    munit_assert_uint(out.status, ==, 0x1234);
    munit_assert_memory_equal(sizeof buffer,buffer,zeros);
    munit_assert_int(io.stopped, ==, 1);
    munit_assert_int(example_card_read(&io,&tag,1,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_TRANSPORT);
    munit_assert_size(script.next, ==, 1);
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult limits(const MunitParameter params[], void* context)
{
  const uint8_t tag = 0x7e;
  const Exchange repeated[] = {
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{0x6c,1},9,2,1},
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,1},{0x6c,2},9,2,1}
  };
  const Exchange continued[] = {
    {{0,0xcb,0x3f,0xff,3,0x5c,1,0x7e,0xff},{0x61,0},9,2,1},
    {{0,0xc0,0,0,0},{0x90,0},5,2,1}
  };
  uint8_t buffer[258], zeros[sizeof buffer] = {0};
  ExampleCardResponse out = {SIZE_MAX,0x1234};
  Script script = {repeated,2,0};
  ExampleCardIO io = {transmit,&script,2,0};
  munit_assert_int(example_card_read(&io,&tag,1,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_PROTOCOL);
  munit_assert_size(script.next, ==, 2);
  munit_assert_size(out.length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof buffer,buffer,zeros);
  for (size_t capacity = 256; capacity <= sizeof buffer; ++capacity) {
    script.steps = continued; script.next = 0;
    io.exchanges_left = 2; io.stopped = 0;
    memset(buffer,0x5a,sizeof buffer);
    ExampleCardResult result = example_card_read(&io,&tag,1,buffer,capacity,&out);
    munit_assert_int(result, ==, capacity == sizeof buffer ? EXAMPLE_CARD_OK : EXAMPLE_CARD_LIMIT);
    munit_assert_size(script.next, ==, capacity - 256);
    if (result == EXAMPLE_CARD_LIMIT) {
      munit_assert_memory_equal(capacity,buffer,zeros);
      munit_assert_uint(buffer[capacity], ==, 0x5a);
    }
  }
  script.next = 0; io.exchanges_left = 2; io.stopped = 0;
  memset(buffer,0x5a,sizeof buffer);
  munit_assert_int(example_card_read(&io,&tag,0,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_int(example_card_select(&io,(ExampleCardApplication)99,buffer,sizeof buffer,&out), ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_size(script.next, ==, 0);
  munit_assert_size(io.exchanges_left, ==, 2);
  for (size_t i = 0; i < sizeof buffer; ++i) munit_assert_uint(buffer[i], ==, 0x5a);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult identity(const MunitParameter params[], void* context)
{
  static const uint8_t identities[][15] = {
    {0x61,13,0x4f,11,0xa0,0,0,3,8,0,0,0x10,0,1,0},
    {0x61,13,0x4f,11,0xa0,0,0,3,0x67,0x20,0,0,1,1,1},
    {0x61,13,0x4f,11,0xa0,0,0,3,0x67,0x20,0,0,1,1,3}
  };
  const ExampleCardModel models[] = {EXAMPLE_CARD_MODEL_PIV,
      EXAMPLE_CARD_MODEL_TWIC_LEGACY,EXAMPLE_CARD_MODEL_TWIC_NEXGEN};
  for (size_t i = 0; i < sizeof identities / sizeof *identities; ++i) {
    const ExampleCardApplication app = i ? EXAMPLE_CARD_TWIC : EXAMPLE_CARD_PIV;
    ExampleCardModel out = (ExampleCardModel)99;
    TC_bytes input = {identities[i],sizeof identities[i]};
    munit_assert_int(example_card_identity(input,app,&out), ==, TC_TLV_OK);
    munit_assert_int(out, ==, models[i]);
    for (size_t n = 0; n < input.length; ++n) {
      TC_bytes prefix = {input.data,n};
      out = (ExampleCardModel)99;
      munit_assert_int(example_card_identity(prefix,app,&out), ==, TC_TLV_INVALID);
      munit_assert_int(out, ==, 99);
    }
    munit_assert_int(example_card_identity(input,i ? EXAMPLE_CARD_PIV : EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_INVALID);
    munit_assert_int(out, ==, 99);
  }
  uint8_t buffer[32];
  memcpy(buffer,identities[2],15);
  ExampleCardModel out = (ExampleCardModel)99;
  TC_bytes input = {buffer,15};
  buffer[13] |= 0x80;
  munit_assert_int(example_card_identity(input,EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_UNSUPPORTED);
  buffer[13] = 1; buffer[14] = 0xff;
  munit_assert_int(example_card_identity(input,EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_UNSUPPORTED);
  memcpy(buffer,identities[2],15);
  memcpy(buffer + 15,identities[2],15);
  input.length = 30;
  munit_assert_int(example_card_identity(input,EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_INVALID);
  /* A duplicate immediate 4F must not be confused with a nested authority RID. */
  memcpy(buffer + 15,identities[2] + 2,13);
  buffer[1] = 26; input.length = 28;
  munit_assert_int(example_card_identity(input,EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_INVALID);
  buffer[1] = 22; input.length = 24;
  const uint8_t authority[] = {0x79,7,0x4f,5,0xa0,0,0,3,0x67};
  memcpy(buffer + 15,authority,sizeof authority);
  munit_assert_int(example_card_identity(input,EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_OK);
  munit_assert_int(out, ==, EXAMPLE_CARD_MODEL_TWIC_NEXGEN);
  buffer[18] = 6;
  out = (ExampleCardModel)99;
  munit_assert_int(example_card_identity(input,EXAMPLE_CARD_TWIC,&out), ==, TC_TLV_INVALID);
  munit_assert_int(out, ==, 99);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult pin(const MunitParameter params[], void* context)
{
  static const uint8_t digits[] = "12345678";
  Exchange steps[] = {
    {{0,0x20,0,0x80},{0x63,0xc3},4,2,1},
    {{0,0x20,0,0x80,8,'1','2','3','4','5','6',0xff,0xff},{0x90,0},13,2,1}
  };
  for (unsigned retry = 0; retry <= 255; ++retry) {
    steps[0].response[1] = (uint8_t)retry;
    Script script = {steps,2,0};
    ExampleCardIO io = {transmit,&script,2,0};
    ExampleCardPIN guard = {0};
    uint16_t status = 0;
    const int allowed = retry >= 0xc2 && retry <= 0xca;
    munit_assert_int(example_card_verify_pin(&io,&guard,digits,6,&status), ==,
        allowed ? EXAMPLE_CARD_OK : EXAMPLE_CARD_REFUSED);
    munit_assert_size(script.next, ==, allowed ? 2 : 1);
    munit_assert_uint(status, ==, allowed ? 0x9000 : 0x6300 + retry);
    munit_assert_int(io.stopped, ==, !allowed);
    /* A new connection must retain the consumed per-run allowance. */
    io.stopped = 0; io.exchanges_left = 2;
    munit_assert_int(example_card_verify_pin(&io,&guard,digits,6,&status), ==, EXAMPLE_CARD_REFUSED);
    munit_assert_size(script.next, ==, allowed ? 2 : 1);
  }
  steps[0].response[0] = 0x90; steps[0].response[1] = 0;
  Script script = {steps,2,0};
  ExampleCardIO io = {transmit,&script,2,0};
  ExampleCardPIN guard = {0};
  uint16_t status = 0;
  munit_assert_int(example_card_verify_pin(&io,&guard,digits,8,&status), ==, EXAMPLE_CARD_OK);
  munit_assert_size(script.next, ==, 1);
  steps[0].response[0] = 0x63; steps[0].response[1] = 0xc3;
  for (size_t n = 6; n <= 8; ++n) {
    memcpy(steps[1].command + 5,digits,n);
    for (int failure = 0; failure < 3; ++failure) {
      steps[1].success = failure != 2;
      steps[1].response[0] = failure ? 0x63 : 0x90;
      steps[1].response[1] = failure ? 0xc2 : 0;
      script.next = 0; io.exchanges_left = 2; io.stopped = 0; guard.used = 0;
      munit_assert_int(example_card_verify_pin(&io,&guard,digits,n,&status), ==,
          failure == 2 ? EXAMPLE_CARD_TRANSPORT : failure ? EXAMPLE_CARD_STATUS : EXAMPLE_CARD_OK);
      munit_assert_size(script.next, ==, 2);
      munit_assert_int(guard.used, ==, 1);
      munit_assert_int(io.stopped, ==, failure != 0);
    }
  }
  /* An incomplete response consumes the allowance at either exchange. */
  for (size_t stage = 0; stage < 2; ++stage) {
    for (size_t response_length = 0; response_length < 2; ++response_length) {
      steps[0].success = steps[1].success = 1;
      steps[0].response_length = steps[1].response_length = 2;
      steps[stage].response_length = response_length;
      script.next = 0; io.exchanges_left = 2; io.stopped = 0; guard.used = 0;
      munit_assert_int(example_card_verify_pin(&io,&guard,digits,8,&status), ==,
          EXAMPLE_CARD_PROTOCOL);
      munit_assert_size(script.next, ==, stage + 1);
      munit_assert_int(io.stopped, ==, 1);
      io.stopped = 0; io.exchanges_left = 2;
      munit_assert_int(example_card_verify_pin(&io,&guard,digits,8,&status), ==,
          EXAMPLE_CARD_REFUSED);
      munit_assert_size(script.next, ==, stage + 1);
    }
  }
  steps[0].response_length = steps[1].response_length = 2;
  steps[0].success = 0;
  script.next = 0; io.exchanges_left = 2; io.stopped = 0; guard.used = 0;
  munit_assert_int(example_card_verify_pin(&io,&guard,digits,8,&status), ==,
      EXAMPLE_CARD_TRANSPORT);
  munit_assert_size(script.next, ==, 1);
  io.stopped = 0; io.exchanges_left = 2;
  munit_assert_int(example_card_verify_pin(&io,&guard,digits,8,&status), ==,
      EXAMPLE_CARD_REFUSED);
  munit_assert_size(script.next, ==, 1);
  script.next = 0; io.exchanges_left = 2; io.stopped = 0; guard.used = 0;
  munit_assert_int(example_card_verify_pin(&io,&guard,digits,5,&status), ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_int(example_card_verify_pin(&io,&guard,digits,9,&status), ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_int(example_card_verify_pin(&io,&guard,(const uint8_t*)"12345x",6,&status), ==, EXAMPLE_CARD_ARGUMENT);
  munit_assert_int(guard.used, ==, 0);
  munit_assert_size(script.next, ==, 0);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/inventory",inventory,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/responses",responses,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extended-responses",extended_responses,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extended-failures",extended_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extended-maximum",extended_maximum,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/object-responses",object_responses,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/selection",selection,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/failures",failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/limits",limits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/identity",identity,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/pin",pin,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/twic/reader",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
