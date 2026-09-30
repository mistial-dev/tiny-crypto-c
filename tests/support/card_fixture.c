/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "card_fixture.h"
#include "cavp.h"
#include "test_io.h"
#include <stdlib.h>
#include <string.h>

/* The longest record is the facial image object, about 24 KB of hex. */
#define LINE_BYTES (64u * 1024u)
#define MAX_FIELDS 8u

static char line[LINE_BYTES];

typedef struct {
  char* fields[MAX_FIELDS];
  size_t count;
} record;

/* Split line in place at spaces and tabs. Returns 0 for too many fields. */
static int record_split(char* text, record* out)
{
  out->count = 0;
  for (char* at = text; *at;) {
    while (*at == ' ' || *at == '\t')
      *at++ = '\0';
    if (!*at)
      break;
    if (out->count == MAX_FIELDS)
      return 0;
    out->fields[out->count++] = at;
    while (*at && *at != ' ' && *at != '\t')
      ++at;
  }
  return 1;
}

/* Decode a hex field, or - for an empty value, into the fixture pool. */
static int bytes_field(tc_card_fixture* fixture, const char* text, TC_bytes* out)
{
  size_t length = 0;
  if (!strcmp(text, "-")) {
    *out = (TC_bytes){NULL, 0};
    return 1;
  }
  uint8_t* start = fixture->pool + fixture->pool_used;
  if (!tc_test_hex_decode(text, TC_TEST_HEX_FIELD, start,
                          TC_CARD_FIXTURE_POOL_BYTES - fixture->pool_used, &length) ||
      !length)
    return 0;
  fixture->pool_used += length;
  *out = (TC_bytes){start, length};
  return 1;
}

/* A hex field of exactly length bytes. */
static int fixed_field(tc_card_fixture* fixture, const char* text, size_t length, TC_bytes* out)
{
  return bytes_field(fixture, text, out) && out->length == length;
}

static int byte_field(tc_card_fixture* fixture, const char* text, uint8_t* out)
{
  TC_bytes value;
  if (!fixed_field(fixture, text, 1, &value))
    return 0;
  *out = value.data[0];
  return 1;
}

static int text_field(const char* text, char* out, size_t capacity)
{
  const size_t length = strlen(text);
  if (length >= capacity)
    return 0;
  memcpy(out, text, length + 1);
  return 1;
}

static int object_record(tc_card_fixture* fixture, const record* r)
{
  TC_bytes tag;
  if (r->count != 3 || fixture->object_count == TC_CARD_FIXTURE_MAX_OBJECTS ||
      !bytes_field(fixture, r->fields[1], &tag) || tag.length < 1 || tag.length > 3)
    return 0;
  tc_card_object* object = &fixture->objects[fixture->object_count];
  object->tag = 0;
  for (size_t i = 0; i < tag.length; ++i)
    object->tag = object->tag << 8 | tag.data[i];
  if (!bytes_field(fixture, r->fields[2], &object->data))
    return 0;
  ++fixture->object_count;
  return 1;
}

static int reference_record(tc_card_fixture* fixture, const record* r)
{
  TC_bytes value;
  if (r->count != 4 || fixture->reference_count == TC_CARD_FIXTURE_MAX_REFERENCES)
    return 0;
  tc_card_reference* reference = &fixture->references[fixture->reference_count];
  memset(reference, 0, sizeof *reference);
  if (!byte_field(fixture, r->fields[1], &reference->reference))
    return 0;
  if (strcmp(r->fields[2], "-")) {
    if (!fixed_field(fixture, r->fields[2], sizeof reference->value, &value))
      return 0;
    memcpy(reference->value, value.data, sizeof reference->value);
    reference->value_known = 1;
  }
  reference->retries = TC_CARD_FIXTURE_DEFAULT_RETRIES;
  if (strcmp(r->fields[3], "-")) {
    char* end = NULL;
    const unsigned long retries = strtoul(r->fields[3], &end, 10);
    if (*end || retries > 15)
      return 0;
    reference->retries = (uint8_t)retries;
  }
  ++fixture->reference_count;
  return 1;
}

static int authenticate_record(tc_card_fixture* fixture, const record* r)
{
  if (r->count != 6 || fixture->authentication_count == TC_CARD_FIXTURE_MAX_AUTHENTICATIONS)
    return 0;
  tc_card_authentication* entry = &fixture->authentications[fixture->authentication_count];
  if (!byte_field(fixture, r->fields[1], &entry->algorithm) ||
      !byte_field(fixture, r->fields[2], &entry->key) ||
      !byte_field(fixture, r->fields[3], &entry->tag) ||
      !bytes_field(fixture, r->fields[4], &entry->input) ||
      !bytes_field(fixture, r->fields[5], &entry->answer) || !entry->answer.length)
    return 0;
  ++fixture->authentication_count;
  return 1;
}

static int session_record(tc_card_fixture* fixture, const record* r)
{
  if (r->count != 7 || fixture->session_count == TC_CARD_FIXTURE_MAX_SESSIONS)
    return 0;
  tc_card_session* session = &fixture->sessions[fixture->session_count];
  if (!byte_field(fixture, r->fields[1], &session->suite) ||
      !bytes_field(fixture, r->fields[2], &session->scalar) ||
      !fixed_field(fixture, r->fields[3], 8, &session->host_id) ||
      !bytes_field(fixture, r->fields[4], &session->command) ||
      !bytes_field(fixture, r->fields[5], &session->answer) ||
      !bytes_field(fixture, r->fields[6], &session->material) || session->material.length % 4 ||
      session->material.length > 4 * 32 || !session->scalar.length || session->command.length < 5 ||
      !session->answer.length)
    return 0;
  ++fixture->session_count;
  return 1;
}

static int replay_record(tc_card_fixture* fixture, const record* r)
{
  if (r->count != 3 || fixture->replay_count == TC_CARD_FIXTURE_MAX_REPLAYS)
    return 0;
  tc_card_replay* replay = &fixture->replays[fixture->replay_count];
  if (!text_field(r->fields[1], replay->name, sizeof replay->name))
    return 0;
  if (!strcmp(r->fields[2], "contact"))
    replay->interface = TC_PIV_CONTACT;
  else if (!strcmp(r->fields[2], "contactless"))
    replay->interface = TC_PIV_CONTACTLESS;
  else
    return 0;
  replay->first = fixture->exchange_count;
  replay->count = 0;
  return 1;
}

static int wire_record(tc_card_fixture* fixture, const record* r)
{
  if (r->count != 3 || fixture->exchange_count == TC_CARD_FIXTURE_MAX_EXCHANGES)
    return 0;
  tc_card_exchange* exchange = &fixture->exchanges[fixture->exchange_count];
  if (!bytes_field(fixture, r->fields[1], &exchange->command) || exchange->command.length < 4 ||
      !bytes_field(fixture, r->fields[2], &exchange->answer) || exchange->answer.length < 2)
    return 0;
  ++fixture->exchange_count;
  ++fixture->replays[fixture->replay_count].count;
  return 1;
}

/* Apply one record. in_replay tracks the replay ... end block. */
static int record_apply(tc_card_fixture* fixture, const record* r, int* in_replay)
{
  const char* kind = r->fields[0];
  if (*in_replay) {
    if (!strcmp(kind, "wire"))
      return wire_record(fixture, r);
    if (!strcmp(kind, "end") && r->count == 1) {
      *in_replay = 0;
      ++fixture->replay_count;
      return 1;
    }
    return 0;
  }
  if (!strcmp(kind, "card"))
    return r->count == 2 && text_field(r->fields[1], fixture->name, sizeof fixture->name);
  if (!strcmp(kind, "source"))
    return r->count == 3;
  if (!strcmp(kind, "select"))
    return r->count == 2 && bytes_field(fixture, r->fields[1], &fixture->select);
  if (!strcmp(kind, "object"))
    return object_record(fixture, r);
  if (!strcmp(kind, "reference"))
    return reference_record(fixture, r);
  if (!strcmp(kind, "authenticate"))
    return authenticate_record(fixture, r);
  if (!strcmp(kind, "session"))
    return session_record(fixture, r);
  if (!strcmp(kind, "replay")) {
    *in_replay = replay_record(fixture, r);
    return *in_replay;
  }
  return 0;
}

long tc_card_fixture_load(tc_card_fixture* fixture, const char* path)
{
  FILE* file = tc_test_fopen(path, "r");
  long number = 0, failed = 0;
  int in_replay = 0;
  if (!file)
    return -1;
  memset(fixture, 0, sizeof *fixture);
  while (!failed && fgets(line, sizeof line, file)) {
    ++number;
    size_t length = strlen(line);
    if (length && line[length - 1] == '\n')
      line[--length] = '\0';
    else if (!feof(file))
      failed = number; /* line longer than the buffer */
    if (length && line[length - 1] == '\r')
      line[--length] = '\0';
    record r;
    if (failed || line[0] == '#')
      continue;
    if (!record_split(line, &r) || (r.count && !record_apply(fixture, &r, &in_replay)))
      failed = number;
  }
  fclose(file);
  if (!failed && in_replay)
    failed = number + 1; /* replay without end */
  return failed;
}

const tc_card_object* tc_card_fixture_object(const tc_card_fixture* fixture, uint32_t tag)
{
  for (size_t i = 0; i < fixture->object_count; ++i)
    if (fixture->objects[i].tag == tag)
      return &fixture->objects[i];
  return NULL;
}

const tc_card_reference* tc_card_fixture_reference(const tc_card_fixture* fixture,
                                                   uint8_t reference)
{
  for (size_t i = 0; i < fixture->reference_count; ++i)
    if (fixture->references[i].reference == reference)
      return &fixture->references[i];
  return NULL;
}

const tc_card_replay* tc_card_fixture_replay(const tc_card_fixture* fixture, const char* name)
{
  for (size_t i = 0; i < fixture->replay_count; ++i)
    if (!strcmp(fixture->replays[i].name, name))
      return &fixture->replays[i];
  return NULL;
}

TC_bytes tc_card_fixture_challenge(const tc_card_fixture* fixture, uint8_t key)
{
  enum { DIGEST_BYTES = 32, ALGORITHM_P256 = 0x11, ALGORITHM_P384 = 0x14, WITNESS = 0x81 };
  for (size_t i = 0; i < fixture->authentication_count; ++i) {
    const tc_card_authentication* entry = &fixture->authentications[i];
    if (entry->key != key || entry->tag != WITNESS)
      continue;
    if (entry->algorithm == ALGORITHM_P256 || entry->algorithm == ALGORITHM_P384)
      return entry->input;
    /* EMSA-PKCS1-v1_5: 00 01 FF .. 00 DigestInfo, the digest last. */
    if (entry->input.length > DIGEST_BYTES && entry->input.data[0] == 0 &&
        entry->input.data[1] == 1)
      return (TC_bytes){entry->input.data + entry->input.length - DIGEST_BYTES, DIGEST_BYTES};
  }
  return (TC_bytes){NULL, 0};
}
