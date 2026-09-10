/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/x509_crl_internal.h"
#include "../../src/x509_crl_source_internal.h"
#include "../../src/cms_internal.h"
#include "../cms/source.h"
#include "../../src/pki_extensions_internal.h"
#include "../../src/pki_bits_internal.h"
#include "../../src/pki_distribution_internal.h"
#include "../../src/pki_identifier_internal.h"
#include "munit.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

enum { NEXT_UPDATE = 1, REVOKED = 2, CRL_EXTENSIONS = 4, ENTRY_EXTENSIONS = 8,
  FIXTURE_CAPACITY = 256, WORK_BUDGET = 4096, FRAME_CAPACITY = 16 };
typedef struct {
  uint8_t bytes[FIXTURE_CAPACITY];
  size_t length, inner_algorithm, outer_algorithm, issuer, time, revoked, signature;
} fixture;

static void append(fixture* out, const void* bytes, size_t length)
{
  munit_assert_size(length, <=, sizeof out->bytes - out->length);
  memcpy(out->bytes + out->length,bytes,length); out->length += length;
}

static void append_extension(fixture* out, uint8_t arc, int critical, TC_bytes value)
{
  enum { SHORT_LENGTH_MAX = 127, EXTENSION_OVERHEAD = 7, CRITICAL_SIZE = 3 };
  munit_assert_size(value.length, <=, SHORT_LENGTH_MAX - EXTENSION_OVERHEAD - CRITICAL_SIZE);
  const uint8_t header[] = {0x30,(uint8_t)(EXTENSION_OVERHEAD + value.length + CRITICAL_SIZE * !!critical),6,3,0x55,0x1d,arc};
  const uint8_t boolean[] = {1,1,0xff}, octets[] = {4,(uint8_t)value.length};
  append(out,header,sizeof header);
  if (critical) append(out,boolean,sizeof boolean);
  append(out,octets,sizeof octets); append(out,value.data,value.length);
}

static fixture make_crl(unsigned version, unsigned flags)
{
  const uint8_t algorithm[] = {0x30,4,6,2,0x2a,3};
  const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t time[] = {0x17,13,'2','6','0','1','0','1','0','0','0','0','0','0','Z'};
  const uint8_t extensions[] = {0x30,10,0x30,8,6,2,0x2a,3,4,2,5,0};
  const uint8_t signature[] = {3,2,0,7};
  fixture out = {{0},4,0,0,0,0,0,0};
  out.bytes[0] = out.bytes[2] = 0x30;
  if (version == 2) append(&out,(const uint8_t[]){2,1,1},3);
  out.inner_algorithm = out.length; append(&out,algorithm,sizeof algorithm);
  out.issuer = out.length; append(&out,issuer,sizeof issuer);
  out.time = out.length; append(&out,time,sizeof time);
  if (flags & NEXT_UPDATE) append(&out,time,sizeof time);
  if (flags & REVOKED) {
    out.revoked = out.length;
    append(&out,(const uint8_t[]){0x30,0,0x30,0,2,1,1},7);
    append(&out,time,sizeof time);
    if (flags & ENTRY_EXTENSIONS) append(&out,extensions,sizeof extensions);
    out.bytes[out.revoked + 1] = (uint8_t)(out.length - out.revoked - 2);
    out.bytes[out.revoked + 3] = (uint8_t)(out.length - out.revoked - 4);
  }
  if (flags & CRL_EXTENSIONS) {
    append(&out,(const uint8_t[]){0xa0,sizeof extensions},2);
    append(&out,extensions,sizeof extensions);
  }
  out.bytes[3] = (uint8_t)(out.length - 4);
  out.outer_algorithm = out.length; append(&out,algorithm,sizeof algorithm);
  out.signature = out.length; append(&out,signature,sizeof signature);
  munit_assert_size(out.length - 2, <, 128); /* Fixtures use short-form DER lengths. */
  out.bytes[1] = (uint8_t)(out.length - 2);
  return out;
}

static MunitResult public_reader(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  fixture input = make_crl(2,NEXT_UPDATE | REVOKED | CRL_EXTENSIONS | ENTRY_EXTENSIONS);
  const TC_bytes encoded = {input.bytes,input.length};
  TC_X509_crl parsed, saved;
  size_t work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_read(encoded,&limits,frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_OK);
  munit_assert_uint(parsed.version, ==, 2);
  munit_assert_ptr_equal(parsed.encoded.data,input.bytes);
  munit_assert_size(parsed.encoded.length, ==, input.length);
  munit_assert_ptr_equal(parsed.issuer.data,input.bytes + input.issuer);
  munit_assert_ptr_equal(parsed.signature.data,input.bytes + input.signature + 3);
  const size_t required = WORK_BUDGET - work;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
    memcpy(&parsed,&saved,sizeof parsed); work = required - short_budget;
    munit_assert_int(TC_X509_crl_read(encoded,&limits,frames,FRAME_CAPACITY,&work,&parsed), ==,
        short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
    if (short_budget) munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  for (size_t length = 0; length < input.length; ++length) {
    memcpy(&parsed,&saved,sizeof parsed); work = WORK_BUDGET;
    munit_assert_int(TC_X509_crl_read((TC_bytes){input.bytes,length},&limits,
        frames,FRAME_CAPACITY,&work,&parsed), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  memcpy(&parsed,&saved,sizeof parsed); work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_read(encoded,NULL,frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_read(encoded,&limits,frames,SIZE_MAX,&work,&parsed), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_read(encoded,&limits,frames,FRAME_CAPACITY,NULL,&parsed), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_read(encoded,&limits,frames,FRAME_CAPACITY,&work,NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_read((TC_bytes){(const uint8_t*)&parsed,sizeof parsed},&limits,
      frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  return MUNIT_OK;
}

static MunitResult public_index(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  enum { RECORD_COUNT = 2, OID_CAPACITY = 8 };
  fixture first = make_crl(1,0), second = make_crl(2,NEXT_UPDATE | REVOKED);
  TC_bytes inputs[] = {{first.bytes,first.length},{second.bytes,second.length}};
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY]; TC_bytes oids[OID_CAPACITY];
  const TC_X509_workspace workspace = {frames,FRAME_CAPACITY,oids,OID_CAPACITY};
  TC_X509_crl_record records[RECORD_COUNT];
  TC_X509_crl_index index, saved;
  memset(&saved,0xa5,sizeof saved);
  size_t work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_index_init(inputs,RECORD_COUNT,&limits,&workspace,&work,
      records,RECORD_COUNT,&index), ==, TC_TLV_OK);
  munit_assert_ptr_equal(index.records,records);
  munit_assert_size(index.count, ==, RECORD_COUNT);
  munit_assert_size(index.other_count, ==, 0);
  munit_assert_ptr_equal(records[0].crl.encoded.data,first.bytes);
  munit_assert_ptr_equal(records[1].crl.encoded.data,second.bytes);
  munit_assert_uint(records[0].crl.version, ==, 1);
  munit_assert_uint(records[1].crl.version, ==, 2);
  const size_t required = WORK_BUDGET - work;
  for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
    index = saved; work = required - short_budget;
    munit_assert_int(TC_X509_crl_index_init(inputs,RECORD_COUNT,&limits,&workspace,&work,
        records,RECORD_COUNT,&index), ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
    if (short_budget) munit_assert_memory_equal(sizeof index,&index,&saved);
  }
  second.bytes[second.outer_algorithm + 5] ^= 1;
  index = saved; work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_index_init(inputs,RECORD_COUNT,&limits,&workspace,&work,
      records,RECORD_COUNT,&index), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  second.bytes[second.outer_algorithm + 5] ^= 1;
  index = saved; work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_index_init(inputs,RECORD_COUNT,&limits,&workspace,&work,
      records,RECORD_COUNT - 1,&index), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  inputs[1] = (TC_bytes){(const uint8_t*)records,sizeof records};
  uint8_t saved_records[sizeof records];
  memset(records,0xa5,sizeof records);
  memcpy(saved_records,records,sizeof records);
  work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_index_init(inputs,RECORD_COUNT,&limits,&workspace,&work,
      records,RECORD_COUNT,&index), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_memory_equal(sizeof records,records,saved_records);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_index_init(NULL,0,&limits,&workspace,&work,NULL,0,&index), ==, TC_TLV_OK);
  munit_assert_size(index.count, ==, 0);
  munit_assert_null(index.records);
  return MUNIT_OK;
}

static MunitResult fields(const MunitParameter params[], void* user)
{
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl parsed, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned version = 1; version <= 2; ++version)
    for (unsigned flags = 0; flags < 16; ++flags) {
      if ((flags & ENTRY_EXTENSIONS) && !(flags & REVOKED)) continue;
      fixture input = make_crl(version,flags);
      int valid = version == 2 || !(flags & (CRL_EXTENSIONS | ENTRY_EXTENSIONS));
      work = WORK_BUDGET; memcpy(&parsed,&saved,sizeof parsed);
      munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,input.length},
          &limits,&tree,&parsed), ==, valid ? TC_TLV_OK : TC_TLV_INVALID);
      if (!valid) { munit_assert_memory_equal(sizeof parsed,&parsed,&saved); continue; }
      munit_assert_uint(parsed.version, ==, version);
      munit_assert_int(parsed.has_next_update, ==, !!(flags & NEXT_UPDATE));
      munit_assert_ptr_equal(parsed.encoded.data,input.bytes);
      munit_assert_ptr_equal(parsed.issuer.data,input.bytes + input.issuer);
      munit_assert_ptr_equal(parsed.signature.data,input.bytes + input.signature + 3);
      munit_assert_int(!!parsed.extensions.length, ==, !!(flags & CRL_EXTENSIONS));
      TC_TLV_reader entries;
      tc_x509_crl_entry entry, previous;
      const size_t required = WORK_BUDGET - work;
      TC_bytes oids[4];
      munit_assert_int(tc_x509_crl_extensions_check(&parsed,&limits,&tree,oids,4), ==, TC_TLV_OK);
      munit_assert_int(tc_x509_crl_entries_init(parsed.revoked,&limits,&tree,&entries), ==, TC_TLV_OK);
      if (flags & REVOKED) {
        TC_TLV_reader start;
        memcpy(&start,&entries,sizeof start);
        const size_t before_entry = work;
        munit_assert_int(tc_x509_crl_entry_next(&entries,version,&tree,&entry), ==, TC_TLV_OK);
        munit_assert_size(entry.serial.length, ==, 1);
        munit_assert_uint(entry.serial.data[0], ==, 1);
        munit_assert_int(!!entry.extensions.length, ==, !!(flags & ENTRY_EXTENSIONS));
        const size_t entry_work = before_entry - work, remaining = work;
        for (size_t budget = 0; budget < entry_work; ++budget) {
          TC_TLV_reader probe;
          memcpy(&probe,&start,sizeof probe);
          memset(&entry,0xa5,sizeof entry); memcpy(&previous,&entry,sizeof previous);
          work = budget;
          munit_assert_int(tc_x509_crl_entry_next(&probe,version,&tree,&entry), ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof entry,&entry,&previous);
          munit_assert_memory_equal(sizeof probe,&probe,&start);
        }
        work = remaining;
      }
      memset(&entry,0xa5,sizeof entry); memcpy(&previous,&entry,sizeof previous);
      munit_assert_int(tc_x509_crl_entry_next(&entries,version,&tree,&entry), ==, TC_TLV_END);
      munit_assert_memory_equal(sizeof entry,&entry,&previous);
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; memcpy(&parsed,&saved,sizeof parsed);
        munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,input.length},
            &limits,&tree,&parsed), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
      }
      work = required;
      munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,input.length},
          &limits,&tree,&parsed), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      for (size_t length = 0; length < input.length; ++length) {
        work = WORK_BUDGET; memcpy(&parsed,&saved,sizeof parsed);
        munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,length},
            &limits,&tree,&parsed), !=, TC_TLV_OK);
        munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
      }
    }
  return MUNIT_OK;
}

static MunitResult malformed(const MunitParameter params[], void* user)
{
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl parsed, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned fault = 0; fault < 9; ++fault) {
    fixture input = make_crl(2,REVOKED | NEXT_UPDATE);
    switch (fault) {
      case 0: input.bytes[6] = 0; break;
      case 1: input.bytes[6] = 2; break;
      case 2: input.bytes[input.outer_algorithm + 5] ^= 1; break;
      case 3: input.bytes[input.issuer] = 0x31; break;
      case 4: input.bytes[input.time + 4] = '9'; break;
      case 5: input.bytes[input.signature + 2] = 1; break;
      case 6: input.bytes[input.revoked + 4] = 4; break;
      case 7: input.bytes[input.revoked + 7] = 4; break;
      default: input.bytes[input.revoked] = 0x31; break;
    }
    work = WORK_BUDGET; memcpy(&parsed,&saved,sizeof parsed);
    munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,input.length},
        &limits,&tree,&parsed), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  fixture input = make_crl(2,REVOKED);
  limits.max_depth = 2; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,input.length},
      &limits,&tree,&parsed), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  limits.max_depth = FRAME_CAPACITY; limits.max_elements = 2; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_read((TC_bytes){input.bytes,input.length},
      &limits,&tree,&parsed), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  return MUNIT_OK;
}

static MunitResult extensions(const MunitParameter params[], void* user)
{
  const uint8_t extension[] = {0x30,8,6,2,0x2a,3,4,2,5,0};
  uint8_t encoded[2 + 3 * sizeof extension] = {0x30,3 * sizeof extension};
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[3];
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  (void)params; (void)user;
  for (size_t i = 0; i < 3; ++i) {
    memcpy(encoded + 2 + i * sizeof extension,extension,sizeof extension);
    encoded[2 + i * sizeof extension + 5] = (uint8_t)(3 - i);
  }
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,sizeof encoded},
      &limits,&tree,oids,3), ==, TC_TLV_OK);
  for (size_t i = 0; i < 3; ++i) munit_assert_size(oids[i].data[1], ==, i + 1);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,sizeof encoded},
        &limits,&tree,oids,3), ==, TC_TLV_LIMIT);
  }
  work = required;
  munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,sizeof encoded},
      &limits,&tree,oids,3), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,sizeof encoded},
      &limits,&tree,oids,2), ==, TC_TLV_LIMIT);
  encoded[2 + 2 * sizeof extension + 5] = 3; work = WORK_BUDGET;
  munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,sizeof encoded},
      &limits,&tree,oids,3), ==, TC_TLV_INVALID);
  encoded[2 + 2 * sizeof extension + 5] = 1;
  encoded[sizeof encoded - 2] = 0; work = WORK_BUDGET;
  munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,sizeof encoded},
      &limits,&tree,oids,3), ==, TC_TLV_INVALID);
  encoded[sizeof encoded - 2] = 5;
  for (size_t length = 0; length < sizeof encoded; ++length) {
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_extensions_check((TC_bytes){encoded,length},
        &limits,&tree,oids,3), !=, TC_TLV_OK);
  }
  return MUNIT_OK;
}

static MunitResult extension_values(const MunitParameter params[], void* user)
{
  uint8_t reason[] = {10,1,0};
  uint8_t number[23] = {2,21,0x7f};
  uint8_t date[] = {0x18,15,'2','0','2','4','0','2','2','9','0','0','0','0','0','0','Z'};
  TC_bytes value;
  TC_X509_time parsed, saved;
  unsigned code;
  (void)params; (void)user;
  for (unsigned i = 0; i <= 255; ++i) {
    reason[2] = (uint8_t)i; code = 99;
    const int valid = i <= 10 && i != 7;
    munit_assert_int(tc_x509_crl_reason_read((TC_bytes){reason,sizeof reason},&code), ==,
        valid ? TC_TLV_OK : TC_TLV_INVALID);
    munit_assert_uint(code, ==, valid ? i : 99);
  }
  for (size_t width = 20; width <= 21; ++width) {
    number[1] = (uint8_t)width;
    munit_assert_int(tc_x509_crl_number_read((TC_bytes){number,width + 2},&value), ==, TC_TLV_OK);
    munit_assert_ptr_equal(value.data,number + 2);
    munit_assert_size(value.length, ==, width);
  }
  const uint8_t invalid_numbers[][4] = {{2,1,0xff,0},{2,2,0,1},{2,0,0,0},{4,1,0,0}};
  const size_t lengths[] = {3,4,2,3};
  for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
    value = (TC_bytes){NULL,99};
    munit_assert_int(tc_x509_crl_number_read((TC_bytes){invalid_numbers[i],lengths[i]},&value), ==, TC_TLV_INVALID);
    munit_assert_null(value.data); munit_assert_size(value.length, ==, 99);
  }
  munit_assert_int(tc_x509_crl_invalidity_date_read((TC_bytes){date,sizeof date},&parsed), ==, TC_TLV_OK);
  munit_assert_uint(parsed.year, ==, 2024); munit_assert_uint(parsed.day, ==, 29);
  memset(&saved,0xa5,sizeof saved); memcpy(&parsed,&saved,sizeof parsed);
  date[5] = '3';
  munit_assert_int(tc_x509_crl_invalidity_date_read((TC_bytes){date,sizeof date},&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  date[5] = '4'; date[0] = 0x17;
  munit_assert_int(tc_x509_crl_invalidity_date_read((TC_bytes){date,sizeof date},&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  date[0] = 0x18;
  const uint8_t arcs[] = {20,27,21,24,35,18,29,35};
  const uint8_t positive[] = {2,1,0};
  const uint8_t authority[] = {0x30,3,0x80,1,42};
  const uint8_t names[] = {0x30,3,0x82,1,'a'};
  const uint8_t issuer_serial[] = {0x30,8,0xa1,3,0x82,1,'a',0x82,1,1};
  reason[2] = 8;
  const TC_bytes values[] = {{positive,sizeof positive},{positive,sizeof positive},
    {reason,sizeof reason},{date,sizeof date},{authority,sizeof authority},
    {names,sizeof names},{names,sizeof names},{issuer_serial,sizeof issuer_serial}};
  for (size_t i = 0; i < sizeof arcs; ++i) {
    const int entry = arcs[i] == 21 || arcs[i] == 24 || arcs[i] == 29;
    uint8_t list[64] = {0x30,0,0x30,0,6,3,0x55,0x1d,0,4,0};
    uint8_t entries[128] = {0x30,0,0x30,0,2,1,1,0x17,13,
      '2','6','0','1','0','1','0','0','0','0','0','0','Z'};
    const size_t list_length = 11 + values[i].length;
    TC_TLV_frame frames[FRAME_CAPACITY];
    TC_bytes oids[1];
    TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
    tc_x509_crl crl = {0};
    size_t work = WORK_BUDGET;
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    list[1] = (uint8_t)(list_length - 2); list[3] = (uint8_t)(list_length - 4);
    list[8] = arcs[i]; list[10] = (uint8_t)values[i].length;
    memcpy(list + 11,values[i].data,values[i].length);
    crl.version = 2;
    if (!entry) crl.extensions = (TC_bytes){list,list_length};
    else {
      memcpy(entries + 22,list,list_length);
      entries[1] = (uint8_t)(20 + list_length); entries[3] = (uint8_t)(18 + list_length);
      crl.revoked = (TC_bytes){entries,22 + list_length};
    }
    munit_assert_int(tc_x509_crl_extensions_check(&crl,&limits,&tree,oids,1), ==, TC_TLV_OK);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget;
      munit_assert_int(tc_x509_crl_extensions_check(&crl,&limits,&tree,oids,1), ==, TC_TLV_LIMIT);
    }
    work = required;
    munit_assert_int(tc_x509_crl_extensions_check(&crl,&limits,&tree,oids,1), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    /* Keep the wrapper intact and change only the extension value's tag. */
    if (!entry) list[11] = 5;
    else entries[22 + 11] = 5;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_extensions_check(&crl,&limits,&tree,oids,1), ==, TC_TLV_INVALID);
    if (i == 5 || i == 6 || i == 7) {
      uint8_t* encoded_value = entry ? entries + 22 + 11 : list + 11;
      memcpy(encoded_value,values[i].data,values[i].length);
      /* EdiPartyName is constructed, not a primitive [5] value. */
      encoded_value[i == 7 ? 4 : 2] = 0x85;
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_extensions_check(&crl,&limits,&tree,oids,1), ==, TC_TLV_INVALID);
    }
  }
  return MUNIT_OK;
}

static TC_status source_memory_read(void* context, uint64_t offset,
    uint8_t* destination, size_t length)
{
  const TC_bytes* bytes = (const TC_bytes*)context;
  if (offset > bytes->length || length > bytes->length - offset) return TC_ERROR;
  memcpy(destination,bytes->data + (size_t)offset,length);
  return TC_OK;
}

static void check_source_layout(TC_bytes bytes, const tc_x509_crl* parsed)
{
  uint8_t window[64];
  TC_source source = {source_memory_read,&bytes,bytes.length};
  tc_source_reader reader;
  tc_x509_crl_layout layout;
  for (size_t capacity = 1; capacity <= sizeof window; capacity *= 2) {
    munit_assert_int(tc_source_reader_init(&reader,&source,
      (TC_buffer){window,capacity},4096,4096),==,TC_RESULT_OK);
    munit_assert_int(tc_x509_crl_source_layout(&reader,&layout),==,TC_TLV_OK);
    const TC_bytes expected[] = {parsed->tbs,parsed->issuer,parsed->revoked,parsed->extensions};
    const tc_source_span actual[] = {layout.tbs,layout.issuer,layout.revoked,layout.extensions};
    for (size_t i = 0; i < sizeof expected / sizeof expected[0]; ++i) {
      munit_assert_true(actual[i].length == expected[i].length);
      if (expected[i].length)
        munit_assert_true(actual[i].offset == (uint64_t)(expected[i].data - bytes.data));
    }
    munit_assert_true(reader.bytes_remaining > 0);
    uint8_t metadata[4096];
    TC_TLV_frame frames[FRAME_CAPACITY];
    size_t work = 100000;
    const TC_TLV_limits limits = {sizeof metadata,sizeof metadata,1024,FRAME_CAPACITY};
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    tc_x509_crl loaded;
    munit_assert_int(tc_x509_crl_source_metadata(&reader,&layout,
      (TC_buffer){metadata,sizeof metadata},&limits,&tree,&loaded),==,TC_TLV_OK);
    munit_assert_uint(loaded.version,==,parsed->version);
    munit_assert_int(loaded.has_next_update,==,parsed->has_next_update);
    munit_assert_size(loaded.issuer.length,==,parsed->issuer.length);
    munit_assert_memory_equal(loaded.issuer.length,loaded.issuer.data,parsed->issuer.data);
    munit_assert_size(loaded.signature.length,==,parsed->signature.length);
    munit_assert_memory_equal(loaded.signature.length,loaded.signature.data,parsed->signature.data);
    munit_assert_size(loaded.extensions.length,==,parsed->extensions.length);
    if (loaded.extensions.length)
      munit_assert_memory_equal(loaded.extensions.length,loaded.extensions.data,parsed->extensions.data);
    munit_assert_size(loaded.tbs.length,==,0);
    munit_assert_size(loaded.revoked.length,==,0);
    tc_x509_crl saved = loaded;
    munit_assert_int(tc_x509_crl_source_metadata(&reader,&layout,
      (TC_buffer){metadata,1},&limits,&tree,&loaded),==,TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof loaded,&loaded,&saved);
    if (bytes.length > FIXTURE_CAPACITY) continue;
    tc_x509_crl_source_entries entries;
    TC_TLV_reader borrowed;
    work = 100000;
    munit_assert_int(tc_x509_crl_source_entries_init(&reader,layout.revoked,parsed->version,16,&entries),==,TC_TLV_OK);
    munit_assert_int(tc_x509_crl_entries_init(parsed->revoked,&limits,&tree,&borrowed),==,TC_TLV_OK);
    for (;;) {
      tc_x509_crl_entry actual_entry, expected_entry;
      TC_TLV_result actual_status = tc_x509_crl_source_entry_next(&reader,&entries,
        (TC_buffer){metadata,sizeof metadata},&limits,&tree,&actual_entry);
      TC_TLV_result expected_status = tc_x509_crl_entry_next(&borrowed,parsed->version,&tree,&expected_entry);
      munit_assert_int(actual_status,==,expected_status);
      if (actual_status == TC_TLV_END) break;
      munit_assert_int(actual_status,==,TC_TLV_OK);
      munit_assert_size(actual_entry.serial.length,==,expected_entry.serial.length);
      munit_assert_memory_equal(actual_entry.serial.length,actual_entry.serial.data,expected_entry.serial.data);
      munit_assert_size(actual_entry.extensions.length,==,expected_entry.extensions.length);
      if (actual_entry.extensions.length)
        munit_assert_memory_equal(actual_entry.extensions.length,actual_entry.extensions.data,expected_entry.extensions.data);
      if (capacity == 1) munit_assert_true((uintptr_t)actual_entry.serial.data >= (uintptr_t)metadata &&
        (uintptr_t)actual_entry.serial.data < (uintptr_t)(metadata + sizeof metadata));
    }
  }
}

static MunitResult source_layout(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  for (unsigned version = 1; version <= 2; ++version) {
    for (unsigned flags = 0; flags < 8; ++flags) {
      if (version == 1 && (flags & CRL_EXTENSIONS)) continue;
      fixture input = make_crl(version,flags);
      size_t work = WORK_BUDGET;
      tc_x509_crl parsed;
      munit_assert_int(TC_X509_crl_read((TC_bytes){input.bytes,input.length},
        &limits,frames,FRAME_CAPACITY,&work,&parsed),==,TC_TLV_OK);
      check_source_layout((TC_bytes){input.bytes,input.length},&parsed);
      for (size_t length = 0; length < input.length; ++length) {
        TC_bytes bytes = {input.bytes,length};
        TC_source source = {source_memory_read,&bytes,length};
        uint8_t window[8];
        tc_source_reader reader;
        tc_x509_crl_layout layout, saved;
        memset(&layout,0xa5,sizeof layout); saved = layout;
        munit_assert_int(tc_source_reader_init(&reader,&source,
          (TC_buffer){window,sizeof window},4096,4096),==,TC_RESULT_OK);
        munit_assert_int(tc_x509_crl_source_layout(&reader,&layout),==,TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof layout,&layout,&saved);
      }
    }
  }
  return MUNIT_OK;
}

static MunitResult source_entry_failures(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  uint8_t window[1], scratch[FIXTURE_CAPACITY];
  for (unsigned failure = 0; failure < 5; ++failure) {
    fixture input = make_crl(2,NEXT_UPDATE | REVOKED | CRL_EXTENSIONS);
    TC_bytes bytes = {input.bytes,input.length};
    TC_source source = {source_memory_read,&bytes,bytes.length};
    tc_source_reader reader;
    tc_x509_crl_layout layout;
    tc_x509_crl_source_entries entries;
    if (failure == 2) input.bytes[input.revoked + 2] = 0x31;
    if (failure == 3) input.bytes[input.revoked + 11] = '9';
    munit_assert_int(tc_source_reader_init(&reader,&source,
      (TC_buffer){window,sizeof window},4096,4096),==,TC_RESULT_OK);
    munit_assert_int(tc_x509_crl_source_layout(&reader,&layout),==,TC_TLV_OK);
    munit_assert_int(tc_x509_crl_source_entries_init(&reader,layout.revoked,2,
      failure == 0 ? 0 : 1,&entries),==,TC_TLV_OK);
    const uint64_t cursor = entries.cursor;
    const uint64_t remaining = entries.remaining;
    size_t work = failure == 4 ? 0 : WORK_BUDGET;
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    tc_x509_crl_entry entry, saved;
    memset(&entry,0xa5,sizeof entry); memcpy(&saved,&entry,sizeof saved);
    const TC_TLV_result expected = failure == 2 || failure == 3 ? TC_TLV_INVALID : TC_TLV_LIMIT;
    munit_assert_int(tc_x509_crl_source_entry_next(&reader,&entries,
      (TC_buffer){scratch,failure == 1 ? 0 : sizeof scratch},&limits,&tree,&entry),==,expected);
    munit_assert_true(entries.cursor == cursor && entries.remaining == remaining);
    munit_assert_memory_equal(sizeof entry,&entry,&saved);
  }
  return MUNIT_OK;
}

static MunitResult source_batch(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t serials[] = {1,3,99};
  tc_x509_crl_serial_query queries[3];
  for (size_t i = 0; i < 3; ++i)
    queries[i] = (tc_x509_crl_serial_query){{serials + i,1},{issuer,sizeof issuer}};
  for (unsigned failure = 0; failure < 4; ++failure) {
    fixture list = {{0x30,0},2,0,0,0,0,0,0};
    for (unsigned i = 0; i < 3; ++i) {
      uint8_t entry[] = {0x30,18,2,1,(uint8_t)(i + 1),0x17,13,
        '2','6','0','1','0','1','0','0','0','0','0','0','Z'};
      if (i == 2 && failure == 1) entry[4] = 1;
      if (i == 2 && failure == 2) entry[9] = '9';
      append(&list,entry,sizeof entry);
    }
    list.bytes[1] = (uint8_t)(list.length - 2);
    TC_bytes bytes = {list.bytes,list.length};
    TC_source source = {source_memory_read,&bytes,bytes.length};
    uint8_t window[8], scratch[FIXTURE_CAPACITY];
    tc_source_reader reader;
    tc_x509_crl crl = {0};
    crl.version = 2; crl.issuer = (TC_bytes){issuer,sizeof issuer};
    tc_x509_crl_extension_info extensions = {0};
    tc_x509_crl_source_revoked revoked;
    tc_x509_crl_source_scan scan;
    tc_x509_crl_match provisional[3], output[3], saved[3];
    memset(output,0xa5,sizeof output); memcpy(saved,output,sizeof saved);
    munit_assert_int(tc_source_reader_init(&reader,&source,
      (TC_buffer){window,sizeof window},4096,4096),==,TC_RESULT_OK);
    munit_assert_int(tc_x509_crl_source_revoked_init(&reader,(tc_source_span){0,bytes.length},
      &crl,&extensions,failure == 3 ? 2 : 3,(TC_buffer){NULL,0},&revoked),==,TC_TLV_OK);
    munit_assert_int(tc_x509_crl_source_scan_init(&reader,&revoked,queries,3,provisional,3,&scan),==,TC_TLV_OK);
    munit_assert_int(tc_x509_crl_source_scan_finish(&scan,output,3),==,TC_TLV_ARGUMENT);
    TC_TLV_frame frames[FRAME_CAPACITY]; TC_bytes oids[2];
    uint32_t left[32], right[32]; uint8_t matched_names[4];
    const TC_X509_name_workspace names = {left,right,32,matched_names,4};
    const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
    size_t work;
    const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
    int complete = 0;
    TC_TLV_result result = TC_TLV_OK;
    unsigned steps = 0;
    while (!complete && result == TC_TLV_OK) {
      work = WORK_BUDGET;
      result = tc_x509_crl_source_scan_step(&scan,1,(TC_buffer){scratch,sizeof scratch},
        &limits,&tree,&names,oids,2,&complete);
      munit_assert_uint(++steps,<=,4);
      munit_assert_memory_equal(sizeof output,output,saved);
    }
    if (failure) {
      munit_assert_int(result,==,failure == 3 ? TC_TLV_LIMIT : TC_TLV_INVALID);
      munit_assert_int(tc_x509_crl_source_scan_finish(&scan,output,3),==,TC_TLV_ARGUMENT);
      munit_assert_memory_equal(sizeof output,output,saved);
    } else {
      munit_assert_int(tc_x509_crl_source_scan_finish(&scan,output,2),==,TC_TLV_LIMIT);
      munit_assert_int(tc_x509_crl_source_scan_finish(&scan,output,3),==,TC_TLV_OK);
      munit_assert_true(output[0].found && output[1].found && !output[2].found);
      const TC_X509_crl_prepared prepared = {queries,output,3,{NULL,0},TC_HASH_SHA256};
      crl.prepared = &prepared;
      for (size_t i = 0; i < 3; ++i) {
        TC_X509_certificate certificate = {0};
        certificate.serial = queries[i].serial; certificate.issuer = queries[i].issuer;
        tc_x509_crl_match found;
        work = WORK_BUDGET;
        munit_assert_int(tc_x509_crl_find(&crl,&extensions,&certificate,
          &limits,&tree,&names,oids,2,&found),==,TC_TLV_OK);
        munit_assert_int(found.found,==,output[i].found);
      }
      const uint8_t missing_serial = 98;
      TC_X509_certificate missing = {0};
      missing.serial = (TC_bytes){&missing_serial,1}; missing.issuer = queries[0].issuer;
      tc_x509_crl_match found, before;
      memset(&found,0xa5,sizeof found); memcpy(&before,&found,sizeof before);
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_find(&crl,&extensions,&missing,
        &limits,&tree,&names,oids,2,&found),==,TC_TLV_UNSUPPORTED);
      munit_assert_memory_equal(sizeof found,&found,&before);
      TC_X509_crl_record record = {0};
      record.crl = crl; record.extensions = extensions;
      const TC_X509_crl_index index = {&record,1,0};
      const TC_bytes overlapping = {(const uint8_t*)output,sizeof output};
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_index_storage_bytes(&index,&overlapping,1,&work),==,TC_TLV_ARGUMENT);
    }
  }
  return MUNIT_OK;
}

static MunitResult corpus_file(const MunitParameter params[], void* user)
{
  enum { MAX_BYTES = 32 * 1024 * 1024, MAX_DEPTH = 32,
    MAX_EXTENSIONS = 256, WORK_PER_BYTE = 32, MIN_WORK = 10000000 };
  const char* path = getenv("TC_CRL_FILE");
  const char* expected = getenv("TC_CRL_EXPECT");
  uint8_t* bytes;
  TC_TLV_frame frames[MAX_DEPTH];
  TC_bytes oids[MAX_EXTENSIONS];
  size_t work, length;
  const tc_pki_tree_workspace tree = {frames,MAX_DEPTH,&work};
  tc_x509_crl parsed, saved;
  FILE* file;
  (void)params; (void)user;
  munit_assert_not_null(path); munit_assert_not_null(expected);
  munit_assert_true(!strcmp(expected,"valid") || !strcmp(expected,"invalid"));
  file = fopen(path,"rb");
  munit_assert_not_null(file);
  munit_assert_int(fseek(file,0,SEEK_END), ==, 0);
  const long file_length = ftell(file);
  munit_assert_true(file_length > 0 && file_length <= MAX_BYTES);
  length = (size_t)file_length;
  munit_assert_int(fseek(file,0,SEEK_SET), ==, 0);
  bytes = munit_malloc(length);
  munit_assert_size(fread(bytes,1,length,file), ==, length);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_false(ferror(file));
  munit_assert_int(fclose(file), ==, 0);
  const TC_TLV_limits limits = {length,length,length / 2 + 1,MAX_DEPTH};
  work = length * WORK_PER_BYTE;
  if (work < MIN_WORK) work = MIN_WORK;
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  TC_TLV_result result = TC_X509_crl_read((TC_bytes){bytes,length},&limits,frames,MAX_DEPTH,&work,&parsed);
  if (!strcmp(expected,"invalid")) {
    munit_assert_int(result, ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  } else {
    munit_assert_int(result, ==, TC_TLV_OK);
    munit_assert_int(tc_x509_crl_extensions_check(&parsed,&limits,&tree,oids,MAX_EXTENSIONS), ==, TC_TLV_OK);
    check_source_layout((TC_bytes){bytes,length},&parsed);
  }
  free(bytes);
  return MUNIT_OK;
}

static MunitResult authority_identifiers(const MunitParameter params[], void* user)
{
  enum { NAME_SCALARS = 32, NAME_ATTRIBUTES = 4 };
  static const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  static const uint8_t names_der[] = {0xa4,14,0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'a'};
  static const uint8_t ski_extension[] = {0x30,12,0x30,10,6,3,0x55,0x1d,14,4,3,4,1,0xaa};
  static const uint8_t serial[] = {0,0x80}, key[] = {0xaa}, wrong_key[] = {0xbb};
  static const uint8_t dns[] = {0x82,1,'a'};
  TC_X509_certificate candidate = {0};
  TC_X509_authority_key_identifier authority = {0};
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  uint32_t left[NAME_SCALARS], right[NAME_SCALARS];
  uint8_t flags[NAME_ATTRIBUTES];
  const TC_X509_name_workspace names = {left,right,NAME_SCALARS,flags,NAME_ATTRIBUTES};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  int matched;
  (void)params; (void)user;
  candidate.issuer = (TC_bytes){issuer,sizeof issuer};
  candidate.serial = (TC_bytes){serial,sizeof serial};
  candidate.extensions = (TC_bytes){ski_extension,sizeof ski_extension};
  for (unsigned fields = 0; fields < 4; ++fields) {
    authority = (TC_X509_authority_key_identifier){0};
    if (fields & 1) {
      authority.has_key_identifier = 1;
      authority.key_identifier = (TC_bytes){key,sizeof key};
    }
    if (fields & 2) {
      authority.issuer = (TC_bytes){names_der,sizeof names_der};
      authority.serial = candidate.serial;
    }
    work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; matched = -1;
      munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, -1);
    }
    work = required;
    munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    munit_assert_size(work, ==, 0);
  }
  authority.key_identifier = (TC_bytes){wrong_key,sizeof wrong_key}; work = WORK_BUDGET;
  munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_false(matched);
  authority.key_identifier = (TC_bytes){key,sizeof key};
  candidate.extensions = (TC_bytes){NULL,0}; work = WORK_BUDGET;
  munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_false(matched);
  candidate.extensions = (TC_bytes){ski_extension,sizeof ski_extension};
  authority.serial_negative = 1; work = WORK_BUDGET;
  munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_false(matched);
  authority.serial_negative = 0;
  authority.serial = (TC_bytes){serial + 1,1}; work = WORK_BUDGET;
  munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_false(matched);
  authority.serial = candidate.serial;
  authority.issuer = (TC_bytes){dns,sizeof dns}; work = WORK_BUDGET; matched = -1;
  munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(matched, ==, -1);
  {
    uint8_t alternatives[sizeof names_der + sizeof dns];
    memcpy(alternatives,names_der,sizeof names_der);
    memcpy(alternatives + sizeof names_der,dns,sizeof dns);
    authority.issuer = (TC_bytes){alternatives,sizeof alternatives}; work = WORK_BUDGET;
    munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_true(matched);
    alternatives[sizeof names_der - 1] = 'B'; work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_UNSUPPORTED);
    munit_assert_int(matched, ==, -1);
    authority.issuer.length = sizeof names_der; work = WORK_BUDGET;
    munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_false(matched);
    alternatives[sizeof names_der - 1] = 'A'; alternatives[sizeof names_der] = 5;
    authority.issuer.length = sizeof alternatives; work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_pki_authority_matches(&authority,&candidate,&limits,&tree,&names,&matched), ==, TC_TLV_INVALID);
    munit_assert_int(matched, ==, -1);
  }
  return MUNIT_OK;
}

static MunitResult signer_usage(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const struct { uint8_t unused, bits; int allowed; } cases[] = {
    {1,2,1},{7,128,0},{1,130,1},{2,4,0}
  };
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_X509_certificate signer = {0};
  size_t work = WORK_BUDGET; int authorized = 99;
  munit_assert_int(tc_x509_crl_signer_usage(&signer,&limits,&work,&authorized), ==, TC_TLV_OK);
  munit_assert_int(authorized, ==, 1);
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i)
    for (int critical = 0; critical <= 1; ++critical) {
      fixture input = {0};
      const uint8_t header[] = {0x30,0}, value[] = {3,2,cases[i].unused,cases[i].bits};
      append(&input,header,sizeof header);
      append_extension(&input,15,critical,(TC_bytes){value,sizeof value});
      input.bytes[1] = (uint8_t)(input.length - 2);
      signer.extensions = (TC_bytes){input.bytes,input.length};
      work = WORK_BUDGET; authorized = 99;
      munit_assert_int(tc_x509_crl_signer_usage(&signer,&limits,&work,&authorized), ==, TC_TLV_OK);
      munit_assert_int(authorized, ==, cases[i].allowed);
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; authorized = 99;
        munit_assert_int(tc_x509_crl_signer_usage(&signer,&limits,&work,&authorized), ==, TC_TLV_LIMIT);
        munit_assert_int(authorized, ==, 99);
      }
      work = required;
      munit_assert_int(tc_x509_crl_signer_usage(&signer,&limits,&work,&authorized), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      append_extension(&input,15,critical,(TC_bytes){value,sizeof value});
      input.bytes[1] = (uint8_t)(input.length - 2); signer.extensions.length = input.length;
      work = WORK_BUDGET; authorized = 99;
      munit_assert_int(tc_x509_crl_signer_usage(&signer,&limits,&work,&authorized), ==, TC_TLV_INVALID);
      munit_assert_int(authorized, ==, 99);
    }
  fixture input = {0};
  const uint8_t header[] = {0x30,0}, invalid[] = {3,2,1,0};
  append(&input,header,sizeof header);
  append_extension(&input,15,0,(TC_bytes){invalid,sizeof invalid});
  input.bytes[1] = (uint8_t)(input.length - 2);
  signer.extensions = (TC_bytes){input.bytes,input.length};
  work = WORK_BUDGET; authorized = 99;
  munit_assert_int(tc_x509_crl_signer_usage(&signer,&limits,&work,&authorized), ==, TC_TLV_INVALID);
  munit_assert_int(authorized, ==, 99);
  return MUNIT_OK;
}

static MunitResult evidence_status(const MunitParameter params[], void* user)
{
  const tc_x509_crl_match absent = {0};
  tc_x509_crl_match revoked = {0};
  tc_x509_crl_evidence evidence, saved;
  tc_x509_crl_status status;
  (void)params; (void)user;
  revoked.found = 1; revoked.reason = 1;
  revoked.revoked_at = (TC_X509_time){2026,1,1,0,0,0};
  for (unsigned subset = 0; subset < 256; ++subset) {
    const uint16_t reasons = (uint16_t)(subset << 1);
    evidence = (tc_x509_crl_evidence){0};
    munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_OK);
    munit_assert_int(status, ==, TC_X509_CRL_UNDETERMINED);
    munit_assert_int(tc_x509_crl_evidence_add(&evidence,reasons,&absent), ==, TC_TLV_OK);
    munit_assert_uint(evidence.reasons, ==, reasons);
    munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_OK);
    munit_assert_int(status, ==, reasons == TC_X509_CRL_ALL_REASONS ?
        TC_X509_CRL_UNREVOKED : TC_X509_CRL_UNDETERMINED);
    memcpy(&saved,&evidence,sizeof saved);
    munit_assert_int(tc_x509_crl_evidence_add(&evidence,reasons,&revoked), ==,
        reasons == TC_X509_CRL_ALL_REASONS ? TC_TLV_END : TC_TLV_OK);
    munit_assert_memory_equal(sizeof evidence,&evidence,&saved);
    if (reasons != TC_X509_CRL_ALL_REASONS)
      munit_assert_int(tc_x509_crl_evidence_add(&evidence,TC_X509_CRL_ALL_REASONS ^ reasons,&absent), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_OK);
    munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
  }
  evidence = (tc_x509_crl_evidence){0};
  munit_assert_int(tc_x509_crl_evidence_add(&evidence,2,&revoked), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_OK);
  munit_assert_int(status, ==, TC_X509_CRL_REVOKED);
  munit_assert_memory_equal(sizeof revoked,&evidence.revocation,&revoked);
  memcpy(&saved,&evidence,sizeof saved);
  munit_assert_int(tc_x509_crl_evidence_add(&evidence,TC_X509_CRL_ALL_REASONS,&absent), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof evidence,&evidence,&saved);
  for (unsigned reason = 0; reason < 256; ++reason) {
    const int valid = reason <= 10 && reason != 7 && reason != 8;
    evidence = (tc_x509_crl_evidence){0}; revoked.reason = reason;
    memcpy(&saved,&evidence,sizeof saved);
    munit_assert_int(tc_x509_crl_evidence_add(&evidence,TC_X509_CRL_ALL_REASONS,&revoked),
        ==, valid ? TC_TLV_OK : TC_TLV_INVALID);
    if (!valid) munit_assert_memory_equal(sizeof evidence,&evidence,&saved);
  }
  {
    tc_x509_crl_match base = revoked, delta = revoked, combined;
    base.reason = 6; delta.reason = 8;
    munit_assert_int(tc_x509_crl_combine(&base,&delta,&combined), ==, TC_TLV_OK);
    evidence = (tc_x509_crl_evidence){0};
    munit_assert_int(tc_x509_crl_evidence_add(&evidence,TC_X509_CRL_ALL_REASONS,&combined), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_OK);
    munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
  }
  const uint16_t invalid_masks[] = {1,1u << 9,1u << 15};
  for (size_t i = 0; i < sizeof invalid_masks / sizeof invalid_masks[0]; ++i) {
    evidence = (tc_x509_crl_evidence){0}; memcpy(&saved,&evidence,sizeof saved);
    munit_assert_int(tc_x509_crl_evidence_add(&evidence,invalid_masks[i],&absent), ==, TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof evidence,&evidence,&saved);
    evidence.reasons = invalid_masks[i]; status = TC_X509_CRL_REVOKED;
    munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_ARGUMENT);
    munit_assert_int(status, ==, TC_X509_CRL_REVOKED);
  }
  for (unsigned field = 0; field < 2; ++field) {
    tc_x509_crl_match invalid = revoked;
    invalid.reason = 1;
    if (field) invalid.has_invalidity_date = 2;
    else invalid.found = 2;
    evidence = (tc_x509_crl_evidence){0}; memcpy(&saved,&evidence,sizeof saved);
    munit_assert_int(tc_x509_crl_evidence_add(&evidence,2,&invalid), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof evidence,&evidence,&saved);
    evidence.reasons = 2; evidence.revocation = invalid; status = TC_X509_CRL_UNREVOKED;
    munit_assert_int(tc_x509_crl_evidence_status(&evidence,&status), ==, TC_TLV_ARGUMENT);
    munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
  }
  evidence = (tc_x509_crl_evidence){0};
  munit_assert_int(tc_x509_crl_evidence_add(&evidence,2,&evidence.revocation), ==, TC_TLV_OK);
  munit_assert_uint(evidence.reasons, ==, 2);
  munit_assert_false(evidence.revocation.found);
  return MUNIT_OK;
}

static MunitResult evidence_equality(const MunitParameter params[], void* user)
{
  tc_x509_crl_evidence left = {0}, right;
  (void)params; (void)user;
  left.reasons = TC_X509_CRL_ALL_REASONS;
  left.revocation.found = 1; left.revocation.reason = 1;
  left.revocation.revoked_at = (TC_X509_time){2026,1,1,0,0,0};
  left.revocation.has_invalidity_date = 1;
  left.revocation.invalidity_date = (TC_X509_time){2025,1,1,0,0,0};
  enum { SAME, REASON, COVERAGE, FOUND, REVOKED_DATE, INVALIDITY_DATE, HAS_INVALIDITY };
  for (unsigned change = SAME; change <= HAS_INVALIDITY; ++change) {
    right = left;
    switch (change) {
      case REASON: right.revocation.reason = 2; break;
      case COVERAGE: right.reasons = 2; break;
      case FOUND: right.revocation.found = 0; break;
      case REVOKED_DATE: ++right.revocation.revoked_at.day; break;
      case INVALIDITY_DATE: ++right.revocation.invalidity_date.day; break;
      case HAS_INVALIDITY: right.revocation.has_invalidity_date = 0; break;
      default: break;
    }
    int equal = -1;
    munit_assert_int(tc_x509_crl_evidence_equal(&left,&right,&equal), ==, TC_TLV_OK);
    munit_assert_int(equal, ==, change == SAME);
  }
  int equal = -1;
  right = left; right.reasons = 1;
  munit_assert_int(tc_x509_crl_evidence_equal(&left,&right,&equal), ==, TC_TLV_ARGUMENT);
  munit_assert_int(equal, ==, -1);
  left = (tc_x509_crl_evidence){0}; right = left;
  right.revocation.revoked_at.year = 2026;
  munit_assert_int(tc_x509_crl_evidence_equal(&left,&right,&equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  return MUNIT_OK;
}

static MunitResult combine_status(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  tc_x509_crl_match base = {0}, delta = {0}, combined, saved;
  memset(&saved,0xa5,sizeof saved);
  base.reason = 6; base.revoked_at = (TC_X509_time){2024,1,1,0,0,0};
  delta.revoked_at = (TC_X509_time){2050,1,1,0,0,0};
  delta.invalidity_date = (TC_X509_time){2049,12,31,0,0,0}; delta.has_invalidity_date = 1;
  for (base.found = 0; base.found <= 1; ++base.found)
    for (delta.found = 0; delta.found <= 1; ++delta.found)
      for (delta.reason = 0; delta.reason < 256; ++delta.reason) {
        const int invalid = delta.found && (delta.reason == 7 || delta.reason > 10);
        combined = saved;
        munit_assert_int(tc_x509_crl_combine(&base,&delta,&combined), ==,
            invalid ? TC_TLV_INVALID : TC_TLV_OK);
        if (invalid) {
          munit_assert_memory_equal(sizeof combined,&combined,&saved);
          continue;
        }
        const int cleared = delta.found && delta.reason == 8;
        const int found = !cleared && (base.found || delta.found);
        munit_assert_int(combined.found, ==, found);
        munit_assert_uint(combined.reason, ==, !found ? 0 : delta.found ? delta.reason : base.reason);
        munit_assert_uint(combined.revoked_at.year, ==, !found ? 0 : delta.found ? 2050 : 2024);
        munit_assert_int(combined.has_invalidity_date, ==, found && delta.found);
        munit_assert_uint(combined.invalidity_date.year, ==, found && delta.found ? 2049 : 0);
      }
  base.found = 1; base.reason = 6;
  munit_assert_int(tc_x509_crl_combine(&base,NULL,&combined), ==, TC_TLV_OK);
  munit_assert_int(combined.found, ==, 1);
  munit_assert_uint(combined.reason, ==, 6);
  const unsigned bad_base_reasons[] = {7,8,11};
  for (size_t i = 0; i < sizeof bad_base_reasons / sizeof bad_base_reasons[0]; ++i) {
    base.reason = bad_base_reasons[i]; combined = saved;
    munit_assert_int(tc_x509_crl_combine(&base,NULL,&combined), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof combined,&combined,&saved);
  }
  base.found = 2; combined = saved;
  munit_assert_int(tc_x509_crl_combine(&base,NULL,&combined), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof combined,&combined,&saved);
  munit_assert_int(tc_x509_crl_combine(NULL,NULL,&combined), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult scope_groups(const MunitParameter params[], void* user)
{
  const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  uint8_t other[sizeof issuer];
  const uint8_t idp[] = {0x30,3,0x84,1,0xff}, different[] = {0x30,3,0x81,1,0xff};
  tc_x509_crl a = {0}, b = {0};
  a.issuer = (TC_bytes){issuer,sizeof issuer}; b.issuer = (TC_bytes){other,sizeof other};
  TC_TLV_frame frames[FRAME_CAPACITY];
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32]; uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  (void)params; (void)user;
  enum { SAME, NORMALIZED_NAME, OTHER_ISSUER, ONE_IDP, SAME_IDP, OTHER_IDP, AUTHORITY_HINT };
  const int expected[] = {1,1,0,0,1,0,1};
  for (unsigned scenario = SAME; scenario <= AUTHORITY_HINT; ++scenario) {
    tc_x509_crl_extension_info ai = {0}, bi = {0};
    memcpy(other,issuer,sizeof other);
    if (scenario == NORMALIZED_NAME) other[sizeof other - 1] = 'a';
    if (scenario == OTHER_ISSUER) other[sizeof other - 1] = 'B';
    if (scenario >= ONE_IDP && scenario <= OTHER_IDP) {
      ai.present = TC_CRL_EXT_DISTRIBUTION;
      ai.distribution_encoded = (TC_bytes){idp,sizeof idp};
      if (scenario != ONE_IDP) {
        bi = ai;
        if (scenario == OTHER_IDP) bi.distribution_encoded = (TC_bytes){different,sizeof different};
      }
    }
    if (scenario == AUTHORITY_HINT) ai.present = TC_CRL_EXT_AUTHORITY;
    int equal = -1; work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_scope_equal(&a,&ai,&b,&bi,&limits,&tree,&names,&equal), ==, TC_TLV_OK);
    munit_assert_int(equal, ==, expected[scenario]);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget <= required; ++budget) {
      equal = -1; work = budget;
      munit_assert_int(tc_x509_crl_scope_equal(&a,&ai,&b,&bi,&limits,&tree,&names,&equal),
          ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
      munit_assert_int(equal, ==, budget == required ? expected[scenario] : -1);
    }
  }
  return MUNIT_OK;
}

static MunitResult delta_pairing(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  uint8_t delta_issuer[sizeof issuer]; memcpy(delta_issuer,issuer,sizeof issuer);
  uint8_t number = 5, minimum = 3, newer = 7;
  tc_x509_crl base = {0}, delta = {0};
  base.issuer = (TC_bytes){issuer,sizeof issuer};
  delta.issuer = (TC_bytes){delta_issuer,sizeof delta_issuer};
  tc_x509_crl_extension_info base_info = {0}, delta_info = {0};
  base_info.present = TC_CRL_EXT_NUMBER;
  delta_info.present = TC_CRL_EXT_NUMBER | TC_CRL_EXT_DELTA;
  delta_info.critical = TC_CRL_EXT_DELTA;
  base_info.number = (TC_bytes){&number,1};
  delta_info.number = (TC_bytes){&newer,1};
  delta_info.base_number = (TC_bytes){&minimum,1};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32]; uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  int compatible;
  for (number = 2; number <= 8; ++number) {
    work = WORK_BUDGET; compatible = 99;
    munit_assert_int(tc_x509_crl_delta_compatible(&base,&base_info,&delta,&delta_info,
        &limits,&tree,&names,&compatible), ==, TC_TLV_OK);
    munit_assert_int(compatible, ==, number >= minimum && number < newer);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; compatible = 99;
      munit_assert_int(tc_x509_crl_delta_compatible(&base,&base_info,&delta,&delta_info,
          &limits,&tree,&names,&compatible), ==, TC_TLV_LIMIT);
      munit_assert_int(compatible, ==, 99);
    }
    work = required;
    munit_assert_int(tc_x509_crl_delta_compatible(&base,&base_info,&delta,&delta_info,
        &limits,&tree,&names,&compatible), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
  }
  number = 5;
  enum { ISSUER_DIFFERENT, ISSUER_CASE, NOT_DELTA, BASE_IS_DELTA, IDP_MISSING,
    IDP_SAME, IDP_DIFFERENT, AKID_MISSING, AKID_SAME, AKID_DIFFERENT, UNKNOWN_CRITICAL };
  const int expected[] = {0,1,0,0,0,1,0,0,1,0};
  const uint8_t idp[] = {0x30,3,0x84,1,0xff}, other_idp[] = {0x30,3,0x81,1,0xff};
  const uint8_t key[] = {1}, other_key[] = {2}, unknown[] = {0x55,0x1d,127};
  for (unsigned change = ISSUER_DIFFERENT; change <= UNKNOWN_CRITICAL; ++change) {
    tc_x509_crl_extension_info a = base_info, b = delta_info;
    delta_issuer[sizeof delta_issuer - 1] = 'A';
    switch (change) {
      case ISSUER_DIFFERENT: delta_issuer[sizeof delta_issuer - 1] = 'B'; break;
      case ISSUER_CASE: delta_issuer[sizeof delta_issuer - 1] = 'a'; break;
      case NOT_DELTA: b.present &= ~TC_CRL_EXT_DELTA; b.critical = 0; break;
      case BASE_IS_DELTA: a.present |= TC_CRL_EXT_DELTA; a.critical |= TC_CRL_EXT_DELTA; break;
      case IDP_MISSING: case IDP_SAME: case IDP_DIFFERENT:
        a.present |= TC_CRL_EXT_DISTRIBUTION; a.critical |= TC_CRL_EXT_DISTRIBUTION;
        a.distribution_encoded = (TC_bytes){idp,sizeof idp};
        if (change != IDP_MISSING) {
          b.present |= TC_CRL_EXT_DISTRIBUTION; b.critical |= TC_CRL_EXT_DISTRIBUTION;
          b.distribution_encoded = change == IDP_SAME ? a.distribution_encoded :
              (TC_bytes){other_idp,sizeof other_idp};
        }
        break;
      case AKID_MISSING: case AKID_SAME: case AKID_DIFFERENT:
        a.present |= TC_CRL_EXT_AUTHORITY; a.authority.has_key_identifier = 1;
        a.authority.key_identifier = (TC_bytes){key,sizeof key};
        if (change != AKID_MISSING) {
          b.present |= TC_CRL_EXT_AUTHORITY; b.authority.has_key_identifier = 1;
          b.authority.key_identifier = change == AKID_SAME ? a.authority.key_identifier :
              (TC_bytes){other_key,sizeof other_key};
        }
        break;
      case UNKNOWN_CRITICAL: b.unknown_critical_oid = (TC_bytes){unknown,sizeof unknown}; break;
    }
    work = WORK_BUDGET; compatible = 99;
    munit_assert_int(tc_x509_crl_delta_compatible(&base,&a,&delta,&b,&limits,&tree,&names,&compatible), ==,
        change == UNKNOWN_CRITICAL ? TC_TLV_UNSUPPORTED : TC_TLV_OK);
    munit_assert_int(compatible, ==, change == UNKNOWN_CRITICAL ? 99 : expected[change]);
  }
  /* Twenty magnitude octets plus DER's leading sign octet. */
  uint8_t large[21] = {0,0x80}, larger[21] = {0,0x80};
  larger[sizeof larger - 1] = 1;
  base_info.number = delta_info.base_number = (TC_bytes){large,sizeof large};
  delta_info.number = (TC_bytes){larger,sizeof larger};
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_delta_compatible(&base,&base_info,&delta,&delta_info,
      &limits,&tree,&names,&compatible), ==, TC_TLV_OK);
  munit_assert_int(compatible, ==, 1);
  return MUNIT_OK;
}

static MunitResult issuer_inheritance(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  fixture list = {0}; const uint8_t list_header[] = {0x30,0x81,0};
  append(&list,list_header,sizeof list_header);
  size_t last_entry_offset = 0;
  for (unsigned i = 0; i < 5; ++i) {
    fixture entry = {0};
    const uint8_t fields[] = {0x30,0,2,1,(uint8_t)(i + 1),0x17,13,
      '2','6','0','1','0','1','0','0','0','0','0','0','Z'};
    append(&entry,fields,sizeof fields);
    if (i == 1 || i == 3) {
      fixture extensions = {0}; const uint8_t header[] = {0x30,0};
      uint8_t names[] = {0x30,19,0x82,1,'x',0xa4,14,0x30,12,0x31,10,
        0x30,8,6,3,0x55,4,3,0x0c,1,'B'};
      names[sizeof names - 1] = i == 1 ? 'B' : 'C';
      append(&extensions,header,sizeof header);
      append_extension(&extensions,29,1,(TC_bytes){names,sizeof names});
      extensions.bytes[1] = (uint8_t)(extensions.length - 2);
      append(&entry,extensions.bytes,extensions.length);
    }
    entry.bytes[1] = (uint8_t)(entry.length - 2);
    last_entry_offset = list.length;
    append(&list,entry.bytes,entry.length);
  }
  munit_assert_size(list.length - 3, >=, 128);
  list.bytes[2] = (uint8_t)(list.length - 3);
  tc_x509_crl crl = {0}; tc_x509_crl_extension_info info = {0};
  crl.version = 2; crl.issuer = (TC_bytes){issuer,sizeof issuer};
  crl.revoked = (TC_bytes){list.bytes,list.length};
  info.present = info.critical = TC_CRL_EXT_DISTRIBUTION; info.distribution.indirect = 1;
  TC_TLV_frame frames[FRAME_CAPACITY]; TC_bytes oids[2];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl_revoked_reader reader;
  tc_x509_crl_revoked_entry parsed, saved;
  for (size_t window_size = 1; window_size <= 64; window_size *= 8) {
    uint8_t window[64], entry_storage[FIXTURE_CAPACITY], issuer_storage[32];
    TC_bytes encoded = {list.bytes,list.length};
    TC_source source = {source_memory_read,&encoded,encoded.length};
    tc_source_reader source_reader;
    tc_x509_crl_source_revoked revoked;
    munit_assert_int(tc_source_reader_init(&source_reader,&source,
      (TC_buffer){window,window_size},16384,16384),==,TC_RESULT_OK);
    munit_assert_int(tc_x509_crl_source_revoked_init(&source_reader,
      (tc_source_span){0,encoded.length},&crl,&info,5,
      (TC_buffer){issuer_storage,sizeof issuer_storage},&revoked),==,TC_TLV_OK);
    for (unsigned i = 0; i < 5; ++i) {
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_source_revoked_next(&source_reader,&revoked,
        (TC_buffer){entry_storage,sizeof entry_storage},&limits,&tree,oids,2,&parsed),==,TC_TLV_OK);
      munit_assert_uint(parsed.entry.serial.data[0],==,i + 1);
      if (!i) munit_assert_ptr_equal(parsed.issuer.name.data,issuer);
      else {
        munit_assert_ptr_equal(parsed.issuer.names.data,issuer_storage);
        munit_assert_uint8(parsed.issuer.names.data[parsed.issuer.names.length - 1],==,i < 3 ? 'B' : 'C');
      }
      TC_bytes discarded;
      munit_assert_int(tc_source_reader_view(&source_reader,0,1,&discarded),==,TC_RESULT_OK);
      memset(entry_storage,0xa5,sizeof entry_storage);
    }
    munit_assert_int(tc_x509_crl_source_revoked_next(&source_reader,&revoked,
      (TC_buffer){entry_storage,sizeof entry_storage},&limits,&tree,oids,2,&parsed),==,TC_TLV_END);
    munit_assert_int(tc_source_reader_init(&source_reader,&source,
      (TC_buffer){window,window_size},16384,16384),==,TC_RESULT_OK);
    munit_assert_int(tc_x509_crl_source_revoked_init(&source_reader,
      (tc_source_span){0,encoded.length},&crl,&info,5,
      (TC_buffer){issuer_storage,1},&revoked),==,TC_TLV_OK);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_source_revoked_next(&source_reader,&revoked,
      (TC_buffer){entry_storage,sizeof entry_storage},&limits,&tree,oids,2,&parsed),==,TC_TLV_OK);
    const uint64_t before = revoked.entries.cursor;
    memcpy(&saved,&parsed,sizeof saved);
    memset(issuer_storage,0xa5,sizeof issuer_storage);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_source_revoked_next(&source_reader,&revoked,
      (TC_buffer){entry_storage,sizeof entry_storage},&limits,&tree,oids,2,&parsed),==,TC_TLV_LIMIT);
    munit_assert_true(revoked.entries.cursor == before);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    for (size_t i = 0; i < sizeof issuer_storage; ++i) munit_assert_uint8(issuer_storage[i],==,0xa5);
  }
  memset(&saved,0xa5,sizeof saved);
  munit_assert_int(tc_x509_crl_revoked_init(&crl,&info,&limits,&tree,&reader), ==, TC_TLV_OK);
  TC_bytes inherited = {NULL,0};
  for (unsigned i = 0; i < 5; ++i) {
    const tc_x509_crl_revoked_reader before = reader;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_revoked_next(&reader,&tree,oids,2,&parsed), ==, TC_TLV_OK);
    munit_assert_uint(parsed.entry.serial.data[0], ==, i + 1);
    if (!i) munit_assert_ptr_equal(parsed.issuer.name.data,issuer);
    else {
      if (i == 1 || i == 3) inherited = parsed.issuer.names;
      munit_assert_ptr_equal(parsed.issuer.names.data,inherited.data);
      munit_assert_uint(inherited.data[inherited.length - 1], ==, i < 3 ? 'B' : 'C');
      munit_assert_size(parsed.issuer.name.length, ==, 0);
    }
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      reader = before; parsed = saved; work = budget;
      munit_assert_int(tc_x509_crl_revoked_next(&reader,&tree,oids,2,&parsed), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof reader,&reader,&before);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
    reader = before; work = required;
    munit_assert_int(tc_x509_crl_revoked_next(&reader,&tree,oids,2,&parsed), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    uint8_t certificate_issuer[sizeof issuer];
    memcpy(certificate_issuer,issuer,sizeof issuer);
    certificate_issuer[sizeof certificate_issuer - 1] = !i ? 'A' : i < 3 ? 'B' : 'C';
    TC_X509_certificate certificate = {0};
    certificate.serial = parsed.entry.serial;
    certificate.issuer = (TC_bytes){certificate_issuer,sizeof certificate_issuer};
    uint32_t left[32], right[32]; uint8_t used[2];
    const TC_X509_name_workspace names = {left,right,32,used,2};
    int matched = 99; work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_entry_matches(&parsed,&certificate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    const size_t match_work = WORK_BUDGET - work;
    for (size_t budget = 0; budget < match_work; ++budget) {
      work = budget; matched = 99;
      munit_assert_int(tc_x509_crl_entry_matches(&parsed,&certificate,&limits,&tree,&names,&matched), ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, 99);
    }
    work = match_work;
    munit_assert_int(tc_x509_crl_entry_matches(&parsed,&certificate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    certificate_issuer[sizeof certificate_issuer - 1] += 'a' - 'A';
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_entry_matches(&parsed,&certificate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, !i);
    const uint8_t other_serial = 99;
    certificate.serial = (TC_bytes){&other_serial,1};
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_entry_matches(&parsed,&certificate,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
  }
  const tc_x509_crl_revoked_reader end = reader;
  parsed = saved;
  munit_assert_int(tc_x509_crl_revoked_next(&reader,&tree,oids,2,&parsed), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof reader,&reader,&end);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  uint32_t scan_left[32], scan_right[32]; uint8_t scan_used[2];
  const TC_X509_name_workspace scan_names = {scan_left,scan_right,32,scan_used,2};
  tc_x509_crl_match found, unchanged;
  memset(&unchanged,0xa5,sizeof unchanged);
  for (unsigned query = 0; query < 7; ++query) {
    uint8_t query_name[sizeof issuer]; memcpy(query_name,issuer,sizeof issuer);
    query_name[sizeof query_name - 1] = query == 6 ? 'B' : query < 1 || query > 4 ? 'A' : query < 3 ? 'B' : 'C';
    const uint8_t serial = query == 6 ? 1 : (uint8_t)(query + 1);
    TC_X509_certificate certificate = {0};
    certificate.serial = (TC_bytes){&serial,1};
    certificate.issuer = (TC_bytes){query_name,sizeof query_name};
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_find(&crl,&info,&certificate,&limits,&tree,&scan_names,oids,2,&found), ==, TC_TLV_OK);
    munit_assert_int(found.found, ==, query < 5);
    if (found.found) {
      munit_assert_uint(found.reason, ==, 0);
      munit_assert_uint(found.revoked_at.year, ==, 2026);
      munit_assert_int(found.has_invalidity_date, ==, 0);
    }
    if (!query) {
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; found = unchanged;
        munit_assert_int(tc_x509_crl_find(&crl,&info,&certificate,&limits,&tree,&scan_names,oids,2,&found), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof found,&found,&unchanged);
      }
      work = required;
      munit_assert_int(tc_x509_crl_find(&crl,&info,&certificate,&limits,&tree,&scan_names,oids,2,&found), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      enum { ENTRY_TIME_TAG_OFFSET = 5 };
      list.bytes[last_entry_offset + ENTRY_TIME_TAG_OFFSET] = 0x16;
      work = WORK_BUDGET; found = unchanged;
      munit_assert_int(tc_x509_crl_find(&crl,&info,&certificate,&limits,&tree,&scan_names,oids,2,&found), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof found,&found,&unchanged);
      list.bytes[last_entry_offset + ENTRY_TIME_TAG_OFFSET] = 0x17;
    }
  }
  /* The last two entries have issuer C; duplicate their serials. */
  enum { ENTRY_SERIAL_OFFSET = 4 };
  list.bytes[last_entry_offset + ENTRY_SERIAL_OFFSET] = 4;
  const uint8_t duplicate_serial = 4;
  uint8_t duplicate_name[sizeof issuer]; memcpy(duplicate_name,issuer,sizeof issuer);
  duplicate_name[sizeof duplicate_name - 1] = 'C';
  TC_X509_certificate duplicate = {0};
  duplicate.serial = (TC_bytes){&duplicate_serial,1};
  duplicate.issuer = (TC_bytes){duplicate_name,sizeof duplicate_name};
  work = WORK_BUDGET; found = unchanged;
  munit_assert_int(tc_x509_crl_find(&crl,&info,&duplicate,&limits,&tree,&scan_names,oids,2,&found), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof found,&found,&unchanged);
  list.bytes[last_entry_offset + ENTRY_SERIAL_OFFSET] = 5;
  /* Direct CRLs cannot change the entry issuer. Failure leaves the first issuer. */
  info.distribution.indirect = 0; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_revoked_init(&crl,&info,&limits,&tree,&reader), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_crl_revoked_next(&reader,&tree,oids,2,&parsed), ==, TC_TLV_OK);
  const tc_x509_crl_revoked_reader before = reader;
  parsed = saved;
  munit_assert_int(tc_x509_crl_revoked_next(&reader,&tree,oids,2,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader,&reader,&before);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  return MUNIT_OK;
}

static MunitResult entry_policy(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  tc_x509_crl_extension_info crl = {0};
  tc_x509_crl_entry_info entry = {0};
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_OK);
  entry.present = TC_CRL_ENTRY_REASON;
  entry.reason = 8;
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_INVALID);
  crl.present = TC_CRL_EXT_DELTA;
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_OK);
  entry.critical = TC_CRL_ENTRY_REASON;
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_INVALID);
  entry.present = entry.critical = TC_CRL_ENTRY_INVALIDITY;
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_INVALID);
  entry.critical = 0;
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_OK);
  entry.present = TC_CRL_ENTRY_ISSUER;
  for (unsigned idp = 0; idp < 2; ++idp)
    for (int indirect = 0; indirect < 2; ++indirect)
      for (unsigned critical = 0; critical < 2; ++critical) {
        crl.present = idp ? TC_CRL_EXT_DISTRIBUTION : 0;
        crl.distribution.indirect = indirect;
        entry.critical = critical ? TC_CRL_ENTRY_ISSUER : 0;
        munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==,
            idp && indirect && critical ? TC_TLV_OK : TC_TLV_INVALID);
      }
  const uint8_t unknown[] = {0x55,0x1d,127};
  entry.unknown_critical_oid = (TC_bytes){unknown,sizeof unknown};
  munit_assert_int(tc_x509_crl_entry_policy(&crl,&entry), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(tc_x509_crl_entry_policy(NULL,&entry), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_x509_crl_entry_policy(&crl,NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult entry_info(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t reason[] = {10,1,8};
  const uint8_t date[] = {0x18,15,'2','0','2','4','0','2','2','9','0','0','0','0','0','0','Z'};
  const uint8_t issuer[] = {0x30,3,0x82,1,'a'};
  const TC_bytes values[] = {{reason,sizeof reason},{date,sizeof date},{issuer,sizeof issuer}};
  const uint8_t arcs[] = {21,24,29};
  const unsigned flags[] = {TC_CRL_ENTRY_REASON,TC_CRL_ENTRY_INVALIDITY,TC_CRL_ENTRY_ISSUER};
  TC_TLV_frame frames[FRAME_CAPACITY]; TC_bytes oids[4];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl_entry_info info, saved;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned critical = 0; critical < 8; ++critical) {
    fixture input = {0};
    const uint8_t sequence[] = {0x30,0}; append(&input,sequence,sizeof sequence);
    unsigned expected = 0;
    for (size_t i = 0; i < sizeof arcs; ++i) {
      const int is_critical = !!(critical & (1u << i));
      append_extension(&input,arcs[i],is_critical,values[i]);
      if (is_critical) expected |= flags[i];
    }
    const size_t unknown_offset = input.length;
    append_extension(&input,127,1,values[0]);
    input.bytes[1] = (uint8_t)(input.length - 2);
    const TC_bytes encoded = {input.bytes,input.length};
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_entry_info_read(encoded,&limits,&tree,oids,4,&info), ==, TC_TLV_OK);
    munit_assert_uint(info.present, ==, TC_CRL_ENTRY_REASON | TC_CRL_ENTRY_INVALIDITY | TC_CRL_ENTRY_ISSUER);
    munit_assert_uint(info.critical, ==, expected);
    munit_assert_uint(info.reason, ==, 8);
    munit_assert_uint(info.invalidity_date.year, ==, 2024);
    munit_assert_uint(info.invalidity_date.day, ==, 29);
    munit_assert_size(info.issuer.length, ==, sizeof issuer - 2);
    munit_assert_memory_equal(info.issuer.length,info.issuer.data,issuer + 2);
    munit_assert_ptr_equal(info.unknown_critical_oid.data,input.bytes + unknown_offset + 4);
    if (!critical) {
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; info = saved;
        munit_assert_int(tc_x509_crl_entry_info_read(encoded,&limits,&tree,oids,4,&info), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof info,&info,&saved);
      }
      work = required;
      munit_assert_int(tc_x509_crl_entry_info_read(encoded,&limits,&tree,oids,4,&info), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
    }
    input.bytes[unknown_offset + 6] = arcs[0];
    work = WORK_BUDGET; info = saved;
    munit_assert_int(tc_x509_crl_entry_info_read(encoded,&limits,&tree,oids,4,&info), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof info,&info,&saved);
  }
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_entry_info_read((TC_bytes){NULL,0},&limits,&tree,oids,4,&info), ==, TC_TLV_OK);
  munit_assert_uint(info.present, ==, 0);
  munit_assert_uint(info.reason, ==, 0);
  return MUNIT_OK;
}

static MunitResult extension_policy(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const struct { unsigned present, critical; TC_TLV_result result; } cases[] = {
    {0,0,TC_TLV_OK},
    {TC_CRL_EXT_NUMBER,0,TC_TLV_OK},
    {TC_CRL_EXT_NUMBER,TC_CRL_EXT_NUMBER,TC_TLV_INVALID},
    {TC_CRL_EXT_DELTA,0,TC_TLV_INVALID},
    {TC_CRL_EXT_DELTA,TC_CRL_EXT_DELTA,TC_TLV_OK},
    {TC_CRL_EXT_DISTRIBUTION,0,TC_TLV_INVALID},
    {TC_CRL_EXT_DISTRIBUTION,TC_CRL_EXT_DISTRIBUTION,TC_TLV_OK},
    {TC_CRL_EXT_FRESHEST,0,TC_TLV_OK},
    {TC_CRL_EXT_FRESHEST,TC_CRL_EXT_FRESHEST,TC_TLV_INVALID},
    {TC_CRL_EXT_ISSUER_ALT,TC_CRL_EXT_ISSUER_ALT,TC_TLV_OK},
    {TC_CRL_EXT_AUTHORITY,TC_CRL_EXT_AUTHORITY,TC_TLV_OK},
    {TC_CRL_EXT_DELTA | TC_CRL_EXT_FRESHEST,TC_CRL_EXT_DELTA,TC_TLV_INVALID},
    {TC_CRL_EXT_NUMBER | TC_CRL_EXT_DELTA | TC_CRL_EXT_DISTRIBUTION,
      TC_CRL_EXT_DELTA | TC_CRL_EXT_DISTRIBUTION,TC_TLV_OK},
    {0,TC_CRL_EXT_NUMBER,TC_TLV_ARGUMENT}
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    tc_x509_crl_extension_info info = {0};
    info.present = cases[i].present; info.critical = cases[i].critical;
    const tc_x509_crl_extension_info saved = info;
    munit_assert_int(tc_x509_crl_extension_policy(&info), ==, cases[i].result);
    munit_assert_memory_equal(sizeof info,&info,&saved);
  }
  const uint8_t unknown[] = {0x55,0x1d,127};
  tc_x509_crl_extension_info info = {0};
  info.unknown_critical_oid = (TC_bytes){unknown,sizeof unknown};
  munit_assert_int(tc_x509_crl_extension_policy(&info), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(tc_x509_crl_extension_policy(NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult extension_info(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const struct { uint8_t arc, length; uint8_t value[16]; unsigned flag; } values[] = {
    {20,3,{2,1,9},TC_X509_CRL_EXT_NUMBER}, {27,3,{2,1,7},TC_X509_CRL_EXT_DELTA},
    {35,5,{0x30,3,0x80,1,42},TC_X509_CRL_EXT_AUTHORITY},
    {28,5,{0x30,3,0x84,1,0xff},TC_X509_CRL_EXT_DISTRIBUTION},
    {46,11,{0x30,9,0x30,7,0xa0,5,0xa0,3,0x82,1,'a'},TC_X509_CRL_EXT_FRESHEST},
    {18,5,{0x30,3,0x82,1,'a'},TC_X509_CRL_EXT_ISSUER_ALT}
  };
  TC_TLV_frame frames[FRAME_CAPACITY]; TC_bytes oids[8];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work;
  const TC_X509_workspace workspace = {frames,FRAME_CAPACITY,oids,8};
  TC_X509_crl_extensions info, saved;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned critical = 0; critical < 64; ++critical) {
    fixture input = {0};
    const uint8_t sequence[] = {0x30,0}; append(&input,sequence,sizeof sequence);
    unsigned present = 0, expected_critical = 0;
    for (size_t i = 0; i < sizeof values / sizeof values[0]; ++i) {
      const int is_critical = !!(critical & (1u << i));
      append_extension(&input,values[i].arc,is_critical,(TC_bytes){values[i].value,values[i].length});
      present |= values[i].flag;
      if (is_critical) expected_critical |= values[i].flag;
    }
    const uint8_t unknown[] = {0x30,13,6,3,0x55,0x1d,127,1,1,0xff,4,3,2,1,9};
    const size_t unknown_offset = input.length;
    append(&input,unknown,sizeof unknown);
    input.bytes[1] = (uint8_t)(input.length - 2);
    work = WORK_BUDGET;
    const TC_bytes encoded = {input.bytes,input.length};
    munit_assert_int(TC_X509_crl_extensions_read(encoded,&limits,&workspace,&work,&info), ==, TC_TLV_OK);
    munit_assert_uint(info.present, ==, present);
    munit_assert_uint(info.critical, ==, expected_critical);
    munit_assert_uint(info.number.data[0], ==, 9);
    munit_assert_uint(info.base_number.data[0], ==, 7);
    munit_assert_uint(info.authority.key_identifier.data[0], ==, 42);
    munit_assert_int(info.distribution.indirect, ==, 1);
    munit_assert_size(info.freshest.length, ==, 11);
    munit_assert_size(info.issuer_alt.length, ==, 3);
    munit_assert_ptr_equal(info.unknown_critical_oid.data,input.bytes + unknown_offset + 4);
    munit_assert_int(tc_x509_crl_extension_policy(&info), ==, TC_TLV_UNSUPPORTED);
    if (!critical) {
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; info = saved;
        munit_assert_int(TC_X509_crl_extensions_read(encoded,&limits,&workspace,&work,&info), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof info,&info,&saved);
      }
      work = required;
      munit_assert_int(TC_X509_crl_extensions_read(encoded,&limits,&workspace,&work,&info), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
    }
    /* Duplicate CRLNumber after the earlier fields have populated scratch. */
    input.bytes[unknown_offset + 6] = 20;
    work = WORK_BUDGET; info = saved;
    munit_assert_int(TC_X509_crl_extensions_read(encoded,&limits,&workspace,&work,&info), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof info,&info,&saved);
  }
  work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_extensions_read((TC_bytes){NULL,0},&limits,&workspace,&work,&info), ==, TC_TLV_OK);
  munit_assert_uint(info.present, ==, 0);
  munit_assert_uint(info.critical, ==, 0);
  const TC_bytes absent = {NULL,0};
  info = saved; work = WORK_BUDGET;
  munit_assert_int(TC_X509_crl_extensions_read(absent,NULL,&workspace,&work,&info), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_extensions_read(absent,&limits,NULL,&work,&info), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_extensions_read(absent,&limits,&workspace,NULL,&info), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_extensions_read(absent,&limits,&workspace,&work,NULL), ==, TC_TLV_ARGUMENT);
  TC_X509_workspace invalid = workspace;
  invalid.extension_capacity = SIZE_MAX;
  munit_assert_int(TC_X509_crl_extensions_read(absent,&limits,&invalid,&work,&info), ==, TC_TLV_ARGUMENT);
  invalid = workspace; invalid.extension_oids = (TC_bytes*)&info; invalid.extension_capacity = 1;
  munit_assert_int(TC_X509_crl_extensions_read(absent,&limits,&invalid,&work,&info), ==, TC_TLV_ARGUMENT);
  invalid.extension_oids = (TC_bytes*)frames;
  munit_assert_int(TC_X509_crl_extensions_read(absent,&limits,&invalid,&work,&info), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_memory_equal(sizeof info,&info,&saved);
  return MUNIT_OK;
}

static MunitResult freshness(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  tc_x509_crl crl = {0};
  crl.this_update = (TC_X509_time){2049,12,31,23,59,59};
  crl.next_update = (TC_X509_time){2050,1,1,0,0,1};
  crl.has_next_update = 1;
  const struct { TC_X509_time at; tc_x509_crl_freshness expected; } cases[] = {
    {{2049,12,31,23,59,58},TC_X509_CRL_FUTURE},
    {{2049,12,31,23,59,59},TC_X509_CRL_CURRENT},
    {{2050,1,1,0,0,0},TC_X509_CRL_CURRENT},
    {{2050,1,1,0,0,1},TC_X509_CRL_STALE},
    {{2050,1,1,0,0,2},TC_X509_CRL_STALE}
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    tc_x509_crl_freshness state = TC_X509_CRL_NO_NEXT_UPDATE;
    munit_assert_int(tc_x509_crl_fresh_at(&crl,&cases[i].at,&state), ==, TC_TLV_OK);
    munit_assert_int(state, ==, cases[i].expected);
  }
  tc_x509_crl_freshness state = TC_X509_CRL_CURRENT;
  crl.has_next_update = 0;
  munit_assert_int(tc_x509_crl_fresh_at(&crl,&crl.this_update,&state), ==, TC_TLV_OK);
  munit_assert_int(state, ==, TC_X509_CRL_NO_NEXT_UPDATE);
  munit_assert_int(tc_x509_crl_fresh_at(&crl,&cases[0].at,&state), ==, TC_TLV_OK);
  munit_assert_int(state, ==, TC_X509_CRL_FUTURE);
  crl.has_next_update = 1;
  crl.next_update = crl.this_update;
  munit_assert_int(tc_x509_crl_fresh_at(&crl,&crl.this_update,&state), ==, TC_TLV_OK);
  munit_assert_int(state, ==, TC_X509_CRL_STALE);
  crl.next_update.second--;
  state = TC_X509_CRL_NO_NEXT_UPDATE;
  munit_assert_int(tc_x509_crl_fresh_at(&crl,&crl.this_update,&state), ==, TC_TLV_INVALID);
  munit_assert_int(state, ==, TC_X509_CRL_NO_NEXT_UPDATE);
  crl.this_update = (TC_X509_time){2024,2,29,0,0,0};
  crl.next_update = (TC_X509_time){2024,3,1,0,0,0};
  munit_assert_int(tc_x509_crl_fresh_at(&crl,&crl.this_update,&state), ==, TC_TLV_OK);
  munit_assert_int(state, ==, TC_X509_CRL_CURRENT);
  TC_X509_time invalid = {2023,2,29,0,0,0};
  for (unsigned field = 0; field < 3; ++field) {
    tc_x509_crl bad = crl;
    const TC_X509_time* at = &crl.this_update;
    if (field == 0) at = &invalid;
    else if (field == 1) bad.this_update = invalid;
    else bad.next_update = invalid;
    state = TC_X509_CRL_NO_NEXT_UPDATE;
    munit_assert_int(tc_x509_crl_fresh_at(&bad,at,&state), ==, TC_TLV_INVALID);
    munit_assert_int(state, ==, TC_X509_CRL_NO_NEXT_UPDATE);
  }
  return MUNIT_OK;
}

static MunitResult scope_reasons(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t issuer[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint16_t expected[] = {TC_X509_CRL_ALL_REASONS,10,6,2};
  const int permitted[4][2] = {{1,1},{1,0},{0,1},{0,0}};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32]; uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl crl = {0}; crl.issuer = (TC_bytes){issuer,sizeof issuer};
  enum { UNRESTRICTED, USER_ONLY, CA_ONLY, ATTRIBUTE_ONLY, SENTINEL = 0xdead };
  for (unsigned type = UNRESTRICTED; type <= ATTRIBUTE_ONLY; ++type)
    for (int ca = 0; ca <= 1; ++ca)
      for (unsigned mask = 0; mask < 4; ++mask) {
        tc_x509_crl_distribution idp = {0}; tc_pki_distribution_point point = {0};
        idp.user_only = type == USER_ONLY; idp.ca_only = type == CA_ONLY;
        idp.attribute_only = type == ATTRIBUTE_ONLY;
        idp.has_reasons = !!(mask & 2); idp.reasons = 6;
        point.has_reasons = !!(mask & 1); point.reasons = 10;
        const uint16_t wanted = permitted[type][ca] ? expected[mask] : 0;
        work = WORK_BUDGET; uint16_t reasons = SENTINEL;
        munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,ca,
            &limits,&tree,&names,&reasons), ==, TC_TLV_OK);
        munit_assert_uint(reasons, ==, wanted);
        const size_t required = WORK_BUDGET - work;
        for (size_t budget = 0; budget < required; ++budget) {
          work = budget; reasons = SENTINEL;
          munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,ca,
              &limits,&tree,&names,&reasons), ==, TC_TLV_LIMIT);
          munit_assert_uint(reasons, ==, SENTINEL);
        }
        work = required;
        munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,ca,
            &limits,&tree,&names,&reasons), ==, TC_TLV_OK);
        munit_assert_size(work, ==, 0);
      }
  tc_pki_distribution_point point = {0}; tc_x509_crl_distribution idp = {0};
  uint16_t reasons = SENTINEL; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_scope_reasons(&crl,NULL,&point,crl.issuer,0,
      &limits,&tree,&names,&reasons), ==, TC_TLV_OK);
  munit_assert_uint(reasons, ==, TC_X509_CRL_ALL_REASONS);
  idp.has_reasons = 1; idp.reasons = 3; point.has_reasons = 1; point.reasons = 4;
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,0,
      &limits,&tree,&names,&reasons), ==, TC_TLV_OK);
  munit_assert_uint(reasons, ==, 0);
  point.has_reasons = 0; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,0,
      &limits,&tree,&names,&reasons), ==, TC_TLV_OK);
  munit_assert_uint(reasons, ==, 2);
  reasons = SENTINEL; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,2,
      &limits,&tree,&names,&reasons), ==, TC_TLV_ARGUMENT);
  munit_assert_uint(reasons, ==, SENTINEL);
  {
    tc_x509_crl_extension_info info = {0};
    tc_x509_crl_coverage coverage, saved;
    memset(&saved,0xa5,sizeof saved);
    crl.this_update = (TC_X509_time){2026,1,1,0,0,0};
    crl.next_update = (TC_X509_time){2027,1,1,0,0,0};
    point = (tc_pki_distribution_point){0}; point.has_reasons = 1; point.reasons = 6;
    info.distribution.ca_only = 1;
    info.distribution.has_reasons = 1; info.distribution.reasons = 10;
    const tc_x509_crl_freshness states[] = {
      TC_X509_CRL_FUTURE,TC_X509_CRL_CURRENT,TC_X509_CRL_STALE,TC_X509_CRL_NO_NEXT_UPDATE};
    for (unsigned state = 0; state < sizeof states / sizeof states[0]; ++state)
      for (int restricted = 0; restricted <= 1; ++restricted)
        for (int ca = 0; ca <= 1; ++ca) {
          TC_X509_time at = crl.this_update;
          if (states[state] == TC_X509_CRL_FUTURE) --at.year;
          if (states[state] == TC_X509_CRL_STALE) ++at.year;
          crl.has_next_update = states[state] != TC_X509_CRL_NO_NEXT_UPDATE;
          info.present = info.critical = restricted ? TC_CRL_EXT_DISTRIBUTION : 0;
          const uint16_t wanted = states[state] != TC_X509_CRL_CURRENT ? 0 :
              !restricted ? point.reasons : ca ? 2 : 0;
          work = WORK_BUDGET;
          munit_assert_int(tc_x509_crl_coverage_at(&crl,&info,&at,&point,crl.issuer,ca,
              &limits,&tree,&names,&coverage), ==, TC_TLV_OK);
          munit_assert_int(coverage.freshness, ==, states[state]);
          munit_assert_uint(coverage.reasons, ==, wanted);
          const size_t required = WORK_BUDGET - work;
          for (size_t budget = 0; budget < required; ++budget) {
            work = budget; memcpy(&coverage,&saved,sizeof coverage);
            munit_assert_int(tc_x509_crl_coverage_at(&crl,&info,&at,&point,crl.issuer,ca,
                &limits,&tree,&names,&coverage), ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof coverage,&coverage,&saved);
          }
          work = required;
          munit_assert_int(tc_x509_crl_coverage_at(&crl,&info,&at,&point,crl.issuer,ca,
              &limits,&tree,&names,&coverage), ==, TC_TLV_OK);
          munit_assert_size(work, ==, 0);
        }
    info.critical = 0;
    work = WORK_BUDGET; memcpy(&coverage,&saved,sizeof coverage);
    munit_assert_int(tc_x509_crl_coverage_at(&crl,&info,&crl.this_update,&point,crl.issuer,0,
        &limits,&tree,&names,&coverage), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof coverage,&coverage,&saved);
    info = (tc_x509_crl_extension_info){0};
    static const uint8_t unknown_oid[] = {0x2a,3};
    info.unknown_critical_oid = (TC_bytes){unknown_oid,sizeof unknown_oid};
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_coverage_at(&crl,&info,&crl.this_update,&point,crl.issuer,0,
        &limits,&tree,&names,&coverage), ==, TC_TLV_UNSUPPORTED);
    munit_assert_memory_equal(sizeof coverage,&coverage,&saved);
    info.unknown_critical_oid = (TC_bytes){NULL,0}; crl.this_update.year = 0;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_coverage_at(&crl,&info,&crl.next_update,&point,crl.issuer,0,
        &limits,&tree,&names,&coverage), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof coverage,&coverage,&saved);
  }
  return MUNIT_OK;
}

static MunitResult name_scope(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  enum { FULL_DN, RELATIVE_DN, DNS_A, DNS_B, ISSUER_DN, DNS_LIST, ISSUER_FALLBACK };
  static const struct { size_t length; uint8_t bytes[32]; } encodings[] = {
    {30,{0xa0,28,0xa4,26,0x30,24,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A',
      0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'B'}},
    {12,{0xa1,10,0x30,8,6,3,0x55,4,3,0x0c,1,'b'}},
    {5,{0xa0,3,0x82,1,'a'}},{5,{0xa0,3,0x82,1,'b'}},
    {18,{0xa0,16,0xa4,14,0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'}},
    {8,{0xa0,6,0x82,1,'a',0x82,1,'b'}}
  };
  static const struct { unsigned idp, dp; int match; } cases[] = {
    {FULL_DN,RELATIVE_DN,1},{RELATIVE_DN,FULL_DN,1},{RELATIVE_DN,RELATIVE_DN,1},
    {FULL_DN,ISSUER_DN,0},{DNS_A,DNS_B,0},{DNS_LIST,DNS_B,1},
    {DNS_B,DNS_LIST,1},{RELATIVE_DN,DNS_A,0},
    {ISSUER_DN,ISSUER_FALLBACK,1},{FULL_DN,ISSUER_FALLBACK,0},{DNS_A,ISSUER_FALLBACK,0}
  };
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32]; uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_pki_distribution_name decoded[sizeof encodings / sizeof encodings[0]];
  for (size_t i = 0; i < sizeof encodings / sizeof encodings[0]; ++i) {
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_distribution_name_read((TC_bytes){encodings[i].bytes,encodings[i].length},
        &limits,&tree,&decoded[i]), ==, TC_TLV_OK);
  }
  tc_x509_crl crl = {0};
  crl.issuer = (TC_bytes){encodings[ISSUER_DN].bytes + 4,encodings[ISSUER_DN].length - 4};
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    tc_x509_crl_distribution idp = {0}; tc_pki_distribution_point point = {0};
    idp.name = decoded[cases[i].idp];
    if (cases[i].dp != ISSUER_FALLBACK) point.name = decoded[cases[i].dp];
    work = WORK_BUDGET; int matched = 99;
    munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, cases[i].match);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; matched = 99;
      munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, 99);
    }
    work = required;
    munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    uint16_t coverage = 0;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_scope_reasons(&crl,&idp,&point,crl.issuer,0,
        &limits,&tree,&names,&coverage), ==, TC_TLV_OK);
    munit_assert_uint(coverage, ==, cases[i].match ? TC_X509_CRL_ALL_REASONS : 0);
  }
  tc_x509_crl_distribution idp = {0}; tc_pki_distribution_point point = {0};
  point.issuer = decoded[ISSUER_DN].contents;
  idp.name = decoded[ISSUER_DN];
  work = WORK_BUDGET; int matched = 99;
  munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  point.name = decoded[RELATIVE_DN]; idp.name = decoded[FULL_DN];
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,(TC_bytes){NULL,0},&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  uint8_t other_issuer[16];
  memcpy(other_issuer,point.issuer.data,sizeof other_issuer);
  other_issuer[sizeof other_issuer - 1] = 'C';
  point.issuer = (TC_bytes){other_issuer,sizeof other_issuer};
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  const uint8_t bad_names[] = {0x82,1,'a',0x85,1,'b'};
  idp.name = decoded[DNS_A]; point.name = decoded[DNS_LIST];
  point.name.contents = (TC_bytes){bad_names,sizeof bad_names};
  work = WORK_BUDGET; matched = 99;
  munit_assert_int(tc_x509_crl_name_matches(&crl,&idp,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, 99);
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_name_matches(&crl,NULL,&point,crl.issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  return MUNIT_OK;
}

static MunitResult appended_names(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t base[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t full[] = {0x30,24,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A',
    0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'B'};
  const uint8_t suffix[] = {0x30,8,6,3,0x55,4,3,0x0c,1,'b'};
  const uint8_t root[] = {0x30,0}, malformed[] = {0x30,0};
  const TC_bytes none = {NULL,0}, a = {base,sizeof base}, ab = {full,sizeof full};
  const TC_bytes b = {suffix,sizeof suffix};
  const struct { TC_bytes left, left_rdn, right, right_rdn; int match; } cases[] = {
    {a,b,ab,none,1},{ab,none,a,b,1},{a,b,a,none,0},{a,none,a,b,0},
    {a,b,a,b,1},{{root,sizeof root},{base + 4,sizeof base - 4},a,none,1}
  };
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32];
  uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  int matched;
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    work = WORK_BUDGET; matched = 99;
    munit_assert_int(tc_pki_name_appended_equal(cases[i].left,cases[i].left_rdn,
        cases[i].right,cases[i].right_rdn,&limits,&names,&tree,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, cases[i].match);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; matched = 99;
      munit_assert_int(tc_pki_name_appended_equal(cases[i].left,cases[i].left_rdn,
          cases[i].right,cases[i].right_rdn,&limits,&names,&tree,&matched), ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, 99);
    }
    work = required;
    munit_assert_int(tc_pki_name_appended_equal(cases[i].left,cases[i].left_rdn,
        cases[i].right,cases[i].right_rdn,&limits,&names,&tree,&matched), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
  }
  work = WORK_BUDGET; matched = 99;
  munit_assert_int(tc_pki_name_appended_equal(a,(TC_bytes){malformed,sizeof malformed},
      a,none,&limits,&names,&tree,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, 99);
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_name_appended_equal(a,(TC_bytes){(const uint8_t*)left,sizeof suffix},
      a,none,&limits,&names,&tree,&matched), ==, TC_TLV_ARGUMENT);
  munit_assert_int(matched, ==, 99);
  munit_assert_size(work, ==, WORK_BUDGET);
  return MUNIT_OK;
}

static MunitResult issuer_linkage(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t directory[] = {0xa4,14,0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  uint8_t crl_name[sizeof directory - 2];
  const uint8_t dns[] = {0x82,1,'a'};
  const TC_bytes certificate_issuer = {directory + 2,sizeof directory - 2};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32];
  uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl crl = {0};
  crl.issuer = (TC_bytes){crl_name,sizeof crl_name};
  static const struct { int explicit_issuer, idp, indirect; uint8_t common_name; int match; } cases[] = {
    {0,0,0,'A',1},{0,0,0,'a',1},{0,0,0,'B',0},
    {1,0,0,'A',0},{1,1,0,'A',0},{1,1,1,'A',1},
    {1,1,1,'a',0},{1,1,1,'B',0}
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    tc_pki_distribution_point point = {0};
    tc_x509_crl_distribution idp = {0};
    memcpy(crl_name,certificate_issuer.data,sizeof crl_name);
    crl_name[sizeof crl_name - 1] = cases[i].common_name;
    if (cases[i].explicit_issuer) point.issuer = (TC_bytes){directory,sizeof directory};
    idp.indirect = cases[i].indirect;
    const tc_x509_crl_distribution* scope = cases[i].idp ? &idp : NULL;
    int matched = 99;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_issuer_matches(&crl,scope,&point,certificate_issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, cases[i].match);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; matched = 99;
      munit_assert_int(tc_x509_crl_issuer_matches(&crl,scope,&point,certificate_issuer,&limits,&tree,&names,&matched), ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, 99);
    }
    work = required; matched = 99;
    munit_assert_int(tc_x509_crl_issuer_matches(&crl,scope,&point,certificate_issuer,&limits,&tree,&names,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, cases[i].match);
    munit_assert_size(work, ==, 0);
    uint16_t coverage = 0;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_scope_reasons(&crl,scope,&point,certificate_issuer,0,
        &limits,&tree,&names,&coverage), ==, TC_TLV_OK);
    munit_assert_uint(coverage, ==, cases[i].match ? TC_X509_CRL_ALL_REASONS : 0);
  }
  tc_pki_distribution_point malformed_point = {0};
  malformed_point.issuer = (TC_bytes){dns,sizeof dns};
  work = WORK_BUDGET;
  int matched = 99;
  munit_assert_int(tc_x509_crl_issuer_matches(&crl,NULL,&malformed_point,certificate_issuer,&limits,&tree,&names,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, 99);
  return MUNIT_OK;
}

static MunitResult distribution_issuer(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const uint8_t directory[] = {0xa4,14,0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t dns[] = {0x82,1,'a'};
  const uint8_t empty_name[] = {0xa4,2,0x30,0};
  uint8_t repeated[sizeof directory * 2], mixed[sizeof directory + sizeof dns];
  memcpy(repeated,directory,sizeof directory);
  memcpy(repeated + sizeof directory,directory,sizeof directory);
  memcpy(mixed,directory,sizeof directory);
  memcpy(mixed + sizeof directory,dns,sizeof dns);
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  const TC_bytes input = {directory,sizeof directory}, saved = {NULL,99};
  TC_bytes name;
  munit_assert_int(tc_pki_distribution_issuer_name(input,&limits,&tree,&name), ==, TC_TLV_OK);
  munit_assert_ptr_equal(name.data,directory + 2);
  munit_assert_size(name.length, ==, sizeof directory - 2);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget; name = saved;
    munit_assert_int(tc_pki_distribution_issuer_name(input,&limits,&tree,&name), ==, TC_TLV_LIMIT);
    munit_assert_ptr_equal(name.data,saved.data);
    munit_assert_size(name.length, ==, saved.length);
  }
  work = required;
  munit_assert_int(tc_pki_distribution_issuer_name(input,&limits,&tree,&name), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  const TC_bytes invalid[] = {{dns,sizeof dns},{empty_name,sizeof empty_name},
    {repeated,sizeof repeated},{mixed,sizeof mixed},{NULL,0}};
  for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    work = WORK_BUDGET; name = saved;
    munit_assert_int(tc_pki_distribution_issuer_name(invalid[i],&limits,&tree,&name), ==, TC_TLV_INVALID);
    munit_assert_ptr_equal(name.data,saved.data);
    munit_assert_size(name.length, ==, saved.length);
  }
  return MUNIT_OK;
}

static MunitResult distribution_points(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const struct { size_t length; int valid, freshest; uint8_t bytes[24]; } cases[] = {
    {9,1,1,{0x30,7,0xa0,5,0xa0,3,0x82,1,'a'}},
    {7,1,0,{0x30,5,0xa2,3,0x82,1,'b'}},
    {13,1,0,{0x30,11,0xa0,5,0xa0,3,0x82,1,'a',0x81,2,6,0x40}},
    {11,1,0,{0x30,9,0x81,2,6,0x40,0xa2,3,0x82,1,'b'}},
    {14,1,0,{0x30,12,0xa0,5,0xa0,3,0x82,1,'a',0xa2,3,0x82,1,'b'}},
    {16,1,1,{0x30,14,0xa0,12,0xa1,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'}},
    {2,0,0,{0x30,0}}, {6,0,0,{0x30,4,0x81,2,6,0x40}},
    {4,0,0,{0x30,2,0xa2,0}}, {7,0,0,{0x30,5,0xa2,3,0x85,1,'b'}},
    {7,0,0,{0x30,5,0x82,3,0x82,1,'b'}},
    {11,0,0,{0x30,9,0xa2,3,0x82,1,'b',0x81,2,6,0x40}},
    {12,0,0,{0x30,10,0xa2,3,0x82,1,'b',0xa2,3,0x82,1,'b'}},
    {13,0,0,{0x30,11,0xa0,5,0xa0,3,0x82,1,'a',0x81,2,6,0x41}}
  };
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_pki_distribution_point point, saved;
  TC_TLV_reader reader, start;
  memset(&saved,0xa5,sizeof saved);
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    uint8_t list[64] = {0x30,(uint8_t)(cases[i].length * 2)};
    memcpy(list + 2,cases[i].bytes,cases[i].length);
    memcpy(list + 2 + cases[i].length,cases[i].bytes,cases[i].length);
    const size_t list_length = 2 + 2 * cases[i].length;
    uint8_t extensions[80] = {0x30,0,0x30,0,6,3,0x55,0x1d,46,4,0};
    extensions[1] = (uint8_t)(9 + list_length);
    extensions[3] = (uint8_t)(7 + list_length);
    extensions[10] = (uint8_t)list_length;
    memcpy(extensions + 11,list,list_length);
    tc_x509_crl crl = {0};
    TC_bytes oids[1];
    crl.version = 2;
    crl.extensions = (TC_bytes){extensions,11 + list_length};
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_extensions_check(&crl,&limits,&tree,oids,1), ==,
        cases[i].freshest ? TC_TLV_OK : TC_TLV_INVALID);
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_distribution_points_init((TC_bytes){list,2 + 2 * cases[i].length},&limits,&tree,&reader), ==, TC_TLV_OK);
    start = reader; point = saved; work = WORK_BUDGET;
    munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==,
        cases[i].valid ? TC_TLV_OK : TC_TLV_INVALID);
    if (!cases[i].valid) {
      munit_assert_memory_equal(sizeof point,&point,&saved);
      munit_assert_memory_equal(sizeof reader,&reader,&start);
      continue;
    }
    const size_t required = WORK_BUDGET - work;
    if (point.name.encoded.length) munit_assert_ptr_equal(point.name.encoded.data,list + 6);
    if (point.has_reasons) munit_assert_uint(point.reasons, ==, 2);
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==, TC_TLV_OK);
    const TC_TLV_reader end = reader;
    point = saved;
    munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==, TC_TLV_END);
    munit_assert_memory_equal(sizeof reader,&reader,&end);
    munit_assert_memory_equal(sizeof point,&point,&saved);
    for (size_t budget = 0; budget < required; ++budget) {
      reader = start; point = saved; work = budget;
      munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof reader,&reader,&start);
      munit_assert_memory_equal(sizeof point,&point,&saved);
    }
    reader = start; work = required;
    munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
  }
  const uint8_t empty[] = {0x30,0};
  work = WORK_BUDGET; start = reader;
  munit_assert_int(tc_pki_distribution_points_init((TC_bytes){empty,sizeof empty},&limits,&tree,&reader), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader,&reader,&start);
  return MUNIT_OK;
}

static MunitResult distribution(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const struct { size_t length; uint8_t bytes[24]; } valid[] = {
    {5,{0x30,3,0x81,1,0xff}}, {5,{0x30,3,0x82,1,0xff}},
    {5,{0x30,3,0x84,1,0xff}}, {5,{0x30,3,0x85,1,0xff}},
    {6,{0x30,4,0x83,2,6,0x40}},
    {9,{0x30,7,0xa0,5,0xa0,3,0x82,1,'a'}},
    {16,{0x30,14,0xa0,12,0xa1,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'}},
    {12,{0x30,10,0x81,1,0xff,0x83,2,6,0x40,0x84,1,0xff}}
  };
  static const struct { size_t length; uint8_t bytes[24]; } invalid[] = {
    {2,{0x30,0}}, {5,{0x30,3,0x81,1,0}}, {5,{0x30,3,0x81,1,1}},
    {5,{0x30,3,0x86,1,0xff}}, {5,{0x30,3,0xa1,1,0xff}},
    {8,{0x30,6,0x81,1,0xff,0x81,1,0xff}},
    {8,{0x30,6,0x84,1,0xff,0x81,1,0xff}},
    {8,{0x30,6,0x81,1,0xff,0x82,1,0xff}},
    {8,{0x30,6,0x82,1,0xff,0x85,1,0xff}},
    {8,{0x30,6,0x81,1,0xff,0x85,1,0xff}},
    {6,{0x30,4,0x83,2,6,0x41}}, {6,{0x30,4,0x83,2,0,0x40}},
    {7,{0x30,5,0x83,3,6,0,0x40}}, {4,{0x30,2,0x83,0}},
    {6,{0x30,4,0xa0,2,0xa0,0}}, {6,{0x30,4,0xa0,2,0xa1,0}},
    {9,{0x30,7,0xa0,5,0xa2,3,0x82,1,'a'}},
    {9,{0x30,7,0xa0,5,0xa0,3,0x85,1,'a'}},
    {9,{0x30,7,0xa0,5,0xa1,3,0x82,1,'a'}}
  };
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl_distribution parsed, saved;
  memset(&saved,0xa5,sizeof saved);
  for (size_t i = 0; i < sizeof valid / sizeof valid[0]; ++i) {
    const TC_bytes input = {valid[i].bytes,valid[i].length};
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_distribution_read(input,&limits,&tree,&parsed), ==, TC_TLV_OK);
    if (parsed.name.encoded.length) {
      munit_assert_ptr_equal(parsed.name.encoded.data,input.data + 4);
      munit_assert_int(parsed.name.relative, ==, input.data[4] == 0xa1);
    }
    if (parsed.has_reasons) munit_assert_uint(parsed.reasons, ==, 2);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      parsed = saved; work = budget;
      munit_assert_int(tc_x509_crl_distribution_read(input,&limits,&tree,&parsed), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
    work = required;
    munit_assert_int(tc_x509_crl_distribution_read(input,&limits,&tree,&parsed), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    for (size_t length = 0; length < input.length; ++length) {
      parsed = saved; work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_distribution_read((TC_bytes){input.data,length},&limits,&tree,&parsed), !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
  }
  for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    parsed = saved; work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_distribution_read((TC_bytes){invalid[i].bytes,invalid[i].length},&limits,&tree,&parsed), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  return MUNIT_OK;
}

static MunitResult named_bits(const MunitParameter params[], void* user)
{
  enum { REASON_BITS = 9, SENTINEL = 0xdead };
  (void)params; (void)user;
  const uint16_t usages[] = {
    TC_KEY_USAGE_DIGITAL_SIGNATURE, TC_KEY_USAGE_CONTENT_COMMITMENT,
    TC_KEY_USAGE_KEY_ENCIPHERMENT, TC_KEY_USAGE_DATA_ENCIPHERMENT,
    TC_KEY_USAGE_KEY_AGREEMENT, TC_KEY_USAGE_CERT_SIGN,
    TC_KEY_USAGE_CRL_SIGN, TC_KEY_USAGE_ENCIPHER_ONLY,
    TC_KEY_USAGE_DECIPHER_ONLY
  };
  munit_assert_uint(TC_KEY_USAGE_ALL, ==, (1u << REASON_BITS) - 1);
  for (unsigned flags = 0; flags < (1u << REASON_BITS); ++flags) {
    uint8_t bytes[2] = {0};
    unsigned count = 0;
    uint16_t out = SENTINEL;
    for (unsigned i = 0; i < REASON_BITS; ++i) {
      if (!(flags & (1u << i))) continue;
      bytes[i / 8] |= (uint8_t)(128u >> (i % 8));
      count = i + 1;
    }
    const size_t length = (count + 7) / 8;
    const unsigned unused = (unsigned)length * 8 - count;
    munit_assert_int(tc_pki_named_bits((TC_bytes){bytes,length},unused,REASON_BITS,&out), ==, TC_TLV_OK);
    munit_assert_uint(out, ==, flags);
    uint8_t key_usage[] = {3,(uint8_t)(length + 1),(uint8_t)unused,bytes[0],bytes[1]};
    out = SENTINEL;
    munit_assert_int(TC_X509_key_usage_read(key_usage,length + 3,&out), ==,
        count ? TC_TLV_OK : TC_TLV_INVALID);
    munit_assert_uint(out, ==, count ? flags : SENTINEL);
    if (count) {
      uint16_t expected = 0;
      for (unsigned i = 0; i < REASON_BITS; ++i)
        if (flags & (1u << i)) expected |= usages[i];
      munit_assert_uint(out, ==, expected);
      out = SENTINEL;
      /* An extra zero octet violates DER's named-bit encoding. */
      uint8_t padded[3] = {bytes[0],bytes[1],0};
      munit_assert_int(tc_pki_named_bits((TC_bytes){padded,length + 1},0,REASON_BITS,&out), ==, TC_TLV_INVALID);
      munit_assert_uint(out, ==, SENTINEL);
      if (unused) {
        bytes[length - 1] |= 1;
        munit_assert_int(tc_pki_named_bits((TC_bytes){bytes,length},unused,REASON_BITS,&out), ==, TC_TLV_INVALID);
        munit_assert_uint(out, ==, SENTINEL);
      }
    }
  }
  uint16_t out = SENTINEL;
  const uint8_t high[] = {0,0x40};
  munit_assert_int(tc_pki_named_bits((TC_bytes){high,sizeof high},6,REASON_BITS,&out), ==, TC_TLV_INVALID);
  munit_assert_int(tc_pki_named_bits((TC_bytes){NULL,0},1,REASON_BITS,&out), ==, TC_TLV_INVALID);
  munit_assert_int(tc_pki_named_bits((TC_bytes){high,1},8,REASON_BITS,&out), ==, TC_TLV_INVALID);
  munit_assert_uint(out, ==, SENTINEL);
  return MUNIT_OK;
}

static MunitResult record_index(const MunitParameter params[], void* user)
{
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[4];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  fixture first = make_crl(1,0), second = make_crl(2,CRL_EXTENSIONS);
  TC_bytes inputs[] = {{first.bytes,first.length},{second.bytes,second.length}};
  candidate_source source = {inputs,2,0,TC_TLV_OK,0};
  const tc_pki_record_source external = {&source,2,read_candidate};
  tc_cms_revocations reader, saved_reader;
  TC_X509_crl_record rows[2];
  TC_X509_crl_index index, saved;
  (void)params; (void)user;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL,0},&external,
      2,2 * FIXTURE_CAPACITY,&limits,&tree,&reader), ==, TC_TLV_OK);
  memcpy(&saved_reader,&reader,sizeof reader);
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,rows,2,&index), ==, TC_TLV_OK);
  const size_t required = WORK_BUDGET - work;
  munit_assert_size(index.count, ==, 2);
  munit_assert_size(index.other_count, ==, 0);
  munit_assert_size(source.calls, ==, 2);
  for (size_t i = 0; i < index.count; ++i) {
    munit_assert_ptr_equal(index.records[i].crl.encoded.data,inputs[i].data);
    munit_assert_int(index.records[i].policy, ==, TC_TLV_OK);
  }
  munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  memset(&saved,0xa5,sizeof saved);
  for (size_t budget = 0; budget <= required; ++budget) {
    work = budget; memcpy(&index,&saved,sizeof index);
    munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,rows,2,&index),
        ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    if (budget < required) munit_assert_memory_equal(sizeof index,&index,&saved);
    munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  }
  work = WORK_BUDGET; memcpy(&index,&saved,sizeof index);
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,rows,1,&index), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  /* Truncated records must not publish a partially populated index. */
  --inputs[1].length;
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,rows,2,&index), !=, TC_TLV_OK);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL,0},NULL,
      0,0,&limits,&tree,&reader), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,NULL,0,NULL,0,&index), ==, TC_TLV_OK);
  munit_assert_size(index.count, ==, 0);
  munit_assert_size(index.other_count, ==, 0);
  const uint8_t other[] = {0xa1,8,0xa1,6,6,2,0x2a,3,5,0};
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){other,sizeof other},NULL,
      1,sizeof other,&limits,&tree,&reader), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,NULL,0,NULL,0,&index), ==, TC_TLV_OK);
  munit_assert_size(index.count, ==, 0);
  munit_assert_size(index.other_count, ==, 1);
  return MUNIT_OK;
}

static MunitResult record_index_storage(const MunitParameter params[], void* user)
{
  fixture input = make_crl(2,0);
  TC_bytes encoded = {input.bytes,input.length}, oids[4];
  TC_TLV_frame frames[FRAME_CAPACITY];
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  size_t work = WORK_BUDGET;
  tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  candidate_source source = {&encoded,1,0,TC_TLV_OK,0};
  const tc_pki_record_source external = {&source,1,read_candidate};
  tc_cms_revocations reader, saved_reader;
  TC_X509_crl_record row, saved_row;
  TC_X509_crl_index index, saved;
  (void)params; (void)user;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL,0},&external,
      1,FIXTURE_CAPACITY,&limits,&tree,&reader), ==, TC_TLV_OK);
  memcpy(&saved_reader,&reader,sizeof reader);
  memset(&saved,0xa5,sizeof saved); memset(&saved_row,0xa5,sizeof saved_row);
  const TC_bytes writes[] = {{(const uint8_t*)&row,sizeof row},
    {(const uint8_t*)oids,sizeof oids},{(const uint8_t*)frames,sizeof frames},
    {(const uint8_t*)&work,sizeof work},{(const uint8_t*)&index,sizeof index}};
  for (size_t i = 0; i < sizeof writes / sizeof writes[0]; ++i) {
    encoded = (TC_bytes){writes[i].data,1};
    memcpy(&index,&saved,sizeof index); memcpy(&row,&saved_row,sizeof row);
    work = WORK_BUDGET; source.calls = 0;
    munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,&index), ==, TC_TLV_ARGUMENT);
    munit_assert_size(source.calls, ==, 1);
    munit_assert_memory_equal(sizeof index,&index,&saved);
    munit_assert_memory_equal(sizeof row,&row,&saved_row);
    munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  }
  encoded = (TC_bytes){input.bytes,input.length};
  work = WORK_BUDGET; source.calls = 0;
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,(TC_bytes*)frames,4,&row,1,&index),
      ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_size(source.calls, ==, 0);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,(TC_X509_crl_index*)&reader),
      ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  munit_assert_size(work, ==, WORK_BUDGET);
  index.count = WORK_BUDGET; memcpy(&saved,&index,sizeof saved);
  tree.work = &index.count;
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,&index), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  munit_assert_size(source.calls, ==, 0);
  tree.work = &work; work = WORK_BUDGET;
  uint8_t* embedded = (uint8_t*)&row;
  munit_assert_size(input.length, <, 128);
  embedded[0] = 0xa1; embedded[1] = (uint8_t)input.length;
  memcpy(embedded + 2,input.bytes,input.length);
  munit_assert_int(tc_cms_revocations_init((TC_bytes){embedded,input.length + 2},NULL,
      1,FIXTURE_CAPACITY,&limits,&tree,&reader), ==, TC_TLV_OK);
  memcpy(&saved_reader,&reader,sizeof reader); memcpy(&saved_row,&row,sizeof row);
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,&index), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_memory_equal(sizeof row,&row,&saved_row);
  munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  return MUNIT_OK;
}

static MunitResult indexed_deltas(const MunitParameter params[], void* user)
{
  const uint8_t issuer[] = {0x30,0}, numbers[] = {5,7,3,4,9};
  TC_X509_crl_record rows[5] = {0};
  const TC_X509_crl_index index = {rows,5,0};
  TC_TLV_frame frames[FRAME_CAPACITY];
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  uint32_t left[32], right[32]; uint8_t used[2];
  const TC_X509_name_workspace names = {left,right,32,used,2};
  size_t work, cursor;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl_selected selected, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (size_t i = 0; i < index.count; ++i) {
    rows[i].crl.issuer = (TC_bytes){issuer,sizeof issuer};
    rows[i].extensions.present = TC_CRL_EXT_NUMBER | (i ? TC_CRL_EXT_DELTA : 0);
    rows[i].extensions.critical = i ? TC_CRL_EXT_DELTA : 0;
    rows[i].extensions.number = (TC_bytes){numbers + i,1};
    rows[i].extensions.base_number = (TC_bytes){numbers + 2,1};
    rows[i].policy = TC_TLV_OK;
  }
  rows[2].policy = TC_TLV_UNSUPPORTED;
  const size_t expected[] = {1,4};
  cursor = 0;
  for (size_t i = 0; i < sizeof expected / sizeof expected[0]; ++i) {
    const size_t start = cursor;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_delta_next(&index,0,&cursor,&limits,&tree,&names,&selected), ==, TC_TLV_OK);
    munit_assert_ptr_equal(selected.base,&rows[0].crl);
    munit_assert_ptr_equal(selected.delta,&rows[expected[i]].crl);
    munit_assert_size(cursor, ==, expected[i] + 1);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget <= required; ++budget) {
      size_t probe = start; work = budget; memcpy(&selected,&saved,sizeof selected);
      munit_assert_int(tc_x509_crl_delta_next(&index,0,&probe,&limits,&tree,&names,&selected),
          ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
      if (budget < required) {
        munit_assert_size(probe, ==, start);
        munit_assert_memory_equal(sizeof selected,&selected,&saved);
      } else munit_assert_size(probe, ==, cursor);
    }
  }
  work = 0; memcpy(&selected,&saved,sizeof selected);
  munit_assert_int(tc_x509_crl_delta_next(&index,0,&cursor,&limits,&tree,&names,&selected), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof selected,&selected,&saved);
  munit_assert_size(cursor, ==, index.count);
  cursor = 0; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_delta_next(&index,1,&cursor,&limits,&tree,&names,&selected), ==, TC_TLV_ARGUMENT);
  rows[0].policy = TC_TLV_INVALID;
  munit_assert_int(tc_x509_crl_delta_next(&index,0,&cursor,&limits,&tree,&names,&selected), ==, TC_TLV_INVALID);
  munit_assert_size(cursor, ==, 0);
  munit_assert_memory_equal(sizeof selected,&selected,&saved);
  return MUNIT_OK;
}

static MunitResult record_index_failures(const MunitParameter params[], void* user)
{
  const TC_TLV_limits limits = {FIXTURE_CAPACITY,FIXTURE_CAPACITY,128,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[4];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  fixture input = make_crl(2,0);
  TC_bytes encoded = {input.bytes,input.length};
  candidate_source source = {&encoded,1,0,TC_TLV_OK,0};
  const tc_pki_record_source external = {&source,1,read_candidate};
  tc_cms_revocations reader, saved_reader;
  TC_X509_crl_record row;
  TC_X509_crl_index index, saved;
  (void)params; (void)user;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL,0},&external,
      1,FIXTURE_CAPACITY,&limits,&tree,&reader), ==, TC_TLV_OK);
  memcpy(&saved_reader,&reader,sizeof reader);
  memset(&saved,0xa5,sizeof saved);
  const TC_TLV_result statuses[] = {TC_TLV_INVALID,TC_TLV_END,TC_TLV_ARGUMENT,
    TC_TLV_LIMIT,TC_TLV_UNSUPPORTED};
  for (size_t i = 0; i < sizeof statuses / sizeof statuses[0]; ++i) {
    source.status = statuses[i]; work = WORK_BUDGET;
    memcpy(&index,&saved,sizeof index);
    const TC_TLV_result expected = source.status == TC_TLV_LIMIT ||
        source.status == TC_TLV_UNSUPPORTED ? source.status : TC_TLV_ARGUMENT;
    munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,&index), ==, expected);
    munit_assert_memory_equal(sizeof index,&index,&saved);
    munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  }
  source.status = TC_TLV_OK; source.increase_work = 1; work = WORK_BUDGET;
  munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,&index), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 0);
  munit_assert_memory_equal(sizeof index,&index,&saved);
  source.increase_work = 0;
  /* Preserve policy failures as metadata so selection can consider other CRLs. */
  const struct { uint8_t arc; int critical; TC_TLV_result policy; } cases[] = {
    {20,0,TC_TLV_OK}, {20,1,TC_TLV_INVALID}, {127,1,TC_TLV_UNSUPPORTED}
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    fixture original = make_crl(2,0);
    input = original;
    input.length = original.outer_algorithm;
    const size_t wrapper = input.length;
    append(&input,(const uint8_t[]){0xa0,0,0x30,0},4);
    append_extension(&input,cases[i].arc,cases[i].critical,
        (TC_bytes){(const uint8_t[]){2,1,9},3});
    input.bytes[wrapper + 1] = (uint8_t)(input.length - wrapper - 2);
    input.bytes[wrapper + 3] = (uint8_t)(input.length - wrapper - 4);
    input.bytes[3] = (uint8_t)(input.length - 4);
    append(&input,original.bytes + original.outer_algorithm,
        original.length - original.outer_algorithm);
    input.bytes[1] = (uint8_t)(input.length - 2);
    encoded.length = input.length; work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_index_init(&reader,&tree,oids,4,&row,1,&index), ==, TC_TLV_OK);
    munit_assert_size(index.count, ==, 1);
    munit_assert_int(row.policy, ==, cases[i].policy);
    munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
  }
  return MUNIT_OK;
}

static MunitResult candidate_arguments(const MunitParameter params[], void* user)
{
  enum { CRL, EXTENSIONS, CANDIDATE, LIMITS, NAMES, TREE, WORK, MATCHED, CASE_COUNT };
  tc_x509_crl crl = {0};
  tc_x509_crl_extension_info extensions = {0};
  TC_X509_certificate candidate = {0};
  TC_TLV_limits limits = {0};
  TC_X509_name_workspace names = {0};
  (void)params; (void)user;
  for (unsigned missing = 0; missing < CASE_COUNT; ++missing) {
    size_t work = 100;
    int matched = -1;
    const tc_pki_tree_workspace tree = {NULL,0,missing == WORK ? NULL : &work};
    munit_assert_int(tc_x509_crl_candidate_matches(missing == CRL ? NULL : &crl,
        missing == EXTENSIONS ? NULL : &extensions,missing == CANDIDATE ? NULL : &candidate,
        missing == LIMITS ? NULL : &limits,missing == NAMES ? NULL : &names,
        missing == TREE ? NULL : &tree,missing == MATCHED ? NULL : &matched), ==, TC_TLV_ARGUMENT);
    munit_assert_size(work, ==, 100);
    munit_assert_int(matched, ==, -1);
  }
  return MUNIT_OK;
}

static MunitResult certificate_fields(const MunitParameter params[], void* user)
{
  enum { ISSUER_ALT_NAME = 18, BASIC_CONSTRAINTS = 19, DISTRIBUTION_POINTS = 31 };
  static const uint8_t ca[] = {0x30,3,1,1,0xff};
  static const uint8_t leaf[] = {0x30,0};
  static const uint8_t malformed[] = {0x30,1};
  static const uint8_t names[] = {0x30,3,0x82,1,'a'};
  static const uint8_t bad_names[] = {0x30,2,0x05,0};
  uint8_t oid[] = {0x55,0x1d,BASIC_CONSTRAINTS};
  TC_TLV_frame frames[FRAME_CAPACITY];
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl_certificate_fields fields = {0}, saved;
  fields.limits = &limits; fields.tree = &tree;
  TC_X509_extension extension = {{oid,sizeof oid},{ca,sizeof ca},0};
  (void)params; (void)user;
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_OK);
  munit_assert_int(fields.ca, ==, 1);
  extension.value = (TC_bytes){leaf,sizeof leaf};
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_OK);
  munit_assert_int(fields.ca, ==, 0);
  memcpy(&saved,&fields,sizeof fields);
  extension.value = (TC_bytes){malformed,sizeof malformed};
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_MORE);
  munit_assert_memory_equal(sizeof fields,&fields,&saved);

  /* Distribution-point framing is checked by the later list traversal. */
  oid[2] = DISTRIBUTION_POINTS;
  extension.value = (TC_bytes){leaf,sizeof leaf};
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_OK);
  munit_assert_ptr_equal(fields.points.data,leaf);
  munit_assert_size(fields.points.length, ==, sizeof leaf);

  oid[2] = ISSUER_ALT_NAME;
  extension.value = (TC_bytes){names,sizeof names};
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_OK);
  munit_assert_ptr_equal(fields.alternative.name.encoded.data,names);
  munit_assert_ptr_equal(fields.alternative.name.contents.data,names + 2);
  munit_assert_size(fields.alternative.name.contents.length, ==, sizeof names - 2);
  memcpy(&saved,&fields,sizeof fields);
  extension.value = (TC_bytes){bad_names,sizeof bad_names};
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof fields,&fields,&saved);
  extension.value = (TC_bytes){names,sizeof names};
  work = 0;
  munit_assert_int(tc_x509_crl_certificate_extension(&fields,&extension), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof fields,&fields,&saved);
  return MUNIT_OK;
}

static MunitResult points_init(const MunitParameter params[], void* user)
{
  static const uint8_t points[] = {0x30,9,0x30,7,0xa0,5,0xa0,3,0x82,1,'a'};
  static const uint8_t bad_tail[] = {0x30,11,0x30,7,0xa0,5,0xa0,3,0x82,1,'a',0x05,0};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[4];
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_x509_crl_certificate_fields fields = {0}, saved;
  TC_TLV_reader reader, unchanged;
  (void)params; (void)user;
  memset(&unchanged,0xa5,sizeof unchanged);
  fields.limits = &limits; fields.tree = &tree; fields.ca = 1;
  fields.points = (TC_bytes){points,sizeof points};
  munit_assert_int(tc_x509_crl_points_init(&fields,NULL,oids,4,&reader), ==, TC_TLV_OK);
  munit_assert_ptr_equal(fields.points.data,points);
  munit_assert_int(fields.ca, ==, 1);
  tc_pki_distribution_point point;
  munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==, TC_TLV_OK);
  munit_assert_int(tc_pki_distribution_point_next(&reader,&tree,&point), ==, TC_TLV_END);

  for (size_t length = 1; length < sizeof points; ++length) {
    fields.points = (TC_bytes){points,length}; saved = fields;
    reader = unchanged; work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_points_init(&fields,NULL,oids,4,&reader), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof fields,&fields,&saved);
    munit_assert_memory_equal(sizeof reader,&reader,&unchanged);
  }
  fields.points = (TC_bytes){bad_tail,sizeof bad_tail}; saved = fields;
  reader = unchanged; work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_points_init(&fields,NULL,oids,4,&reader), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof fields,&fields,&saved);
  munit_assert_memory_equal(sizeof reader,&reader,&unchanged);
  fields.points = (TC_bytes){points,sizeof points}; saved = fields;
  reader = unchanged; work = 0;
  munit_assert_int(tc_x509_crl_points_init(&fields,NULL,oids,4,&reader), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof fields,&fields,&saved);
  munit_assert_memory_equal(sizeof reader,&reader,&unchanged);

  /* An extension-free certificate uses the default issuer scope. */
  const TC_X509_certificate certificate = {0};
  work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_points_init(&fields,&certificate,oids,4,&reader), ==, TC_TLV_OK);
  munit_assert_size(fields.points.length, ==, 0);
  munit_assert_int(fields.ca, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/fields",fields,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/public-reader",public_reader,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/public-index",public_index,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/malformed",malformed,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extensions",extensions,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extension-values",extension_values,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/named-bits",named_bits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/distribution",distribution,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/distribution-points",distribution_points,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/distribution-issuer",distribution_issuer,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/issuer-linkage",issuer_linkage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/appended-names",appended_names,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/name-scope",name_scope,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-reasons",scope_reasons,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/freshness",freshness,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extension-info",extension_info,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/extension-policy",extension_policy,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/entry-info",entry_info,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/entry-policy",entry_policy,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/issuer-inheritance",issuer_inheritance,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/delta-pairing",delta_pairing,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/scope-groups",scope_groups,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/combine-status",combine_status,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/evidence-status",evidence_status,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/evidence-equality",evidence_equality,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/signer-usage",signer_usage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/candidate-arguments",candidate_arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/certificate-fields",certificate_fields,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/points-init",points_init,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/authority-identifiers",authority_identifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/record-index",record_index,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/record-index-storage",record_index_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/indexed-deltas",indexed_deltas,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/record-index-failures",record_index_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/source-layout",source_layout,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/source-entry-failures",source_entry_failures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/source-batch",source_batch,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/corpus",corpus_file,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  if (!getenv("TC_CRL_FILE")) {
    const size_t end = sizeof tests / sizeof tests[0] - 1;
    tests[end - 1] = tests[end];
  }
  MunitSuite suite = {"/x509/crl",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
