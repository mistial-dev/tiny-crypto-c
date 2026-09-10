/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/pki_children_internal.h"
#include "../../src/cms_internal.h"
#include "source.h"
#include "munit.h"
#include <string.h>

static MunitResult fields(const MunitParameter params[], void* user)
{
  static const uint8_t ber[] = {0x30,0x80,2,1,1,0x30,0x80,4,2,0,0,0,0,0,0};
  TC_TLV_limits limits = {64,64,16,4};
  TC_TLV_frame frames[4];
  TC_TLV_element children[2];
  size_t work = 100, count = 99;
  (void)params; (void)user;
  munit_assert_int(tc_pki_children((TC_bytes){ber,sizeof ber},0x30,TC_TLV_BER,
      &limits,frames,4,&work,children,2,&count), ==, TC_TLV_OK);
  munit_assert_size(count, ==, 2);
  munit_assert_ptr_equal(children[0].value.data,ber + 4);
  munit_assert_size(children[0].value.length, ==, 1);
  munit_assert_ptr_equal(children[1].encoded.data,ber + 5);
  munit_assert_size(children[1].encoded.length, ==, 8);
  munit_assert_size(children[1].value.length, ==, 4);
  munit_assert_uint(children[1].value.data[2], ==, 0);
  for (size_t length = 0; length < sizeof ber; ++length) {
    work = 100; count = 99;
    munit_assert_int(tc_pki_children((TC_bytes){ber,length},0x30,TC_TLV_BER,
        &limits,frames,4,&work,children,2,&count), !=, TC_TLV_OK);
    munit_assert_size(count, ==, 99);
  }
  work = 100;
  munit_assert_int(tc_pki_children((TC_bytes){ber,sizeof ber},0x30,TC_TLV_BER,
      &limits,frames,4,&work,children,1,&count), ==, TC_TLV_LIMIT);
  work = 100;
  munit_assert_int(tc_pki_children((TC_bytes){ber,sizeof ber},0x30,TC_TLV_DER,
      &limits,frames,4,&work,children,2,&count), !=, TC_TLV_OK);
  work = sizeof ber - 1;
  munit_assert_int(tc_pki_children((TC_bytes){ber,sizeof ber},0x30,TC_TLV_BER,
      &limits,frames,4,&work,children,2,&count), ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}
static MunitResult envelope(const MunitParameter params[], void* user)
{
  uint8_t encoded[] = {0x30,35,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2,
    0xa0,22,0x30,20,2,1,1,0x31,0,0x30,11,6,9,
    0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0x31,0,0,0};
  TC_TLV_limits limits = {128,128,32,8};
  TC_TLV_frame frames[8];
  tc_cms_signed_data result, saved;
  size_t work;
  (void)params; (void)user;
  for (unsigned indefinite = 0; indefinite < 2; ++indefinite) {
    size_t length = sizeof encoded - (indefinite ? 0 : 2);
    encoded[1] = indefinite ? 0x80 : 35; work = 1000;
    munit_assert_int(tc_cms_signed_data_read((TC_bytes){encoded,length},
        &limits,frames,8,&work,&result), ==, TC_TLV_OK);
    munit_assert_uint(result.version, ==, 1);
    munit_assert_false(result.has_content);
    munit_assert_ptr_equal(result.content_type.data,encoded + 26);
    munit_assert_ptr_equal(result.signers.data,encoded + 35);
    memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
    for (size_t truncated = 0; truncated < length; ++truncated) {
      work = 1000;
      munit_assert_int(tc_cms_signed_data_read((TC_bytes){encoded,truncated},
          &limits,frames,8,&work,&result), !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
  }
  encoded[35] = 0x30; work = 1000;
  munit_assert_int(tc_cms_signed_data_read((TC_bytes){encoded,sizeof encoded},
      &limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  {
    const uint8_t unknown[] = {0x30,4,6,2,0x2a,3};
    const uint8_t indefinite[] = {0x30,0x80,6,2,0x2a,3,5,0,0,0};
    const uint8_t no_oid[] = {0x30,2,5,0};
    const uint8_t bad_oid[] = {0x30,3,6,1,0x80};
    const uint8_t extra[] = {0x30,8,6,2,0x2a,3,5,0,5,0};
    const TC_bytes cases[] = {{unknown,sizeof unknown},{indefinite,sizeof indefinite},
      {no_oid,sizeof no_oid},{bad_oid,sizeof bad_oid},{extra,sizeof extra}};
    uint8_t input[128];
    encoded[35] = 0x31;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
      size_t length = 20;
      memcpy(input,encoded,length);
      input[1] = input[14] = input[16] = 0x80;
      input[length++] = 0x31; input[length++] = (uint8_t)cases[i].length;
      memcpy(input + length,cases[i].data,cases[i].length); length += cases[i].length;
      memcpy(input + length,encoded + 22,15); length += 15;
      memset(input + length,0,6); length += 6;
      memcpy(&result,&saved,sizeof result); work = 1000;
      munit_assert_int(tc_cms_signed_data_read((TC_bytes){input,length},
          &limits,frames,8,&work,&result), ==, i < 2 ? TC_TLV_OK : TC_TLV_INVALID);
      if (i >= 2) munit_assert_memory_equal(sizeof result,&result,&saved);
      else {
        const size_t required = 1000 - work;
        for (size_t budget = 0; budget < required; ++budget) {
          work = budget; memcpy(&result,&saved,sizeof result);
          munit_assert_int(tc_cms_signed_data_read((TC_bytes){input,length},
              &limits,frames,8,&work,&result), ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof result,&result,&saved);
        }
        work = required;
        munit_assert_int(tc_cms_signed_data_read((TC_bytes){input,length},
            &limits,frames,8,&work,&result), ==, TC_TLV_OK);
        munit_assert_size(work, ==, 0);
      }
    }
  }
  return MUNIT_OK;
}

static MunitResult versions(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 4096, FRAME_CAPACITY = 8 };
  uint8_t content_type[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
  /* Empty choice bodies isolate the version rule from certificate schemas. */
  uint8_t certificates[] = {0xa0,2,0x30,0}, revocations[] = {0xa1,2,0x30,0};
  const uint8_t empty_signers[] = {0x31,0};
  const uint8_t key_id_signer[] = {0x31,23,0x30,21,2,1,3,0x80,1,0xaa,
    0x30,4,6,2,0x2a,3,0x30,4,6,2,0x2a,3,4,1,0xbb};
  const uint8_t choice_tags[] = {0x30,0xa0,0xa1,0xa2,0xa3};
  const unsigned choice_versions[] = {1,1,3,4,5};
  TC_TLV_limits limits = {256,256,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_signed_data input = {0};
  (void)params; (void)user;
  input.content_type = (TC_bytes){content_type,sizeof content_type};
  for (unsigned cert = 0; cert <= sizeof choice_tags; ++cert)
    for (unsigned rev = 0; rev < 3; ++rev)
      for (unsigned type = 0; type < 2; ++type)
        for (unsigned signer = 0; signer < 2; ++signer) {
          unsigned expected = type || signer ? 3 : 1;
          content_type[sizeof content_type - 1] = type ? 2 : 1;
          input.certificates = cert ? (TC_bytes){certificates,sizeof certificates} : (TC_bytes){NULL,0};
          if (cert) {
            certificates[2] = choice_tags[cert - 1];
            if (choice_versions[cert - 1] > expected) expected = choice_versions[cert - 1];
          }
          input.revocations = rev ? (TC_bytes){revocations,sizeof revocations} : (TC_bytes){NULL,0};
          revocations[2] = rev == 2 ? 0xa1 : 0x30;
          if (rev == 2) expected = 5;
          input.signers = signer ? (TC_bytes){key_id_signer,sizeof key_id_signer} :
              (TC_bytes){empty_signers,sizeof empty_signers};
          for (unsigned version = 0; version <= 6; ++version) {
            input.version = version; work = WORK_BUDGET;
            munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), ==,
                version == expected ? TC_TLV_OK : TC_TLV_INVALID);
          }
          input.version = expected; work = WORK_BUDGET;
          munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), ==, TC_TLV_OK);
          const size_t required = WORK_BUDGET - work;
          for (size_t budget = 0; budget < required; ++budget) {
            work = budget;
            munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), ==, TC_TLV_LIMIT);
          }
          work = required;
          munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), ==, TC_TLV_OK);
          munit_assert_size(work, ==, 0);
        }
  /* A highest-version choice must not hide a later invalid choice. */
  const uint8_t bad_choices[] = {0xa0,4,0xa3,0,0xa4,0};
  input.certificates = (TC_bytes){bad_choices,sizeof bad_choices};
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), ==, TC_TLV_INVALID);
  input.certificates = (TC_bytes){NULL,0};
  revocations[2] = 0xa0; work = WORK_BUDGET;
  munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), ==, TC_TLV_INVALID);
  revocations[2] = 0xa1;
  for (size_t length = 0; length < sizeof key_id_signer; ++length) {
    input.signers.length = length; work = WORK_BUDGET;
    munit_assert_int(tc_cms_signed_data_version_check(&input,&limits,&tree), !=, TC_TLV_OK);
  }
  return MUNIT_OK;
}

static MunitResult other_formats(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 1024, FRAME_CAPACITY = 8 };
  uint8_t simple[] = {0xa3,6,6,2,0x2a,3,5,0};
  uint8_t nested[] = {0xa3,0x80,6,2,0x2a,3,0x30,0x80,4,1,7,0,0,0,0};
  uint8_t missing[] = {0xa3,4,6,2,0x2a,3};
  uint8_t extra[] = {0xa3,8,6,2,0x2a,3,5,0,5,0};
  uint8_t bad_oid[] = {0xa3,5,6,1,0x80,5,0};
  uint8_t wrong_field[] = {0xa3,4,5,0,5,0};
  TC_bytes cases[] = {{simple,sizeof simple},{nested,sizeof nested},
    {missing,sizeof missing},{extra,sizeof extra},{bad_oid,sizeof bad_oid},
    {wrong_field,sizeof wrong_field}};
  uint8_t* roots[] = {simple,nested,missing,extra,bad_oid,wrong_field};
  TC_TLV_limits limits = {128,128,32,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_other_format parsed, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned kind = TC_CMS_OTHER_CERTIFICATE; kind <= TC_CMS_OTHER_REVOCATION; ++kind) {
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
      roots[i][0] = kind == TC_CMS_OTHER_CERTIFICATE ? 0xa3 : 0xa1;
      memcpy(&parsed,&saved,sizeof parsed); work = WORK_BUDGET;
      munit_assert_int(tc_cms_other_format_read(cases[i],(tc_cms_other_kind)kind,
          &limits,&tree,&parsed), ==, i < 2 ? TC_TLV_OK : TC_TLV_INVALID);
      if (i >= 2) { munit_assert_memory_equal(sizeof parsed,&parsed,&saved); continue; }
      munit_assert_ptr_equal(parsed.format.data,cases[i].data + 4);
      munit_assert_size(parsed.format.length, ==, 2);
      munit_assert_ptr_equal(parsed.value.data,cases[i].data + 6);
      munit_assert_size(parsed.value.length, ==, i ? 7 : 2);
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; memcpy(&parsed,&saved,sizeof parsed);
        munit_assert_int(tc_cms_other_format_read(cases[i],(tc_cms_other_kind)kind,
            &limits,&tree,&parsed), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
      }
      work = required;
      munit_assert_int(tc_cms_other_format_read(cases[i],(tc_cms_other_kind)kind,
          &limits,&tree,&parsed), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      for (size_t length = 0; length < cases[i].length; ++length) {
        work = WORK_BUDGET; memcpy(&parsed,&saved,sizeof parsed);
        munit_assert_int(tc_cms_other_format_read((TC_bytes){cases[i].data,length},
            (tc_cms_other_kind)kind,&limits,&tree,&parsed), !=, TC_TLV_OK);
        munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
      }
      work = WORK_BUDGET;
      munit_assert_int(tc_cms_other_format_read(cases[i],(tc_cms_other_kind)(1 - kind),
          &limits,&tree,&parsed), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
  }
  {
    uint8_t collection[] = {0xa0,8,0xa3,6,6,2,0x2a,3,5,0};
    tc_cms_candidates reader, unchanged;
    tc_cms_certificate_choice choice;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_candidates_init((TC_bytes){collection,sizeof collection},
        NULL,1,sizeof collection,&limits,&tree,&reader), ==, TC_TLV_OK);
    munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    munit_assert_int(choice.kind, ==, TC_CMS_CERT_OTHER);
    collection[4] = 5; work = WORK_BUDGET;
    munit_assert_int(tc_cms_candidates_init((TC_bytes){collection,sizeof collection},
        NULL,1,sizeof collection,&limits,&tree,&reader), ==, TC_TLV_OK);
    memcpy(&unchanged,&reader,sizeof unchanged);
    munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader,&reader,&unchanged);
  }
  return MUNIT_OK;
}

static MunitResult revocation_records(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 4096, FRAME_CAPACITY = 8, RECORD_COUNT = 3 };
  /* Choice framing only; typed CRL processing must reject the empty SEQUENCE. */
  static const uint8_t embedded[] = {0xa1,0x80,0x30,0,0xa1,5,6,1,42,5,0,0,0};
  static const uint8_t external_bytes[] = {0x30,0};
  static const uint8_t bad_choice[] = {0xa1,2,0x31,0};
  static const uint8_t bad_other[] = {0xa1,5,0xa1,3,6,1,42};
  const TC_bytes records[] = {{external_bytes,sizeof external_bytes}};
  candidate_source context = {records,1,0,TC_TLV_OK,0};
  tc_pki_record_source external = {&context,1,read_candidate};
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_revocations reader, saved;
  tc_cms_revocation_choice choice, previous;
  const TC_bytes input = {embedded,sizeof embedded};
  (void)params; (void)user;
  munit_assert_int(tc_cms_revocations_init(input,&external,RECORD_COUNT,
      sizeof embedded + sizeof external_bytes,&limits,&tree,&reader), ==, TC_TLV_OK);
  const tc_cms_revocations start = reader;
  const size_t before = work;
  for (size_t i = 0; i < RECORD_COUNT; ++i) {
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    munit_assert_int(choice.kind, ==, i == 1 ? TC_CMS_REVOCATION_OTHER : TC_CMS_REVOCATION_CRL);
    munit_assert_ptr_equal(choice.encoded.data,i < 2 ? embedded + 2 + i * 2 : external_bytes);
  }
  const size_t required = before - work;
  munit_assert_size(context.calls, ==, 1);
  munit_assert_size(reader.collection.remaining, ==, 0);
  munit_assert_size(reader.collection.bytes_left, ==, 0);
  memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous); work = 0;
  munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof reader,&reader,&saved);
  munit_assert_memory_equal(sizeof choice,&choice,&previous);
  for (size_t budget = 0; budget <= required; ++budget) {
    reader = start; work = budget;
    TC_TLV_result result = TC_TLV_OK;
    for (size_t i = 0; i < RECORD_COUNT && result == TC_TLV_OK; ++i) {
      memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous);
      result = tc_cms_revocations_next(&reader,&tree,&choice);
    }
    munit_assert_int(result, ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    if (result != TC_TLV_OK) {
      munit_assert_memory_equal(sizeof reader,&reader,&saved);
      munit_assert_memory_equal(sizeof choice,&choice,&previous);
    } else munit_assert_size(work, ==, 0);
  }
  const TC_TLV_result errors[] = {TC_TLV_END,TC_TLV_INVALID,TC_TLV_LIMIT,TC_TLV_UNSUPPORTED};
  for (size_t failure = 0; failure < sizeof errors / sizeof *errors + 2; ++failure) {
    reader = start; work = WORK_BUDGET;
    context.status = TC_TLV_OK; context.increase_work = 0;
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    if (failure < sizeof errors / sizeof *errors) context.status = errors[failure];
    else if (failure == sizeof errors / sizeof *errors) context.increase_work = 1;
    else reader.collection.bytes_left = sizeof external_bytes - 1;
    const TC_TLV_result expected = context.status == TC_TLV_LIMIT || context.status == TC_TLV_UNSUPPORTED
      ? context.status : reader.collection.bytes_left < sizeof external_bytes ? TC_TLV_LIMIT : TC_TLV_ARGUMENT;
    memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous);
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, expected);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
    munit_assert_memory_equal(sizeof choice,&choice,&previous);
    if (context.increase_work) munit_assert_size(work, ==, 0);
  }
  const TC_bytes malformed[] = {{bad_choice,sizeof bad_choice},{bad_other,sizeof bad_other}};
  for (size_t i = 0; i < sizeof malformed / sizeof *malformed; ++i) {
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_revocations_init(malformed[i],NULL,RECORD_COUNT,WORK_BUDGET,
        &limits,&tree,&reader), ==, TC_TLV_OK);
    memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous);
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
    munit_assert_memory_equal(sizeof choice,&choice,&previous);
  }
  for (size_t length = 1; length < sizeof embedded; ++length) {
    work = WORK_BUDGET; memcpy(&saved,&reader,sizeof saved);
    munit_assert_int(tc_cms_revocations_init((TC_bytes){embedded,length},NULL,RECORD_COUNT,
        WORK_BUDGET,&limits,&tree,&reader), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
  }
  return MUNIT_OK;
}

static MunitResult guarded_records(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 4096, FRAME_CAPACITY = 8 };
  uint8_t bytes[] = {0x30,0};
  TC_bytes record = {bytes,sizeof bytes};
  candidate_source context = {&record,1,0,TC_TLV_OK,0};
  const tc_pki_record_source source = {&context,1,read_candidate};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_revocations reader, saved;
  tc_cms_revocation_choice choice, previous;
  TC_bytes writes[] = {{(const uint8_t*)frames,sizeof frames},
    {(const uint8_t*)&choice,sizeof choice},{(const uint8_t*)&reader,sizeof reader}};
  tc_pki_record_guard guard = {&source,writes,sizeof writes / sizeof writes[0]};
  const tc_pki_record_source guarded = {&guard,1,tc_pki_record_guard_read};
  (void)params; (void)user;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL,0},&guarded,1,
      WORK_BUDGET,&limits,&tree,&reader), ==, TC_TLV_OK);
  memcpy(&saved,&reader,sizeof saved);
  memset(&previous,0xa5,sizeof previous);
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_OK);
  munit_assert_ptr_equal(choice.encoded.data,bytes);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget <= required; ++budget) {
    memcpy(&reader,&saved,sizeof reader); memcpy(&choice,&previous,sizeof choice);
    work = budget;
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice),
        ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    if (budget < required) {
      munit_assert_memory_equal(sizeof reader,&reader,&saved);
      munit_assert_memory_equal(sizeof choice,&choice,&previous);
    }
  }
  for (size_t target = 0; target < guard.write_count; ++target) {
    record = (TC_bytes){writes[target].data,1};
    memcpy(&reader,&saved,sizeof reader); memcpy(&choice,&previous,sizeof choice);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_revocations_next(&reader,&tree,&choice), ==, TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
    munit_assert_memory_equal(sizeof choice,&choice,&previous);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/fields",fields,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/envelope",envelope,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/versions",versions,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/other-formats",other_formats,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/revocation-records",revocation_records,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/guarded-records",guarded_records,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/cms/children",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
