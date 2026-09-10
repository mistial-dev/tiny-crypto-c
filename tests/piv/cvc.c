/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_cvc.h>
#include <stdio.h>
#include <string.h>

#include "munit.h"

#if !TC_ENABLE_EC
/* Isolate the curve-capability check from signature mathematics. */
static TC_X509_signature_result accepted_signature(void* context,
    const TC_bytes* message, size_t count, const TC_DER_algorithm* algorithm,
    TC_bytes signature, const TC_X509_public_key* key, size_t* work)
{
  ++*(unsigned*)context;
  (void)message; (void)count; (void)algorithm; (void)signature; (void)key; (void)work;
  return TC_X509_SIGNATURE_VALID;
}

static void disabled_chain(TC_bytes card, TC_bytes intermediate)
{
  static const uint8_t extensions[] = {0x30,19,0x30,17,6,3,0x55,0x1d,0x0e,
    4,10,4,8,1,2,3,4,5,6,7,8};
  static const uint8_t algorithm[] = {0x2a,0x86,0x48,0xce,0x3d,2,1};
  static const uint8_t key[] = {4};
  TC_X509_certificate signer = {0};
  signer.extensions = (TC_bytes){extensions,sizeof extensions};
  signer.public_key.algorithm.oid = (TC_bytes){algorithm,sizeof algorithm};
  signer.public_key.key = (TC_bytes){key,sizeof key};
  const TC_TLV_limits limits = {1024,1024,64,8};
  TC_PIV_CVC_chain_request request = {card,intermediate,{NULL,0},TC_EC_P256,&signer};
  unsigned calls = 0;
  const TC_X509_signature_provider provider = {accepted_signature,&calls,NULL};
  TC_EC_workspace points;
  TC_PIV_CVC out, saved;
  memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof saved);
  size_t work = 100000;
  munit_assert_int(TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,&out), ==,
      TC_X509_SIGNATURE_UNSUPPORTED);
  munit_assert_memory_equal(sizeof out,&out,&saved);
  munit_assert_uint(calls, ==, intermediate.length ? 0 : 1);
}
#endif

static MunitResult test_format(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  /* Format fixture: P-256 card CVC, with r=s=1. */
  static const uint8_t prefix[] = {
    0x7f,0x21,0x81,0x91, 0x5f,0x29,1,0x80, 0x42,8,1,2,3,4,5,6,7,8,
    0x5f,0x20,16, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    0x7f,0x49,77, 6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7, 0x86,65,4
  };
  static const uint8_t suffix[] = {
    0x5f,0x4c,1,0, 0x5f,0x37,25, 0x30,23,
    0x30,10,6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2,
    3,9,0,0x30,6,2,1,1,2,1,1
  };
  /* SP 800-73 Part 2, Tables 19/20: tag order, field widths, key format,
   * role, AlgorithmIdentifier and DER signature syntax. */
  static const struct { size_t offset; uint8_t value; } malformed[] = {
    {0,0x7e}, {5,0x28}, {6,2}, {8,0x43}, {9,7}, {19,0x21}, {20,8},
    {38,0x48}, {40,5}, {41,7}, {50,0x85}, {51,64}, {52,0}, {52,2}, {52,6},
    {118,0x29}, {119,2}, {120,0x12}, {122,0x38}, {124,0x31}, {126,0x31},
    {128,5}, {130,0x80}, {138,4}, {140,1}, {141,0x31}, {143,3}, {145,0}, {148,0xff}
  };
  uint8_t data[sizeof prefix + 64 + sizeof suffix];
  uint8_t extended[sizeof data + 4];
  uint8_t intermediate[399];
  uint8_t p384[178];
  TC_PIV_CVC cvc, saved;
  size_t i;
  memcpy(data, prefix, sizeof prefix);
  memset(data + sizeof prefix, 1, 64);
  memcpy(data + sizeof prefix + 64, suffix, sizeof suffix);
  munit_assert(sizeof data == 149);
  munit_assert(TC_PIV_CVC_read(data, sizeof data, &cvc) == TC_TLV_OK);
  munit_assert(cvc.key_bits == 256 && cvc.role == TC_PIV_CVC_CARD_APPLICATION && cvc.subject.length == 16);
  munit_assert(cvc.public_key.length == 65 && cvc.ecdsa.r.length == 1 && cvc.ecdsa.s.length == 1);
  munit_assert(cvc.signed_data.data == data + 4 && cvc.signed_data.length == sizeof data - 4 - 28);
  saved = cvc;
#if !TC_ENABLE_EC
  disabled_chain((TC_bytes){data,sizeof data},(TC_bytes){NULL,0});
#endif
  {
    union { TC_PIV_CVC result; uint8_t bytes[sizeof data + sizeof(TC_PIV_CVC)]; } storage;
    uint8_t original[sizeof storage];
    const size_t offsets[] = {0,1,sizeof(TC_PIV_CVC) - 1};
    for (size_t offset_index = 0; offset_index < sizeof offsets / sizeof *offsets; ++offset_index) {
      memset(&storage,0x5a,sizeof storage);
      memcpy(storage.bytes + offsets[offset_index],data,sizeof data);
      memcpy(original,&storage,sizeof original);
      munit_assert_int(TC_PIV_CVC_read(storage.bytes + offsets[offset_index],sizeof data,
          &storage.result), ==, TC_TLV_ARGUMENT);
      munit_assert_memory_equal(sizeof original,original,&storage);
    }
  }
  {
    uint8_t long_oid[sizeof data + 1];
    memcpy(long_oid, data, 41);
    long_oid[41] = 0x81;
    memcpy(long_oid + 42, data + 41, sizeof data - 41);
    ++long_oid[3]; ++long_oid[39];
    munit_assert_int(TC_PIV_CVC_read(long_oid, sizeof long_oid, &cvc), ==, TC_TLV_OK);
    munit_assert(cvc.curve_oid.data == long_oid + 43);
    munit_assert_size(cvc.signed_data.length, ==, saved.signed_data.length + 1);
    munit_assert_memory_equal(cvc.signed_data.length, cvc.signed_data.data, long_oid + 4);
    cvc = saved;
  }
  {
    /* Table 19, cipher suite 7: P-384 with ECDSA/SHA-384. */
    static const uint8_t key_header[] = {
      0x7f,0x49,106, 6,5,0x2b,0x81,4,0,0x22, 0x86,97,4
    };
    memcpy(p384, data, 37);
    p384[3] = sizeof p384 - 4;
    memcpy(p384 + 37, key_header, sizeof key_header);
    memset(p384 + 50, 1, 96);
    memcpy(p384 + 146, suffix, sizeof suffix);
    p384[166] = 3;
    munit_assert(TC_PIV_CVC_read(p384, sizeof p384, &cvc) == TC_TLV_OK);
    munit_assert(cvc.key_bits == 384 && cvc.public_key.length == 97);
    munit_assert(cvc.signed_data.data == p384 + 4 && cvc.signed_data.length == 146);
    munit_assert(cvc.signature_algorithm.oid.data[7] == 3);
    saved = cvc;
    for (i = 0; i < sizeof p384; ++i) {
      munit_assert(TC_PIV_CVC_read(p384, i, &cvc) != TC_TLV_OK);
      munit_assert(memcmp(&cvc, &saved, sizeof cvc) == 0);
    }
    p384[166] = 2;
    munit_assert(TC_PIV_CVC_read(p384, sizeof p384, &cvc) == TC_TLV_UNSUPPORTED);
    munit_assert(memcmp(&cvc, &saved, sizeof cvc) == 0);
    munit_assert(TC_PIV_CVC_read(data, sizeof data, &cvc) == TC_TLV_OK);
    saved = cvc;
  }
  {
    static const uint8_t rsa_signature_header[] = {
      0x5f,0x37,0x82,1,0x18, 0x30,0x82,1,0x14,
      0x30,13,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,11,5,0,
      3,0x82,1,1,0
    };
    intermediate[0] = 0x7f; intermediate[1] = 0x21;
    intermediate[2] = 0x82; intermediate[3] = 1; intermediate[4] = 0x8a;
    memcpy(intermediate + 5, data + 4, 25);
    intermediate[21] = 8;
    memcpy(intermediate + 30, data + 37, 84);
    intermediate[113] = TC_PIV_CVC_INTERMEDIATE;
    memcpy(intermediate + 114, rsa_signature_header, sizeof rsa_signature_header);
    memset(intermediate + 143, 1, 256);
    munit_assert(TC_PIV_CVC_read(intermediate, sizeof intermediate, &cvc) == TC_TLV_OK);
    munit_assert(cvc.role == TC_PIV_CVC_INTERMEDIATE && cvc.subject.length == 8 && cvc.signature.length == 256);
    munit_assert(cvc.signed_data.data == intermediate + 5 && cvc.signed_data.length == 109);
    munit_assert(!cvc.ecdsa.r.data && !cvc.ecdsa.s.data);
#if !TC_ENABLE_EC && !TC_ENABLE_SHA1
    {
      uint8_t linked_card[sizeof data];
      memcpy(linked_card,data,sizeof data);
      memcpy(linked_card + 10,cvc.subject.data,cvc.subject.length);
      disabled_chain((TC_bytes){linked_card,sizeof linked_card},
          (TC_bytes){intermediate,sizeof intermediate});
    }
#endif
    intermediate[136] = 4;
    munit_assert(TC_PIV_CVC_read(intermediate, sizeof intermediate, &cvc) == TC_TLV_INVALID);
    intermediate[136] = 5;
    memmove(intermediate + 136, intermediate + 138, 261);
    intermediate[4] -= 2; intermediate[118] -= 2;
    intermediate[122] -= 2; intermediate[124] -= 2;
    munit_assert(TC_PIV_CVC_read(intermediate, sizeof intermediate - 2, &cvc) == TC_TLV_INVALID);
    cvc = saved;
  }
  for (i = 0; i < sizeof malformed / sizeof malformed[0]; ++i) {
    uint8_t byte = data[malformed[i].offset];
    data[malformed[i].offset] = malformed[i].value;
    munit_assert(TC_PIV_CVC_read(data, sizeof data, &cvc) != TC_TLV_OK);
    munit_assert(memcmp(&cvc, &saved, sizeof cvc) == 0);
    data[malformed[i].offset] = byte;
  }
  /* ECDSA parameters must be absent, including ASN.1 NULL. */
  memcpy(extended, data, 138);
  extended[138] = 5; extended[139] = 0;
  memcpy(extended + 140, data + 138, sizeof data - 138);
  extended[3] += 2; extended[123] += 2; extended[125] += 2; extended[127] += 2;
  munit_assert(TC_PIV_CVC_read(extended, sizeof data + 2, &cvc) == TC_TLV_INVALID);
  /* A repeated role is still invalid when all enclosing lengths fit. */
  memcpy(extended, data, 121);
  memcpy(extended + 121, data + 117, 4);
  memcpy(extended + 125, data + 121, sizeof data - 121);
  extended[3] += 4;
  munit_assert(TC_PIV_CVC_read(extended, sizeof extended, &cvc) == TC_TLV_INVALID);
  munit_assert(memcmp(&cvc, &saved, sizeof cvc) == 0);
  for (i = 0; i < sizeof data; ++i) {
    munit_assert(TC_PIV_CVC_read(data, i, &cvc) != TC_TLV_OK);
    munit_assert(memcmp(&cvc, &saved, sizeof cvc) == 0);
  }
  data[7] = 0x81;
  munit_assert(TC_PIV_CVC_read(data, sizeof data, &cvc) == TC_TLV_UNSUPPORTED);
  data[7] = 0x80;
  data[sizeof prefix - 1] = 2;
  munit_assert(TC_PIV_CVC_read(data, sizeof data, &cvc) == TC_TLV_INVALID);
  data[sizeof prefix - 1] = 4;
  data[sizeof data - 1] = 0;
  munit_assert(TC_PIV_CVC_read(data, sizeof data, &cvc) == TC_TLV_INVALID);
  munit_assert(memcmp(&cvc, &saved, sizeof cvc) == 0);
  munit_assert(TC_PIV_CVC_read(NULL, 1, &cvc) == TC_TLV_ARGUMENT);
  munit_assert(TC_PIV_CVC_read(data, sizeof data, NULL) == TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/format", test_format, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/cvc", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
