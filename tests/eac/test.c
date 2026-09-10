/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/eac_cvc.h>
#include "munit.h"
#include <string.h>

static MunitResult key_limits(const MunitParameter params[], void* user)
{
  static const uint8_t encoded[] = {0x7f,0x49,19,6,10,4,0,0x7f,0,7,2,2,2,1,1,
                                   0x81,2,0x0c,0xa1,0x82,1,17};
  TC_TLV_limits limits = {sizeof encoded,sizeof encoded,4,1};
  TC_EAC_CVC_public_key key, saved;
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_EAC_CVC_public_key_read(encoded, sizeof encoded, &limits, &key), ==, TC_TLV_OK);
  munit_assert_int(key.algorithm, ==, TC_EAC_RSA_V15);
  munit_assert_uint(key.hash_bits, ==, 160);
  munit_assert_size(key.modulus.length, ==, 2);
  saved = key;
  for (i = 0; i < sizeof encoded; ++i) {
    munit_assert_int(TC_EAC_CVC_public_key_read(encoded, i, &limits, &key), ==, TC_TLV_MORE);
    munit_assert_memory_equal(sizeof key, &key, &saved);
  }
  --limits.max_input;
  munit_assert_int(TC_EAC_CVC_public_key_read(encoded, sizeof encoded, &limits, &key), ==, TC_TLV_LIMIT);
  ++limits.max_input; --limits.max_elements;
  munit_assert_int(TC_EAC_CVC_public_key_read(encoded, sizeof encoded, &limits, &key), ==, TC_TLV_LIMIT);
  ++limits.max_elements; limits.max_depth = 0;
  munit_assert_int(TC_EAC_CVC_public_key_read(encoded, sizeof encoded, &limits, &key), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof key, &key, &saved);
  return MUNIT_OK;
}

static MunitResult issuer_widths(const MunitParameter params[], void* user)
{
  uint8_t prime[32] = {0x80}, order[48] = {0x80}, point[65] = {4}, signature[96] = {1};
  TC_EAC_CVC certificate;
  TC_EAC_CVC_public_key issuer, domain;
  (void)params; (void)user;
  memset(&certificate, 0, sizeof certificate);
  memset(&issuer, 0, sizeof issuer); memset(&domain, 0, sizeof domain);
  certificate.public_key.algorithm = TC_EAC_ECDSA;
  certificate.public_key.point.data = point; certificate.public_key.point.length = sizeof point;
  certificate.signature.data = signature; certificate.signature.length = sizeof signature;
  issuer.algorithm = domain.algorithm = TC_EAC_ECDSA;
  issuer.has_domain = domain.has_domain = 1;
  issuer.order.data = order; issuer.order.length = sizeof order;
  domain.p.data = prime; domain.p.length = sizeof prime;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_OK);
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, NULL), ==, TC_TLV_ARGUMENT);
  --certificate.signature.length;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_INVALID);
  ++certificate.signature.length; certificate.public_key.point.length -= 2;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_INVALID);
  certificate.public_key.point.length += 2;
  issuer.has_domain = 0;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_ARGUMENT);
  issuer.algorithm = TC_EAC_RSA_PSS; issuer.modulus.data = signature; issuer.modulus.length = sizeof signature;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_OK);
  --issuer.modulus.length;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_INVALID);
  certificate.public_key.point.data = NULL;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_INVALID);
  certificate.signature.data = NULL;
  munit_assert_int(TC_EAC_CVC_check_encoding(&certificate, &issuer, &domain), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult extension_limits(const MunitParameter params[], void* user)
{
  uint8_t encoded[] = {0x65,9,0x73,7,6,2,0x2a,3,0x80,1,42};
  TC_TLV_limits limits = {sizeof encoded,sizeof encoded,3,3};
  TC_TLV_reader reader, saved_reader;
  TC_EAC_CVC_extension extension, saved;
  (void)params; (void)user;
  memset(&extension, 0xa5, sizeof extension); saved = extension;
  --limits.max_elements;
  munit_assert_int(TC_EAC_CVC_extensions_init(&reader, (TC_bytes){encoded,sizeof encoded}, &limits), ==, TC_TLV_OK);
  saved_reader = reader;
  munit_assert_int(TC_EAC_CVC_extension_next(&reader, &extension), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof extension, &extension, &saved);
  ++limits.max_elements;
  munit_assert_int(TC_EAC_CVC_extensions_init(&reader, (TC_bytes){encoded,sizeof encoded}, &limits), ==, TC_TLV_OK);
  saved_reader = reader;
  encoded[8] = 4;
  munit_assert_int(TC_EAC_CVC_extension_next(&reader, &extension), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof extension, &extension, &saved);
  encoded[8] = 0x80;
  munit_assert_int(TC_EAC_CVC_extension_next(&reader, &extension), ==, TC_TLV_OK);
  munit_assert_size(extension.fields.length, ==, 3);
  munit_assert_size(reader.elements, ==, 3);
  saved_reader = reader; saved = extension;
  munit_assert_int(TC_EAC_CVC_extension_next(&reader, &extension), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof extension, &extension, &saved);
  return MUNIT_OK;
}

static MunitResult certificate_limits(const MunitParameter params[], void* user)
{
  static const uint8_t encoded[] = {
    0x7f,0x21,0x64,0x7f,0x4e,0x5c,0x5f,0x29,0x01,0x00,0x42,0x0b,
    'D','E','T','E','S','T','0','0','0','0','1',
    0x7f,0x49,0x13,0x06,0x0a,0x04,0x00,0x7f,0x00,0x07,0x02,0x02,0x02,0x01,0x01,
    0x81,0x02,0x0c,0xa1,0x82,0x01,0x11,0x5f,0x20,0x0b,
    'D','E','T','E','S','T','0','0','0','0','1',
    0x7f,0x4c,0x12,0x06,0x09,0x04,0x00,0x7f,0x00,0x07,0x03,0x01,0x02,0x02,
    0x53,0x05,0xc0,0x00,0x00,0x00,0x00,
    0x5f,0x25,0x06,0x02,0x06,0x00,0x01,0x00,0x01,
    0x5f,0x24,0x06,0x03,0x00,0x00,0x01,0x00,0x01,0x5f,0x37,0x02,0x01,0x01
  };
  TC_TLV_limits limits = {sizeof encoded,sizeof encoded,15,3};
  TC_TLV_frame frames[3];
  TC_EAC_CVC_workspace workspace = {frames,3};
  TC_EAC_CVC certificate, saved;
  (void)params; (void)user;
  munit_assert_int(TC_EAC_CVC_read(encoded, sizeof encoded, &limits, &workspace, &certificate), ==, TC_TLV_OK);
  saved = certificate;
  --limits.max_elements;
  munit_assert_int(TC_EAC_CVC_read(encoded, sizeof encoded, &limits, &workspace, &certificate), ==, TC_TLV_LIMIT);
  ++limits.max_elements; --limits.max_depth;
  munit_assert_int(TC_EAC_CVC_read(encoded, sizeof encoded, &limits, &workspace, &certificate), ==, TC_TLV_LIMIT);
  ++limits.max_depth; --workspace.frame_capacity;
  munit_assert_int(TC_EAC_CVC_read(encoded, sizeof encoded, &limits, &workspace, &certificate), ==, TC_TLV_LIMIT);
  workspace.frame_capacity = 0; workspace.frames = NULL;
  munit_assert_int(TC_EAC_CVC_read(encoded, sizeof encoded, &limits, &workspace, &certificate), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof certificate, &certificate, &saved);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/certificate-limits", certificate_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/extension-limits", extension_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/key-limits", key_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/issuer-widths", issuer_widths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/eac", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
