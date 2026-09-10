/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_X509_OPENSSL_FIXTURE_H_
#define TC_TEST_X509_OPENSSL_FIXTURE_H_
#include "munit.h"
#include <tiny_crypto/common.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/err.h>

static inline X509* make_certificate(EVP_PKEY* key, const char* common_name, const X509* issuer)
{
  X509* cert = X509_new();
  X509_NAME* name;
  munit_assert_not_null(cert);
  munit_assert_int(X509_set_version(cert, 2), ==, 1);
  munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1), ==, 1);
  munit_assert_int(ASN1_TIME_set_string_X509(X509_getm_notBefore(cert), "20240101000000Z"), ==, 1);
  munit_assert_int(ASN1_TIME_set_string_X509(X509_getm_notAfter(cert), "20280101000000Z"), ==, 1);
  name = X509_get_subject_name(cert);
  munit_assert_int(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)common_name, -1, -1, 0), ==, 1);
  munit_assert_int(X509_set_issuer_name(cert, issuer ? X509_get_subject_name(issuer) : name), ==, 1);
  munit_assert_int(X509_set_pubkey(cert, key), ==, 1);
  return cert;
}

static inline size_t encode_certificate(X509* cert, EVP_PKEY* key, const EVP_MD* digest, uint8_t* der, size_t capacity)
{
  unsigned char* output = der;
  int length;
  munit_assert_int(X509_sign(cert, key, digest), >, 0);
  length = i2d_X509(cert, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_size((size_t)length, <=, capacity);
  munit_assert_int(i2d_X509(cert, &output), ==, length);
  return (size_t)length;
}
static inline void add_extension(X509* cert, int nid, const char* value)
{
  X509V3_CTX context;
  CONF* config = NCONF_new(NULL);
  X509_EXTENSION* extension;
  munit_assert_not_null(config);
  X509V3_set_ctx(&context, NULL, cert, NULL, NULL, 0);
  X509V3_set_nconf(&context, config);
  ERR_clear_error();
  extension = X509V3_EXT_nconf_nid(config, &context, nid, value);
  if (!extension) ERR_print_errors_fp(stderr);
  NCONF_free(config);
  munit_assert_not_null(extension);
  munit_assert_int(X509_add_ext(cert, extension, -1), ==, 1);
  X509_EXTENSION_free(extension);
}
static inline void add_card_identifiers(X509* card, TC_bytes fascn, const char* uuid_urn)
{
  GENERAL_NAMES* names = sk_GENERAL_NAME_new_null();
  GENERAL_NAME* fascn_name = GENERAL_NAME_new();
  OTHERNAME* other = OTHERNAME_new();
  ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
  munit_assert_not_null(names);
  munit_assert_not_null(fascn_name);
  munit_assert_not_null(other);
  munit_assert_not_null(value);
  ASN1_OBJECT_free(other->type_id);
  other->type_id = OBJ_txt2obj("2.16.840.1.101.3.6.6",1);
  munit_assert_not_null(other->type_id);
  munit_assert_int(ASN1_OCTET_STRING_set(value,fascn.data,(int)fascn.length), ==, 1);
  ASN1_TYPE_set(other->value,V_ASN1_OCTET_STRING,value);
  GENERAL_NAME_set0_value(fascn_name,GEN_OTHERNAME,other);
  munit_assert_int(sk_GENERAL_NAME_push(names,fascn_name), >, 0);
  if (uuid_urn) {
    GENERAL_NAME* uuid_name = GENERAL_NAME_new();
    ASN1_IA5STRING* uri = ASN1_IA5STRING_new();
    munit_assert_not_null(uuid_name);
    munit_assert_not_null(uri);
    munit_assert_int(ASN1_STRING_set(uri,uuid_urn,(int)strlen(uuid_urn)), ==, 1);
    GENERAL_NAME_set0_value(uuid_name,GEN_URI,uri);
    munit_assert_int(sk_GENERAL_NAME_push(names,uuid_name), >, 0);
  }
  munit_assert_int(X509_add1_ext_i2d(card,NID_subject_alt_name,names,0,0), ==, 1);
  GENERAL_NAMES_free(names);
}
#endif
