/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_CMS_OPENSSL_FIXTURE_H_
#define TC_TEST_CMS_OPENSSL_FIXTURE_H_
#include "../x509/openssl_fixture.h"
#include <limits.h>
#include <openssl/cms.h>

/* AlgorithmIdentifier parameters are outside the signed attributes. */
static inline void cms_fixture_omit_rsa_parameters(CMS_ContentInfo *cms) {
  CMS_SignerInfo *signer =
      sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
  X509_ALGOR *algorithm;
  CMS_SignerInfo_get0_algs(signer, NULL, NULL, NULL, &algorithm);
  munit_assert_int(OBJ_obj2nid(algorithm->algorithm), ==, NID_rsaEncryption);
  ASN1_OBJECT *oid = OBJ_dup(algorithm->algorithm);
  munit_assert_not_null(oid);
  munit_assert_int(X509_ALGOR_set0(algorithm, oid, V_ASN1_UNDEF, NULL), ==, 1);
}

static inline size_t omit_cms_rsa_parameters(TC_bytes encoded, uint8_t *out,
                                             size_t capacity) {
  const unsigned char *input = encoded.data;
  CMS_ContentInfo *copy =
      d2i_CMS_ContentInfo(NULL, &input, (long)encoded.length);
  munit_assert_not_null(copy);
  cms_fixture_omit_rsa_parameters(copy);
  int length = i2d_CMS_ContentInfo(copy, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_size((size_t)length, <=, capacity);
  unsigned char *output = out;
  munit_assert_int(i2d_CMS_ContentInfo(copy, &output), ==, length);
  CMS_ContentInfo_free(copy);
  return (size_t)length;
}

static inline TC_bytes cms_fixture_child(TC_bytes *parent, int expected_tag,
                                         int expected_class) {
  enum { PARSE_ERROR = 0x80, INDEFINITE_LENGTH = 1 };
  const unsigned char *value = parent->data;
  long length = 0;
  int tag, class_id;
  munit_assert_size(parent->length, <=, LONG_MAX);
  const int flags =
      ASN1_get_object(&value, &length, &tag, &class_id, (long)parent->length);
  munit_assert_int(flags & (PARSE_ERROR | INDEFINITE_LENGTH), ==, 0);
  munit_assert_int(tag, ==, expected_tag);
  munit_assert_int(class_id, ==, expected_class);
  munit_assert_long(length, >=, 0);
  const size_t header = (size_t)(value - parent->data);
  munit_assert_size(header, <=, parent->length);
  munit_assert_size((size_t)length, <=, parent->length - header);
  parent->data = value + length;
  parent->length -= header + (size_t)length;
  return (TC_bytes){value, (size_t)length};
}

static inline TC_bytes cms_fixture_attributes(TC_bytes input) {
  TC_bytes content_info =
      cms_fixture_child(&input, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
  munit_assert_size(input.length, ==, 0);
  (void)cms_fixture_child(&content_info, V_ASN1_OBJECT, V_ASN1_UNIVERSAL);
  TC_bytes wrapper =
      cms_fixture_child(&content_info, 0, V_ASN1_CONTEXT_SPECIFIC);
  TC_bytes data =
      cms_fixture_child(&wrapper, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
  (void)cms_fixture_child(&data, V_ASN1_INTEGER, V_ASN1_UNIVERSAL);
  (void)cms_fixture_child(&data, V_ASN1_SET, V_ASN1_UNIVERSAL);
  (void)cms_fixture_child(&data, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
  munit_assert_size(data.length, >, 0);
  if (data.data[0] == 0xa0)
    (void)cms_fixture_child(&data, 0, V_ASN1_CONTEXT_SPECIFIC);
  munit_assert_size(data.length, >, 0);
  if (data.data[0] == 0xa1)
    (void)cms_fixture_child(&data, 1, V_ASN1_CONTEXT_SPECIFIC);
  TC_bytes signers = cms_fixture_child(&data, V_ASN1_SET, V_ASN1_UNIVERSAL);
  TC_bytes signer =
      cms_fixture_child(&signers, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
  munit_assert_size(signers.length, ==, 0);
  (void)cms_fixture_child(&signer, V_ASN1_INTEGER, V_ASN1_UNIVERSAL);
  (void)cms_fixture_child(&signer, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
  (void)cms_fixture_child(&signer, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
  const TC_bytes before = signer;
  (void)cms_fixture_child(&signer, 0, V_ASN1_CONTEXT_SPECIFIC);
  return (TC_bytes){before.data, before.length - signer.length};
}

/* Reverse the SET OF order and sign those exact bytes using the fixture key. */
static inline size_t cms_fixture_reverse_attributes(uint8_t *encoded,
                                                    size_t length,
                                                    size_t capacity,
                                                    EVP_PKEY *key) {
  enum { CAPACITY = 2048, ATTRIBUTES = 16, SIGNATURE_BYTES = 80 };
  TC_bytes field = cms_fixture_attributes((TC_bytes){encoded, length});
  const uint8_t *header = field.data;
  const TC_bytes attributes =
      cms_fixture_child(&field, 0, V_ASN1_CONTEXT_SPECIFIC);
  const size_t header_length = (size_t)(attributes.data - header);
  uint8_t preimage[CAPACITY], signed_value[SIGNATURE_BYTES];
  munit_assert_size(header_length + attributes.length, <=, sizeof preimage);
  memcpy(preimage, header, header_length);
  preimage[0] = 0x31;
  TC_bytes children[ATTRIBUTES], remaining = attributes;
  size_t count = 0;
  while (remaining.length) {
    const TC_bytes before = remaining;
    munit_assert_size(count, <, ATTRIBUTES);
    (void)cms_fixture_child(&remaining, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    children[count++] =
        (TC_bytes){before.data, before.length - remaining.length};
  }
  munit_assert_size(count, >, 1);
  size_t used = header_length;
  while (count) {
    const TC_bytes child = children[--count];
    memcpy(preimage + used, child.data, child.length);
    used += child.length;
  }
  munit_assert_int(
      memcmp(attributes.data, preimage + header_length, attributes.length), !=,
      0);
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  munit_assert_not_null(context);
  size_t signature_length = sizeof signed_value;
  munit_assert_int(EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key),
                   ==, 1);
  munit_assert_int(
      EVP_DigestSign(context, signed_value, &signature_length, preimage, used),
      ==, 1);
  munit_assert_int(EVP_DigestVerifyInit(context, NULL, EVP_sha256(), NULL, key),
                   ==, 1);
  munit_assert_int(
      EVP_DigestVerify(context, signed_value, signature_length, preimage, used),
      ==, 1);
  EVP_MD_CTX_free(context);
  /* Re-encode the envelope around the new signature before changing its SET. */
  const unsigned char *input = encoded;
  munit_assert_size(length, <=, LONG_MAX);
  CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &input, (long)length);
  munit_assert_not_null(cms);
  CMS_SignerInfo *signer =
      sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
  munit_assert_not_null(signer);
  munit_assert_int(ASN1_OCTET_STRING_set(CMS_SignerInfo_get0_signature(signer),
                                         signed_value, (int)signature_length),
                   ==, 1);
  const int result = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(result, >, 0);
  munit_assert_size((size_t)result, <=, capacity);
  unsigned char *output = encoded;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &output), ==, result);
  CMS_ContentInfo_free(cms);
  field = cms_fixture_attributes((TC_bytes){encoded, (size_t)result});
  const TC_bytes replacement =
      cms_fixture_child(&field, 0, V_ASN1_CONTEXT_SPECIFIC);
  munit_assert_size(replacement.length, ==, attributes.length);
  memcpy((uint8_t *)replacement.data, preimage + header_length,
         replacement.length);
  return (size_t)result;
}

static inline size_t encode_issuer_crl_entries(X509 *issuer, EVP_PKEY *key,
                                               X509 *revoked,
                                               size_t filler_entries,
                                               uint8_t *out, size_t capacity) {
  X509_CRL *crl = X509_CRL_new();
  munit_assert_not_null(crl);
  munit_assert_int(X509_CRL_set_version(crl, 1), ==, 1);
  munit_assert_int(X509_CRL_set_issuer_name(crl, X509_get_subject_name(issuer)),
                   ==, 1);
  munit_assert_int(X509_CRL_set1_lastUpdate(crl, X509_get0_notBefore(issuer)),
                   ==, 1);
  munit_assert_int(X509_CRL_set1_nextUpdate(crl, X509_get0_notAfter(issuer)),
                   ==, 1);
  ASN1_INTEGER *number = ASN1_INTEGER_new();
  munit_assert_not_null(number);
  munit_assert_int(ASN1_INTEGER_set(number, 1), ==, 1);
  munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_crl_number, number, 0, 0), ==,
                   1);
  ASN1_INTEGER_free(number);
  for (size_t i = 0; i < filler_entries; ++i) {
    X509_REVOKED *entry = X509_REVOKED_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    munit_assert_not_null(entry);
    munit_assert_not_null(serial);
    munit_assert_int(ASN1_INTEGER_set_uint64(serial, 100000 + (uint64_t)i), ==,
                     1);
    munit_assert_int(X509_REVOKED_set_serialNumber(entry, serial), ==, 1);
    munit_assert_int(
        X509_REVOKED_set_revocationDate(entry, X509_getm_notBefore(issuer)), ==,
        1);
    munit_assert_int(X509_CRL_add0_revoked(crl, entry), ==, 1);
    ASN1_INTEGER_free(serial);
  }
  if (revoked) {
    X509_REVOKED *entry = X509_REVOKED_new();
    munit_assert_not_null(entry);
    munit_assert_int(
        X509_REVOKED_set_serialNumber(entry, X509_get_serialNumber(revoked)),
        ==, 1);
    munit_assert_int(
        X509_REVOKED_set_revocationDate(entry, X509_getm_notBefore(revoked)),
        ==, 1);
    munit_assert_int(X509_CRL_add0_revoked(crl, entry), ==, 1);
  }
  munit_assert_int(X509_CRL_sign(crl, key, EVP_sha256()), >, 0);
  const int length = i2d_X509_CRL(crl, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_size((size_t)length, <=, capacity);
  unsigned char *cursor = out;
  munit_assert_int(i2d_X509_CRL(crl, &cursor), ==, length);
  X509_CRL_free(crl);
  return (size_t)length;
}

static inline size_t encode_issuer_crl(X509 *issuer, EVP_PKEY *key,
                                       X509 *revoked, uint8_t *out,
                                       size_t capacity) {
  return encode_issuer_crl_entries(issuer, key, revoked, 0, out, capacity);
}

static void set_cms_signer_name(CMS_ContentInfo *cms, X509_NAME *name) {
  ASN1_OBJECT *oid = OBJ_txt2obj("2.16.840.1.101.3.6.5", 1);
  CMS_SignerInfo *signer =
      sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
  unsigned char *encoded_name = NULL;
  munit_assert_not_null(oid);
  munit_assert_not_null(signer);
  int position = CMS_signed_get_attr_by_OBJ(signer, oid, -1);
  if (position >= 0)
    X509_ATTRIBUTE_free(CMS_signed_delete_attr(signer, position));
  int length = i2d_X509_NAME(name, &encoded_name);
  munit_assert_int(length, >, 0);
  munit_assert_int(CMS_signed_add1_attr_by_OBJ(signer, oid, V_ASN1_SEQUENCE,
                                               encoded_name, length),
                   ==, 1);
  OPENSSL_free(encoded_name);
  ASN1_OBJECT_free(oid);
}
static inline void add_cms_octet_attribute(CMS_ContentInfo *cms,
                                           const char *identifier,
                                           const uint8_t *bytes, int length) {
  ASN1_OBJECT *oid = OBJ_txt2obj(identifier, 1);
  munit_assert_not_null(oid);
  CMS_SignerInfo *signer =
      sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
  munit_assert_int(CMS_signed_add1_attr_by_OBJ(signer, oid, V_ASN1_OCTET_STRING,
                                               bytes, length),
                   ==, 1);
  ASN1_OBJECT_free(oid);
}

static inline size_t encode_biometric_record_parameters(
    X509 *certificate, EVP_PKEY *key, int include_certificate,
    int omit_rsa_parameters, TC_bytes fascn, TC_bytes guid, TC_bytes record,
    uint16_t format_type, uint32_t biometric_type, uint8_t data_type,
    uint8_t *out, size_t capacity) {
  enum {
    HEADER_BYTES = 88,
    P256_SIGNATURE_BYTES = 72,
    MAX_SIGNATURE_ATTEMPTS = 128
  };
  const size_t signed_bytes = HEADER_BYTES + record.length;
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED |
                         (include_certificate ? 0 : CMS_NOCERTS);
  const size_t target_signature_length = EVP_PKEY_is_a(key, "RSA")
                                             ? (size_t)EVP_PKEY_get_size(key)
                                             : P256_SIGNATURE_BYTES;
  munit_assert_size(record.length, <=, UINT32_MAX);
  munit_assert_size(capacity, >, signed_bytes);
  memset(out, 0, signed_bytes);
  out[0] = 3;
  out[1] = 0x0d;
  out[2] = (uint8_t)(record.length >> 24);
  out[3] = (uint8_t)(record.length >> 16);
  out[4] = (uint8_t)(record.length >> 8);
  out[5] = (uint8_t)record.length;
  out[8] = 0;
  out[9] = 0x1b;
  out[10] = (uint8_t)(format_type >> 8);
  out[11] = (uint8_t)format_type;
  static const uint8_t date[] = {20, 25, 1, 1, 0, 0, 0, 'Z'};
  memcpy(out + 12, date, sizeof date);
  memcpy(out + 20, date, sizeof date);
  memcpy(out + 28, date, sizeof date);
  out[29] = 28;
  out[36] = (uint8_t)(biometric_type >> 16);
  out[37] = (uint8_t)(biometric_type >> 8);
  out[38] = (uint8_t)biometric_type;
  out[39] = data_type;
  memcpy(out + 59, fascn.data, fascn.length);
  memcpy(out + HEADER_BYTES, record.data, record.length);
  size_t expected = 0;
  /* The signed header contains the CMS length. RSA has fixed-width signatures;
   * choose the usual 72-byte length for P-256 with bounded retries. */
  for (unsigned attempt = 0; attempt < MAX_SIGNATURE_ATTEMPTS; ++attempt) {
    out[6] = (uint8_t)(expected >> 8);
    out[7] = (uint8_t)expected;
    CMS_ContentInfo *cms =
        CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
    BIO *input = BIO_new_mem_buf(out, (int)signed_bytes);
    ASN1_OBJECT *type = OBJ_txt2obj("2.16.840.1.101.3.6.2", 1);
    munit_assert_not_null(cms);
    munit_assert_not_null(input);
    munit_assert_not_null(type);
    munit_assert_int(CMS_set1_eContentType(cms, type), ==, 1);
    set_cms_signer_name(cms, X509_get_subject_name(certificate));
    if (fascn.length)
      add_cms_octet_attribute(cms, "2.16.840.1.101.3.6.6", fascn.data,
                              (int)fascn.length);
    if (guid.length)
      add_cms_octet_attribute(cms, "1.3.6.1.1.16.4", guid.data,
                              (int)guid.length);
    munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
    if (omit_rsa_parameters)
      cms_fixture_omit_rsa_parameters(cms);
    CMS_SignerInfo *signer =
        sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
    munit_assert_int(CMS_SignerInfo_verify(signer), ==, 1);
    const int signature_length =
        ASN1_STRING_length(CMS_SignerInfo_get0_signature(signer));
    const int length = i2d_CMS_ContentInfo(cms, NULL);
    munit_assert_int(length, >, 0);
    munit_assert_size((size_t)length, <=, capacity - signed_bytes);
    const int ready = expected == (size_t)length &&
                      (size_t)signature_length == target_signature_length;
    if (ready) {
      unsigned char *cursor = out + signed_bytes;
      munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
    }
    expected =
        (size_t)length + target_signature_length - (size_t)signature_length;
    CMS_ContentInfo_free(cms);
    BIO_free(input);
    ASN1_OBJECT_free(type);
    if (ready)
      return signed_bytes + (size_t)length;
  }
  munit_error("could not encode fixed-length biometric signature");
  return 0;
}

static inline size_t
encode_biometric_parameters(X509 *certificate, EVP_PKEY *key,
                            int include_certificate, int omit_rsa_parameters,
                            TC_bytes fascn, TC_bytes guid, uint8_t *out,
                            size_t capacity) {
  enum { RECORD_BYTES = 38 };
  static const uint8_t record[RECORD_BYTES] = {
      'F', 'M', 'R', 0,   ' ',  '2', '0', 0, 0,   RECORD_BYTES,
      0,   1,   0,   1,   0x80, 1,   1,   0, 1,   0,
      0,   197, 0,   197, 2,    0,   2,   0, 100, 0,
      0,   0,   7,   0,   100,  0,   0,   0};
  return encode_biometric_record_parameters(
      certificate, key, include_certificate, omit_rsa_parameters, fascn, guid,
      (TC_bytes){record, sizeof record}, 0x0201, 8, 0x80, out, capacity);
}
static inline size_t encode_biometric(X509 *certificate, EVP_PKEY *key,
                                      int include_certificate, TC_bytes fascn,
                                      TC_bytes guid, uint8_t *out,
                                      size_t capacity) {
  return encode_biometric_parameters(certificate, key, include_certificate, 0,
                                     fascn, guid, out, capacity);
}

static inline size_t cms_fixture_field(uint8_t *out, size_t capacity,
                                       uint8_t tag, const uint8_t *bytes,
                                       size_t length) {
  munit_assert_size(length, <=, 65535);
  const size_t header = length < 128 ? 2 : length < 256 ? 3 : 4;
  munit_assert_size(length + header, <=, capacity);
  out[0] = tag;
  if (header == 2)
    out[1] = (uint8_t)length;
  else {
    out[1] = header == 3 ? 0x81 : 0x82;
    if (header == 4)
      out[2] = (uint8_t)(length >> 8);
    out[header - 1] = (uint8_t)length;
  }
  if (length)
    memcpy(out + header, bytes, length);
  return header + length;
}

static inline size_t encode_security_inventory_parameters(
    X509 *certificate, EVP_PKEY *key, int omit_rsa_parameters,
    const uint16_t *containers, const TC_bytes *contents, size_t count,
    uint8_t *out, size_t capacity) {
  enum {
    DIGEST_BYTES = 32,
    ENTRY_BYTES = 39,
    MAX_GROUPS = 16,
    CAPACITY = 2048
  };
  uint8_t entries[MAX_GROUPS * ENTRY_BYTES], body[CAPACITY], lds[CAPACITY],
      encoded[CAPACITY];
  uint8_t mapping[MAX_GROUPS * 3];
  munit_assert_size(count, >=, 2);
  munit_assert_size(count, <=, MAX_GROUPS);
  for (size_t i = 0; i < count; ++i) {
    uint8_t *entry = entries + i * ENTRY_BYTES;
    const uint8_t header[] = {0x30, ENTRY_BYTES - 2, 2, 1, (uint8_t)(i + 1),
                              4,    DIGEST_BYTES};
    memcpy(entry, header, sizeof header);
    unsigned digest_length;
    munit_assert_int(EVP_Digest(contents[i].data, contents[i].length,
                                entry + sizeof header, &digest_length,
                                EVP_sha256(), NULL),
                     ==, 1);
    munit_assert_uint(digest_length, ==, DIGEST_BYTES);
    mapping[i * 3] = (uint8_t)(i + 1);
    mapping[i * 3 + 1] = (uint8_t)(containers[i] >> 8);
    mapping[i * 3 + 2] = (uint8_t)containers[i];
  }
  static const uint8_t prefix[] = {2,    1,    0, 0x30, 11, 6, 9, 0x60,
                                   0x86, 0x48, 1, 0x65, 3,  4, 2, 1};
  memcpy(body, prefix, sizeof prefix);
  const size_t body_length =
      sizeof prefix + cms_fixture_field(body + sizeof prefix,
                                        sizeof body - sizeof prefix, 0x30,
                                        entries, count * ENTRY_BYTES);
  const size_t lds_length =
      cms_fixture_field(lds, sizeof lds, 0x30, body, body_length);
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_NOCERTS;
  CMS_ContentInfo *cms =
      CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
  BIO *input = BIO_new_mem_buf(lds, (int)lds_length);
  ASN1_OBJECT *type = OBJ_txt2obj("1.3.27.1.1.1", 1);
  munit_assert_not_null(cms);
  munit_assert_not_null(input);
  munit_assert_not_null(type);
  munit_assert_int(CMS_set1_eContentType(cms, type), ==, 1);
  munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
  if (omit_rsa_parameters)
    cms_fixture_omit_rsa_parameters(cms);
  const int length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_int(length, <=, CAPACITY);
  unsigned char *cursor = encoded;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
  size_t used = cms_fixture_field(out, capacity, 0xba, mapping, count * 3);
  used += cms_fixture_field(out + used, capacity - used, 0xbb, encoded,
                            (size_t)length);
  used += cms_fixture_field(out + used, capacity - used, 0xfe, NULL, 0);
  CMS_ContentInfo_free(cms);
  BIO_free(input);
  ASN1_OBJECT_free(type);
  return used;
}

static inline size_t encode_security_inventory(X509 *certificate, EVP_PKEY *key,
                                               const uint16_t *containers,
                                               const TC_bytes *contents,
                                               size_t count, uint8_t *out,
                                               size_t capacity) {
  return encode_security_inventory_parameters(certificate, key, 0, containers,
                                              contents, count, out, capacity);
}

static inline size_t encode_security_object(X509 *certificate, EVP_PKEY *key,
                                            const TC_bytes contents[2],
                                            uint8_t *out, size_t capacity) {
  static const uint16_t containers[] = {0x3000, 0x3002};
  return encode_security_inventory(certificate, key, containers, contents, 2,
                                   out, capacity);
}
#endif
