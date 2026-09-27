/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Test-only fixture builder. Inputs are the checked-in synthetic private keys. */
#include "../cms/openssl_fixture.h"
#include "fascn_fixture.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

enum { CAPACITY = 20000 };

static void write_file(const char *directory, const char *name,
                       const uint8_t *data, size_t length) {
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", directory, name), >, 0);
  FILE *file = fopen(path, "wb");
  munit_assert_not_null(file);
  munit_assert_size(fwrite(data, 1, length, file), ==, length);
  munit_assert_int(fclose(file), ==, 0);
}

static EVP_PKEY *read_key(const char *directory, const char *name) {
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", directory, name), >, 0);
  FILE *file = fopen(path, "rb");
  munit_assert_not_null(file);
  EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_not_null(key);
  return key;
}

static void write_card_authentication_proof(const char *directory,
                                            EVP_PKEY *card_key) {
  uint8_t challenge[256], signature[256];
  challenge[0] = 0;
  for (size_t i = 1; i < sizeof challenge; ++i)
    challenge[i] = (uint8_t)(0x5a ^ (uint8_t)i);
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(card_key, NULL);
  munit_assert_not_null(context);
  munit_assert_int(EVP_PKEY_sign_init(context), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(context, RSA_NO_PADDING), ==, 1);
  size_t length = sizeof signature;
  munit_assert_int(EVP_PKEY_sign(context, signature, &length, challenge,
                                sizeof challenge), ==, 1);
  munit_assert_size(length, ==, sizeof signature);
  write_file(directory, "ga-challenge.bin", challenge, sizeof challenge);
  write_file(directory, "ga-signature.bin", signature, sizeof signature);
  EVP_PKEY_CTX_free(context);
}

static size_t read_test_image(const char *directory, uint8_t *out,
                              size_t capacity) {
  char path[512];
  munit_assert_int(snprintf(path,sizeof path,"%s/../common/test-face.jpg",
      directory), >, 0);
  FILE *file = fopen(path,"rb");
  munit_assert_not_null(file);
  size_t length = fread(out,1,capacity,file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  return length;
}

static void write_cert(const char *directory, const char *name,
                       X509 *cert, EVP_PKEY *issuer_key) {
  uint8_t der[CAPACITY];
  size_t length = encode_certificate(cert, issuer_key, EVP_sha256(), der, sizeof der);
  write_file(directory, name, der, length);
}

static size_t field(uint8_t *output, uint8_t tag, const uint8_t *value,
                    size_t length) {
  return cms_fixture_field(output, CAPACITY, tag, value, length);
}

static void write_certificate_object(const char *directory, const char *name,
                                     X509 *cert, EVP_PKEY *issuer_key) {
  uint8_t der[CAPACITY], body[CAPACITY], encoded[CAPACITY];
  size_t der_length = encode_certificate(cert,issuer_key,EVP_sha256(),der,sizeof der);
  size_t body_length = field(body,0x70,der,der_length);
  const uint8_t compression = 0;
  body_length += field(body + body_length,0x71,&compression,1);
  body[body_length++] = 0xfe;
  body[body_length++] = 0;
  size_t length = field(encoded,0x53,body,body_length);
  write_file(directory,name,encoded,length);
}

static TC_bytes contents(const uint8_t *encoded, size_t length) {
  size_t header = 2;
  if (length < 2) munit_error("short fixture TLV");
  if (encoded[1] == 0x81) header = 3;
  if (encoded[1] == 0x82) header = 4;
  munit_assert_size(length, >=, header);
  return (TC_bytes){encoded + header, length - header};
}

static size_t encrypted_object(const uint8_t key[16], const uint8_t *plaintext,
                               size_t plaintext_length, uint8_t *out) {
  uint8_t ciphertext[CAPACITY];
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int first = 0, last = 0;
  munit_assert_not_null(context);
  munit_assert_size(plaintext_length + 16, <=, sizeof ciphertext);
  munit_assert_int(EVP_EncryptInit_ex(context, EVP_aes_128_ecb(), NULL, key, NULL), ==, 1);
  munit_assert_int(EVP_EncryptUpdate(context, ciphertext, &first, plaintext,
                                    (int)plaintext_length), ==, 1);
  munit_assert_int(EVP_EncryptFinal_ex(context, ciphertext + first, &last), ==, 1);
  EVP_CIPHER_CTX_free(context);
  uint8_t inner[CAPACITY];
  size_t inner_length = field(inner, 0xbc, ciphertext, (size_t)first + (size_t)last);
  return field(out, 0x53, inner, inner_length);
}

static size_t security_inventory(X509 *signer, EVP_PKEY *signer_key,
                                 const uint8_t *groups,
                                 const uint16_t *containers,
                                 const TC_bytes *hashed, size_t count,
                                 int use_sha1, uint8_t *output) {
  const unsigned digest_bytes = use_sha1 ? 20 : 32;
  const unsigned entry_bytes = digest_bytes + 7;
  uint8_t entries[5 * 39], mapping[5 * 3], body[CAPACITY], lds[CAPACITY],
      cms_der[CAPACITY];
  munit_assert_size(count, <=, 5);
  for (size_t i = 0; i < count; ++i) {
    uint8_t *entry = entries + i * entry_bytes;
    const uint8_t header[] = {0x30,(uint8_t)(entry_bytes - 2),0x02,1,
                              groups[i],0x04,(uint8_t)digest_bytes};
    memcpy(entry,header,sizeof header);
    unsigned digest_length = 0;
    munit_assert_int(EVP_Digest(hashed[i].data,hashed[i].length,
        entry + sizeof header,&digest_length,use_sha1 ? EVP_sha1() : EVP_sha256(),NULL), ==, 1);
    munit_assert_uint(digest_length, ==, digest_bytes);
    mapping[3 * i] = groups[i];
    mapping[3 * i + 1] = (uint8_t)(containers[i] >> 8);
    mapping[3 * i + 2] = (uint8_t)containers[i];
  }
  static const uint8_t sha256_prefix[] = {2,1,0,0x30,11,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1};
  static const uint8_t sha1_prefix[] = {2,1,0,0x30,7,6,5,0x2b,0x0e,3,2,0x1a};
  const uint8_t *prefix = use_sha1 ? sha1_prefix : sha256_prefix;
  size_t prefix_length = use_sha1 ? sizeof sha1_prefix : sizeof sha256_prefix;
  memcpy(body,prefix,prefix_length);
  size_t body_length = prefix_length + field(body + prefix_length,0x30,entries,count * entry_bytes);
  size_t lds_length = field(lds,0x30,body,body_length);
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_NOCERTS |
                         CMS_NO_SIGNING_TIME;
  CMS_ContentInfo *cms = CMS_sign(signer,signer_key,NULL,NULL,flags | CMS_PARTIAL);
  BIO *input = BIO_new_mem_buf(lds,(int)lds_length);
  ASN1_OBJECT *type = OBJ_txt2obj("1.3.27.1.1.1",1);
  munit_assert_not_null(cms); munit_assert_not_null(input); munit_assert_not_null(type);
  munit_assert_int(CMS_set1_eContentType(cms,type), ==, 1);
  munit_assert_int(CMS_final(cms,input,NULL,flags), ==, 1);
  int cms_length = i2d_CMS_ContentInfo(cms,NULL);
  munit_assert_int(cms_length, >, 0);
  unsigned char *cursor = cms_der;
  munit_assert_int(i2d_CMS_ContentInfo(cms,&cursor), ==, cms_length);
  size_t used = field(output,0xba,mapping,count * 3);
  used += field(output + used,0xbb,cms_der,(size_t)cms_length);
  used += field(output + used,0xfe,NULL,0);
  CMS_ContentInfo_free(cms); BIO_free(input); ASN1_OBJECT_free(type);
  return used;
}

static size_t signed_chuid(X509 *signer, EVP_PKEY *signer_key,
                           const uint8_t fascn[25], const uint8_t uuid[16],
                           uint8_t *out, uint8_t *unsigned_out,
                           size_t *unsigned_length, int piv) {
  uint8_t body[CAPACITY], content[59], cms_der[CAPACITY];
  size_t used = 0;
  used += field(content + used, 0x30, fascn, 25);
  used += field(content + used, 0x34, uuid, 16);
  used += field(content + used, 0x35, (const uint8_t *)"20271231", 8);
  munit_assert_size(used, ==, 55);
  if (piv) { content[used++] = 0x3d; content[used++] = 0; }
  content[used++] = 0xfe;
  content[used++] = 0;
  *unsigned_length = field(unsigned_out, 0x53, content, used);

  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED |
                         CMS_NO_SIGNING_TIME;
  CMS_ContentInfo *cms = CMS_sign(signer, signer_key, NULL, NULL, flags | CMS_PARTIAL);
  BIO *input = BIO_new_mem_buf(content, (int)used);
  ASN1_OBJECT *type = OBJ_txt2obj("2.16.840.1.101.3.6.1", 1);
  munit_assert_not_null(cms);
  munit_assert_not_null(input);
  munit_assert_not_null(type);
  munit_assert_int(CMS_set1_eContentType(cms, type), ==, 1);
  set_cms_signer_name(cms, X509_get_subject_name(signer));
  munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
  int cms_length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(cms_length, >, 0);
  unsigned char *cursor = cms_der;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, cms_length);
  CMS_ContentInfo_free(cms);
  BIO_free(input);
  ASN1_OBJECT_free(type);
  memcpy(body, content, used - 2);
  size_t body_length = used - 2;
  body_length += field(body + body_length, 0x3e, cms_der, (size_t)cms_length);
  body[body_length++] = 0xfe;
  body[body_length++] = 0;
  return field(out, 0x53, body, body_length);
}

static void add_twic_fascn(X509 *card, TC_bytes fascn) {
  GENERAL_NAMES *names = sk_GENERAL_NAME_new_null();
  GENERAL_NAME *name = GENERAL_NAME_new();
  OTHERNAME *other = OTHERNAME_new();
  ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
  munit_assert_not_null(names);
  munit_assert_not_null(name);
  munit_assert_not_null(other);
  munit_assert_not_null(value);
  ASN1_OBJECT_free(other->type_id);
  other->type_id = OBJ_txt2obj("1.3.6.1.4.1.29138.6.6", 1);
  munit_assert_not_null(other->type_id);
  munit_assert_int(ASN1_OCTET_STRING_set(value, fascn.data,
                                        (int)fascn.length), ==, 1);
  ASN1_TYPE_set(other->value, V_ASN1_OCTET_STRING, value);
  GENERAL_NAME_set0_value(name, GEN_OTHERNAME, other);
  munit_assert_int(sk_GENERAL_NAME_push(names, name), >, 0);
  munit_assert_int(X509_add1_ext_i2d(card, NID_subject_alt_name, names, 0, 0),
                   ==, 1);
  GENERAL_NAMES_free(names);
}

static void add_raw_extension(X509 *certificate, const char *oid,
                              const uint8_t *der, size_t length) {
  ASN1_OBJECT *object = OBJ_txt2obj(oid, 1);
  ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
  munit_assert_not_null(object);
  munit_assert_not_null(value);
  munit_assert_int(ASN1_OCTET_STRING_set(value, der, (int)length), ==, 1);
  X509_EXTENSION *extension = X509_EXTENSION_create_by_OBJ(NULL, object, 0,
                                                             value);
  munit_assert_not_null(extension);
  munit_assert_int(X509_add_ext(certificate, extension, -1), ==, 1);
  X509_EXTENSION_free(extension);
  ASN1_OCTET_STRING_free(value);
  ASN1_OBJECT_free(object);
}

static void add_authority_key_id(X509 *certificate, X509 *issuer) {
  ASN1_OCTET_STRING *subject_key = X509_get_ext_d2i(
      issuer, NID_subject_key_identifier, NULL, NULL);
  AUTHORITY_KEYID *authority = AUTHORITY_KEYID_new();
  munit_assert_not_null(subject_key);
  munit_assert_not_null(authority);
  authority->keyid = ASN1_OCTET_STRING_dup(subject_key);
  munit_assert_not_null(authority->keyid);
  munit_assert_int(X509_add1_ext_i2d(certificate, NID_authority_key_identifier,
                                      authority, 0, 0), ==, 1);
  AUTHORITY_KEYID_free(authority);
  ASN1_OCTET_STRING_free(subject_key);
}

static void write_trust_anchor_info(const char *directory, X509 *root,
                                    EVP_PKEY *root_key) {
  uint8_t spki[CAPACITY], name[CAPACITY], certificate[CAPACITY];
  uint8_t path[CAPACITY], info[CAPACITY], choice[CAPACITY], list[CAPACITY];
  int spki_length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(root), NULL);
  int name_length = i2d_X509_NAME(X509_get_subject_name(root), NULL);
  int certificate_length = i2d_X509(root, NULL);
  munit_assert_int(spki_length, >, 0);
  munit_assert_int(name_length, >, 0);
  munit_assert_int(certificate_length, >, 0);
  unsigned char *cursor = spki;
  munit_assert_int(i2d_X509_PUBKEY(X509_get_X509_PUBKEY(root), &cursor), ==,
                   spki_length);
  cursor = name;
  munit_assert_int(i2d_X509_NAME(X509_get_subject_name(root), &cursor), ==,
                   name_length);
  cursor = certificate;
  munit_assert_int(i2d_X509(root, &cursor), ==, certificate_length);
  ASN1_OCTET_STRING *ski = X509_get_ext_d2i(root, NID_subject_key_identifier,
                                            NULL, NULL);
  munit_assert_not_null(ski);
  TC_bytes certificate_body = contents(certificate, (size_t)certificate_length);
  size_t path_length = (size_t)name_length;
  memcpy(path, name, path_length);
  path_length += field(path + path_length, 0xa0, certificate_body.data,
                       certificate_body.length);
  size_t info_length = (size_t)spki_length;
  memcpy(info, spki, info_length);
  size_t key_field_length = field(info + info_length, 4, ski->data,
                                  (size_t)ski->length);
  info_length += key_field_length;
  size_t path_start = info_length;
  info_length += field(info + info_length, 0x30, path, path_length);
  size_t choice_length = field(choice, 0x30, info, info_length);
  size_t wrapper_length = field(list, 0xa2, choice, choice_length);
  size_t list_length = field(choice, 0x30, list, wrapper_length);
  write_file(directory,"trust-anchors.der",choice,list_length);
  size_t certificate_list_length = field(list,0x30,certificate,
                                          (size_t)certificate_length);
  write_file(directory,"trust-anchor-certificate.der",list,
             certificate_list_length);
  /* A matching embedded certificate makes altered key identity invalid. */
  info[(size_t)spki_length + 2] ^= 1;
  choice_length = field(choice,0x30,info,info_length);
  wrapper_length = field(list,0xa2,choice,choice_length);
  list_length = field(choice,0x30,list,wrapper_length);
  write_file(directory,"trust-anchor-bad-keyid.der",choice,list_length);
  info[(size_t)spki_length + 2] ^= 1;
  TC_bytes path_body = contents(info + path_start,info_length - path_start);
  ((uint8_t *)path_body.data)[(size_t)name_length - 1] ^= 1;
  choice_length = field(choice,0x30,info,info_length);
  wrapper_length = field(list,0xa2,choice,choice_length);
  list_length = field(choice,0x30,list,wrapper_length);
  write_file(directory,"trust-anchor-bad-name.der",choice,list_length);
  ((uint8_t *)path_body.data)[(size_t)name_length - 1] ^= 1;
  info[(size_t)spki_length - 1] ^= 1;
  choice_length = field(choice,0x30,info,info_length);
  wrapper_length = field(list,0xa2,choice,choice_length);
  list_length = field(choice,0x30,list,wrapper_length);
  write_file(directory,"trust-anchor-bad-key.der",choice,list_length);
  info[(size_t)spki_length - 1] ^= 1;
  X509 *bad_usage = X509_dup(root);
  munit_assert_not_null(bad_usage);
  int usage_index = X509_get_ext_by_NID(bad_usage,NID_key_usage,-1);
  munit_assert_int(usage_index, >=, 0);
  X509_EXTENSION *old_usage = X509_delete_ext(bad_usage,usage_index);
  munit_assert_not_null(old_usage);
  X509_EXTENSION_free(old_usage);
  add_extension(bad_usage,NID_key_usage,"critical,digitalSignature");
  munit_assert_int(X509_sign(bad_usage,root_key,EVP_sha256()), >, 0);
  int bad_certificate_length = i2d_X509(bad_usage,NULL);
  munit_assert_int(bad_certificate_length, >, 0);
  cursor = certificate;
  munit_assert_int(i2d_X509(bad_usage,&cursor), ==, bad_certificate_length);
  certificate_body = contents(certificate,(size_t)bad_certificate_length);
  path_length = (size_t)name_length;
  memcpy(path,name,path_length);
  path_length += field(path + path_length,0xa0,certificate_body.data,
                       certificate_body.length);
  info_length = (size_t)spki_length + key_field_length;
  info_length += field(info + info_length,0x30,path,path_length);
  choice_length = field(choice,0x30,info,info_length);
  wrapper_length = field(list,0xa2,choice,choice_length);
  list_length = field(choice,0x30,list,wrapper_length);
  write_file(directory,"trust-anchor-bad-certsign.der",choice,list_length);
  X509_free(bad_usage);
  ASN1_OCTET_STRING_free(ski);
}

static void make_profile(const char *profile, const char *directory,
                         const char *key_directory) {
  const int legacy = !strcmp(profile, "legacy");
  munit_assert_true(legacy || !strcmp(profile, "nexgen"));
  EVP_PKEY *root_key = read_key(key_directory, "root.pem");
  EVP_PKEY *issuer_key = read_key(key_directory, "issuer.pem");
  EVP_PKEY *signer_key = read_key(key_directory, "signer.pem");
  EVP_PKEY *card_key = read_key(key_directory, "card.pem");
  write_card_authentication_proof(directory, card_key);
  EVP_PKEY *piv_auth_key = read_key(key_directory, "piv-auth.pem");
  X509 *root = make_certificate(root_key, legacy ? "Synthetic Legacy root" : "Synthetic NEXGEN root", NULL);
  add_extension(root, NID_basic_constraints, "critical,CA:TRUE,pathlen:2");
  add_extension(root, NID_key_usage, "critical,keyCertSign,cRLSign");
  add_extension(root, NID_subject_key_identifier, "hash");
  write_cert(directory, "root.der", root, root_key);
  write_trust_anchor_info(directory, root, root_key);
  X509 *issuer = make_certificate(issuer_key, legacy ? "Synthetic Legacy issuer" : "Synthetic NEXGEN issuer", root);
  add_extension(issuer, NID_basic_constraints, "critical,CA:TRUE,pathlen:1");
  add_extension(issuer, NID_key_usage, "critical,keyCertSign,cRLSign");
  add_extension(issuer, NID_subject_key_identifier, "hash");
  add_authority_key_id(issuer,root);
  write_cert(directory, "issuer.der", issuer, root_key);
  uint8_t crl_der[CAPACITY];
  size_t crl_length = encode_issuer_crl(root,root_key,NULL,crl_der,sizeof crl_der);
  write_file(directory,"root-crl.der",crl_der,crl_length);
  crl_length = encode_issuer_crl(issuer,issuer_key,NULL,crl_der,sizeof crl_der);
  write_file(directory,"issuer-crl.der",crl_der,crl_length);
  X509 *signer = make_certificate(signer_key, legacy ? "Synthetic Legacy content signer" : "Synthetic NEXGEN content signer", issuer);
  add_extension(signer, NID_key_usage, "critical,digitalSignature");
  add_extension(signer, NID_info_access,
                "OCSP;URI:http://fixture.invalid/ocsp");
  add_extension(signer, NID_crl_distribution_points,
                "URI:http://fixture.invalid/crl");
  add_extension(signer, NID_certificate_policies,"2.16.840.1.101.3.6.7");
  add_extension(signer, NID_ext_key_usage,
      "2.16.840.1.101.3.6.7,1.3.6.1.4.1.29138.6.7");
  static const uint8_t private_key_period[] = {
      0x30,0x22,0x80,0x0f,'2','0','2','4','0','1','0','1','0','0','0','0','0','0','Z',
      0x81,0x0f,'2','0','2','8','0','1','0','1','0','0','0','0','0','0','Z'};
  add_raw_extension(signer,"2.5.29.16",private_key_period,
                    sizeof private_key_period);
  add_authority_key_id(signer,issuer);
  add_extension(signer, NID_subject_key_identifier, "hash");
  write_cert(directory, "signer.der", signer, issuer_key);
  X509 *card = make_certificate(card_key, legacy ? "Synthetic Legacy card" : "Synthetic NEXGEN card", issuer);
  static const uint8_t private_card_type[] = {0x04,0x01,0x01};
  add_raw_extension(card,"1.3.6.1.4.1.29138.6.9.1",private_card_type,
                    sizeof private_card_type);
  add_extension(card, NID_key_usage, "critical,digitalSignature");
  add_extension(card, NID_certificate_policies,
                "1.3.6.1.4.1.29138.2.1.3.17");
  add_extension(card, NID_info_access,
                "OCSP;URI:http://fixture.invalid/ocsp");
  add_extension(card, NID_ext_key_usage,
                "critical,1.3.6.1.4.1.29138.6.8");
  uint8_t fascn[25], uuid[16];
  /* These numbers are invented for this test corpus. */
  const unsigned agency = legacy ? 1234 : 4321;
  const unsigned system = legacy ? 5678 : 8765;
  const unsigned credential = legacy ? 135791 : 246802;
  /* The FASC-N and UUID are supplied by the companion fixture manifest. */
  extern void synthetic_fascn(unsigned, unsigned, unsigned, uint8_t[25]);
  synthetic_fascn(agency, system, credential, fascn);
  static const uint8_t prefix[10] = {0x91,0xbe,0x20,0x94,0xf6,0xdc,0x53,0x49,0x80,0};
  memset(uuid,0,sizeof uuid);
  if (!legacy) {
    memcpy(uuid, prefix, sizeof prefix);
    uint64_t number = ((uint64_t)agency * 10000 + system) * 1000000 + credential;
    for (size_t i = 0; i < 6; ++i) { uuid[15 - i] = (uint8_t)number; number >>= 8; }
  }
  char uuid_urn[64];
  munit_assert_int(snprintf(uuid_urn, sizeof uuid_urn,
      "urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
      uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]), >, 0);
  add_twic_fascn(card, (TC_bytes){fascn, sizeof fascn});
  add_extension(card, NID_crl_distribution_points,
                "URI:http://fixture.invalid/crl");
  add_authority_key_id(card,issuer);
  add_extension(card, NID_subject_key_identifier, "hash");
  write_cert(directory, "card.der", card, issuer_key);
  write_certificate_object(directory,"piv-card-auth-cert.bin",card,issuer_key);
  if (!legacy)
    write_certificate_object(directory,"card-auth-cert.bin",card,issuer_key);

  X509 *piv_auth = make_certificate(piv_auth_key,
      legacy ? "Synthetic Legacy PIV authentication" : "Synthetic NEXGEN PIV authentication",
      issuer);
  add_raw_extension(piv_auth,"1.3.6.1.4.1.29138.6.9.1",
                    private_card_type,sizeof private_card_type);
  add_extension(piv_auth,NID_key_usage,"critical,digitalSignature");
  add_extension(piv_auth,NID_certificate_policies,"1.3.6.1.4.1.29138.2.1.3.13");
  add_extension(piv_auth,NID_ext_key_usage,
      "2.5.29.37.0,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.20.2.2");
  add_extension(piv_auth,NID_info_access,
                "OCSP;URI:http://fixture.invalid/ocsp");
  add_card_identifiers(piv_auth,(TC_bytes){fascn,sizeof fascn},uuid_urn);
  add_extension(piv_auth,NID_crl_distribution_points,
                "URI:http://fixture.invalid/crl");
  add_authority_key_id(piv_auth,issuer);
  add_extension(piv_auth,NID_subject_key_identifier,"hash");
  write_cert(directory,"piv-auth.der",piv_auth,issuer_key);
  write_certificate_object(directory,"piv-auth-cert.bin",piv_auth,issuer_key);
  if (legacy) {
    static const struct {
      const char *key, *subject, *usage, *eku, *policy, *der, *object;
    } certificates[] = {
      {"piv-sign.pem","Synthetic Legacy PIV signature","critical,digitalSignature",
       "2.5.29.37.0,1.3.6.1.5.5.7.3.2","1.3.6.1.4.1.29138.2.1.3.5",
       "piv-sign.der","piv-sign-cert.bin"},
      {"piv-key-management.pem","Synthetic Legacy PIV key management",
       "critical,keyEncipherment",
       "2.5.29.37.0,1.3.6.1.5.5.7.3.4,1.3.6.1.4.1.311.10.3.4",
       "1.3.6.1.4.1.29138.2.1.3.6","piv-key-management.der",
       "piv-key-management-cert.bin"}
    };
    for (size_t i = 0; i < sizeof certificates / sizeof *certificates; ++i) {
      EVP_PKEY *key = read_key(key_directory,certificates[i].key);
      X509 *cert = make_certificate(key,certificates[i].subject,issuer);
      add_extension(cert,NID_key_usage,certificates[i].usage);
      add_extension(cert,NID_certificate_policies,certificates[i].policy);
      add_extension(cert,NID_ext_key_usage,certificates[i].eku);
      add_extension(cert,NID_info_access,
                    "OCSP;URI:http://fixture.invalid/ocsp");
      add_card_identifiers(cert,(TC_bytes){fascn,sizeof fascn},uuid_urn);
      add_extension(cert,NID_crl_distribution_points,
                    "URI:http://fixture.invalid/crl");
      add_authority_key_id(cert,issuer);
      add_extension(cert,NID_subject_key_identifier,"hash");
      write_cert(directory,certificates[i].der,cert,issuer_key);
      write_certificate_object(directory,certificates[i].object,cert,issuer_key);
      X509_free(cert);
      EVP_PKEY_free(key);
    }
  }

  /* GET DATA returns a 53 envelope around C0/C1/C2 on the Legacy card. */
  uint8_t tpk[26] = {0x53,24,0xc0,16};
  for (size_t i = 0; i < 16; ++i) tpk[4 + i] = (uint8_t)(i + (legacy ? 0x10 : 0x30));
  tpk[20] = 0xc1; tpk[21] = 1; tpk[22] = 8;
  tpk[23] = 0xc2; tpk[24] = 1; tpk[25] = 0;
  write_file(directory, "tpk.bin", tpk, sizeof tpk);

  uint8_t chuid[CAPACITY], unsigned_chuid[CAPACITY];
  uint8_t piv_chuid[CAPACITY];
  size_t piv_chuid_length = 0;
  size_t unsigned_length = 0;
  size_t chuid_length = signed_chuid(signer, signer_key, fascn, uuid, chuid,
                                    unsigned_chuid, &unsigned_length, 0);
  write_file(directory, "signed-chuid.bin", chuid, chuid_length);
  write_file(directory, "unsigned-chuid.bin", unsigned_chuid, unsigned_length);
  {
    uint8_t unused[CAPACITY];
    size_t unused_length = 0;
    piv_chuid_length = signed_chuid(signer, signer_key, fascn, uuid,
        piv_chuid, unused, &unused_length, 1);
    write_file(directory, "piv-signed-chuid.bin", piv_chuid, piv_chuid_length);
  }
  if (!legacy) {
    static const uint8_t empty_object[] = {0x53,0};
    write_file(directory,"personal.bin",empty_object,sizeof empty_object);
    write_file(directory,"handwritten.bin",empty_object,sizeof empty_object);
    write_file(directory,"iris.bin",empty_object,sizeof empty_object);
    static const char *piv_empty[] = {
      "piv-5fc10a.bin","piv-5fc10b.bin","piv-5fc10c.bin",
      "piv-5fc10d.bin","piv-5fc10e.bin","piv-5fc10f.bin"
    };
    for (size_t i = 0; i < sizeof piv_empty / sizeof *piv_empty; ++i)
      write_file(directory,piv_empty[i],empty_object,sizeof empty_object);
    static const uint8_t discovery[] = {
      0x7e,18,0x4f,11,0xa0,0,0,3,0x67,0x20,0,0,1,1,3,
      0x5f,0x2f,2,0x40,0
    };
    write_file(directory,"discovery.bin",discovery,sizeof discovery);
    uint8_t piv_twic_discovery[sizeof discovery];
    memcpy(piv_twic_discovery,discovery,sizeof discovery);
    static const uint8_t piv_aid[] = {0xa0,0,0,3,8,0,0,0x10,0,1,0};
    memcpy(piv_twic_discovery + 4,piv_aid,sizeof piv_aid);
    write_file(directory,"piv-twic-discovery.bin",piv_twic_discovery,
        sizeof piv_twic_discovery);
  }
  uint8_t piv_discovery[70], discovery_body[68];
  size_t discovery_length = 0;
  uint8_t f0[21];
  memset(f0,0,sizeof f0);
  memcpy(f0,uuid,sizeof uuid);
  discovery_length += field(discovery_body + discovery_length,0xf0,f0,sizeof f0);
  const uint8_t one = 1;
  discovery_length += field(discovery_body + discovery_length,0xf1,&one,1);
  discovery_length += field(discovery_body + discovery_length,0xf2,&one,1);
  discovery_length += field(discovery_body + discovery_length,0xf3,NULL,0);
  discovery_length += field(discovery_body + discovery_length,0xf4,&one,1);
  discovery_length += field(discovery_body + discovery_length,0xf5,&one,1);
  uint8_t f6[17] = {0};
  memcpy(f6,uuid,sizeof uuid);
  discovery_length += field(discovery_body + discovery_length,0xf6,f6,sizeof f6);
  static const uint8_t empty_tags[] = {0xf7,0xfa,0xfb,0xfc,0xfd,0xfe};
  for (size_t i = 0; i < sizeof empty_tags; ++i)
    discovery_length += field(discovery_body + discovery_length,empty_tags[i],NULL,0);
  munit_assert_size(discovery_length, ==, sizeof discovery_body);
  size_t piv_discovery_length = field(piv_discovery,0x53,discovery_body,discovery_length);
  munit_assert_size(piv_discovery_length, ==, sizeof piv_discovery);
  write_file(directory,"piv-discovery.bin",piv_discovery,piv_discovery_length);

  uint8_t biometric[CAPACITY], fingerprint[CAPACITY], face[CAPACITY];
  static const uint8_t fmr_header[] = {
    'F','M','R',0,' ','2','0',0,2,30,0,1,0,1,0x80,1,
    1,0x97,2,0x0b,0,197,0,197,2,0
  };
  uint8_t fingerprint_record[542];
  memset(fingerprint_record,0,sizeof fingerprint_record);
  memcpy(fingerprint_record,fmr_header,sizeof fmr_header);
  fingerprint_record[8] = (uint8_t)(sizeof fingerprint_record >> 8);
  fingerprint_record[9] = (uint8_t)sizeof fingerprint_record;
  size_t minutia_offset = sizeof fmr_header;
  for (unsigned view = 0; view < 2; ++view) {
    fingerprint_record[minutia_offset++] = (uint8_t)(view ? 7 : 2);
    fingerprint_record[minutia_offset++] = 0;
    fingerprint_record[minutia_offset++] = 100;
    const unsigned points = view ? 45 : 39;
    fingerprint_record[minutia_offset++] = (uint8_t)points;
    for (unsigned point = 0; point < points; ++point) {
      unsigned x = 10 + (point % 20) * 10;
      unsigned y = 10 + (point / 20) * 50 + view * 5;
      fingerprint_record[minutia_offset++] = (uint8_t)(x >> 8);
      fingerprint_record[minutia_offset++] = (uint8_t)x;
      fingerprint_record[minutia_offset++] = (uint8_t)(y >> 8);
      fingerprint_record[minutia_offset++] = (uint8_t)y;
      fingerprint_record[minutia_offset++] = (uint8_t)((point * 17) % 180);
      fingerprint_record[minutia_offset++] = 80;
    }
    fingerprint_record[minutia_offset++] = 0;
    fingerprint_record[minutia_offset++] = 0;
  }
  munit_assert_size(minutia_offset, ==, sizeof fingerprint_record);
  size_t biometric_length = encode_biometric_record_parameters_flags(
      signer, signer_key, 0, 0, (TC_bytes){fascn, sizeof fascn},
      (TC_bytes){uuid, sizeof uuid},
      (TC_bytes){fingerprint_record,sizeof fingerprint_record},
      0x0201, 8, 0x80, biometric, sizeof biometric, CMS_NO_SIGNING_TIME);
  uint8_t piv_fingerprint[CAPACITY], piv_finger_body[CAPACITY];
  size_t piv_finger_body_length = field(piv_finger_body,0xbc,biometric,biometric_length);
  piv_finger_body[piv_finger_body_length++] = 0xfe;
  piv_finger_body[piv_finger_body_length++] = 0;
  size_t piv_finger_length = field(piv_fingerprint,0x53,piv_finger_body,piv_finger_body_length);
  write_file(directory,"piv-fingerprint.bin",piv_fingerprint,piv_finger_length);
  size_t fingerprint_length = encrypted_object(tpk + 4, biometric, biometric_length, fingerprint);
  write_file(directory, "fingerprint.bin", fingerprint, fingerprint_length);
  uint8_t face_record[9713];
  memset(face_record,0,sizeof face_record);
  static const uint8_t face_header[] = {
    'F','A','C',0,'0','1','0',0,0,0,0,0,0,1,
    0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,
    1,0,1,0x12,1,0x6c,1,2,0,0,0,80
  };
  munit_assert_size(sizeof face_header, ==, 46);
  memcpy(face_record,face_header,sizeof face_header);
  face_record[8] = (uint8_t)(sizeof face_record >> 24);
  face_record[9] = (uint8_t)(sizeof face_record >> 16);
  face_record[10] = (uint8_t)(sizeof face_record >> 8);
  face_record[11] = (uint8_t)sizeof face_record;
  const size_t face_block = sizeof face_record - 14;
  face_record[14] = (uint8_t)(face_block >> 24);
  face_record[15] = (uint8_t)(face_block >> 16);
  face_record[16] = (uint8_t)(face_block >> 8);
  face_record[17] = (uint8_t)face_block;
  munit_assert_size(read_test_image(directory,face_record + 46,
      sizeof face_record - 46), ==, sizeof face_record - 46);
  biometric_length = encode_biometric_record_parameters_flags(signer, signer_key, 0, 0,
      (TC_bytes){fascn, sizeof fascn}, (TC_bytes){uuid, sizeof uuid},
      (TC_bytes){face_record, sizeof face_record}, 0x0501, 2, 0x20,
      biometric, sizeof biometric, CMS_NO_SIGNING_TIME);
  uint8_t piv_face[CAPACITY], piv_face_body[CAPACITY];
  size_t piv_face_body_length = field(piv_face_body,0xbc,biometric,biometric_length);
  piv_face_body[piv_face_body_length++] = 0xfe;
  piv_face_body[piv_face_body_length++] = 0;
  size_t piv_face_length = field(piv_face,0x53,piv_face_body,piv_face_body_length);
  write_file(directory,"piv-face.bin",piv_face,piv_face_length);
  size_t face_length = 0;
  if (!legacy) {
    face_length = encrypted_object(tpk + 4, biometric, biometric_length, face);
    write_file(directory, "face.bin", face, face_length);
  }

  uint8_t printed_plaintext[140];
  static const uint8_t printed_tags[] = {1,2,4,5,6,7,8};
  static const uint8_t printed_lengths[] = {32,20,9,10,15,20,20};
  size_t printed_offset = 0;
  for (size_t i = 0; i < sizeof printed_tags; ++i) {
    printed_plaintext[printed_offset++] = printed_tags[i];
    printed_plaintext[printed_offset++] = printed_lengths[i];
    memset(printed_plaintext + printed_offset,'X',printed_lengths[i]);
    printed_offset += printed_lengths[i];
  }
  munit_assert_size(printed_offset, ==, sizeof printed_plaintext);
  memcpy(printed_plaintext + 2,"SYNTHETIC TEST CREDENTIAL",25);
  memcpy(printed_plaintext + 58,"01JAN2027",9);
  if (!legacy) {
    uint8_t printed[CAPACITY];
    size_t printed_length = encrypted_object(tpk + 4, printed_plaintext,
        sizeof printed_plaintext, printed);
    write_file(directory, "printed.bin", printed, printed_length);
  }

  uint8_t piv_printed_body[128], piv_printed[128];
  size_t piv_printed_length = 0;
  static const uint8_t piv_printed_tags[] = {1,2,4,5,6};
  static const uint8_t piv_printed_lengths[] = {10,0,9,10,15};
  for (size_t i = 0; i < sizeof piv_printed_tags; ++i) {
    uint8_t value[15];
    memset(value,'X',sizeof value);
    if (piv_printed_tags[i] == 4) memcpy(value,"01JAN2027",9);
    piv_printed_length += field(piv_printed_body + piv_printed_length,
        piv_printed_tags[i],value,piv_printed_lengths[i]);
  }
  piv_printed_body[piv_printed_length++] = 0xfe;
  piv_printed_body[piv_printed_length++] = 0;
  piv_printed_length = field(piv_printed,0x53,piv_printed_body,piv_printed_length);
  write_file(directory,"piv-printed.bin",piv_printed,piv_printed_length);

  const uint8_t piv_groups[] = {2,4,1,7,6};
  const uint16_t piv_containers[] = {0x3000,0x6010,0xdb00,0x6030,0x3001};
  TC_bytes piv_hashed[] = {
    contents(piv_chuid,piv_chuid_length),
    contents(piv_fingerprint,piv_finger_length),
    contents(piv_discovery,piv_discovery_length),
    contents(piv_face,piv_face_length),
    contents(piv_printed,piv_printed_length)
  };
  uint8_t piv_security_body[CAPACITY], piv_security[CAPACITY];
  size_t piv_security_body_length = security_inventory(signer,signer_key,
      piv_groups,piv_containers,piv_hashed,5,legacy,piv_security_body);
  size_t piv_security_length = field(piv_security,0x53,piv_security_body,
      piv_security_body_length);
  write_file(directory,"piv-security.bin",piv_security,piv_security_length);

  if (!legacy) {
  const uint16_t containers[] = {0x3002,0x3000,0x6030,0x3001,0x2003};
  TC_bytes hashed[] = {
    contents(unsigned_chuid, unsigned_length), contents(chuid, chuid_length),
    contents(face, face_length), {printed_plaintext, sizeof printed_plaintext},
    contents(fingerprint, fingerprint_length)
  };
  uint8_t security_body[CAPACITY], security[CAPACITY];
  const uint8_t groups[] = {9,2,7,6,4};
  size_t security_body_length = security_inventory(signer, signer_key,
      groups, containers, hashed, sizeof containers / sizeof *containers,
      0, security_body);
  size_t security_length = field(security, 0x53, security_body, security_body_length);
  write_file(directory, "security.bin", security, security_length);
  } else {
    const uint8_t groups[] = {9,2,4};
    const uint16_t containers[] = {0x3002,0x3000,0x2003};
    TC_bytes hashed[] = {
      contents(unsigned_chuid, unsigned_length), contents(chuid, chuid_length),
      contents(fingerprint, fingerprint_length)
    };
    uint8_t security_body[CAPACITY], security[CAPACITY];
    size_t security_body_length = security_inventory(signer, signer_key,
        groups, containers, hashed, sizeof containers / sizeof *containers,
        1, security_body);
    size_t security_length = field(security, 0x53, security_body, security_body_length);
    write_file(directory, "security.bin", security, security_length);
  }
  X509_free(piv_auth); X509_free(card); X509_free(signer); X509_free(issuer); X509_free(root);
  EVP_PKEY_free(piv_auth_key);
  EVP_PKEY_free(card_key); EVP_PKEY_free(signer_key);
  EVP_PKEY_free(issuer_key); EVP_PKEY_free(root_key);
}

/* PACS TIG 5-bit odd-parity FASC-N encoding for fixture identifiers. */
static void put_character(uint8_t out[25], size_t index, unsigned value) {
  unsigned parity = 1;
  for (unsigned bit = 0; bit < 5; ++bit) {
    size_t position = index * 5 + bit;
    unsigned set = bit == 4 ? parity : (value >> bit) & 1u;
    parity ^= set;
    out[position / 8] |= (uint8_t)(set << (7 - position % 8));
  }
}
void synthetic_fascn(unsigned agency, unsigned system, unsigned credential,
                     uint8_t out[25]) {
  static const struct { unsigned first, digits; } positions[] = {
    {1,4},{6,4},{11,6},{18,1},{20,1},{22,10},{32,1},{33,4},{37,1}
  };
  uint64_t values[] = {agency,system,credential,0,0,0,0,0,0};
  memset(out,0,25);
  unsigned checksum = 0;
  size_t field_index = 0;
  for (size_t i = 0; i < 39; ++i) {
    while (field_index < 9 && i >= positions[field_index].first + positions[field_index].digits)
      ++field_index;
    if (field_index < 9 && i >= positions[field_index].first) continue;
    unsigned control = i == 0 ? 0x0b : i == 38 ? 0x0f : 0x0d;
    put_character(out,i,control); checksum ^= control;
  }
  for (size_t i = 0; i < 9; ++i) {
    for (size_t j = positions[i].digits; j; --j) {
      unsigned digit = (unsigned)(values[i] % 10);
      values[i] /= 10;
      put_character(out,positions[i].first + j - 1,digit); checksum ^= digit;
    }
  }
  put_character(out,39,checksum);
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s legacy|nexgen OUTPUT_DIRECTORY KEY_DIRECTORY\n", argv[0]);
    return 2;
  }
  make_profile(argv[1],argv[2],argv[3]);
  return 0;
}
