/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/hash.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

enum {
  RECORD_HEADER = 40,
  MAX_CVC = 1024,
  MAX_CERTIFICATE = 4096,
  PARSER_FRAMES = 32,
  PARSER_OIDS = 64,
  WORK_BUDGET = 1000000
};

typedef enum {
  CORPUS_PARSE_ONLY = 0,
  CORPUS_ACCEPTED = 1,
  CORPUS_REJECTED = 2,
  CORPUS_UNSUPPORTED = 3
} corpus_verdict;

static uint32_t read_u32(const uint8_t value[4])
{
  return (uint32_t)value[0] << 24 | (uint32_t)value[1] << 16 |
      (uint32_t)value[2] << 8 | value[3];
}

static void read_exact(uint8_t* out, size_t length)
{
  munit_assert_size(fread(out,1,length,stdin), ==, length);
}

static void check_parsed(const uint8_t* encoded, size_t length,
    unsigned curve_code, unsigned expected_role, unsigned subject_length,
    const uint8_t expected_issuer[8], const uint8_t expected_subject[16])
{
  TC_PIV_CVC cvc;
  munit_assert_int(TC_PIV_CVC_read(encoded,length,&cvc), ==, TC_TLV_OK);
  munit_assert_uint(cvc.role, ==, expected_role);
  munit_assert_uint(cvc.key_bits, ==, curve_code == 1 ? 256 : 384);
  munit_assert_size(cvc.issuer.length, ==, 8);
  munit_assert_memory_equal(8,cvc.issuer.data,expected_issuer);
  munit_assert_size(cvc.subject.length, ==, subject_length);
  munit_assert_memory_equal(subject_length,cvc.subject.data,expected_subject);
  munit_assert_true(cvc.signed_data.data >= encoded);
  munit_assert_true(cvc.signed_data.data + cvc.signed_data.length <= encoded + length);
  munit_assert_true(cvc.public_key.data >= encoded);
  munit_assert_true(cvc.public_key.data + cvc.public_key.length <= encoded + length);
  munit_assert_true(cvc.signature.data >= encoded);
  munit_assert_true(cvc.signature.data + cvc.signature.length <= encoded + length);
}

static void check_intermediate_signatures(TC_bytes card_bytes, TC_bytes intermediate_bytes,
    TC_EC_curve curve, int expected_subject_match, const TC_X509_certificate* signer,
    const TC_X509_signature_provider* provider)
{
  static const uint8_t ec_public_key_oid[] = {0x2a,0x86,0x48,0xce,0x3d,2,1};
  uint8_t parameters[11];
  TC_PIV_CVC card, intermediate;
  munit_assert_int(TC_PIV_CVC_read(card_bytes.data,card_bytes.length,&card), ==, TC_TLV_OK);
  munit_assert_int(TC_PIV_CVC_read(intermediate_bytes.data,intermediate_bytes.length,&intermediate), ==,
      TC_TLV_OK);
  uint8_t digest[TC_SHA1_DIGESTLEN];
  munit_assert_int(TC_SHA1_digest(intermediate.public_key.data,intermediate.public_key.length,digest), ==,
      TC_OK);
  munit_assert_int(!memcmp(digest,intermediate.subject.data,8), ==, expected_subject_match);
  size_t work = WORK_BUDGET;
  munit_assert_int(TC_X509_signature_verify_message(&intermediate.signed_data,1,
      &intermediate.signature_algorithm,intermediate.signature,&signer->public_key,provider,&work), ==,
      TC_X509_SIGNATURE_VALID);
  parameters[0] = 6;
  parameters[1] = (uint8_t)intermediate.curve_oid.length;
  munit_assert_size(intermediate.curve_oid.length, <=, sizeof parameters - 2);
  memcpy(parameters + 2,intermediate.curve_oid.data,intermediate.curve_oid.length);
  TC_X509_public_key key = {0};
  key.type = TC_KEY_EC;
  key.algorithm.oid = (TC_bytes){ec_public_key_oid,sizeof ec_public_key_oid};
  key.algorithm.parameters = (TC_bytes){parameters,intermediate.curve_oid.length + 2};
  key.curve = curve;
  key.bits = intermediate.key_bits;
  key.key = intermediate.public_key;
  key.curve_oid = intermediate.curve_oid;
  work = WORK_BUDGET;
  munit_assert_int(TC_X509_signature_verify_message(&card.signed_data,1,
      &card.signature_algorithm,card.signature,&key,provider,&work), ==,
      TC_X509_SIGNATURE_VALID);
}

static MunitResult records(const MunitParameter params[], void* context)
{
  static uint8_t card[MAX_CVC], intermediate[MAX_CVC], certificate[MAX_CERTIFICATE];
  static uint8_t saved_card[MAX_CVC], saved_intermediate[MAX_CVC], saved_certificate[MAX_CERTIFICATE];
  static uint8_t tampered[MAX_CVC];
  uint8_t header[RECORD_HEADER];
  size_t record_count = 0, parse_count = 0, accepted_count = 0, rejected_count = 0;
  size_t count;
  while ((count = fread(header,1,sizeof header,stdin)) != 0) {
    munit_assert_size(count, ==, sizeof header);
    const unsigned verdict = header[0], curve_code = header[1];
    const unsigned role = header[2], subject_length = header[3];
    const size_t card_length = read_u32(header + 4);
    const size_t intermediate_length = read_u32(header + 8);
    const size_t certificate_length = read_u32(header + 12);
    munit_assert_uint(verdict, <=, CORPUS_UNSUPPORTED);
    munit_assert(curve_code == 1 || curve_code == 2);
    munit_assert(role == TC_PIV_CVC_CARD_APPLICATION || role == TC_PIV_CVC_INTERMEDIATE);
    munit_assert_uint(subject_length, ==,
        role == TC_PIV_CVC_CARD_APPLICATION ? 16 : 8);
    munit_assert_size(card_length, >, 0);
    munit_assert_size(card_length, <=, sizeof card);
    munit_assert_size(intermediate_length, <=, sizeof intermediate);
    munit_assert_size(certificate_length, <=, sizeof certificate);
    read_exact(card,card_length);
    read_exact(intermediate,intermediate_length);
    read_exact(certificate,certificate_length);
    memcpy(saved_card,card,card_length);
    memcpy(saved_intermediate,intermediate,intermediate_length);
    memcpy(saved_certificate,certificate,certificate_length);
    check_parsed(card,card_length,curve_code,role,subject_length,header + 16,header + 24);
    parse_count += 1 + (intermediate_length != 0);
    if (verdict != CORPUS_PARSE_ONLY) {
      TC_TLV_frame frames[PARSER_FRAMES];
      TC_bytes oids[PARSER_OIDS];
      TC_X509_workspace parser = {frames,PARSER_FRAMES,oids,PARSER_OIDS};
      const TC_TLV_limits limits = {MAX_CERTIFICATE,MAX_CERTIFICATE,256,PARSER_FRAMES};
      TC_X509_certificate signer;
      munit_assert_size(certificate_length, >, 0);
      munit_assert_int(TC_X509_read(certificate,certificate_length,&limits,&parser,&signer), ==, TC_TLV_OK);
      TC_ECDSA_workspace ecdsa;
      TC_EC_workspace point;
      TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(2048)];
      const TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
      const TC_X509_native_workspace native = {&ecdsa,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
      const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
      const TC_EC_curve curve = curve_code == 1 ? TC_EC_P256 : TC_EC_P384;
      if (intermediate_length) check_intermediate_signatures(
          (TC_bytes){card,card_length},(TC_bytes){intermediate,intermediate_length},
          curve,verdict != CORPUS_REJECTED,&signer,&provider);
      const TC_PIV_CVC_chain_request request = {
        {card,card_length},{intermediate,intermediate_length},
        {header + 24,subject_length},curve,&signer
      };
      TC_PIV_CVC out, saved;
      memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof saved);
      size_t work = WORK_BUDGET;
      const TC_X509_signature_result result = TC_PIV_CVC_chain_verify(
          &request,&limits,&provider,&point,&work,&out);
      const TC_X509_signature_result expected = verdict == CORPUS_ACCEPTED ? TC_X509_SIGNATURE_VALID :
          verdict == CORPUS_REJECTED ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_UNSUPPORTED;
      munit_assert_int(result, ==, expected);
      if (result == TC_X509_SIGNATURE_VALID) {
        munit_assert_true(out.public_key.data >= card);
        munit_assert_true(out.public_key.data + out.public_key.length <= card + card_length);
        ++accepted_count;
        memcpy(tampered,card,card_length);
        tampered[card_length - 1] ^= 1;
        TC_PIV_CVC_chain_request changed = request;
        changed.card = (TC_bytes){tampered,card_length};
        work = WORK_BUDGET;
        memcpy(&out,&saved,sizeof out);
        munit_assert_int(TC_PIV_CVC_chain_verify(&changed,&limits,&provider,&point,&work,&out), ==,
            TC_X509_SIGNATURE_INVALID);
        munit_assert_memory_equal(sizeof out,&out,&saved);
      } else {
        munit_assert_memory_equal(sizeof out,&out,&saved);
        if (result == TC_X509_SIGNATURE_INVALID) ++rejected_count;
      }
    }
    munit_assert_memory_equal(card_length,card,saved_card);
    munit_assert_memory_equal(intermediate_length,intermediate,saved_intermediate);
    munit_assert_memory_equal(certificate_length,certificate,saved_certificate);
    ++record_count;
  }
  munit_assert_int(ferror(stdin), ==, 0);
  munit_assert_size(record_count, >, 0);
  printf("%zu CVC corpus records checked: %zu parsed, %zu chains accepted, %zu rejected\n",
      record_count,parse_count,accepted_count,rejected_count);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
#ifdef _WIN32
  if (_setmode(_fileno(stdin),_O_BINARY) == -1) return 1;
#endif
  MunitTest tests[] = {{"/records",records,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/piv/cvc-corpus",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
