/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/x509_crypto.h>
#include "../cms/openssl_fixture.h"
#include "../../examples/credential_object.h"
#include "../../examples/pki_input.h"
#include <openssl/core_names.h>

enum { CAPACITY = 2048, FRAMES = 16, OIDS = 16, WORK = 1000000 };

static size_t cvc_field(uint8_t* out, size_t capacity, unsigned tag, const void* bytes, size_t length)
{
  if (tag > 255) {
    munit_assert_size(capacity, >, 1);
    *out = (uint8_t)(tag >> 8);
    return 1 + cms_fixture_field(out + 1,capacity - 1,(uint8_t)tag,bytes,length);
  }
  return cms_fixture_field(out,capacity,(uint8_t)tag,bytes,length);
}

static size_t encode_cvc(EVP_PKEY* key, EVP_PKEY* signer, unsigned bits, unsigned role,
    const uint8_t issuer[8], const uint8_t* subject, int bad_point, uint8_t out[CAPACITY])
{
  static const uint8_t p256[] = {0x2a,0x86,0x48,0xce,0x3d,3,1,7};
  static const uint8_t p384[] = {0x2b,0x81,4,0,0x22};
  static const uint8_t ec_algorithm[] = {0x30,10,6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2};
  static const uint8_t rsa_algorithm[] = {0x30,13,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,11,5,0};
  uint8_t body[CAPACITY], public_key[128], point[97], signature[513], digital[600], encoded[640];
  size_t point_length = 0;
  munit_assert_int(EVP_PKEY_get_octet_string_param(key,OSSL_PKEY_PARAM_PUB_KEY,
      point,sizeof point,&point_length), ==, 1);
  if (bad_point) memset(point + 1,0,point_length - 1);
  const uint8_t profile = 0x80, role_byte = (uint8_t)role;
  size_t used = cvc_field(body,sizeof body,0x5f29,&profile,1);
  used += cvc_field(body + used,sizeof body - used,0x42,issuer,8);
  used += cvc_field(body + used,sizeof body - used,0x5f20,subject,
      role == TC_PIV_CVC_INTERMEDIATE ? 8 : 16);
  size_t key_length = cvc_field(public_key,sizeof public_key,6,bits == 256 ? p256 : p384,
      bits == 256 ? sizeof p256 : sizeof p384);
  key_length += cvc_field(public_key + key_length,sizeof public_key - key_length,0x86,point,point_length);
  used += cvc_field(body + used,sizeof body - used,0x7f49,public_key,key_length);
  used += cvc_field(body + used,sizeof body - used,0x5f4c,&role_byte,1);
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  munit_assert_not_null(context);
  const EVP_MD* hash = role == TC_PIV_CVC_INTERMEDIATE || bits == 256 ? EVP_sha256() : EVP_sha384();
  munit_assert_int(EVP_DigestSignInit(context,NULL,hash,NULL,signer), ==, 1);
  size_t signature_length = sizeof signature - 1;
  munit_assert_int(EVP_DigestSign(context,signature + 1,&signature_length,body,used), ==, 1);
  EVP_MD_CTX_free(context);
  signature[0] = 0; /* DER BIT STRING unused-bit count. */
  const size_t algorithm_length = role == TC_PIV_CVC_INTERMEDIATE ? sizeof rsa_algorithm : sizeof ec_algorithm;
  memcpy(digital,role == TC_PIV_CVC_INTERMEDIATE ? rsa_algorithm : ec_algorithm,algorithm_length);
  if (role == TC_PIV_CVC_CARD_APPLICATION && bits == 384) digital[algorithm_length - 1] = 3;
  size_t digital_length = algorithm_length + cvc_field(digital + algorithm_length,
      sizeof digital - algorithm_length,3,signature,signature_length + 1);
  size_t encoded_length = cvc_field(encoded,sizeof encoded,0x30,digital,digital_length);
  used += cvc_field(body + used,sizeof body - used,0x5f37,encoded,encoded_length);
  return cvc_field(out,CAPACITY,0x7f21,body,used);
}

static void trusted_chain(const ExampleCVCRequest* request, X509* root, EVP_PKEY* root_key,
    X509* signer, const TC_X509_signature_provider* provider)
{
  uint8_t root_bytes[CAPACITY], crl_bytes[CAPACITY];
  const TC_bytes root_der = {root_bytes,encode_certificate(root,root_key,EVP_sha256(),root_bytes,sizeof root_bytes)};
  TC_TLV_frame frames[FRAMES];
  TC_bytes oids[OIDS];
  TC_X509_workspace parser = {frames,FRAMES,oids,OIDS};
  const TC_TLV_limits limits = {CAPACITY,CAPACITY,128,FRAMES};
  TC_X509_certificate parsed_root;
  munit_assert_int(TC_X509_read(root_der.data,root_der.length,&limits,&parser,&parsed_root), ==, TC_TLV_OK);
  TC_X509_certificate parsed_signer;
  munit_assert_int(TC_X509_read(request->signer_certificate.data,request->signer_certificate.length,
      &limits,&parser,&parsed_signer), ==, TC_TLV_OK);
  TC_X509_store_anchor anchor = {{parsed_root.subject,parsed_root.public_key},{{NULL,0},{NULL,0}}};
  ExampleX509Source arrays = {&root_der,1,&anchor,1};
  const TC_X509_store_source source = example_x509_source(&arrays);
  TC_X509_store store = {0};
  TC_X509_store_snapshot slot = {0}, *held;
  munit_assert_int(TC_X509_store_prepare(&slot,&source), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_publish(&store,0,&slot), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_acquire(&store,&held), ==, TC_TLV_OK);
  static const uint8_t content_signing[] = {0x60,0x86,0x48,1,0x65,3,6,7};
  TC_X509_path_options options = {0};
  options.at = (TC_X509_time){2026,1,1,0,0,0};
  options.parsing = limits;
  options.max_certificates = EXAMPLE_X509_PATH_CAPACITY;
  options.max_input = CAPACITY * EXAMPLE_X509_PATH_CAPACITY;
  options.max_work = WORK;
  options.signatures = *provider;
  options.purpose = (TC_bytes){content_signing,sizeof content_signing};
  enum { VALID, REVOKED, WRONG_ANCHOR, EXPIRED, NO_WORK, NO_SNAPSHOT, DIFFERENT_TIME,
    BAD_PURPOSE, MISSING_POLICY, WRONG_USAGE, TWIC_POLICY, CASES };
  for (unsigned test = VALID; test < CASES; ++test) {
    const TC_bytes crl = {crl_bytes,encode_issuer_crl(root,root_key,test == REVOKED ? signer : NULL,
        crl_bytes,sizeof crl_bytes)};
    TC_X509_crl_record record;
    TC_X509_crl_index index;
    size_t work = WORK;
    munit_assert_int(TC_X509_crl_index_init(&crl,1,&limits,&parser,&work,&record,1,&index), ==, TC_TLV_OK);
    TC_X509_path_options policy = options;
    ExampleCVCRequest selected = *request;
    uint8_t changed_certificate[CAPACITY];
    if (test == MISSING_POLICY || test == TWIC_POLICY || test == WRONG_USAGE) {
      X509* changed = X509_dup(signer);
      munit_assert_not_null(changed);
      const int nid = test == WRONG_USAGE ? NID_key_usage : NID_certificate_policies;
      const int position = X509_get_ext_by_NID(changed,nid,-1);
      munit_assert_int(position, >=, 0);
      X509_EXTENSION_free(X509_delete_ext(changed,position));
      if (test == WRONG_USAGE) add_extension(changed,NID_key_usage,"critical,keyEncipherment");
      selected.signer_certificate = (TC_bytes){changed_certificate,encode_certificate(changed,root_key,
        EVP_sha256(),changed_certificate,sizeof changed_certificate)};
      X509_free(changed);
      if (test == TWIC_POLICY) selected.profile = TC_TWIC_NEXGEN_CARD;
    }
    if (test == EXPIRED) policy.at.year = 2030;
    if (test == BAD_PURPOSE) policy.purpose = (TC_bytes){NULL,0};
    TC_X509_path_options crl_policy = policy;
    crl_policy.purpose = (TC_bytes){NULL,0};
    crl_policy.key_usage = TC_KEY_USAGE_CRL_SIGN;
    if (test == DIFFERENT_TIME) ++crl_policy.at.day;
    const TC_X509_revocation_options revocation = {&index,NULL,&crl_policy,0,CAPACITY,
      TC_X509_CRL_COMPLETE_ONLY,TC_X509_CRL_ORDER_NUMBER};
    if (test == WRONG_ANCHOR) anchor.trust.public_key = parsed_signer.public_key;
    ExampleCVCCredentialWorkspace workspace;
    memset(&workspace,0xa5,sizeof workspace);
    TC_PIV_CVC out, saved;
    memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof saved);
    work = test == NO_WORK ? 0 : WORK;
    const TC_credential_status result = example_validate_cvc(&selected,test == NO_SNAPSHOT ? NULL : held,
        &policy,&revocation,&work,&workspace,&out);
    if (test == VALID || test == TWIC_POLICY) munit_assert_int(result, ==, TC_CREDENTIAL_VALID);
    else {
      if (test == REVOKED) munit_assert_int(result, ==, TC_CREDENTIAL_REVOKED);
      else if (test == NO_WORK) munit_assert_int(result, ==, TC_CREDENTIAL_LIMIT);
      else if (test == NO_SNAPSHOT) munit_assert_int(result, ==, TC_CREDENTIAL_UNAVAILABLE);
      else if (test == DIFFERENT_TIME || test == BAD_PURPOSE) munit_assert_int(result, ==, TC_CREDENTIAL_ERROR);
      else munit_assert_int(result, !=, TC_CREDENTIAL_VALID);
      munit_assert_memory_equal(sizeof out,&out,&saved);
    }
    if (test != NO_SNAPSHOT && test != DIFFERENT_TIME && test != BAD_PURPOSE) {
      const uint8_t* bytes = (const uint8_t*)&workspace;
      for (size_t i = 0; i < sizeof workspace; ++i) munit_assert_uint(bytes[i], ==, 0);
    }
    anchor.trust.public_key = parsed_root.public_key;
  }
  munit_assert_int(TC_X509_store_release(held), ==, TC_TLV_OK);
}

static MunitResult chains(const MunitParameter params[], void* context)
{
  const unsigned bits = !strcmp(munit_parameters_get(params,"curve"),"p256") ? 256 : 384;
  const int indirect = !strcmp(munit_parameters_get(params,"issuer"),"intermediate");
  const char* group = bits == 256 ? "prime256v1" : "secp384r1";
  EVP_PKEY* card_key = EVP_EC_gen(group);
  EVP_PKEY* intermediate_key = EVP_EC_gen(group);
  EVP_PKEY* signing_key = indirect ? EVP_RSA_gen(2048) : EVP_EC_gen(group);
  munit_assert_not_null(card_key); munit_assert_not_null(intermediate_key); munit_assert_not_null(signing_key);
  EVP_PKEY* root_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(root_key);
  X509* root = make_certificate(root_key,"Synthetic CVC root",NULL);
  add_extension(root,NID_basic_constraints,"critical,CA:TRUE");
  add_extension(root,NID_key_usage,"critical,keyCertSign,cRLSign");
  X509* certificate = make_certificate(signing_key,"Synthetic CVC signer",root);
  add_extension(certificate,NID_basic_constraints,"critical,CA:FALSE");
  add_extension(certificate,NID_key_usage,"critical,digitalSignature");
  add_extension(certificate,NID_ext_key_usage,"2.16.840.1.101.3.6.7");
  add_extension(certificate,NID_certificate_policies,"2.16.840.1.101.3.2.1.3.39");
  add_extension(certificate,NID_subject_key_identifier,"01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14");
  uint8_t signer_der[CAPACITY];
  const size_t signer_length = encode_certificate(certificate,root_key,EVP_sha256(),signer_der,sizeof signer_der);
  TC_TLV_frame frames[FRAMES];
  TC_bytes oids[OIDS];
  TC_X509_workspace parser = {frames,FRAMES,oids,OIDS};
  const TC_TLV_limits limits = {CAPACITY,CAPACITY,128,FRAMES};
  TC_X509_certificate signer;
  munit_assert_int(TC_X509_read(signer_der,signer_length,&limits,&parser,&signer), ==, TC_TLV_OK);
  const uint8_t ski[] = {1,2,3,4,5,6,7,8};
  const uint8_t uuid[] = {0,1,2,3,4,5,0x46,7,0x88,9,10,11,12,13,14,15};
  uint8_t point[97], intermediate_id[EVP_MAX_MD_SIZE];
  size_t point_length = 0;
  unsigned digest_length = 0;
  munit_assert_int(EVP_PKEY_get_octet_string_param(intermediate_key,OSSL_PKEY_PARAM_PUB_KEY,
      point,sizeof point,&point_length), ==, 1);
  munit_assert_int(EVP_Digest(point,point_length,intermediate_id,&digest_length,EVP_sha1(),NULL), ==, 1);
  TC_ECDSA_workspace ec;
  TC_EC_workspace points;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(2048)];
  const TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  const TC_X509_native_workspace native = {&ec,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  enum { VALID, CARD_SIGNATURE, INTER_SIGNATURE, CARD_ISSUER, INTER_ISSUER, INTER_SUBJECT,
    WRONG_UUID, WRONG_CURVE, BAD_CARD_POINT, BAD_INTER_POINT, NO_WORK, SHORT_LIMIT,
    MISSING_SKI, SHORT_SKI, NO_PROVIDER, UNSUPPORTED_CURVE, REVERSED_CHAIN, CASES };
  for (unsigned test = VALID; test < CASES; ++test) {
    if (!indirect && (test == INTER_SIGNATURE || test == INTER_ISSUER ||
        test == INTER_SUBJECT || test == BAD_INTER_POINT || test == REVERSED_CHAIN)) continue;
    uint8_t card[CAPACITY] = {0}, intermediate[CAPACITY] = {0};
    uint8_t card_issuer[8], intermediate_issuer[8], subject[8], expected_uuid[16];
    memcpy(subject,intermediate_id,sizeof subject);
    memcpy(card_issuer,indirect ? intermediate_id : ski,sizeof card_issuer);
    memcpy(intermediate_issuer,ski,sizeof intermediate_issuer);
    memcpy(expected_uuid,uuid,sizeof uuid);
    if (test == CARD_ISSUER) card_issuer[0] ^= 1;
    if (test == INTER_ISSUER) intermediate_issuer[0] ^= 1;
    if (test == INTER_SUBJECT) { subject[0] ^= 1; card_issuer[0] ^= 1; }
    if (test == BAD_INTER_POINT) {
      uint8_t invalid_point[97] = {4}, digest[EVP_MAX_MD_SIZE];
      munit_assert_int(EVP_Digest(invalid_point,point_length,digest,&digest_length,EVP_sha1(),NULL), ==, 1);
      memcpy(subject,digest,sizeof subject);
      memcpy(card_issuer,digest,sizeof card_issuer);
    }
    if (test == WRONG_UUID) expected_uuid[0] ^= 1;
    const size_t card_length = encode_cvc(card_key,indirect ? intermediate_key : signing_key,bits,
        TC_PIV_CVC_CARD_APPLICATION,card_issuer,uuid,test == BAD_CARD_POINT,card);
    const size_t intermediate_length = indirect ? encode_cvc(intermediate_key,signing_key,bits,
        TC_PIV_CVC_INTERMEDIATE,intermediate_issuer,subject,test == BAD_INTER_POINT,intermediate) : 0;
    if (test == CARD_SIGNATURE) card[card_length - 1] ^= 1;
    if (test == INTER_SIGNATURE) intermediate[intermediate_length - 1] ^= 1;
    TC_PIV_CVC_chain_request request = {{card,card_length},{intermediate,intermediate_length},
      {expected_uuid,sizeof expected_uuid},bits == 256 ? TC_EC_P256 : TC_EC_P384,&signer};
    if (test == WRONG_CURVE) request.curve = bits == 256 ? TC_EC_P384 : TC_EC_P256;
    if (test == UNSUPPORTED_CURVE) request.curve = TC_EC_P192;
    if (test == REVERSED_CHAIN) {
      request.card = (TC_bytes){intermediate,intermediate_length};
      request.intermediate = (TC_bytes){card,card_length};
    }
    TC_X509_certificate changed_signer = signer;
    static const uint8_t short_ski[] = {0x30,18,0x30,16,6,3,0x55,0x1d,0x0e,4,9,4,7,1,2,3,4,5,6,7};
    if (test == MISSING_SKI) changed_signer.extensions = (TC_bytes){NULL,0};
    if (test == SHORT_SKI) changed_signer.extensions = (TC_bytes){short_ski,sizeof short_ski};
    request.signer = &changed_signer;
    TC_X509_signature_provider selected = provider;
    if (test == NO_PROVIDER) selected.verify = NULL;
    TC_TLV_limits bounded = limits;
    if (test == SHORT_LIMIT) bounded.max_input = card_length - 1;
    size_t work = test == NO_WORK ? 0 : WORK;
    TC_PIV_CVC out, saved;
    memset(&out,0xa5,sizeof out); memcpy(&saved,&out,sizeof saved);
    TC_X509_signature_result result = TC_PIV_CVC_chain_verify(&request,&bounded,&selected,&points,&work,&out);
    munit_assert_int(result, ==, test == VALID ? TC_X509_SIGNATURE_VALID :
        test == NO_WORK || test == SHORT_LIMIT ? TC_X509_SIGNATURE_LIMIT :
        test == NO_PROVIDER || test == UNSUPPORTED_CURVE ? TC_X509_SIGNATURE_UNSUPPORTED : TC_X509_SIGNATURE_INVALID);
    munit_assert_size(work, <=, WORK);
    if (test == VALID) {
      munit_assert_uint(out.key_bits, ==, bits);
      munit_assert_memory_equal(sizeof uuid,out.subject.data,uuid);
      const ExampleCVCRequest credential = {{card,card_length},{intermediate,intermediate_length},
        {uuid,sizeof uuid},{signer_der,signer_length},request.curve,TC_PIV_CARD};
      trusted_chain(&credential,root,root_key,certificate,&provider);
      munit_assert_true(out.public_key.data >= card && out.public_key.data + out.public_key.length <= card + card_length);
      const uint8_t* scratch = (const uint8_t*)&points;
      for (size_t i = 0; i < sizeof points; ++i) munit_assert_uint(scratch[i], ==, 0);
      const size_t required = WORK - work;
      const size_t budgets[] = {1,card_length - 1,card_length,required / 2,required - 1,required,required + 1};
      for (size_t i = 0; i < sizeof budgets / sizeof *budgets; ++i) {
        work = budgets[i];
        memcpy(&out,&saved,sizeof out);
        result = TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,&out);
        munit_assert_int(result, ==, budgets[i] < required ? TC_X509_SIGNATURE_LIMIT : TC_X509_SIGNATURE_VALID);
        munit_assert_size(work, <=, budgets[i]);
        if (budgets[i] < required) munit_assert_memory_equal(sizeof out,&out,&saved);
      }
      work = WORK;
      const size_t original_work = work;
      munit_assert_int(TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,
          (TC_PIV_CVC*)&points), ==, TC_X509_SIGNATURE_ERROR);
      munit_assert_size(work, ==, original_work);
      for (unsigned part = 0; part < (indirect ? 2u : 1u); ++part) {
        TC_bytes* input = part ? &request.intermediate : &request.card;
        const size_t complete_length = input->length;
        for (size_t length = 0; length < complete_length; ++length) {
          /* Zero intermediate length selects the direct-issuer path. */
          input->length = length;
          work = WORK;
          memcpy(&out,&saved,sizeof out);
          munit_assert_int(TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,&out), !=,
              TC_X509_SIGNATURE_VALID);
          munit_assert_memory_equal(sizeof out,&out,&saved);
        }
        input->length = complete_length;
      }
      uint8_t unchanged[CAPACITY];
      memcpy(unchanged,card,sizeof card);
      work = WORK;
      munit_assert_int(TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,
          (TC_PIV_CVC*)card), ==, TC_X509_SIGNATURE_ERROR);
      munit_assert_size(work, ==, WORK);
      munit_assert_memory_equal(sizeof card,card,unchanged);
      request.card.length = SIZE_MAX;
      munit_assert_int(TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,&out), ==,
          TC_X509_SIGNATURE_ERROR);
      munit_assert_size(work, ==, WORK);
      request.card.length = card_length;
      request.card_uuid = (TC_bytes){NULL,0};
      work = WORK;
      munit_assert_int(TC_PIV_CVC_chain_verify(&request,&limits,&provider,&points,&work,&out), ==,
          TC_X509_SIGNATURE_VALID);
      munit_assert_memory_equal(sizeof uuid,out.subject.data,uuid);
    } else munit_assert_memory_equal(sizeof out,&out,&saved);
  }
  X509_free(certificate);
  X509_free(root); EVP_PKEY_free(root_key);
  EVP_PKEY_free(signing_key); EVP_PKEY_free(intermediate_key); EVP_PKEY_free(card_key);
  (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  char* curves[] = {"p256","p384",NULL};
  char* issuers[] = {"direct","intermediate",NULL};
  MunitParameterEnum params[] = {{"curve",curves},{"issuer",issuers},{NULL,NULL}};
  MunitTest tests[] = {{"/chains",chains,NULL,NULL,MUNIT_TEST_OPTION_NONE,params},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/piv/cvc",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
