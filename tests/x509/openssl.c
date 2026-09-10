/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include "../../src/x509_path_internal.h"
#include "../../src/pki_source_internal.h"
#include <tiny_crypto/x509_store.h>
#include "../../examples/x509_client.h"
#include "munit.h"
#include <openssl/core_names.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>

static TC_X509_signature_result verify(void* context, const TC_bytes* message, size_t count, const TC_DER_algorithm* algorithm,
                                       TC_bytes signature, const TC_X509_public_key* issuer, size_t* work)
{
  static const uint8_t prefix[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3};
  const char* group;
  const EVP_MD* digest;
  EVP_PKEY_CTX* decoder = NULL;
  EVP_PKEY* key = NULL;
  EVP_MD_CTX* verifier = NULL;
  OSSL_PARAM_BLD* builder = NULL;
  OSSL_PARAM* parameters = NULL;
  TC_X509_signature_result result = TC_X509_SIGNATURE_ERROR;
  int valid;
  unsigned* calls = (unsigned*)context;
  ++*calls;
  if (*work < 100)
    return TC_X509_SIGNATURE_LIMIT;
  *work -= 100;
  if (issuer->type != TC_KEY_EC || algorithm->oid.length != 8 ||
      memcmp(algorithm->oid.data, prefix, sizeof prefix))
    return TC_X509_SIGNATURE_UNSUPPORTED;
  if (algorithm->parameters.length)
    return TC_X509_SIGNATURE_INVALID;
  if (algorithm->oid.data[7] == 2)
    digest = EVP_sha256();
  else if (algorithm->oid.data[7] == 3)
    digest = EVP_sha384();
  else
    return TC_X509_SIGNATURE_UNSUPPORTED;
  if (issuer->curve == TC_EC_P256)
    group = "prime256v1";
  else if (issuer->curve == TC_EC_P384)
    group = "secp384r1";
  else
    return TC_X509_SIGNATURE_UNSUPPORTED;
  decoder = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  builder = OSSL_PARAM_BLD_new();
  verifier = EVP_MD_CTX_new();
  if (!decoder || !builder || !verifier)
    goto done;
  if (!OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, group, 0) ||
      !OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY, issuer->key.data, issuer->key.length))
    goto done;
  parameters = OSSL_PARAM_BLD_to_param(builder);
  if (!parameters || EVP_PKEY_fromdata_init(decoder) <= 0 ||
      EVP_PKEY_fromdata(decoder, &key, EVP_PKEY_PUBLIC_KEY, parameters) <= 0)
    goto done;
  if (EVP_DigestVerifyInit(verifier, NULL, digest, NULL, key) <= 0)
    goto done;
  for (size_t i = 0; i < count; ++i)
    if (message[i].length && EVP_DigestVerifyUpdate(verifier,message[i].data,message[i].length) <= 0) goto done;
  valid = EVP_DigestVerifyFinal(verifier, signature.data, signature.length);
  result = valid == 1 ? TC_X509_SIGNATURE_VALID : valid == 0 ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_ERROR;
done:
  EVP_MD_CTX_free(verifier);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(decoder);
  OSSL_PARAM_free(parameters);
  OSSL_PARAM_BLD_free(builder);
  return result;
}

#include "openssl_fixture.h"

static size_t certificate(EVP_PKEY* key, const EVP_MD* digest, uint8_t* der, size_t capacity)
{
  X509* cert = make_certificate(key, "Certificate signature test", NULL);
  size_t length = encode_certificate(cert, key, digest, der, capacity);
  X509_free(cert);
  return length;
}

static MunitResult signatures(const MunitParameter params[], void* user)
{
  static const char* groups[] = {"prime256v1", "secp384r1"};
  const EVP_MD* digests[] = {EVP_sha256(), EVP_sha384()};
  uint8_t der[2048], other_der[2048];
  TC_TLV_frame frames[16];
  TC_bytes oids[8];
  TC_X509_workspace workspace = {frames, 16, oids, 8};
  const TC_TLV_limits limits = {2048, 2048, 128, 16};
  TC_X509_certificate parsed, other;
  unsigned group, hash, calls = 0;
  TC_X509_signature_provider provider = {verify,&calls,NULL};
  (void)params;
  (void)user;
  for (group = 0; group < 2; ++group) {
    EVP_PKEY* key = EVP_EC_gen(groups[group]);
    EVP_PKEY* wrong = EVP_EC_gen(groups[group]);
    munit_assert_not_null(key);
    munit_assert_not_null(wrong);
    for (hash = 0; hash < 2; ++hash) {
      size_t length = certificate(key, digests[hash], der, sizeof der);
      size_t other_length = certificate(wrong, digests[hash], other_der, sizeof other_der);
      size_t work = 10000, offset;
      munit_assert_int(TC_X509_read(der, length, &limits, &workspace, &parsed), ==, TC_TLV_OK);
      munit_assert_int(TC_X509_read(other_der, other_length, &limits, &workspace, &other), ==, TC_TLV_OK);
      calls = 0;
      munit_assert_int(TC_X509_signature_verify(&parsed, &parsed.public_key, &provider, &work), ==,
                       TC_X509_SIGNATURE_VALID);
      munit_assert_uint(calls, ==, 1);
      {
        TC_X509_trust_anchor anchor = {parsed.subject, parsed.public_key};
        uint32_t left[64], right[64];
        uint8_t used[4], changed_name[256];
        TC_X509_name_workspace names = {left, right, 64, used, 4};
        work = 100000;
        calls = 0;
        munit_assert_int(
            TC_X509_issuer_check(&parsed, anchor.name, &anchor.public_key, &provider, &limits, &names, &work), ==,
            TC_X509_SIGNATURE_VALID);
        munit_assert_uint(calls, ==, 1);
        munit_assert_size(anchor.name.length, <=, sizeof changed_name);
        memcpy(changed_name, anchor.name.data, anchor.name.length);
        changed_name[anchor.name.length - 1] = '!';
        anchor.name.data = changed_name;
        work = 100000;
        calls = 0;
        munit_assert_int(
            TC_X509_issuer_check(&parsed, anchor.name, &anchor.public_key, &provider, &limits, &names, &work), ==,
            TC_X509_SIGNATURE_INVALID);
        munit_assert_uint(calls, ==, 0);
        anchor.name = parsed.subject;
        anchor.public_key = other.public_key;
        work = 100000;
        munit_assert_int(
            TC_X509_issuer_check(&parsed, anchor.name, &anchor.public_key, &provider, &limits, &names, &work), ==,
            TC_X509_SIGNATURE_INVALID);
        munit_assert_uint(calls, ==, 1);
      }
      work = 10000;
      munit_assert_int(TC_X509_signature_verify(&parsed, &other.public_key, &provider, &work), ==,
                       TC_X509_SIGNATURE_INVALID);
      offset = (size_t)(parsed.serial.data - der);
      der[offset] ^= 3;
      work = 10000;
      munit_assert_int(TC_X509_signature_verify(&parsed, &parsed.public_key, &provider, &work), ==,
                       TC_X509_SIGNATURE_INVALID);
      der[offset] ^= 3;
      offset = (size_t)(parsed.signature.data - der) + parsed.signature.length - 1;
      der[offset] ^= 1;
      work = 10000;
      munit_assert_int(TC_X509_signature_verify(&parsed, &parsed.public_key, &provider, &work), ==,
                       TC_X509_SIGNATURE_INVALID);
      der[offset] ^= 1;
      work = 10000;
      munit_assert_int(TC_X509_signature_verify(&parsed, &parsed.public_key, &provider, &work), ==,
                       TC_X509_SIGNATURE_VALID);
    }
    EVP_PKEY_free(wrong);
    EVP_PKEY_free(key);
  }
  return MUNIT_OK;
}

static void add_unknown_extension(X509* certificate, int critical)
{
  static const unsigned char value[] = {5, 0};
  ASN1_OBJECT* oid = OBJ_txt2obj("1.2.3.999", 1);
  ASN1_OCTET_STRING* contents = ASN1_OCTET_STRING_new();
  X509_EXTENSION* extension;
  munit_assert_not_null(oid);
  munit_assert_not_null(contents);
  munit_assert_int(ASN1_OCTET_STRING_set(contents, value, sizeof value), ==, 1);
  extension = X509_EXTENSION_create_by_OBJ(NULL, oid, critical, contents);
  munit_assert_not_null(extension);
  munit_assert_int(X509_add_ext(certificate, extension, -1), ==, 1);
  X509_EXTENSION_free(extension);
  ASN1_OCTET_STRING_free(contents);
  ASN1_OBJECT_free(oid);
}

static int verify_chain(X509* const certs[4], const char* policy, unsigned long flags, int purpose)
{
  X509_STORE* store = X509_STORE_new();
  X509_STORE_CTX* context = X509_STORE_CTX_new();
  STACK_OF(X509)* intermediates = sk_X509_new_null();
  int valid;
  munit_assert_not_null(store);
  munit_assert_not_null(context);
  munit_assert_not_null(intermediates);
  munit_assert_int(X509_STORE_add_cert(store, certs[0]), ==, 1);
  munit_assert_int(sk_X509_push(intermediates, certs[1]), >, 0);
  munit_assert_int(sk_X509_push(intermediates, certs[2]), >, 0);
  munit_assert_int(X509_STORE_CTX_init(context, store, certs[3], intermediates), ==, 1);
  if (purpose)
    munit_assert_int(X509_STORE_CTX_set_purpose(context, purpose), ==, 1);
  /* Match the test's 2026-01-01 UTC validation time. */
  X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(context), (time_t)1767225600);
  if (policy) {
    ASN1_OBJECT* oid = OBJ_txt2obj(policy, 1);
    munit_assert_not_null(oid);
    munit_assert_int(X509_VERIFY_PARAM_add0_policy(X509_STORE_CTX_get0_param(context), oid), ==, 1);
    munit_assert_int(X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(context),
                                                 X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY | flags),
                     ==, 1);
  }
  valid = X509_verify_cert(context);
  X509_STORE_CTX_free(context);
  X509_STORE_free(store);
  sk_X509_free(intermediates);
  return valid;
}

typedef struct {
  const TC_bytes* candidates;
  const TC_X509_trust_anchor* anchor;
  TC_TLV_result failure;
  int fail_anchor, increase_work, omit_record, exhaust_work;
  TC_X509_name_constraints names;
} test_search_store;

static TC_TLV_result store_read(test_search_store* store, int anchor, size_t* work)
{
  if (store->increase_work) { ++*work; return TC_TLV_OK; }
  if (store->exhaust_work) { *work = 0; return TC_TLV_OK; }
  if (*work < 7) { *work = 0; return TC_TLV_LIMIT; }
  *work -= 7;
  return store->fail_anchor == anchor ? store->failure : TC_TLV_OK;
}

static TC_TLV_result store_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  test_search_store* store = context;
  TC_TLV_result result = store_read(store,0,work);
  if (result == TC_TLV_OK && !(store->omit_record && !store->fail_anchor)) *out = store->candidates[index];
  return result;
}

static TC_TLV_result store_anchor(void* context, size_t index, size_t* work, tc_x509_search_anchor* out)
{
  test_search_store* store = context;
  TC_TLV_result result = store_read(store,1,work);
  munit_assert_size(index, ==, 0);
  if (result == TC_TLV_OK && !(store->omit_record && store->fail_anchor)) {
    out->trust = *store->anchor;
    out->names = store->names;
  }
  return result;
}

static TC_TLV_result budget_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  (void)context; (void)index;
  /* A callback must not return writable budget storage as certificate bytes. */
  *out = (TC_bytes){(const uint8_t*)work,sizeof *work};
  return TC_TLV_OK;
}

static TC_TLV_result store_indexed_anchor(void* context, size_t index, size_t* work,
    TC_X509_store_anchor* out)
{
  test_search_store* store = context;
  TC_TLV_result result = store_read(store,1,work);
  if (result == TC_TLV_OK) {
    out->trust = store->anchor[index];
    out->names = store->names;
  }
  return result;
}

static void snapshot_discovery(TC_bytes target, const tc_x509_search_source* source,
    const TC_X509_path_options* options, const TC_X509_path_workspace* workspace)
{
  TC_X509_store trust_store = {0};
  TC_X509_store_snapshot slots[2] = {0}, *held, *current;
  tc_x509_search_source untrusted = *source;
  TC_bytes paths[3], retained_key;
  tc_x509_search_frame frames[3];
  tc_x509_search_workspace search = {paths,frames,3};
  tc_x509_search_result result, saved;
  TC_X509_path_options bounded = *options;
  bounded.max_work = 2000000;
  untrusted.anchor_count = 0;
  untrusted.anchor = NULL;
  munit_assert_int(TC_X509_store_prepare(&slots[0],source), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_publish(&trust_store,0,&slots[0]), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_acquire(&trust_store,&held), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_path_build(target,&held->source,&bounded,workspace,
      &search,&result), ==, TC_X509_PATH_VALID);
  retained_key = result.validation.public_key.key;
  bounded.max_work = result.validation.work_used;
  munit_assert_int(TC_X509_path_build(target,&held->source,&bounded,workspace,
      &search,&result), ==, TC_X509_PATH_VALID);
  --bounded.max_work;
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  munit_assert_int(TC_X509_path_build(target,&held->source,&bounded,workspace,
      &search,&result), ==, TC_X509_PATH_LIMIT);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  bounded.max_work = 2000000;
  {
    TC_X509_search_workspace bad = search;
    bad.frames = (TC_X509_search_frame*)paths;
    munit_assert_int(TC_X509_path_build(target,&held->source,&bounded,workspace,
        &bad,&result), ==, TC_X509_PATH_ERROR);
    munit_assert_memory_equal(sizeof result,&result,&saved);
    bad = search; bad.capacity = SIZE_MAX;
    munit_assert_int(TC_X509_path_build(target,&held->source,&bounded,workspace,
        &bad,&result), ==, TC_X509_PATH_ERROR);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  /* A discarded update leaves the published source available to new readers. */
  munit_assert_int(TC_X509_store_prepare(&slots[1],&untrusted), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_discard(&slots[1]), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_acquire(&trust_store,&current), ==, TC_TLV_OK);
  munit_assert_ptr_equal(current,held);
  munit_assert_int(TC_X509_store_release(current), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_prepare(&slots[1],&untrusted), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_publish(&trust_store,1,&slots[1]), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_acquire(&trust_store,&current), ==, TC_TLV_OK);
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  munit_assert_int(TC_X509_path_build(target,&current->source,&bounded,workspace,
      &search,&result), ==, TC_X509_PATH_INVALID);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  munit_assert_int(held->state, ==, TC_X509_SNAPSHOT_RETIRED);
  munit_assert_int(TC_X509_path_build(target,&held->source,&bounded,workspace,
      &search,&result), ==, TC_X509_PATH_VALID);
  munit_assert_ptr_equal(result.validation.public_key.key.data,retained_key.data);
  munit_assert_size(result.validation.public_key.key.length, ==, retained_key.length);
  munit_assert_int(TC_X509_store_prepare(held,source), ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_store_release(current), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_release(held), ==, TC_TLV_OK);
  munit_assert_int(slots[0].state, ==, TC_X509_SNAPSHOT_FREE);
}

static void alternate_issuers(X509* const certs[4], EVP_PKEY* const keys[4], const EVP_MD* digest,
    const TC_bytes encoded_path[3], const TC_X509_trust_anchor* anchor,
    const TC_X509_path_options* options, const TC_X509_path_workspace* workspace)
{
  uint8_t wrong_der[2048];
  X509* wrong = X509_dup(certs[2]);
  X509* wrong_chain[4] = {certs[0],certs[1],wrong,certs[3]};
  TC_bytes candidates[3], slots[3];
  tc_x509_search_frame frames[3];
  tc_x509_search_workspace search = {slots,frames,3};
  tc_x509_search_result found, saved;
  TC_X509_trust_anchor anchors[2] = {*anchor,*anchor};
  TC_X509_path_options bounded = *options;
  TC_X509_certificate wrong_parsed;
  TC_X509_workspace parser = {workspace->frames,workspace->frame_capacity,
                              workspace->oids,workspace->oid_capacity};
  size_t budget;
  munit_assert_not_null(wrong);
  /* Same issuer and subject, valid issuer signature, but a different subject key. */
  munit_assert_int(X509_set_pubkey(wrong, keys[0]), ==, 1);
  candidates[0].data = wrong_der;
  candidates[0].length = encode_certificate(wrong, keys[1], digest, wrong_der, sizeof wrong_der);
  candidates[1] = encoded_path[0]; candidates[2] = encoded_path[1];
  munit_assert_int(verify_chain(wrong_chain,NULL,0,0), ==, 0);
  memset(&found, 0xa5, sizeof found); memcpy(&saved, &found, sizeof saved);
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,2,anchor,1,
      options,workspace,&search,&budget,&found), ==, TC_X509_PATH_INVALID);
  munit_assert_memory_equal(sizeof found, &found, &saved);
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,anchor,1,
      options,workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
  munit_assert_ptr_equal(found.path[1].data, encoded_path[1].data);
  munit_assert_int(TC_X509_read(encoded_path[1].data,encoded_path[1].length,
      &options->parsing,&parser,&wrong_parsed), ==, TC_TLV_OK);
  anchors[0].public_key = wrong_parsed.public_key;
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,anchors,2,
      options,workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
  munit_assert_size(found.anchor_index, ==, 1);
  munit_assert_ptr_equal(found.path[1].data, encoded_path[1].data);
  {
    test_search_store store = {candidates,anchors,TC_TLV_OK,0,0,0,0,{{NULL,0},{NULL,0}}};
    const TC_X509_store_source source = {&store,3,2,store_candidate,store_indexed_anchor};
    TC_X509_store_source selected, previous;
    tc_pki_anchor_source selection, prior;
    /* Both anchors have the same name, but only the second key verifies. */
    for (size_t anchor_index = 0; anchor_index < source.anchor_count; ++anchor_index) {
      munit_assert_int(tc_pki_source_select_anchor(&source,anchor_index,&selection,&selected), ==, TC_TLV_OK);
      munit_assert_size(selected.anchor_count, ==, 1);
      munit_assert_size(selected.candidate_count, ==, source.candidate_count);
      munit_assert_size(selection.anchor_index, ==, anchor_index);
      memcpy(&found,&saved,sizeof found);
      munit_assert_int(TC_X509_path_build(encoded_path[2],&selected,options,workspace,&search,&found),
          ==, anchor_index ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
      if (anchor_index) {
        munit_assert_size(found.anchor_index, ==, 0);
        munit_assert_ptr_equal(found.path[1].data,encoded_path[1].data);
      } else munit_assert_memory_equal(sizeof found,&found,&saved);
      {
        TC_X509_path_options shared = *options;
        shared.max_work = 0;
        budget = 2000000;
        munit_assert_int(tc_x509_path_build_work(encoded_path[2],&selected,&shared,workspace,&search,
            &budget,&found), ==, anchor_index ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
        munit_assert_size(budget, <, 2000000);
        const size_t consumed = 2000000 - budget;
        if (anchor_index) munit_assert_size(found.validation.work_used, ==, consumed);
        budget = consumed - 1;
        memcpy(&found,&saved,sizeof found);
        munit_assert_int(tc_x509_path_build_work(encoded_path[2],&selected,&shared,workspace,&search,
            &budget,&found), ==, TC_X509_PATH_LIMIT);
        munit_assert_memory_equal(sizeof found,&found,&saved);
        munit_assert_size(budget, ==, 0);
        munit_assert_int(tc_x509_path_build_work(encoded_path[2],&selected,&shared,workspace,&search,
            &budget,&found), ==, TC_X509_PATH_LIMIT);
        munit_assert_memory_equal(sizeof found,&found,&saved);
        munit_assert_size(budget, ==, 0);
        budget = consumed;
        munit_assert_int(tc_x509_path_build_work(encoded_path[2],&selected,&shared,workspace,&search,
            &budget,&found), ==, anchor_index ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
        munit_assert_size(budget, ==, 0);
      }
    }
    memcpy(&previous,&selected,sizeof previous); memcpy(&prior,&selection,sizeof prior);
    {
      TC_X509_store_source aliasing = source, view;
      tc_pki_anchor_source context;
      aliasing.candidate = budget_candidate;
      munit_assert_int(tc_pki_source_select_anchor(&aliasing,1,&context,&view), ==, TC_TLV_OK);
      memcpy(&found,&saved,sizeof found);
      munit_assert_int(TC_X509_path_build(encoded_path[2],&view,options,workspace,&search,&found),
          ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found,&found,&saved);
    }
    munit_assert_int(tc_pki_source_select_anchor(&source,source.anchor_count,&selection,&selected),
        ==, TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof selected,&selected,&previous);
    munit_assert_memory_equal(sizeof selection,&selection,&prior);
    {
      static const uint8_t excluded[] = {0x30,6,0x82,4,'t','e','s','t'};
      store.names.excluded = (TC_bytes){excluded,sizeof excluded};
      memcpy(&found,&saved,sizeof found);
      munit_assert_int(TC_X509_path_build(encoded_path[2],&selected,options,workspace,&search,&found),
          ==, TC_X509_PATH_INVALID);
      munit_assert_memory_equal(sizeof found,&found,&saved);
      store.names.excluded = (TC_bytes){NULL,0};
    }
    {
      TC_X509_store_anchor result, old;
      memset(&old,0xa5,sizeof old); memcpy(&result,&old,sizeof result);
      budget = 2000000;
      munit_assert_int(selected.anchor(selected.context,1,&budget,&result), ==, TC_TLV_ARGUMENT);
      munit_assert_memory_equal(sizeof result,&result,&old);
      munit_assert_size(budget, ==, 2000000);
      budget = 0;
      munit_assert_int(selected.anchor(selected.context,0,&budget,&result), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof result,&result,&old);
    }
  }
  bounded.max_input = encoded_path[0].length + encoded_path[1].length + encoded_path[2].length;
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,anchor,1,
      &bounded,workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
  --bounded.max_input;
  budget = 2000000;
  memcpy(&found, &saved, sizeof found);
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,anchor,1,
      &bounded,workspace,&search,&budget,&found), ==, TC_X509_PATH_LIMIT);
  munit_assert_memory_equal(sizeof found, &found, &saved);
  bounded.max_input = encoded_path[2].length - 1;
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,anchor,1,
      &bounded,workspace,&search,&budget,&found), ==, TC_X509_PATH_LIMIT);
  munit_assert_memory_equal(sizeof found, &found, &saved);
  {
    test_search_store store = {candidates,anchor,TC_TLV_OK,0,0,0,0,{{NULL,0},{NULL,0}}};
    tc_x509_search_source source = {&store,3,1,store_candidate,store_anchor};
    snapshot_discovery(encoded_path[2],&source,options,workspace);
    static const TC_TLV_result failures[] = {TC_TLV_ARGUMENT,TC_TLV_END,TC_TLV_LIMIT,TC_TLV_UNSUPPORTED};
    static const TC_X509_path_status statuses[] = {
      TC_X509_PATH_ERROR,TC_X509_PATH_ERROR,TC_X509_PATH_LIMIT,TC_X509_PATH_UNSUPPORTED
    };
    budget = 2000000;
    munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,options,workspace,
        &search,&budget,&found), ==, TC_X509_PATH_VALID);
    munit_assert_ptr_equal(found.path[1].data, encoded_path[1].data);
    {
      static const uint8_t permitted[] = {
        0x30,14,0x82,12,'e','x','a','m','p','l','e','.','t','e','s','t'
      };
      TC_X509_path_options restricted = *options;
      store.names.permitted = (TC_bytes){permitted,sizeof permitted};
      budget = 2000000;
      munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,&restricted,workspace,
          &search,&budget,&found), ==, TC_X509_PATH_VALID);
      restricted.anchor_names.excluded = store.names.permitted;
      budget = 2000000; memcpy(&found,&saved,sizeof found);
      munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,&restricted,workspace,
          &search,&budget,&found), ==, TC_X509_PATH_INVALID);
      munit_assert_memory_equal(sizeof found,&found,&saved);
      restricted.anchor_names.excluded = (TC_bytes){NULL,0};
      restricted.anchor_names.permitted = store.names.permitted;
      store.names.excluded = store.names.permitted;
      budget = 2000000;
      munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,&restricted,workspace,
          &search,&budget,&found), ==, TC_X509_PATH_INVALID);
      munit_assert_memory_equal(sizeof found,&found,&saved);
      store.names = (TC_X509_name_constraints){{NULL,0},{NULL,0}};
    }
    for (store.fail_anchor = 0; store.fail_anchor < 2; ++store.fail_anchor) {
      for (size_t fault = 0; fault < sizeof failures / sizeof *failures; ++fault) {
        store.failure = failures[fault]; budget = 2000000;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,options,workspace,
            &search,&budget,&found), ==, statuses[fault]);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
            &search,&found), ==, statuses[fault]);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
    }
    store.increase_work = 1; budget = 2000000;
    munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,options,workspace,
        &search,&budget,&found), ==, TC_X509_PATH_ERROR);
    munit_assert_size(budget, ==, 0);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
        &search,&found), ==, TC_X509_PATH_ERROR);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    store.increase_work = 0; store.failure = TC_TLV_OK; store.omit_record = 1;
    for (store.fail_anchor = 0; store.fail_anchor < 2; ++store.fail_anchor) {
      budget = 2000000;
      munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,options,workspace,
          &search,&budget,&found), ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
          &search,&found), ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found, &found, &saved);
    }
    store.omit_record = 0; store.exhaust_work = 1; budget = 2000000;
    munit_assert_int(tc_x509_path_search_source(encoded_path[2],&source,options,workspace,
        &search,&budget,&found), ==, TC_X509_PATH_LIMIT);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
        &search,&found), ==, TC_X509_PATH_LIMIT);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    store.exhaust_work = 0;
    {
      TC_X509_trust_anchor bad_anchor = *anchor;
      TC_bytes bad_candidate = {(const uint8_t*)workspace->frames,1};
      TC_bytes* anchor_fields[] = {
        &bad_anchor.name,&bad_anchor.public_key.algorithm.oid,
        &bad_anchor.public_key.algorithm.parameters,&bad_anchor.public_key.key,
        &bad_anchor.public_key.modulus,&bad_anchor.public_key.exponent,
        &bad_anchor.public_key.curve_oid
      };
      store.anchor = &bad_anchor;
      /* Every borrowed anchor field is checked before name or key processing. */
      for (size_t i = 0; i < sizeof anchor_fields / sizeof *anchor_fields; ++i) {
        *anchor_fields[i] = bad_candidate;
        munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
            &search,&found), ==, TC_X509_PATH_ERROR);
        munit_assert_memory_equal(sizeof found,&found,&saved);
        bad_anchor = *anchor;
      }
      store.anchor = anchor;
      store.names.permitted = bad_candidate;
      munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
          &search,&found), ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found,&found,&saved);
      store.names.permitted = (TC_bytes){NULL,0};
      store.names.excluded = bad_candidate;
      munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
          &search,&found), ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found,&found,&saved);
      store.names.excluded = (TC_bytes){NULL,0};
      source.candidate_count = 1; store.candidates = &bad_candidate;
      munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
          &search,&found), ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found,&found,&saved);
      bad_candidate = (TC_bytes){NULL,1};
      munit_assert_int(TC_X509_path_build(encoded_path[2],&source,options,workspace,
          &search,&found), ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found,&found,&saved);
    }
  }
  X509_free(wrong);
}

static void cross_signed_issuer(X509* const certs[4], const char* group, const EVP_MD* digest,
    const TC_bytes encoded_path[3], const TC_X509_trust_anchor* anchor,
    const TC_X509_path_options* options, const TC_X509_path_workspace* workspace)
{
  EVP_PKEY* foreign_key = EVP_EC_gen(group);
  X509* foreign_root;
  X509* cross = X509_dup(certs[1]);
  X509* oracle[4];
  uint8_t root_der[2048], cross_der[2048];
  TC_bytes candidates[3], slots[3];
  tc_x509_search_frame frames[3];
  tc_x509_search_workspace search = {slots,frames,3};
  tc_x509_search_result found, saved;
  TC_X509_certificate root;
  TC_X509_trust_anchor foreign_anchor;
  TC_X509_workspace parser = {workspace->frames,workspace->frame_capacity,
                              workspace->oids,workspace->oid_capacity};
  size_t length, budget;
  munit_assert_not_null(foreign_key);
  munit_assert_not_null(cross);
  foreign_root = make_certificate(foreign_key,"Other Anchor",NULL);
  add_extension(foreign_root,NID_basic_constraints,"critical,CA:TRUE,pathlen:2");
  add_extension(foreign_root,NID_key_usage,"critical,keyCertSign");
  length = encode_certificate(foreign_root,foreign_key,digest,root_der,sizeof root_der);
  munit_assert_int(TC_X509_read(root_der,length,&options->parsing,&parser,&root), ==, TC_TLV_OK);
  foreign_anchor.name = root.subject; foreign_anchor.public_key = root.public_key;
  munit_assert_int(X509_set_issuer_name(cross,X509_get_subject_name(foreign_root)), ==, 1);
  candidates[0].data = cross_der;
  candidates[0].length = encode_certificate(cross,foreign_key,digest,cross_der,sizeof cross_der);
  candidates[1] = encoded_path[1]; candidates[2] = encoded_path[0];
  oracle[0] = foreign_root; oracle[1] = cross; oracle[2] = certs[2]; oracle[3] = certs[3];
  munit_assert_int(verify_chain(oracle,NULL,0,0), ==, 1);
  memset(&found,0xa5,sizeof found); memcpy(&saved,&found,sizeof saved);
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,2,anchor,1,
      options,workspace,&search,&budget,&found), ==, TC_X509_PATH_INVALID);
  munit_assert_memory_equal(sizeof found,&found,&saved);
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,anchor,1,
      options,workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
  munit_assert_ptr_equal(found.path[0].data,encoded_path[0].data);
  budget = 2000000;
  munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,&foreign_anchor,1,
      options,workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
  munit_assert_ptr_equal(found.path[0].data,cross_der);
  X509_free(cross);
  X509_free(foreign_root);
  EVP_PKEY_free(foreign_key);
}

static MunitResult paths(const MunitParameter params[], void* user)
{
  enum { USAGE_VALID = 15, LEAF_EKU, ISSUER_EKU, LEAF_KU, UNKNOWN_CRITICAL, UNKNOWN_NONCRITICAL, PATH_CASE_COUNT };
  static const char* groups[] = {"prime256v1", "secp384r1"};
  static const char* subjects[] = {"Anchor", "Issuing CA", "Intermediate CA", "Target"};
  const EVP_MD* digests[] = {EVP_sha256(), EVP_sha384()};
  uint8_t der[4][2048], used[8];
  uint8_t original_hash[4][32], checked_hash[32];
  uint32_t left[64], right[64];
  TC_TLV_frame frames[16];
  TC_bytes oids[16];
  TC_X509_workspace parse_workspace = {frames, 16, oids, 16};
  TC_X509_name_workspace names = {left, right, 64, used, 8};
  TC_X509_constraint_workspace constraints = {frames, 16, &names};
  const TC_TLV_limits limits = {2048, 2048, 256, 16};
  const TC_X509_time at = {2026, 1, 1, 0, 0, 0};
  TC_X509_certificate parsed[4];
  TC_bytes encoded_path[3];
  TC_X509_trust_anchor anchor;
  unsigned group, scenario, source, i, calls = 0;
  TC_X509_signature_provider provider = {verify,&calls,NULL};
  tc_x509_path_input input = {parsed + 1, 3, 3, 6144, &anchor, &at, &provider, &limits, encoded_path, &parse_workspace};
  (void)params;
  (void)user;
  for (group = 0; group < 2; ++group) {
    EVP_PKEY* keys[4];
    for (i = 0; i < 4; ++i) {
      keys[i] = EVP_EC_gen(groups[group]);
      munit_assert_not_null(keys[i]);
    }
    for (scenario = 0; scenario < PATH_CASE_COUNT; ++scenario) {
      X509* certs[4];
      size_t work = 1000000;
      int accepted = 99;
      for (i = 0; i < 4; ++i) {
        size_t length;
        EVP_PKEY* signer = keys[i ? i - 1 : 0];
        certs[i] = make_certificate(keys[i], subjects[i], i ? certs[i - 1] : NULL);
        if (i < 3) {
          const char* basic = i ? "critical,CA:TRUE,pathlen:1" : "critical,CA:TRUE,pathlen:2";
          if (scenario == 2 && i == 2)
            basic = "critical,CA:FALSE";
          if (scenario == 4 && i == 1)
            basic = "critical,CA:TRUE,pathlen:0";
          add_extension(certs[i], NID_basic_constraints, basic);
          add_extension(certs[i], NID_key_usage,
                        scenario == 3 && i == 2 ? "critical,digitalSignature" : "critical,keyCertSign");
        }
        if (i == 1)
          add_extension(certs[i], NID_name_constraints, "critical,permitted;DNS:example.test");
        if (i == 2 && scenario == ISSUER_EKU)
          add_extension(certs[i], NID_ext_key_usage, "critical,clientAuth");
        if (i && scenario >= 8 && scenario != 12) {
          const char* policy = "1.2.3.4";
          if (scenario >= 13)
            policy = "2.5.29.32.0";
          else if (scenario >= 9 && scenario <= 11 && i > 1)
            policy = "1.2.3.5";
          add_extension(certs[i], NID_certificate_policies, policy);
          if (i == 1 && scenario >= 9 && scenario <= 11)
            add_extension(certs[i], NID_policy_mappings, "1.2.3.4:1.2.3.5");
        }
        if (i == 3) {
          if (scenario >= USAGE_VALID) {
            add_extension(certs[i], NID_ext_key_usage,
                          scenario == LEAF_EKU ? "critical,clientAuth" : "critical,serverAuth");
            add_extension(certs[i], NID_key_usage,
                          scenario == LEAF_KU ? "critical,cRLSign" : "critical,digitalSignature");
            if (scenario == UNKNOWN_CRITICAL || scenario == UNKNOWN_NONCRITICAL)
              add_unknown_extension(certs[i], scenario == UNKNOWN_CRITICAL);
          }
          add_extension(certs[i], NID_subject_alt_name, scenario == 1 ? "DNS:outside.test" : "DNS:card.example.test");
          if (scenario == 5)
            munit_assert_int(ASN1_TIME_set_string_X509(X509_getm_notAfter(certs[i]), "20250101000000Z"), ==, 1);
          if (scenario == 6)
            signer = keys[0];
          if (scenario == 7)
            munit_assert_int(X509_set_issuer_name(certs[i], X509_get_subject_name(certs[0])), ==, 1);
        }
        length = encode_certificate(certs[i], signer, digests[group], der[i], sizeof der[i]);
        munit_assert_int(EVP_Digest(der[i], length, original_hash[i], NULL, EVP_sha256(), NULL), ==, 1);
        munit_assert_int(TC_X509_read(der[i], length, &limits, &parse_workspace, &parsed[i]), ==, TC_TLV_OK);
        if (i)
          encoded_path[i - 1] = parsed[i].encoded;
      }
      anchor.name = parsed[0].subject;
      anchor.public_key = parsed[0].public_key;
      for (source = 0; source < 2; ++source) {
        input.certificates = source ? NULL : parsed + 1;
        work = 1000000;
        if (scenario < 8)
          munit_assert_int(verify_chain(certs, NULL, 0, 0), ==, scenario == 0);
        calls = 0;
        munit_assert_int(tc_x509_path_basic(&input, &names, &work, &accepted), ==, TC_TLV_OK);
        munit_assert_int(accepted, ==, scenario < 2 || scenario >= 8);
        if (accepted) {
          munit_assert_uint(calls, ==, 3);
          if (source && scenario == 0) {
            size_t required = 1000000 - work, budget = required - 1;
            int checked = 99;
            munit_assert_int(tc_x509_path_basic(&input, &names, &budget, &checked), ==, TC_TLV_LIMIT);
            munit_assert_int(checked, ==, 99);
            budget = required;
            munit_assert_int(tc_x509_path_basic(&input, &names, &budget, &checked), ==, TC_TLV_OK);
            munit_assert_int(checked, ==, 1);
            munit_assert_size(budget, ==, 0);
            parse_workspace.frame_capacity = 0;
            budget = 1000000; checked = 99;
            munit_assert_int(tc_x509_path_basic(&input, &names, &budget, &checked), ==, TC_TLV_LIMIT);
            munit_assert_int(checked, ==, 99);
            parse_workspace.frame_capacity = 16;
          }
          munit_assert_int(tc_x509_path_names(&input, &constraints, &work, &accepted), ==, TC_TLV_OK);
          munit_assert_int(accepted, ==, scenario != 1);
        }
        if (scenario >= 8) {
          const uint8_t initial_oid[] = {0x2a, 3, 4}, wrong_oid[] = {0x2a, 3, 5};
          TC_bytes initial = {scenario == 11 ? wrong_oid : initial_oid, 3};
          tc_x509_policy_options options = {&initial, 1, 1, scenario == 10, scenario == 13};
          tc_x509_policy_node nodes[16];
          tc_x509_policy_edge edges[32];
          tc_x509_policy_expected expected[16];
          tc_x509_policy_graph graph = {nodes, 16, 0, edges, 32, 0, expected, 16, 0, 0};
          TC_bytes policies[8], output[8];
          TC_X509_policy_mapping mappings[8];
          tc_x509_policy_workspace policy_workspace = {&graph, policies, 8, mappings, 8, output, 8, &names, frames, 16};
          size_t count;
          int wanted = scenario == 8 || scenario == 9 || scenario >= 14;
          unsigned long flags = scenario == 10 ? X509_V_FLAG_INHIBIT_MAP : scenario == 13 ? X509_V_FLAG_INHIBIT_ANY : 0;
          if (scenario < USAGE_VALID)
            munit_assert_int(verify_chain(certs, scenario == 11 ? "1.2.3.5" : "1.2.3.4", flags, 0), ==, wanted);
          munit_assert_int(tc_x509_path_policies(&input, &options, &policy_workspace, &work, &count, &accepted), ==,
                           TC_TLV_OK);
          munit_assert_int(accepted, ==, wanted);
          munit_assert_size(count, ==, wanted ? 1 : 0);
          if (wanted) {
            static const uint8_t server_auth[] = {0x2b, 6, 1, 5, 5, 7, 3, 1};
            tc_x509_path_usage usage = {{NULL, 0}, 0, 0, 0, 0};
            tc_x509_extension_workspace extension_workspace = {policies, 8, {frames, 16, &names}};
            TC_TLV_result result;
            int usage_valid = scenario < USAGE_VALID || scenario == USAGE_VALID || scenario == UNKNOWN_NONCRITICAL;
            if (scenario >= USAGE_VALID) {
              usage.purpose.data = server_auth;
              usage.purpose.length = sizeof server_auth;
              usage.key_usage = 1;
              munit_assert_int(verify_chain(certs, "1.2.3.4", flags, X509_PURPOSE_SSL_SERVER), ==, usage_valid);
            }
            munit_assert_memory_equal(sizeof initial_oid, output[0].data, initial_oid);
            accepted = 99;
            result = tc_x509_path_extensions(&input, &usage, &extension_workspace, &work, &accepted);
            if (scenario == UNKNOWN_CRITICAL) {
              munit_assert_int(result, ==, TC_TLV_UNSUPPORTED);
              munit_assert_int(accepted, ==, 99);
            } else {
              munit_assert_int(result, ==, TC_TLV_OK);
              munit_assert_int(accepted, ==, usage_valid);
            }
          }
        }
      }
      {
        static const uint8_t policy_a[] = {0x2a,3,4}, policy_b[] = {0x2a,3,5};
        static const uint8_t server_auth[] = {0x2b,6,1,5,5,7,3,1};
        TC_bytes initial = {scenario == 11 ? policy_b : policy_a,3};
        TC_X509_policy_node nodes[16];
        TC_X509_policy_edge edges[32];
        TC_X509_policy_expected expected[16];
        TC_X509_policy_mapping mappings[8];
        TC_bytes policies[8];
        TC_X509_path_workspace workspace = TC_X509_PATH_WORKSPACE_INIT(
          frames,oids,left,right,used,nodes,edges,expected,mappings,policies);
        TC_X509_path_options options;
        TC_X509_path_result result, unchanged;
        TC_X509_path_status wanted = TC_X509_PATH_INVALID;
        memset(&options, 0, sizeof options);
        options.at = at; options.parsing = limits;
        options.max_certificates = 3; options.max_input = 6144; options.max_work = 1000000;
        options.signatures = provider;
        options.initial_policies = &initial; options.initial_policy_count = 1;
        if (scenario >= 8) options.flags |= TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
        if (scenario == 10) options.flags |= TC_X509_PATH_INHIBIT_MAPPING;
        if (scenario == 13) options.flags |= TC_X509_PATH_INHIBIT_ANY_POLICY;
        if (scenario >= USAGE_VALID) {
          options.purpose.data = server_auth; options.purpose.length = sizeof server_auth;
          options.key_usage = 1;
        }
        if (scenario == 0 || scenario == 8 || scenario == 9 || scenario == 14
            || scenario == USAGE_VALID || scenario == UNKNOWN_NONCRITICAL) wanted = TC_X509_PATH_VALID;
        if (scenario == UNKNOWN_CRITICAL) wanted = TC_X509_PATH_UNSUPPORTED;
        memset(&result, 0xa5, sizeof result); memcpy(&unchanged, &result, sizeof result);
        munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, wanted);
        if (scenario >= USAGE_VALID) {
          const unsigned original_flags = options.flags;
          TC_X509_path_result explicit_result;
          memcpy(&explicit_result,&unchanged,sizeof explicit_result);
          options.flags |= TC_X509_PATH_INHIBIT_ANY_PURPOSE | TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE;
          munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&explicit_result), ==, wanted);
          if (wanted != TC_X509_PATH_VALID)
            munit_assert_memory_equal(sizeof explicit_result,&explicit_result,&unchanged);
          TC_bytes discovered[3], candidates[2] = {encoded_path[1],encoded_path[0]};
          tc_x509_search_frame search_frames[3];
          tc_x509_search_workspace search = {discovered,search_frames,3};
          tc_x509_search_result found, preserved;
          size_t budget = 2000000;
          memset(&preserved,0xa5,sizeof preserved);
          memcpy(&found,&preserved,sizeof found);
          munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,2,&anchor,1,
              &options,&workspace,&search,&budget,&found), ==, wanted);
          if (wanted != TC_X509_PATH_VALID)
            munit_assert_memory_equal(sizeof found,&found,&preserved);
          else {
            munit_assert_size(found.count, ==, 3);
            for (size_t entry = 0; entry < found.count; ++entry)
              munit_assert_ptr_equal(found.path[entry].data,encoded_path[entry].data);
          }
          options.flags = original_flags;
        }
        {
          TC_X509_path_result candidate;
          size_t remaining = 2000000, spent, before;
          memcpy(&candidate, &unchanged, sizeof candidate);
          munit_assert_int(tc_x509_path_validate_budget(encoded_path,3,&anchor,&options,
              &workspace,&remaining,&candidate), ==, wanted);
          spent = 2000000 - remaining;
          munit_assert_size(spent, >, 0);
          if (wanted == TC_X509_PATH_VALID) munit_assert_size(candidate.work_used, ==, spent);
          else munit_assert_memory_equal(sizeof candidate, &candidate, &unchanged);
          before = remaining;
          munit_assert_int(tc_x509_path_validate_budget(encoded_path,3,&anchor,&options,
              &workspace,&remaining,&candidate), ==, wanted);
          munit_assert_size(before - remaining, ==, spent);
          remaining = 0;
          memcpy(&candidate, &unchanged, sizeof candidate);
          munit_assert_int(tc_x509_path_validate_budget(encoded_path,3,&anchor,&options,
              &workspace,&remaining,&candidate), ==, TC_X509_PATH_LIMIT);
          munit_assert_size(remaining, ==, 0);
          munit_assert_memory_equal(sizeof candidate, &candidate, &unchanged);
        }
        if (wanted != TC_X509_PATH_VALID) {
          munit_assert_memory_equal(sizeof result, &result, &unchanged);
        } else {
          size_t required = result.work_used;
          if (scenario == 0) {
            TC_bytes message[3];
            size_t cuts[] = {0,1,parsed[3].tbs.length / 2,parsed[3].tbs.length};
            for (size_t split = 0; split < 4; ++split) {
              size_t verify_work = 1000000;
              message[0] = (TC_bytes){parsed[3].tbs.data,cuts[split]};
              message[1] = (TC_bytes){NULL,0};
              message[2] = (TC_bytes){parsed[3].tbs.data + cuts[split],parsed[3].tbs.length - cuts[split]};
              munit_assert_int(TC_X509_signature_verify_message(message,3,&parsed[3].signature_algorithm,
                  parsed[3].signature,&parsed[2].public_key,&provider,&verify_work), ==, TC_X509_SIGNATURE_VALID);
            }
            {
              uint8_t wrong_tag = parsed[3].tbs.data[0] ^ 1;
              size_t verify_work = 1000000;
              message[0] = (TC_bytes){&wrong_tag,1};
              message[1] = (TC_bytes){parsed[3].tbs.data + 1,parsed[3].tbs.length - 1};
              munit_assert_int(TC_X509_signature_verify_message(message,2,&parsed[3].signature_algorithm,
                  parsed[3].signature,&parsed[2].public_key,&provider,&verify_work), ==, TC_X509_SIGNATURE_INVALID);
            }
            alternate_issuers(certs,keys,digests[group],encoded_path,&anchor,&options,&workspace);
            cross_signed_issuer(certs,groups[group],digests[group],encoded_path,&anchor,&options,&workspace);
            TC_bytes path_slots[4], candidates[3] = {encoded_path[1], encoded_path[2], encoded_path[0]};
            tc_x509_search_frame search_frames[4];
            tc_x509_search_workspace search = {path_slots,search_frames,4};
            tc_x509_search_result found, saved;
            size_t budget = 2000000, consumed;
            memset(&found, 0xa5, sizeof found);
            memcpy(&saved, &found, sizeof saved);
            munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,&anchor,1,
                &options,&workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
            consumed = 2000000 - budget;
            munit_assert_size(found.count, ==, 3);
            munit_assert_size(found.anchor_index, ==, 0);
            munit_assert_size(found.validation.work_used, ==, consumed);
            for (size_t entry = 0; entry < 3; ++entry)
              munit_assert_ptr_equal(found.path[entry].data, encoded_path[entry].data);
            budget = consumed;
            munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,&anchor,1,
                &options,&workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
            munit_assert_size(budget, ==, 0);
            budget = consumed - 1;
            memcpy(&found, &saved, sizeof found);
            munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,&anchor,1,
                &options,&workspace,&search,&budget,&found), ==, TC_X509_PATH_LIMIT);
            munit_assert_memory_equal(sizeof found, &found, &saved);
            candidates[0] = encoded_path[0]; candidates[2] = encoded_path[1];
            budget = 2000000;
            munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,&anchor,1,
                &options,&workspace,&search,&budget,&found), ==, TC_X509_PATH_VALID);
            search.capacity = 2; budget = 2000000;
            memcpy(&found, &saved, sizeof found);
            munit_assert_int(tc_x509_path_search(encoded_path[2],candidates,3,&anchor,1,
                &options,&workspace,&search,&budget,&found), ==, TC_X509_PATH_LIMIT);
            munit_assert_memory_equal(sizeof found, &found, &saved);
            search.capacity = 4; budget = 2000000;
            munit_assert_int(tc_x509_path_search(encoded_path[2],NULL,0,&anchor,1,
                &options,&workspace,&search,&budget,&found), ==, TC_X509_PATH_INVALID);
            munit_assert_memory_equal(sizeof found, &found, &saved);
          }
          munit_assert_ptr_equal(result.public_key.key.data, parsed[3].public_key.key.data);
          munit_assert_ptr_equal(result.policies, policies);
          munit_assert_size(result.policy_count, ==, scenario == 0 ? 0 : 1);
          options.max_work = required;
          munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_VALID);
          options.max_work = required - 1;
          memcpy(&unchanged, &result, sizeof result);
          munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_LIMIT);
          munit_assert_memory_equal(sizeof result, &result, &unchanged);
          options.max_work = 1000000;
          workspace.policies = workspace.oids;
          munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
          munit_assert_memory_equal(sizeof result, &result, &unchanged);
          workspace.policies = policies;
          options.signatures.verify = NULL;
          munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_UNSUPPORTED);
          munit_assert_memory_equal(sizeof result, &result, &unchanged);
          options.signatures = provider;
          if (scenario == 0) {
            static const uint8_t domain[] = {
              0x30,14,0x82,12,'e','x','a','m','p','l','e','.','t','e','s','t'
            };
            options.anchor_names.permitted.data = domain;
            options.anchor_names.permitted.length = sizeof domain;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_VALID);
            memcpy(&unchanged, &result, sizeof result);
            options.anchor_names.excluded = options.anchor_names.permitted;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_INVALID);
            munit_assert_memory_equal(sizeof result, &result, &unchanged);
            memset(&options.anchor_names, 0, sizeof options.anchor_names);
            options.at.month = 13;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
            options.at = at;
            options.flags = ~(unsigned)TC_X509_PATH_SUPPORTED_FLAGS;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
            options.flags = 0;
            options.initial_policies = NULL;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
            options.initial_policies = &initial;
            workspace.names.left = workspace.names.right;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
            workspace.names.left = left;
            workspace.frame_capacity = SIZE_MAX;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
            workspace.frame_capacity = 16;
            options.max_certificates = 2;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_LIMIT);
            options.max_certificates = 3;
            options.max_input = 1;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_LIMIT);
            options.max_input = 6144;
            options.max_work = 0;
            munit_assert_int(TC_X509_path_validate(encoded_path,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_LIMIT);
            options.max_work = 1000000;
            munit_assert_int(TC_X509_path_validate(encoded_path,0,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_INVALID);
            munit_assert_int(TC_X509_path_validate(NULL,3,&anchor,&options,&workspace,&result), ==, TC_X509_PATH_ERROR);
            munit_assert_memory_equal(sizeof result, &result, &unchanged);
          }
        }
      }
      if (scenario == 0 || scenario == 1 || scenario == 5) {
        ExampleX509SearchWorkspace search_storage;
        TC_X509_search_result found, saved_search;
        test_search_store records = {encoded_path,&anchor,TC_TLV_OK,0,0,0,0,{{NULL,0},{NULL,0}}};
        TC_X509_store_source source = {&records,3,1,store_candidate,store_anchor};
        ExampleX509Workspace storage;
        TC_X509_path_result result, unchanged;
        memset(&result, 0xa5, sizeof result); memcpy(&unchanged, &result, sizeof result);
        munit_assert_int(example_check_client_certificate(encoded_path,3,&anchor,&at,&provider,
          1000000,&storage,&result), ==, scenario == 0 ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
        if (scenario == 0) {
          munit_assert_ptr_equal(result.public_key.key.data, parsed[3].public_key.key.data);
          memcpy(&unchanged, &result, sizeof result);
          munit_assert_int(example_check_client_certificate(encoded_path,3,&anchor,&at,&provider,
            0,&storage,&result), ==, TC_X509_PATH_LIMIT);
        }
        munit_assert_memory_equal(sizeof result, &result, &unchanged);
        memset(&found,0xa5,sizeof found); memcpy(&saved_search,&found,sizeof found);
        munit_assert_int(example_find_client_path(encoded_path[2],&source,&at,&provider,
          2000000,&search_storage,&found), ==, scenario == 0 ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
        if (scenario == 0) {
          munit_assert_size(found.count, ==, 3);
          munit_assert_ptr_equal(found.validation.public_key.key.data,parsed[3].public_key.key.data);
          memcpy(&saved_search,&found,sizeof found);
        }
        munit_assert_memory_equal(sizeof found,&found,&saved_search);
        munit_assert_int(example_find_client_path(encoded_path[2],&source,&at,&provider,
          0,&search_storage,&found), ==, TC_X509_PATH_LIMIT);
        munit_assert_memory_equal(sizeof found,&found,&saved_search);
        munit_assert_int(example_find_client_path(encoded_path[2],&source,&at,&provider,
          2000000,NULL,&found), ==, TC_X509_PATH_ERROR);
        munit_assert_memory_equal(sizeof found,&found,&saved_search);
      }
      for (i = 0; i < 4; ++i) {
        munit_assert_int(
            EVP_Digest(parsed[i].encoded.data, parsed[i].encoded.length, checked_hash, NULL, EVP_sha256(), NULL), ==,
            1);
        munit_assert_memory_equal(sizeof checked_hash, checked_hash, original_hash[i]);
      }
      for (i = 0; i < 4; ++i)
        X509_free(certs[i]);
    }
    for (i = 0; i < 4; ++i)
      EVP_PKEY_free(keys[i]);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/ecdsa", signatures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/paths", paths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/openssl", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
