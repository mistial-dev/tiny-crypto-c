/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The CMS signer path builder and credential validation with the native
 * provider: embedded intermediates, explicit anchors, signer identifiers,
 * content forms and signed attributes. OpenSSL generates the fixtures. */
#include "../../examples/cms_reader.h"
#include "../../examples/credential_object.h"
#include "../../examples/credential_workflow.h"
#include "../../src/cms_internal.h"
#include "../../src/pki_tree_internal.h"
#include "../../src/source_internal.h"
#include "../../src/x509_crl_internal.h"
#include "../x509/openssl_fixture.h"
#include "cms_crl_harness.h"
#include "envelope.h"
#include "munit.h"
#include "native_support.h"
#include "openssl_fixture.h"
#include "source.h"
#include <tiny_crypto/x509_crl_source.h>
#include <tiny_crypto/x509_crypto.h>
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

/* Prepare one in-memory CRL through the source path. The returned job owns
 * the record's digest and matches until TC_X509_crl_prepare_clear. */
static TC_X509_crl_job* prepare_crl_record(const TC_bytes* encoded,
                                           const TC_X509_crl_target* targets, size_t count,
                                           const TC_X509_crl_prepare_options* options,
                                           const TC_X509_crl_prepare_workspace* workspace,
                                           TC_X509_crl_record* out)
{
  TC_bytes bytes = *encoded;
  const TC_source source = {tc_source_memory_read, &bytes, bytes.length};
  TC_X509_crl_job* job = NULL;
  size_t work = 60000;
  munit_assert_int(
      TC_X509_crl_prepare_begin(&source, targets, count, options, workspace, &work, &job), ==,
      TC_TLV_OK);
  int complete = 0;
  while (!complete) {
    work = 60000;
    munit_assert_int(TC_X509_crl_prepare_step(job, 4, 128, &work, &complete), ==, TC_TLV_OK);
  }
  munit_assert_int(TC_X509_crl_prepare_finish(job, out), ==, TC_TLV_OK);
  return job;
}

enum {
  CERT_CAPACITY = 1024,
  CMS_CAPACITY = 4096,
  FRAME_CAPACITY = 16,
  POLICY_CAPACITY = 16,
  NAME_SCALARS = 128,
  PATH_CAPACITY = 3,
  INDEX_CAPACITY = 2,
  RSA_BITS = 2048,
  SIGNATURE_CAPACITY = RSA_BITS / 8,
  WORK_BUDGET = 1000000
};

static const uint8_t message[] = {'p', 'a', 't', 'h'};

/* A root, an intermediate and a leaf that signs a CMS SignedData over
 * message. The CMS embeds the intermediate and a CRL from the leaf. The key,
 * content and identifier parameters select the leaf key type, attached,
 * detached or empty content, and the signer identifier form. Each test gets
 * a fresh fixture, and every span in it borrows the fixture's own arrays. */
typedef struct {
  uint8_t root_der[CERT_CAPACITY], intermediate_der[CERT_CAPACITY], leaf_der[CERT_CAPACITY];
  uint8_t encoded[CMS_CAPACITY], name_flags[POLICY_CAPACITY];
  uint32_t left[NAME_SCALARS], right[NAME_SCALARS];
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[POLICY_CAPACITY], policies[POLICY_CAPACITY], path[PATH_CAPACITY],
      index[INDEX_CAPACITY];
  TC_X509_policy_node nodes[POLICY_CAPACITY];
  TC_X509_policy_edge edges[POLICY_CAPACITY];
  TC_X509_policy_expected expected[POLICY_CAPACITY];
  TC_X509_policy_mapping mappings[POLICY_CAPACITY];
  TC_X509_search_frame search_frames[PATH_CAPACITY];
  TC_X509_certificate certificate_cache[PATH_CAPACITY];
  TC_X509_extension_summary summaries[PATH_CAPACITY];
  TC_X509_path_workspace validation;
  TC_X509_search_workspace search;
  TC_X509_workspace parser;
  TC_TLV_limits limits;
  TC_ECDSA_workspace ec;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(RSA_BITS)];
  TC_RSA_workspace rsa;
  TC_X509_native_workspace native;
  TC_X509_path_options options;
  TC_CMS_signed_data container;
  EVP_PKEY *root_key, *intermediate_key, *leaf_key;
  int rsa_signer;
  X509 *root, *intermediate, *leaf;
  size_t root_length, intermediate_length, leaf_length, message_length;
  int detached;
  TC_bytes detached_input;
  BIO* content;
  unsigned cms_flags;
  CMS_ContentInfo* cms;
  X509_CRL* crl;
  int length;
  TC_X509_store_anchor anchor;
  TC_X509_store_source external;
  TC_bytes target;
} path_fixture;

/* Index the embedded certificates for path building. The sources borrow the
 * fixture and tree for the rest of the test. */
static void path_sources_init(path_fixture* f, const tc_pki_tree_workspace* tree,
                              tc_cms_candidates* candidates, tc_cms_path_source* context,
                              TC_X509_store_source* indexed)
{
  munit_assert_int(tc_cms_candidates_init(f->container.certificates, &f->external, INDEX_CAPACITY,
                                          CMS_CAPACITY, &f->limits, tree, candidates),
                   ==, TC_TLV_OK);
  munit_assert_int(
      tc_cms_path_source_init(candidates, tree, f->index, INDEX_CAPACITY, context, indexed), ==,
      TC_TLV_OK);
  munit_assert_size(indexed->candidate_count, ==, INDEX_CAPACITY);
  munit_assert_size(indexed->anchor_count, ==, f->external.anchor_count);
}

static void* path_setup(const MunitParameter params[], void* user)
{
  path_fixture* f = calloc(1, sizeof *f);
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  TC_X509_certificate parsed_root;
  TC_X509_search_result found;
  unsigned char* cursor;
  (void)user;
  munit_assert_not_null(f);
  f->validation = (TC_X509_path_workspace)TC_X509_PATH_WORKSPACE_INIT(
      f->frames, f->oids, f->left, f->right, f->name_flags, f->nodes, f->edges, f->expected,
      f->mappings, f->policies, f->certificate_cache, f->summaries);
  f->search = (TC_X509_search_workspace){f->path, f->search_frames, PATH_CAPACITY};
  f->parser = (TC_X509_workspace){{f->frames, FRAME_CAPACITY}, f->oids, POLICY_CAPACITY};
  f->limits = (TC_TLV_limits){CMS_CAPACITY, CMS_CAPACITY, 256, FRAME_CAPACITY};
  f->rsa = (TC_RSA_workspace){f->rsa_words, sizeof f->rsa_words / sizeof *f->rsa_words};
  f->native = (TC_X509_native_workspace){&f->ec, &f->rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  f->root_key = EVP_EC_gen("prime256v1");
  f->intermediate_key = EVP_EC_gen("prime256v1");
  f->rsa_signer = !strcmp(munit_parameters_get(params, "key"), "rsa");
  f->leaf_key = f->rsa_signer ? EVP_RSA_gen(RSA_BITS) : EVP_EC_gen("prime256v1");
  munit_assert_not_null(f->root_key);
  munit_assert_not_null(f->intermediate_key);
  munit_assert_not_null(f->leaf_key);
  f->root = make_certificate(f->root_key, "Root", NULL);
  f->intermediate = make_certificate(f->intermediate_key, "Intermediate", f->root);
  f->leaf = make_certificate(f->leaf_key, "Leaf", f->intermediate);
  add_extension(f->root, NID_basic_constraints, "critical,CA:TRUE");
  add_extension(f->root, NID_key_usage, "critical,keyCertSign,cRLSign");
  add_extension(f->intermediate, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
  add_extension(f->intermediate, NID_key_usage, "critical,keyCertSign,cRLSign");
  add_extension(f->leaf, NID_key_usage, "critical,digitalSignature,cRLSign");
  add_extension(f->leaf, NID_subject_key_identifier, "hash");
  f->root_length =
      encode_certificate(f->root, f->root_key, EVP_sha256(), f->root_der, sizeof f->root_der);
  f->intermediate_length = encode_certificate(f->intermediate, f->root_key, EVP_sha256(),
                                              f->intermediate_der, sizeof f->intermediate_der);
  f->leaf_length = encode_certificate(f->leaf, f->intermediate_key, EVP_sha256(), f->leaf_der,
                                      sizeof f->leaf_der);
  const char* content_kind = munit_parameters_get(params, "content");
  f->message_length = content_kind && !strncmp(content_kind, "empty-", 6) ? 0 : sizeof message;
  f->detached = content_kind && strstr(content_kind, "detached");
  f->detached_input = (TC_bytes){f->detached ? message : NULL, f->detached ? f->message_length : 0};
  f->content = BIO_new_mem_buf(message, (int)f->message_length);
  munit_assert_not_null(f->content);
  const char* identifier = munit_parameters_get(params, "identifier");
  f->cms_flags = CMS_BINARY | CMS_NOSMIMECAP;
  if (identifier && !strcmp(identifier, "key-id"))
    f->cms_flags |= CMS_USE_KEYID;
  if (f->detached)
    f->cms_flags |= CMS_DETACHED;
  f->cms = CMS_sign(f->leaf, f->leaf_key, NULL, f->content, f->cms_flags);
  munit_assert_not_null(f->cms);
  munit_assert_int(CMS_add1_cert(f->cms, f->intermediate), ==, 1);
  f->crl = X509_CRL_new();
  munit_assert_not_null(f->crl);
  munit_assert_int(X509_CRL_set_version(f->crl, 1), ==, 1);
  munit_assert_int(X509_CRL_set_issuer_name(f->crl, X509_get_subject_name(f->leaf)), ==, 1);
  munit_assert_int(X509_CRL_set1_lastUpdate(f->crl, X509_get0_notBefore(f->leaf)), ==, 1);
  munit_assert_int(X509_CRL_set1_nextUpdate(f->crl, X509_get0_notAfter(f->leaf)), ==, 1);
  munit_assert_int(X509_CRL_sign(f->crl, f->leaf_key, EVP_sha256()), >, 0);
  munit_assert_int(CMS_add1_crl(f->cms, f->crl), ==, 1);
  f->length = i2d_CMS_ContentInfo(f->cms, NULL);
  munit_assert_int(f->length, >, 0);
  munit_assert_size((size_t)f->length, <=, sizeof f->encoded);
  cursor = f->encoded;
  munit_assert_int(i2d_CMS_ContentInfo(f->cms, &cursor), ==, f->length);
  munit_assert_int(
      TC_X509_read((TC_bytes){f->root_der, f->root_length}, &f->limits, &f->parser, &parsed_root),
      ==, TC_TLV_OK);
  f->anchor = (TC_X509_store_anchor){.trust = {parsed_root.subject, parsed_root.public_key}};
  f->external = (TC_X509_store_source){&f->anchor, 0, 1, NULL, crl_trust_anchor};
  f->options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  f->options.parsing = f->limits;
  f->options.max_certificates = PATH_CAPACITY;
  f->options.max_input = CMS_CAPACITY;
  f->options.max_work = WORK_BUDGET;
  f->options.signatures = TC_X509_native_provider(&f->native);
  f->target = (TC_bytes){f->leaf_der, f->leaf_length};
  /* The leaf alone cannot reach the root. The embedded intermediate can. */
  munit_assert_int(
      TC_X509_path_build(f->target, &f->external, &f->options, &f->validation, &f->search, &found),
      ==, TC_X509_PATH_INVALID);
  munit_assert_int(tc_cms_signed_data_read((TC_bytes){f->encoded, (size_t)f->length}, TC_TLV_BER,
                                           &f->limits, (TC_TLV_frames){f->frames, FRAME_CAPACITY},
                                           &work, &f->container),
                   ==, TC_TLV_OK);
  path_sources_init(f, &tree, &candidates, &context, &indexed);
  munit_assert_int(
      TC_X509_path_build(f->target, &indexed, &f->options, &f->validation, &f->search, &found), ==,
      TC_X509_PATH_VALID);
  munit_assert_size(found.count, ==, 2);
  munit_assert_size(found.anchor_index, ==, 0);
  munit_assert_size(found.path[0].length, ==, f->intermediate_length);
  munit_assert_memory_equal(f->intermediate_length, found.path[0].data, f->intermediate_der);
  munit_assert_true((uintptr_t)found.path[0].data >= (uintptr_t)f->encoded &&
                    (uintptr_t)found.path[0].data < (uintptr_t)(f->encoded + sizeof f->encoded));
  return f;
}

static void path_teardown(void* fixture)
{
  path_fixture* f = fixture;
  X509_CRL_free(f->crl);
  CMS_ContentInfo_free(f->cms);
  BIO_free(f->content);
  X509_free(f->leaf);
  X509_free(f->intermediate);
  X509_free(f->root);
  EVP_PKEY_free(f->leaf_key);
  EVP_PKEY_free(f->intermediate_key);
  EVP_PKEY_free(f->root_key);
  free(f);
}

/* The first SignerInfo and its content digest. */
typedef struct {
  TC_TLV_reader signers;
  TC_CMS_signer_info signer;
  TC_X509_search_result saved;
  uint8_t digest[TC_SHA256_DIGESTLEN];
  TC_CMS_signature_workspace signature;
  TC_bytes content_digest;
} signer_context;

static void signer_context_init(path_fixture* f, const tc_pki_tree_workspace* tree,
                                signer_context* signing)
{
  memset(signing, 0, sizeof *signing);
  signing->signature = (TC_CMS_signature_workspace){{f->frames, FRAME_CAPACITY}, NULL, 0};
  signing->content_digest = (TC_bytes){signing->digest, sizeof signing->digest};
  *tree->work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signers_init(f->container.signers, &cms_policy, &f->limits,
                                       (TC_TLV_frames){f->frames, FRAME_CAPACITY}, tree->work,
                                       &signing->signers),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_CMS_signer_next(&signing->signers, (TC_TLV_frames){f->frames, FRAME_CAPACITY},
                                      tree->work, &signing->signer),
                   ==, TC_TLV_OK);
  if (f->container.has_content) {
    munit_assert_int(TC_CMS_content_digest(f->container.content, TC_HASH_SHA256, &f->limits,
                                           (TC_TLV_frames){f->frames, FRAME_CAPACITY}, tree->work,
                                           signing->digest, sizeof signing->digest),
                     ==, TC_TLV_OK);
  } else {
    unsigned digest_length;
    munit_assert_int(
        EVP_Digest(message, f->message_length, signing->digest, &digest_length, EVP_sha256(), NULL),
        ==, 1);
    munit_assert_size(digest_length, ==, sizeof signing->digest);
  }
  memset(&signing->saved, 0xa5, sizeof signing->saved);
}

/* The CMS signer search over embedded and indexed candidates, with an
 * exact and a short budget. */
static MunitResult signer_find(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const intermediate_der = f->intermediate_der;
  uint8_t* const leaf_der = f->leaf_der;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_path_options options = f->options;
  TC_CMS_signed_data container = f->container;
  const size_t intermediate_length = f->intermediate_length;
  const size_t leaf_length = f->leaf_length;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_X509_search_result found;
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  path_sources_init(f, &tree, &candidates, &context, &indexed);
  signer_context signing;
  signer_context_init(f, &tree, &signing);
  TC_CMS_signer_info signer = signing.signer;
  TC_X509_search_result saved = signing.saved;
  const TC_CMS_signature_workspace signature = signing.signature;
  const TC_bytes content_digest = signing.content_digest;
  (void)params;
  {
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(
        tc_cms_signer_find(
            &candidates,
            &(tc_cms_signer_search){
                &signer, container.content_type, content_digest,
                (TC_CMS_verification_policy){.attributes = TC_CMS_ATTRIBUTES_DER,
                                             .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                &indexed, &options, &tree, &signature, &validation, &search, NULL},
            &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_size(found.anchor_index, ==, 0);
    munit_assert_memory_equal(intermediate_length, found.path[0].data, intermediate_der);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(found.validation.work_used, ==, required);
    work = required;
    munit_assert_int(
        tc_cms_signer_find(
            &candidates,
            &(tc_cms_signer_search){
                &signer, container.content_type, content_digest,
                (TC_CMS_verification_policy){.attributes = TC_CMS_ATTRIBUTES_DER,
                                             .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                &indexed, &options, &tree, &signature, &validation, &search, NULL},
            &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(work, ==, 0);
  }
  return MUNIT_OK;
}

/* The combined credential example over a held trust snapshot, with issuer
 * and root CRLs, revoked signers and intermediates and exhausted work. */
static MunitResult credential_workflow(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const root_der = f->root_der;
  uint8_t* const intermediate_der = f->intermediate_der;
  uint8_t* const leaf_der = f->leaf_der;
  uint8_t* const encoded = f->encoded;
  TC_bytes* const index = f->index;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_workspace parser = f->parser;
  const TC_TLV_limits limits = f->limits;
  TC_X509_path_options options = f->options;
  TC_CMS_signed_data container = f->container;
  EVP_PKEY* root_key = f->root_key;
  EVP_PKEY* intermediate_key = f->intermediate_key;
  EVP_PKEY* leaf_key = f->leaf_key;
  const int rsa_signer = f->rsa_signer;
  X509* root = f->root;
  X509* intermediate = f->intermediate;
  X509* leaf = f->leaf;
  const size_t root_length = f->root_length;
  const size_t intermediate_length = f->intermediate_length;
  const size_t leaf_length = f->leaf_length;
  const size_t message_length = f->message_length;
  const int detached = f->detached;
  const TC_bytes detached_input = f->detached_input;
  const unsigned cms_flags = f->cms_flags;
  int length = f->length;
  TC_X509_store_anchor anchor = f->anchor;
  const TC_X509_store_source external = f->external;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_X509_search_result found;
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  path_sources_init(f, &tree, &candidates, &context, &indexed);
  signer_context signing;
  signer_context_init(f, &tree, &signing);
  TC_CMS_signer_info signer = signing.signer;
  (void)params;
  {
    uint8_t signature_bytes[SIGNATURE_CAPACITY];
    uint8_t signed_digest[TC_CMS_SIGNED_DIGEST_BYTES];
    TC_CMS_path_options settings = {options, INDEX_CAPACITY, CMS_CAPACITY, {0}};
    TC_CMS_path_workspace workspace = {validation,      search,
                                       index,           INDEX_CAPACITY,
                                       signature_bytes, sizeof signature_bytes,
                                       signed_digest,   sizeof signed_digest};
    const TC_bytes envelope = {encoded, (size_t)length};
    {
      ExampleCMSCredentialWorkspace credential;
      const TC_bytes certificates[] = {{root_der, root_length},
                                       {intermediate_der, intermediate_length},
                                       {leaf_der, leaf_length}};
      candidate_source supplied = {certificates, 3, 0, TC_TLV_OK, 0};
      const TC_X509_store_source certificate_source = {&supplied, 3, 0, read_candidate, NULL};
      combined_store_source combined = {&certificate_source, &external};
      const TC_X509_store_source complete = {&combined, 3, 1, combined_candidate, combined_anchor};
      TC_CMS_path_options credential_settings = settings;
      credential_settings.max_candidates += complete.candidate_count;
      TC_X509_store_snapshot slot = {0}, *held = NULL;
      TC_X509_store store = {0};
      const TC_X509_crl_index no_crls = {NULL, 0, 0};
      TC_CMS_revocation_policy revocation = {&no_crls, &options, CMS_CAPACITY,
                                             TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER};
      {
        const TC_CMS_revocation_policy cms_revocation = {
            revocation.index, revocation.signer_policy, revocation.max_candidate_bytes,
            revocation.delta_policy, revocation.order_policy};
        union {
          TC_CMS_validation_request request;
          TC_bytes path[EXAMPLE_X509_PATH_CAPACITY];
        } aliased;
        const TC_CMS_validation_request request = {
            envelope,           0,        container.content_type, detached ? &detached_input : NULL,
            detached ? 1u : 0u, {NULL, 0}};
        const TC_CMS_credential_workspace scratch = {&workspace,
                                                     aliased.path,
                                                     EXAMPLE_X509_PATH_CAPACITY,
                                                     credential.crl_states,
                                                     sizeof credential.crl_states,
                                                     credential.nodes,
                                                     EXAMPLE_CMS_REVOCATION_NODES,
                                                     credential.scopes,
                                                     EXAMPLE_CMS_CRL_CAPACITY,
                                                     credential.signer_path,
                                                     EXAMPLE_X509_PATH_CAPACITY,
                                                     credential.signer_policies,
                                                     EXAMPLE_X509_POLICY_CAPACITY};
        uint8_t saved[sizeof aliased];
        memset(&aliased, 0, sizeof aliased);
        aliased.request = request;
        memcpy(saved, &aliased, sizeof saved);
        work = WORK_BUDGET;
        munit_assert_int(TC_CMS_credential_validate(NULL, &complete, &credential_settings,
                                                    &cms_revocation, &scratch, &work),
                         ==, TC_CREDENTIAL_ERROR);
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_int(TC_CMS_credential_validate(&aliased.request, &complete,
                                                    &credential_settings, &cms_revocation, &scratch,
                                                    &work),
                         ==, TC_CREDENTIAL_ERROR);
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_memory_equal(sizeof saved, &aliased, saved);
        for (unsigned area = 0; area < 2; ++area) {
          TC_CMS_validation_request overlap = request;
          overlap.signer_certificate =
              (TC_bytes){area ? credential.crl_states : (const uint8_t*)aliased.path, 1};
          work = WORK_BUDGET;
          munit_assert_int(TC_CMS_credential_validate(&overlap, &complete, &credential_settings,
                                                      &cms_revocation, &scratch, &work),
                           ==, TC_CREDENTIAL_ERROR);
          munit_assert_size(work, ==, WORK_BUDGET);
          munit_assert_memory_equal(sizeof saved, &aliased, saved);
        }
      }
      work = WORK_BUDGET;
      const TC_CMS_validation_request request = {
          envelope,           0,        container.content_type, detached ? &detached_input : NULL,
          detached ? 1u : 0u, {NULL, 0}};
      munit_assert_int(example_validate_cms_from_store(&request, &store, &credential_settings,
                                                       &revocation, &work, &credential),
                       ==, TC_CREDENTIAL_UNAVAILABLE);
      munit_assert_size(work, ==, WORK_BUDGET);
      munit_assert_int(TC_X509_store_prepare(&slot, &complete), ==, TC_TLV_OK);
      munit_assert_int(TC_X509_store_publish(&store, 0, &slot), ==, TC_TLV_OK);
      munit_assert_int(TC_X509_store_acquire(&store, &held), ==, TC_TLV_OK);
      {
        enum { MISSING_INDEX, MISSING_RECORDS, BAD_DELTA, BAD_ORDER, TOO_MANY_CRLS, CASE_COUNT };
        TC_X509_crl_record extra_records[EXAMPLE_CMS_CRL_CAPACITY + 1];
        for (unsigned kind = 0; kind < CASE_COUNT; ++kind) {
          TC_X509_crl_index bad_index = {NULL, 0, 0};
          TC_CMS_revocation_policy bad = revocation;
          bad.index = &bad_index;
          if (kind == MISSING_INDEX)
            bad.index = NULL;
          else if (kind == MISSING_RECORDS)
            bad_index.count = 1;
          else if (kind == BAD_DELTA)
            bad.delta_policy = (TC_X509_crl_delta_policy)-1;
          else if (kind == BAD_ORDER)
            bad.order_policy = (TC_X509_crl_order_policy)-1;
          else {
            bad_index.records = extra_records;
            bad_index.count = sizeof extra_records / sizeof extra_records[0];
          }
          work = WORK_BUDGET;
          munit_assert_int(example_validate_cms_from_store(&request, &store, &credential_settings,
                                                           &bad, &work, &credential),
                           ==, kind == TOO_MANY_CRLS ? TC_CREDENTIAL_LIMIT : TC_CREDENTIAL_ERROR);
          munit_assert_size(work, ==, WORK_BUDGET);
          munit_assert_size(slot.readers, ==, 1);
        }
      }
      work = WORK_BUDGET;
      /* A valid CMS path still requires revocation evidence. */
      munit_assert_int(example_validate_cms_credential(&request, held, &credential_settings,
                                                       &revocation, &work, &credential),
                       ==, TC_CREDENTIAL_UNSUPPORTED);
      work = 0;
      munit_assert_int(example_validate_cms_credential(&request, held, &credential_settings,
                                                       &revocation, &work, &credential),
                       ==, TC_CREDENTIAL_LIMIT);
      TC_X509_path_options different_time = options;
      different_time.at.year++;
      revocation.signer_policy = &different_time;
      work = WORK_BUDGET;
      munit_assert_int(example_validate_cms_credential(&request, held, &credential_settings,
                                                       &revocation, &work, &credential),
                       ==, TC_CREDENTIAL_ERROR);
      munit_assert_size(work, ==, WORK_BUDGET);
      revocation.signer_policy = &options;
      for (unsigned revoked = 0; revoked < 3; ++revoked) {
        uint8_t issuer_crl[CERT_CAPACITY], root_crl[CERT_CAPACITY];
        const TC_bytes crls[] = {
            {issuer_crl,
             encode_issuer_crl(intermediate, intermediate_key, revoked == 1 ? leaf : NULL,
                               issuer_crl, sizeof issuer_crl)},
            {root_crl, encode_issuer_crl(root, root_key, revoked == 2 ? intermediate : NULL,
                                         root_crl, sizeof root_crl)}};
        TC_X509_crl_record records[2];
        TC_X509_crl_index crl_index;
        work = WORK_BUDGET;
        munit_assert_int(
            TC_X509_crl_index_init(crls, 2, &limits, &parser, &work, records, 2, &crl_index), ==,
            TC_TLV_OK);
        munit_assert_int(records[0].policy, ==, TC_TLV_OK);
        munit_assert_int(records[1].policy, ==, TC_TLV_OK);
        revocation.index = &crl_index;
        {
          TC_X509_certificate target_certificates[3];
          const TC_bytes target_der[] = {{leaf_der, leaf_length},
                                         {intermediate_der, intermediate_length},
                                         {root_der, root_length}};
          TC_X509_crl_target targets[3];
          for (size_t target = 0; target < 3; ++target) {
            munit_assert_int(
                TC_X509_read(target_der[target], &limits, &parser, &target_certificates[target]),
                ==, TC_TLV_OK);
            size_t usage_work = WORK_BUDGET;
            int authorized = 0;
            munit_assert_int(tc_x509_crl_signer_usage(&target_certificates[target], &limits,
                                                      &usage_work, &authorized),
                             ==, TC_TLV_OK);
            munit_assert_int(authorized, ==, 1);
            targets[target] = (TC_X509_crl_target){target_certificates[target].serial,
                                                   target_certificates[target].issuer};
          }
          for (size_t record = 0; record < 2; ++record) {
            TC_X509_search_result trusted_signer;
            work = WORK_BUDGET;
            TC_X509_path_status signer_status = tc_x509_crl_signer_validate(
                &records[record].crl, &target_certificates[record + 1],
                &(tc_x509_crl_trust){&held->source, 0, &options,
                                     &(tc_pki_tree_workspace){validation.frames.data,
                                                              validation.frames.capacity, &work},
                                     &validation, &search,
                                     &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                &trusted_signer);
            munit_assert_int(signer_status, ==, TC_X509_PATH_VALID);
          }
          TC_X509_crl_storage job_storage[3][256];
          TC_X509_crl_job* jobs[3];
          uint8_t metadata[3][CERT_CAPACITY], window[64], entry[256], issuer_storage[256];
          uint8_t unusable_crl[CERT_CAPACITY];
          TC_X509_crl_match matches[3][3];
          /* records 0-1 prepare the issuer and root CRLs. Record 2 is an
             * issuer CRL with an unknown critical extension that omits the
             * leaf. RFC 5280 section 5.2 forbids using it for status. */
          TC_X509_crl_record prepared_records[3];
          const TC_bytes sources[3] = {
              crls[0],
              crls[1],
              {unusable_crl, encode_unknown_critical_crl(intermediate, intermediate_key, NULL,
                                                         unusable_crl, sizeof unusable_crl)}};
          for (size_t record = 0; record < 3; ++record) {
            const TC_X509_crl_prepare_options preparation_options = {
                limits, sources[record].length, sources[record].length * 4 + 1024, 4096, 128};
            const TC_X509_crl_prepare_workspace preparation = {
                {(uint8_t*)job_storage[record], sizeof job_storage[record]},
                {window, sizeof window},
                {metadata[record], sizeof metadata[record]},
                {entry, sizeof entry},
                {issuer_storage, sizeof issuer_storage},
                parser,
                validation.names,
                matches[record],
                3};
            jobs[record] = prepare_crl_record(&sources[record], targets, 3, &preparation_options,
                                              &preparation, &prepared_records[record]);
            munit_assert_int(prepared_records[record].policy, ==,
                             record == 2 ? TC_TLV_UNSUPPORTED : TC_TLV_OK);
          }
          const TC_credential_status expected =
              revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID;
          const TC_X509_crl_record with_issuer[] = {prepared_records[2], prepared_records[0],
                                                    prepared_records[1]};
          const TC_X509_crl_record without_issuer[] = {prepared_records[2], prepared_records[1]};
          const TC_X509_crl_index prepared_indexes[] = {
              {prepared_records, 2, 0}, {with_issuer, 3, 0}, {without_issuer, 2, 0}};
          for (size_t chosen = 0; chosen < 3; ++chosen) {
            TC_CMS_revocation_policy prepared_policy = revocation;
            prepared_policy.index = &prepared_indexes[chosen];
            work = WORK_BUDGET;
            /* Without the issuer CRL the leaf has no usable evidence. A root
               * revocation of the intermediate is found first. */
            munit_assert_int(example_validate_cms_credential(&request, held, &credential_settings,
                                                             &prepared_policy, &work, &credential),
                             ==,
                             chosen == 2 && revoked != 2 ? TC_CREDENTIAL_UNSUPPORTED : expected);
          }
          for (size_t record = 0; record < 3; ++record)
            TC_X509_crl_prepare_clear(jobs[record]);
        }
        /* Explicit signer selection must retain identity and revocation
           * checks. */
        for (unsigned choice = 0; choice < 5; ++choice) {
          TC_CMS_validation_request selected = request;
          uint8_t certificate_free[CMS_CAPACITY];
          selected.signer_certificate = choice == 1
                                            ? (TC_bytes){intermediate_der, intermediate_length}
                                            : (TC_bytes){leaf_der, leaf_length};
          if (choice == 2)
            selected.signer_certificate.data = NULL;
          if (choice == 3)
            selected.signer_certificate.length = 0;
          if (choice == 4) {
            BIO* input = BIO_new_mem_buf(message, (int)message_length);
            munit_assert_not_null(input);
            CMS_ContentInfo* omitted =
                CMS_sign(leaf, leaf_key, NULL, input, cms_flags | CMS_NOCERTS);
            munit_assert_not_null(omitted);
            int encoded_length = i2d_CMS_ContentInfo(omitted, NULL);
            munit_assert_int(encoded_length, >, 0);
            munit_assert_size((size_t)encoded_length, <=, sizeof certificate_free);
            unsigned char* output = certificate_free;
            munit_assert_int(i2d_CMS_ContentInfo(omitted, &output), ==, encoded_length);
            selected.encoded = (TC_bytes){certificate_free, (size_t)encoded_length};
            CMS_ContentInfo_free(omitted);
            BIO_free(input);
          }
          work = WORK_BUDGET;
          munit_assert_int(example_validate_cms_credential(&selected, held, &credential_settings,
                                                           &revocation, &work, &credential),
                           ==,
                           (choice == 2 || choice == 3) ? TC_CREDENTIAL_ERROR
                           : choice == 1                ? TC_CREDENTIAL_INVALID
                           : revoked                    ? TC_CREDENTIAL_REVOKED
                                                        : TC_CREDENTIAL_VALID);
          if (choice == 2 || choice == 3)
            munit_assert_size(work, ==, WORK_BUDGET);
        }
        if (rsa_signer) {
          uint8_t without_null[CMS_CAPACITY];
          const TC_bytes compatible_input = {
              without_null, omit_cms_rsa_parameters(envelope, without_null, sizeof without_null)};
          for (unsigned variant = 0; variant < 4; ++variant) {
            const int allow = variant == 1, invalid_policy = variant >= 2;
            TC_CMS_path_options policy = credential_settings;
            policy.verification.rsa_parameters =
                allow ? TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT : TC_CMS_RSA_PARAMETERS_NULL;
            if (variant == 2)
              policy.verification.rsa_parameters = (TC_CMS_rsa_parameters)-1;
            if (variant == 3)
              policy.verification.attributes = (TC_CMS_attribute_encoding)-1;
            work = WORK_BUDGET;
            memset(&found, 0xa5, sizeof found);
            TC_X509_search_result preserved;
            memcpy(&preserved, &found, sizeof found);
            munit_assert_int(
                TC_CMS_signed_data_path_build(&(TC_CMS_validation_request){compatible_input,
                                                                           0,
                                                                           container.content_type,
                                                                           &detached_input,
                                                                           detached ? 1u : 0u,
                                                                           {NULL, 0}},
                                              &external, &policy, &workspace, &work, &found),
                ==,
                invalid_policy ? TC_X509_PATH_ERROR
                : allow        ? TC_X509_PATH_VALID
                               : TC_X509_PATH_INVALID);
            if (!allow)
              munit_assert_memory_equal(sizeof found, &found, &preserved);
            if (invalid_policy)
              munit_assert_size(work, ==, WORK_BUDGET);
            work = WORK_BUDGET;
            TC_CMS_validation_request compatible = request;
            compatible.encoded = compatible_input;
            munit_assert_int(example_validate_cms_from_store(&compatible, &store, &policy,
                                                             &revocation, &work, &credential),
                             ==,
                             invalid_policy ? TC_CREDENTIAL_ERROR
                             : !allow       ? TC_CREDENTIAL_INVALID
                             : revoked      ? TC_CREDENTIAL_REVOKED
                                            : TC_CREDENTIAL_VALID);
            if (invalid_policy)
              munit_assert_size(work, ==, WORK_BUDGET);
            munit_assert_size(slot.readers, ==, 1);
          }
        }
        const size_t split = message_length / 2;
        const TC_bytes parts[] = {
            {message, split}, {NULL, 0}, {message + split, message_length - split}};
        const TC_CMS_validation_request fragmented = {
            envelope,           0,        container.content_type, detached ? parts : NULL,
            detached ? 3u : 0u, {NULL, 0}};
        work = WORK_BUDGET;
        munit_assert_int(example_validate_cms_credential(&fragmented, held, &credential_settings,
                                                         &revocation, &work, &credential),
                         ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
        work = WORK_BUDGET;
        munit_assert_int(example_validate_cms_from_store(&request, &store, &credential_settings,
                                                         &revocation, &work, &credential),
                         ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
        munit_assert_size(slot.readers, ==, 1);
        work = WORK_BUDGET;
        munit_assert_int(example_validate_cms_from_store(&fragmented, &store, &credential_settings,
                                                         &revocation, &work, &credential),
                         ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
        munit_assert_size(slot.readers, ==, 1);
        if (!revoked) {
          const size_t credential_work = WORK_BUDGET - work;
          munit_assert_size(credential_work, >, 0);
          for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
            work = credential_work - short_budget;
            munit_assert_int(example_validate_cms_from_store(&fragmented, &store,
                                                             &credential_settings, &revocation,
                                                             &work, &credential),
                             ==, short_budget ? TC_CREDENTIAL_LIMIT : TC_CREDENTIAL_VALID);
            if (!short_budget)
              munit_assert_size(work, ==, 0);
            munit_assert_size(slot.readers, ==, 1);
          }
          enum { CRL_RECORDS, CMS_SCRATCH, HELD_PATH, CRL_STATES, CRL_NODES, ALIAS_COUNT };
          for (unsigned alias = 0; alias < ALIAS_COUNT; ++alias) {
            TC_X509_crl_record aliased_record = records[0];
            TC_X509_crl_index aliased_index = {&aliased_record, 1, 0};
            TC_CMS_revocation_policy aliased_policy = revocation;
            uint8_t saved_storage[sizeof credential];
            const void* overlapping = &credential.cms;
            if (alias == HELD_PATH)
              overlapping = credential.held_path;
            if (alias == CRL_STATES)
              overlapping = credential.crl_states;
            if (alias == CRL_NODES)
              overlapping = credential.nodes;
            if (alias == CRL_RECORDS)
              aliased_index.records = (const TC_X509_crl_record*)&credential.cms;
            else
              aliased_record.crl.encoded = (TC_bytes){overlapping, 1};
            aliased_policy.index = &aliased_index;
            memcpy(saved_storage, &credential, sizeof credential);
            work = WORK_BUDGET;
            munit_assert_int(example_validate_cms_from_store(&fragmented, &store,
                                                             &credential_settings, &aliased_policy,
                                                             &work, &credential),
                             ==, TC_CREDENTIAL_ERROR);
            munit_assert_size(work, ==, WORK_BUDGET);
            munit_assert_size(slot.readers, ==, 1);
            munit_assert_memory_equal(sizeof credential, &credential, saved_storage);
          }
          {
            const void* targets[] = {&credential.cms, credential.held_path, credential.crl_states,
                                     credential.nodes};
            for (size_t alias = 0; alias < sizeof targets / sizeof *targets; ++alias) {
              const TC_bytes returned = {targets[alias], 1};
              candidate_source aliased = {&returned, 1, 0, TC_TLV_OK, 0};
              const TC_X509_store_source candidates = {&aliased, 1, 0, read_candidate, NULL};
              combined_store_source combined_alias = {&candidates, &external};
              const TC_X509_store_source source_alias = {&combined_alias, 1, 1, combined_candidate,
                                                         combined_anchor};
              TC_X509_store alias_store = {0};
              TC_X509_store_snapshot alias_slot = {0};
              munit_assert_int(TC_X509_store_prepare(&alias_slot, &source_alias), ==, TC_TLV_OK);
              munit_assert_int(TC_X509_store_publish(&alias_store, 0, &alias_slot), ==, TC_TLV_OK);
              work = WORK_BUDGET;
              munit_assert_int(example_validate_cms_from_store(&fragmented, &alias_store,
                                                               &credential_settings, &revocation,
                                                               &work, &credential),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(aliased.calls, ==, 1);
              munit_assert_size(alias_slot.readers, ==, 0);
            }
          }
          TC_X509_certificate wrong_key;
          munit_assert_int(TC_X509_read((TC_bytes){intermediate_der, intermediate_length}, &limits,
                                        &parser, &wrong_key),
                           ==, TC_TLV_OK);
          TC_X509_store_anchor wrong_anchor = anchor;
          wrong_anchor.trust.public_key = wrong_key.public_key;
          const TC_X509_store_source wrong_trust = {&wrong_anchor, 0, 1, NULL, crl_trust_anchor};
          combined_store_source wrong_combined = {&certificate_source, &wrong_trust};
          TC_X509_store_source wrong_source = {&wrong_combined, 3, 1, combined_candidate,
                                               combined_anchor};
          for (unsigned missing_anchor = 0; missing_anchor < 2; ++missing_anchor) {
            TC_X509_store rejected_store = {0};
            TC_X509_store_snapshot rejected_slot = {0}, *rejected_snapshot = NULL;
            wrong_source.anchor_count = missing_anchor ? 0 : 1;
            munit_assert_int(TC_X509_store_prepare(&rejected_slot, &wrong_source), ==, TC_TLV_OK);
            munit_assert_int(TC_X509_store_publish(&rejected_store, 0, &rejected_slot), ==,
                             TC_TLV_OK);
            munit_assert_int(TC_X509_store_acquire(&rejected_store, &rejected_snapshot), ==,
                             TC_TLV_OK);
            work = WORK_BUDGET;
            munit_assert_int(example_validate_cms_credential(&request, rejected_snapshot,
                                                             &credential_settings, &revocation,
                                                             &work, &credential),
                             ==, TC_CREDENTIAL_INVALID);
            munit_assert_int(TC_X509_store_release(rejected_snapshot), ==, TC_TLV_OK);
          }
          enum { WRONG_USAGE, EXPIRED, TAMPERED_SIGNATURE, ABSENT_SIGNER, FAILURE_COUNT };
          for (unsigned failure = 0; failure < FAILURE_COUNT; ++failure) {
            TC_CMS_path_options rejected = credential_settings;
            TC_X509_path_options crl_policy = options;
            TC_bytes input = envelope;
            size_t signer_index = 0;
            uint8_t changed[CMS_CAPACITY];
            if (failure == WRONG_USAGE) {
              rejected.path.flags |= TC_X509_PATH_REQUIRE_KEY_USAGE;
              rejected.path.key_usage = TC_KEY_USAGE_KEY_ENCIPHERMENT;
            } else if (failure == EXPIRED) {
              rejected.path.at.year = 2040;
              crl_policy.at = rejected.path.at;
            } else if (failure == TAMPERED_SIGNATURE) {
              memcpy(changed, encoded, (size_t)length);
              const size_t end =
                  (size_t)(signer.signature.data - encoded) + signer.signature.length;
              munit_assert_size(end, >, 0);
              munit_assert_size(end, <=, (size_t)length);
              changed[end - 1] ^= 1;
              input.data = changed;
            } else {
              signer_index = SIZE_MAX;
            }
            revocation.signer_policy = &crl_policy;
            TC_CMS_validation_request rejected_request = request;
            rejected_request.encoded = input;
            rejected_request.signer_index = signer_index;
            work = WORK_BUDGET;
            munit_assert_int(example_validate_cms_credential(&rejected_request, held, &rejected,
                                                             &revocation, &work, &credential),
                             ==, TC_CREDENTIAL_INVALID);
            work = WORK_BUDGET;
            munit_assert_int(example_validate_cms_from_store(&rejected_request, &store, &rejected,
                                                             &revocation, &work, &credential),
                             ==, TC_CREDENTIAL_INVALID);
            munit_assert_size(slot.readers, ==, 1);
          }
          revocation.signer_policy = &options;
        }
      }
      revocation.index = &no_crls;
      munit_assert_int(TC_X509_store_release(held), ==, TC_TLV_OK);
      revocation.signer_policy = &options;
      munit_assert_int(example_validate_cms_credential(&request, &slot, &settings, &revocation,
                                                       &work, &credential),
                       ==, TC_CREDENTIAL_ERROR);
    }
  }
  return MUNIT_OK;
}

/* The public signer path builder: required signer certificates, detached
 * content, index capacities and overlapping writable ranges. */
static MunitResult signer_path_build(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const leaf_der = f->leaf_der;
  uint8_t* const encoded = f->encoded;
  TC_bytes* const path = f->path;
  TC_bytes* const index = f->index;
  TC_X509_search_frame* const search_frames = f->search_frames;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_path_options options = f->options;
  TC_CMS_signed_data container = f->container;
  const size_t leaf_length = f->leaf_length;
  const size_t message_length = f->message_length;
  const int detached = f->detached;
  const TC_bytes detached_input = f->detached_input;
  int length = f->length;
  const TC_X509_store_source external = f->external;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_X509_search_result found;
  signer_context signing;
  signer_context_init(f, &tree, &signing);
  TC_CMS_signer_info signer = signing.signer;
  TC_X509_search_result saved = signing.saved;
  const TC_bytes content_digest = signing.content_digest;
  (void)params;
  {
    uint8_t signature_bytes[SIGNATURE_CAPACITY];
    uint8_t signed_digest[TC_CMS_SIGNED_DIGEST_BYTES];
    TC_CMS_path_options settings = {options, INDEX_CAPACITY, CMS_CAPACITY, {0}};
    TC_CMS_path_workspace workspace = {validation,      search,
                                       index,           INDEX_CAPACITY,
                                       signature_bytes, sizeof signature_bytes,
                                       signed_digest,   sizeof signed_digest};
    const TC_bytes envelope = {encoded, (size_t)length};
    work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signed_data_path_build(&(TC_CMS_validation_request){envelope,
                                                                   0,
                                                                   container.content_type,
                                                                   &detached_input,
                                                                   detached ? 1u : 0u,
                                                                   {NULL, 0}},
                                      &external, &settings, &workspace, &work, &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t envelope_work = WORK_BUDGET - work;
    munit_assert_size(found.validation.work_used, ==, envelope_work);
    work = envelope_work;
    munit_assert_int(
        TC_CMS_signed_data_path_build(&(TC_CMS_validation_request){envelope,
                                                                   0,
                                                                   container.content_type,
                                                                   &detached_input,
                                                                   detached ? 1u : 0u,
                                                                   {NULL, 0}},
                                      &external, &settings, &workspace, &work, &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(work, ==, 0);
    {
      const size_t split = message_length / 2;
      TC_bytes parts[] = {{message, split}, {NULL, 0}, {message + split, message_length - split}};
      work = WORK_BUDGET;
      munit_assert_int(
          TC_CMS_signed_data_path_build(&(TC_CMS_validation_request){envelope,
                                                                     0,
                                                                     container.content_type,
                                                                     detached ? parts : NULL,
                                                                     detached ? 3 : 0,
                                                                     {NULL, 0}},
                                        &external, &settings, &workspace, &work, &found),
          ==, TC_X509_PATH_VALID);
      const size_t parts_work = WORK_BUDGET - work;
      munit_assert_size(found.validation.work_used, ==, parts_work);
      work = parts_work;
      munit_assert_int(
          TC_CMS_signed_data_path_build(&(TC_CMS_validation_request){envelope,
                                                                     0,
                                                                     container.content_type,
                                                                     detached ? parts : NULL,
                                                                     detached ? 3 : 0,
                                                                     {NULL, 0}},
                                        &external, &settings, &workspace, &work, &found),
          ==, TC_X509_PATH_VALID);
      munit_assert_size(work, ==, 0);
      for (unsigned failure = 0; failure < 6; ++failure) {
        const TC_bytes* supplied = parts;
        size_t count = 3;
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        if (failure == 0) {
          supplied = NULL;
          count = 1;
        }
        if (failure == 1)
          supplied = (const TC_bytes*)&found;
        if (failure == 2)
          parts[0] = (TC_bytes){NULL, 1};
        if (failure == 3) {
          parts[0] = (TC_bytes){message, split};
          supplied = detached ? parts : NULL;
          count = detached ? 3 : 0;
          work = parts_work - 1;
        }
        if (failure == 4)
          count = SIZE_MAX;
        if (failure == 5)
          parts[0] = (TC_bytes){(const uint8_t*)&found, 1};
        munit_assert_int(TC_CMS_signed_data_path_build(
                             &(TC_CMS_validation_request){
                                 envelope, 0, container.content_type, supplied, count, {NULL, 0}},
                             &external, &settings, &workspace, &work, &found),
                         ==, failure == 3 ? TC_X509_PATH_LIMIT : TC_X509_PATH_ERROR);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        if (failure != 3)
          munit_assert_size(work, ==, WORK_BUDGET);
      }
      parts[0] = (TC_bytes){message, split};
      if (!detached) {
        work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signed_data_path_build(
                             &(TC_CMS_validation_request){
                                 envelope, 0, container.content_type, parts, 3, {NULL, 0}},
                             &external, &settings, &workspace, &work, &found),
                         ==, TC_X509_PATH_ERROR);
      } else {
        static const uint8_t extra_byte = 0xff;
        parts[1] = (TC_bytes){&extra_byte, 1};
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(TC_CMS_signed_data_path_build(
                             &(TC_CMS_validation_request){
                                 envelope, 0, container.content_type, parts, 3, {NULL, 0}},
                             &external, &settings, &workspace, &work, &found),
                         ==, TC_X509_PATH_INVALID);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        TC_CMS_path_options bounded = settings;
        bounded.path.parsing.max_input = envelope.length;
        const TC_bytes oversized[] = {envelope, envelope};
        work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signed_data_path_build(
                             &(TC_CMS_validation_request){
                                 envelope, 0, container.content_type, oversized, 2, {NULL, 0}},
                             &external, &bounded, &workspace, &work, &found),
                         ==, TC_X509_PATH_LIMIT);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
    }
    for (unsigned failure = 0; failure < 5; ++failure) {
      static const uint8_t other_type[] = {42, 3}, bad_content[] = {0xff};
      TC_bytes type = container.content_type, supplied = detached_input;
      size_t selected = 0;
      work = WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      if (failure == 0)
        work = envelope_work - 1;
      if (failure == 1)
        selected = 1;
      if (failure == 2)
        selected = SIZE_MAX;
      if (failure == 3)
        type = (TC_bytes){other_type, sizeof other_type};
      if (failure == 4)
        supplied = (TC_bytes){bad_content, sizeof bad_content};
      munit_assert_int(TC_CMS_signed_data_path_build(
                           &(TC_CMS_validation_request){envelope,
                                                        selected,
                                                        type,
                                                        &supplied,
                                                        supplied.data || supplied.length ? 1u : 0u,
                                                        {NULL, 0}},
                           &external, &settings, &workspace, &work, &found),
                       ==,
                       failure == 0                ? TC_X509_PATH_LIMIT
                       : failure == 4 && !detached ? TC_X509_PATH_ERROR
                                                   : TC_X509_PATH_INVALID);
      munit_assert_memory_equal(sizeof found, &found, &saved);
    }
    {
      static const uint8_t absent[] = {0x31, 13, 0x30, 11, 6, 9, 0x60, 0x86,
                                       0x48, 1,  0x65, 3,  4, 2, 1};
      static const uint8_t null[] = {0x31, 15,   0x30, 13, 6, 9, 0x60, 0x86, 0x48,
                                     1,    0x65, 3,    4,  2, 1, 5,    0};
      static const uint8_t long_null[] = {0x31, 16,   0x30, 14, 6, 9, 0x60, 0x86, 0x48,
                                          1,    0x65, 3,    4,  2, 1, 5,    0x81, 0};
      static const uint8_t invalid[] = {0x31, 15,   0x30, 13, 6, 9, 0x60, 0x86, 0x48,
                                        1,    0x65, 3,    4,  2, 1, 4,    0};
      static const uint8_t wrong[] = {0x31, 13, 0x30, 11, 6, 9, 0x60, 0x86,
                                      0x48, 1,  0x65, 3,  4, 2, 2};
      static const uint8_t empty[] = {0x31, 0};
      static const uint8_t extra[] = {0x31, 18,   0x30, 3,    6, 1,    42, 0x30, 11, 6,
                                      9,    0x60, 0x86, 0x48, 1, 0x65, 3,  4,    2,  1};
      const struct {
        TC_bytes algorithms;
        TC_X509_path_status status;
      } variants[] = {{{absent, sizeof absent}, TC_X509_PATH_VALID},
                      {{null, sizeof null}, TC_X509_PATH_VALID},
                      {{long_null, sizeof long_null}, TC_X509_PATH_VALID},
                      {{extra, sizeof extra}, TC_X509_PATH_VALID},
                      {{invalid, sizeof invalid}, TC_X509_PATH_INVALID},
                      {{wrong, sizeof wrong}, TC_X509_PATH_INVALID},
                      {{empty, sizeof empty}, TC_X509_PATH_INVALID}};
      uint8_t rewritten[CMS_CAPACITY];
      for (size_t i = 0; i < sizeof variants / sizeof *variants; ++i) {
        const size_t rewritten_length = test_cms_encode_envelope(
            &container, variants[i].algorithms, container.signers, rewritten, sizeof rewritten);
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(TC_CMS_signed_data_path_build(
                             &(TC_CMS_validation_request){(TC_bytes){rewritten, rewritten_length},
                                                          0,
                                                          container.content_type,
                                                          &detached_input,
                                                          detached ? 1u : 0u,
                                                          {NULL, 0}},
                             &external, &settings, &workspace, &work, &found),
                         ==, variants[i].status);
        if (variants[i].status != TC_X509_PATH_VALID)
          munit_assert_memory_equal(sizeof found, &found, &saved);
      }
      /* A caller can select the second signer even if the first signature
         * fails. */
      uint8_t two_signers[CMS_CAPACITY];
      munit_assert_size(2 * signer.encoded.length + 4, <=, sizeof two_signers);
      two_signers[0] = 0x31;
      two_signers[1] = 0x80;
      memcpy(two_signers + 2, signer.encoded.data, signer.encoded.length);
      memcpy(two_signers + 2 + signer.encoded.length, signer.encoded.data, signer.encoded.length);
      memset(two_signers + 2 + 2 * signer.encoded.length, 0, 2);
      const size_t bad_signature_offset =
          2 + (size_t)(signer.signature.data - signer.encoded.data) + signer.signature.length - 1;
      two_signers[bad_signature_offset] ^= 1;
      size_t rewritten_length = test_cms_encode_envelope(
          &container, container.digest_algorithms,
          (TC_bytes){two_signers, 2 * signer.encoded.length + 4}, rewritten, sizeof rewritten);
      for (size_t selected = 0; selected < 3; ++selected) {
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(TC_CMS_signed_data_path_build(
                             &(TC_CMS_validation_request){(TC_bytes){rewritten, rewritten_length},
                                                          selected,
                                                          container.content_type,
                                                          &detached_input,
                                                          detached ? 1u : 0u,
                                                          {NULL, 0}},
                             &external, &settings, &workspace, &work, &found),
                         ==, selected == 1 ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
        if (selected != 1)
          munit_assert_memory_equal(sizeof found, &found, &saved);
      }
    }
    work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signer_path_build(
            &(TC_CMS_signer_path_request){
                &signer, container.content_type, content_digest, container.certificates, {NULL, 0}},
            &external, &settings, &workspace, &work, &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_size(found.anchor_index, ==, 0);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t total = WORK_BUDGET - work;
    munit_assert_size(found.validation.work_used, ==, total);
    /* A required signer certificate limits the signer search to that record.
       * The leaf is selected. Another certificate cannot sign, so no path is
       * found and the result is unchanged. */
    const TC_bytes other_certificate = found.path[0];
    TC_X509_search_result selected_path;
    work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signer_path_build(&(TC_CMS_signer_path_request){&signer,
                                                               container.content_type,
                                                               content_digest,
                                                               container.certificates,
                                                               {leaf_der, leaf_length}},
                                 &external, &settings, &workspace, &work, &selected_path),
        ==, TC_X509_PATH_VALID);
    munit_assert_memory_equal(leaf_length, selected_path.path[1].data, leaf_der);
    memcpy(&selected_path, &saved, sizeof selected_path);
    work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signer_path_build(
            &(TC_CMS_signer_path_request){&signer, container.content_type, content_digest,
                                          container.certificates, other_certificate},
            &external, &settings, &workspace, &work, &selected_path),
        ==, TC_X509_PATH_INVALID);
    munit_assert_memory_equal(sizeof selected_path, &selected_path, &saved);
    /* A half-empty signer certificate span and a missing detached span array
       * are argument errors. */
    work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signer_path_build(
            &(TC_CMS_signer_path_request){
                &signer, container.content_type, content_digest, container.certificates, {NULL, 1}},
            &external, &settings, &workspace, &work, &selected_path),
        ==, TC_X509_PATH_ERROR);
    munit_assert_size(work, ==, WORK_BUDGET);
    munit_assert_int(
        TC_CMS_signed_data_path_build(
            &(TC_CMS_validation_request){envelope, 0, container.content_type, NULL, 1, {NULL, 0}},
            &external, &settings, &workspace, &work, &selected_path),
        ==, TC_X509_PATH_ERROR);
    munit_assert_size(work, ==, WORK_BUDGET);
    ExampleCMSPathWorkspace example;
    munit_assert_int(
        example_check_cms_signed_data(&(TC_CMS_validation_request){envelope,
                                                                   0,
                                                                   container.content_type,
                                                                   &detached_input,
                                                                   detached ? 1u : 0u,
                                                                   {NULL, 0}},
                                      &external, &settings, WORK_BUDGET, &example, &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    munit_assert_int(
        example_find_cms_signer_path(
            &(TC_CMS_signer_path_request){
                &signer, container.content_type, content_digest, container.certificates, {NULL, 0}},
            &external, &settings, WORK_BUDGET, &example, &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    work = total;
    munit_assert_int(
        TC_CMS_signer_path_build(
            &(TC_CMS_signer_path_request){
                &signer, container.content_type, content_digest, container.certificates, {NULL, 0}},
            &external, &settings, &workspace, &work, &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(work, ==, 0);
    for (unsigned failure = 0; failure < 4; ++failure) {
      TC_CMS_path_options short_settings = settings;
      TC_CMS_path_workspace short_workspace = workspace;
      work = WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      if (failure == 0)
        work = total - 1;
      if (failure == 1)
        short_settings.max_candidates = INDEX_CAPACITY - 1;
      if (failure == 2)
        short_settings.max_candidate_bytes = container.certificates.length - 1;
      if (failure == 3)
        short_workspace.certificate_capacity = INDEX_CAPACITY - 1;
      munit_assert_int(
          TC_CMS_signer_path_build(&(TC_CMS_signer_path_request){&signer,
                                                                 container.content_type,
                                                                 content_digest,
                                                                 container.certificates,
                                                                 {NULL, 0}},
                                   &external, &short_settings, &short_workspace, &work, &found),
          ==, TC_X509_PATH_LIMIT);
      munit_assert_memory_equal(sizeof found, &found, &saved);
    }
    {
      TC_CMS_path_workspace short_workspace = workspace;
      short_workspace.signed_digest_capacity = TC_CMS_SIGNED_DIGEST_BYTES - 1;
      work = WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(
          TC_CMS_signer_path_build(&(TC_CMS_signer_path_request){&signer,
                                                                 container.content_type,
                                                                 content_digest,
                                                                 container.certificates,
                                                                 {NULL, 0}},
                                   &external, &settings, &short_workspace, &work, &found),
          ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found, &found, &saved);
    }
    TC_bytes writes[TC_X509_PATH_STORAGE_COUNT + 7];
    tc_pki_storage_plan plan;
    tc_pki_storage_plan_begin(&plan, writes, TC_X509_PATH_STORAGE_COUNT, 0);
    tc_x509_path_storage_plan(&plan, &validation);
    munit_assert_int(tc_pki_storage_plan_finish(&plan, NULL), ==, TC_TLV_OK);
    size_t n = TC_X509_PATH_STORAGE_COUNT;
    writes[n++] = (TC_bytes){(const uint8_t*)path, sizeof f->path};
    writes[n++] = (TC_bytes){(const uint8_t*)search_frames, sizeof f->search_frames};
    writes[n++] = (TC_bytes){(const uint8_t*)index, sizeof f->index};
    writes[n++] = (TC_bytes){signature_bytes, sizeof signature_bytes};
    writes[n++] = (TC_bytes){signed_digest, sizeof signed_digest};
    writes[n++] = (TC_bytes){(const uint8_t*)&found, sizeof found};
    writes[n++] = (TC_bytes){(const uint8_t*)&work, sizeof work};
    for (size_t i = 0; i < n; ++i) {
      work = WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      void* before = munit_malloc(writes[i].length);
      memcpy(before, writes[i].data, writes[i].length);
      const TC_bytes aliased = {writes[i].data, 1};
      munit_assert_int(
          TC_CMS_signer_path_build(
              &(TC_CMS_signer_path_request){
                  &signer, container.content_type, aliased, container.certificates, {NULL, 0}},
              &external, &settings, &workspace, &work, &found),
          ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(writes[i].length, writes[i].data, before);
      munit_assert_size(work, ==, WORK_BUDGET);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      munit_assert_int(
          TC_CMS_signed_data_path_build(
              &(TC_CMS_validation_request){
                  envelope, 0, aliased, &detached_input, detached ? 1u : 0u, {NULL, 0}},
              &external, &settings, &workspace, &work, &found),
          ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(writes[i].length, writes[i].data, before);
      munit_assert_size(work, ==, WORK_BUDGET);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      free(before);
    }
    settings.path.max_work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signer_path_build(
            &(TC_CMS_signer_path_request){
                &signer, container.content_type, content_digest, container.certificates, {NULL, 0}},
            &external, &settings, &workspace, &settings.path.max_work, &found),
        ==, TC_X509_PATH_ERROR);
    munit_assert_size(settings.path.max_work, ==, WORK_BUDGET);
    /* Indexing checks external bytes before writing even the first span. */
    const TC_bytes aliased_record = {(const uint8_t*)index, sizeof f->index};
    candidate_source record_context = {&aliased_record, 1, 0, TC_TLV_OK, 0};
    TC_X509_store_source aliased_source = {&record_context, 1, 0, read_candidate, NULL};
    TC_bytes saved_index[INDEX_CAPACITY];
    memcpy(saved_index, index, sizeof f->index);
    work = WORK_BUDGET;
    munit_assert_int(
        TC_CMS_signer_path_build(
            &(TC_CMS_signer_path_request){
                &signer, container.content_type, content_digest, (TC_bytes){NULL, 0}, {NULL, 0}},
            &aliased_source, &settings, &workspace, &work, &found),
        ==, TC_X509_PATH_ERROR);
    munit_assert_memory_equal(sizeof f->index, index, saved_index);
    munit_assert_memory_equal(sizeof found, &found, &saved);
  }
  return MUNIT_OK;
}

/* Signer path failures: short work, missing intermediates and anchors,
 * expiry, changed content or signatures, wrong identifiers and providers. */
static MunitResult signer_path_failures(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const intermediate_der = f->intermediate_der;
  uint8_t* const leaf_der = f->leaf_der;
  uint8_t* const encoded = f->encoded;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_path_options options = f->options;
  TC_CMS_signed_data container = f->container;
  const size_t intermediate_length = f->intermediate_length;
  const size_t leaf_length = f->leaf_length;
  const TC_X509_store_source external = f->external;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_X509_search_result found;
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  path_sources_init(f, &tree, &candidates, &context, &indexed);
  signer_context signing;
  signer_context_init(f, &tree, &signing);
  TC_CMS_signer_info signer = signing.signer;
  TC_X509_search_result saved = signing.saved;
  uint8_t* const digest = signing.digest;
  const TC_CMS_signature_workspace signature = signing.signature;
  const TC_bytes content_digest = signing.content_digest;
  (void)params;
  {
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(
        tc_cms_signer_find(
            &candidates,
            &(tc_cms_signer_search){
                &signer, container.content_type, content_digest,
                (TC_CMS_verification_policy){.attributes = TC_CMS_ATTRIBUTES_DER,
                                             .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                &indexed, &options, &tree, &signature, &validation, &search, NULL},
            &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_size(found.anchor_index, ==, 0);
    munit_assert_memory_equal(intermediate_length, found.path[0].data, intermediate_der);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(found.validation.work_used, ==, required);
    enum {
      SHORT_WORK,
      MISSING_INTERMEDIATE,
      NO_ANCHOR,
      EXPIRED,
      BAD_CONTENT,
      BAD_SIGNATURE,
      WRONG_IDENTIFIER,
      MISSING_DIGEST_PROVIDER,
      MISSING_PATH_PROVIDER
    };
    const struct {
      unsigned kind;
      TC_X509_path_status status;
    } failures[] = {{SHORT_WORK, TC_X509_PATH_LIMIT},
                    {MISSING_INTERMEDIATE, TC_X509_PATH_INVALID},
                    {NO_ANCHOR, TC_X509_PATH_INVALID},
                    {EXPIRED, TC_X509_PATH_INVALID},
                    {BAD_CONTENT, TC_X509_PATH_INVALID},
                    {BAD_SIGNATURE, TC_X509_PATH_INVALID},
                    {WRONG_IDENTIFIER, TC_X509_PATH_INVALID},
                    {MISSING_DIGEST_PROVIDER, TC_X509_PATH_UNSUPPORTED},
                    {MISSING_PATH_PROVIDER, TC_X509_PATH_UNSUPPORTED}};
    for (size_t i = 0; i < sizeof failures / sizeof *failures; ++i) {
      TC_X509_path_options checked = options;
      TC_X509_store_source source = indexed;
      TC_CMS_signer_info proposed = signer;
      static const uint8_t wrong_serial[] = {0x7f};
      static const uint8_t wrong_key_id[] = {0x80, 1, 0xff};
      work = WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      switch (failures[i].kind) {
      case SHORT_WORK:
        work = required - 1;
        break;
      case MISSING_INTERMEDIATE:
        source = external;
        break;
      case NO_ANCHOR:
        source.anchor_count = 0;
        break;
      case EXPIRED:
        checked.at.year = 2029;
        break;
      case BAD_CONTENT:
        digest[0] ^= 1;
        break;
      case BAD_SIGNATURE:
        encoded[(size_t)(signer.signature.data - encoded) + signer.signature.length - 1] ^= 1;
        break;
      case WRONG_IDENTIFIER:
        if (proposed.version == 3)
          proposed.subject_key_id = (TC_bytes){wrong_key_id, sizeof wrong_key_id};
        else
          proposed.serial = (TC_bytes){wrong_serial, sizeof wrong_serial};
        break;
      case MISSING_DIGEST_PROVIDER:
        checked.signatures.verify_digest = NULL;
        break;
      case MISSING_PATH_PROVIDER:
        checked.signatures.verify = NULL;
        break;
      }
      munit_assert_int(
          tc_cms_signer_find(
              &candidates,
              &(tc_cms_signer_search){
                  &proposed, container.content_type, content_digest,
                  (TC_CMS_verification_policy){.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                  &source, &checked, &tree, &signature, &validation, &search, NULL},
              &found),
          ==, failures[i].status);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      if (failures[i].kind == BAD_CONTENT)
        digest[0] ^= 1;
      if (failures[i].kind == BAD_SIGNATURE)
        encoded[(size_t)(signer.signature.data - encoded) + signer.signature.length - 1] ^= 1;
    }
  }
  return MUNIT_OK;
}

/* Content-verification and path failures retried with another candidate. */
static MunitResult signer_retries(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const leaf_der = f->leaf_der;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  const TC_TLV_limits limits = f->limits;
  TC_X509_path_options options = f->options;
  TC_CMS_signed_data container = f->container;
  const TC_bytes target = f->target;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_X509_search_result found;
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  path_sources_init(f, &tree, &candidates, &context, &indexed);
  signer_context signing;
  signer_context_init(f, &tree, &signing);
  TC_CMS_signer_info signer = signing.signer;
  TC_X509_search_result saved = signing.saved;
  const TC_CMS_signature_workspace signature = signing.signature;
  const TC_bytes content_digest = signing.content_digest;
  (void)params;
  {
    /* Retry both content-verification and path failures with another candidate.
     */
    const TC_bytes records[] = {target, target};
    candidate_source records_context = {records, 2, 0, TC_TLV_OK, 0};
    const TC_X509_store_source records_source = {&records_context, 2, 0, read_candidate, NULL};
    tc_cms_candidates retries, before;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &records_source, 2,
                                            2 * CERT_CAPACITY, &limits, &tree, &retries),
                     ==, TC_TLV_OK);
    memcpy(&before, &retries, sizeof before);
    const TC_X509_signature_result retry_results[] = {
        TC_X509_SIGNATURE_INVALID, TC_X509_SIGNATURE_UNSUPPORTED, TC_X509_SIGNATURE_LIMIT,
        TC_X509_SIGNATURE_ERROR};
    for (size_t call = 1; call <= 2; ++call) {
      for (size_t i = 0; i < sizeof retry_results / sizeof *retry_results; ++i) {
        signature_retry_probe probe = {options.signatures, 0, call, retry_results[i]};
        TC_X509_path_options checked = options;
        checked.signatures = (TC_X509_signature_provider){retry_signature, &probe, retry_digest};
        work = WORK_BUDGET;
        records_context.calls = 0;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(
            tc_cms_signer_find(
                &retries,
                &(tc_cms_signer_search){
                    &signer, container.content_type, content_digest,
                    (TC_CMS_verification_policy){.attributes = TC_CMS_ATTRIBUTES_DER,
                                                 .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                    &indexed, &checked, &tree, &signature, &validation, &search, NULL},
                &found),
            ==,
            retry_results[i] == TC_X509_SIGNATURE_ERROR ? TC_X509_PATH_ERROR : TC_X509_PATH_VALID);
        munit_assert_memory_equal(sizeof retries, &retries, &before);
        if (retry_results[i] == TC_X509_SIGNATURE_ERROR) {
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(records_context.calls, ==, 1);
        } else {
          munit_assert_size(records_context.calls, ==, 2);
          munit_assert_ptr_equal(found.path[found.count - 1].data, leaf_der);
        }
      }
    }
  }
  return MUNIT_OK;
}

/* Embedded and external CMS revocation records and the embedded CRL. */
static MunitResult revocations(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const intermediate_der = f->intermediate_der;
  uint8_t* const leaf_der = f->leaf_der;
  uint8_t* const encoded = f->encoded;
  TC_bytes* const oids = f->oids;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  const TC_TLV_limits limits = f->limits;
  TC_X509_path_options options = f->options;
  TC_CMS_signed_data container = f->container;
  const size_t intermediate_length = f->intermediate_length;
  const size_t leaf_length = f->leaf_length;
  const TC_X509_store_source external = f->external;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_X509_search_result found;
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  path_sources_init(f, &tree, &candidates, &context, &indexed);
  (void)params;
  {
    tc_cms_revocations revocations;
    tc_cms_revocation_choice record;
    TC_X509_crl parsed_crl;
    TC_X509_crl_extensions extensions;
    TC_X509_search_result saved;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_revocations_init(container.revocations, NULL, 1, CMS_CAPACITY, &limits,
                                             &tree, &revocations),
                     ==, TC_TLV_OK);
    munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==, TC_TLV_OK);
    munit_assert_int(record.kind, ==, TC_CMS_REVOCATION_CRL);
    munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==, TC_TLV_END);
    {
      const TC_bytes external_crl = record.encoded;
      candidate_source context = {&external_crl, 1, 0, TC_TLV_OK, 0};
      const tc_pki_record_source source = {&context, 1, read_candidate};
      munit_assert_int(tc_cms_revocations_init(container.revocations, &source, 2, 2 * CMS_CAPACITY,
                                               &limits, &tree, &revocations),
                       ==, TC_TLV_OK);
      munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==, TC_TLV_OK);
      munit_assert_size(context.calls, ==, 0);
      munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==, TC_TLV_OK);
      munit_assert_size(context.calls, ==, 1);
      munit_assert_ptr_equal(record.encoded.data, external_crl.data);
      munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==, TC_TLV_END);
    }
    munit_assert_int(tc_x509_crl_read(record.encoded, &limits, &tree, &parsed_crl), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_crl_extension_info_read(parsed_crl.extensions, &limits, &tree, oids,
                                                     POLICY_CAPACITY, &extensions),
                     ==, TC_TLV_OK);
    memset(&saved, 0xa5, sizeof saved);
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_find(
                         &candidates, &parsed_crl, &extensions,
                         &(tc_x509_crl_trust){&external, 0, &options, &tree, &validation, &search,
                                              &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                         &found),
                     ==, TC_X509_PATH_INVALID);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_find(
                         &candidates, &parsed_crl, &extensions,
                         &(tc_x509_crl_trust){&indexed, 0, &options, &tree, &validation, &search,
                                              &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                         &found),
                     ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_size(found.anchor_index, ==, 0);
    munit_assert_memory_equal(intermediate_length, found.path[0].data, intermediate_der);
    munit_assert_size(found.path[1].length, ==, leaf_length);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t signature_offset =
        (size_t)(found.path[0].data - encoded) + found.path[0].length - 1;
    encoded[signature_offset] ^= 1;
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_find(
                         &candidates, &parsed_crl, &extensions,
                         &(tc_x509_crl_trust){&indexed, 0, &options, &tree, &validation, &search,
                                              &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                         &found),
                     ==, TC_X509_PATH_INVALID);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    encoded[signature_offset] ^= 1;
  }
  return MUNIT_OK;
}

/* Signed attributes beyond the interpreted set under each attribute policy. */
static MunitResult signed_attributes(const MunitParameter params[], void* user)
{
  path_fixture* f = user;
  uint8_t* const encoded = f->encoded;
  TC_bytes* const index = f->index;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_path_options options = f->options;
  EVP_PKEY* leaf_key = f->leaf_key;
  X509* root = f->root;
  X509* intermediate = f->intermediate;
  X509* leaf = f->leaf;
  const size_t message_length = f->message_length;
  const int detached = f->detached;
  const TC_bytes detached_input = f->detached_input;
  const unsigned cms_flags = f->cms_flags;
  int length = f->length;
  const TC_X509_store_source external = f->external;
  size_t work = WORK_BUDGET;
  TC_X509_search_result found;
  unsigned char* cursor;
  (void)params;
  {
    /* Signed attributes beyond the interpreted set. RFC 6211 section 3.1
     * applies its checks to validators that support the attribute, and
     * RFC 5035 section 2 recommends recognizing the signing-certificate
     * attributes. The default policy skips both. */
    static const uint8_t algorithm_protection[] = {
        0x30, 0x19, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, 0xa1, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
    static const uint8_t signing_certificate_v2[] = {
        0x30, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20, 1,  2,  3,  4,  5,  6,
        7,    8,    9,    10,   11,   12,   13,   14,   15, 16, 17, 18, 19, 20,
        21,   22,   23,   24,   25,   26,   27,   28,   29, 30, 31, 32};
    enum {
      NAMED,           /* pivSigner-DN matches the signer under PIV identifiers. */
      WRONG_NAME,      /* pivSigner-DN names another certificate. */
      LISTED,          /* Adds cmsAlgorithmProtection and signingCertificateV2. */
      LISTED_REJECTED, /* The same attributes under TC_CMS_OTHER_ATTRIBUTES_REJECT. */
      GENERIC_NAME,    /* pivSigner-DN outside the CMS identifiers. */
      GENERIC_SKIPPED, /* The wrong pivSigner-DN skipped by SKIP_ALL under CMS identifiers. */
      CASE_COUNT
    };
    uint8_t signed_digest[TC_CMS_SIGNED_DIGEST_BYTES];
    const TC_CMS_path_workspace workspace = {
        validation, search, index, INDEX_CAPACITY, NULL, 0, signed_digest, sizeof signed_digest};
    static const uint8_t id_data[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1};
    for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
      const int wrong_name = scenario == WRONG_NAME || scenario == GENERIC_SKIPPED;
      TC_CMS_path_options settings = {
          options, INDEX_CAPACITY, CMS_CAPACITY, {.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV}};
      if (scenario == LISTED_REJECTED)
        settings.verification.other_attributes = TC_CMS_OTHER_ATTRIBUTES_REJECT;
      if (scenario == GENERIC_NAME || scenario == GENERIC_SKIPPED)
        settings.verification.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_CMS;
      if (scenario == GENERIC_SKIPPED)
        settings.verification.other_attributes = TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL;
      CMS_ContentInfo* named = CMS_sign(leaf, leaf_key, NULL, NULL, cms_flags | CMS_PARTIAL);
      BIO* named_content = BIO_new_mem_buf(message, (int)message_length);
      munit_assert_not_null(named);
      munit_assert_not_null(named_content);
      set_cms_signer_name(named, X509_get_subject_name(wrong_name ? root : leaf));
      if (scenario == LISTED || scenario == LISTED_REJECTED) {
        add_cms_sequence_attribute(named, "1.2.840.113549.1.9.52", algorithm_protection,
                                   (int)sizeof algorithm_protection);
        add_cms_sequence_attribute(named, "1.2.840.113549.1.9.16.2.47", signing_certificate_v2,
                                   (int)sizeof signing_certificate_v2);
      }
      munit_assert_int(CMS_add1_cert(named, intermediate), ==, 1);
      munit_assert_int(CMS_final(named, named_content, NULL, cms_flags), ==, 1);
      munit_assert_int(
          CMS_SignerInfo_verify(sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(named), 0)), ==, 1);
      length = i2d_CMS_ContentInfo(named, NULL);
      munit_assert_int(length, >, 0);
      munit_assert_size((size_t)length, <=, sizeof f->encoded);
      cursor = encoded;
      munit_assert_int(i2d_CMS_ContentInfo(named, &cursor), ==, length);
      work = WORK_BUDGET;
      TC_X509_search_result saved;
      memset(&saved, 0xa5, sizeof saved);
      memcpy(&found, &saved, sizeof found);
      const TC_X509_path_status expected = scenario == WRONG_NAME ? TC_X509_PATH_INVALID
                                           : scenario == LISTED_REJECTED || scenario == GENERIC_NAME
                                               ? TC_X509_PATH_UNSUPPORTED
                                               : TC_X509_PATH_VALID;
      munit_assert_int(TC_CMS_signed_data_path_build(
                           &(TC_CMS_validation_request){(TC_bytes){encoded, (size_t)length},
                                                        0,
                                                        (TC_bytes){id_data, sizeof id_data},
                                                        &detached_input,
                                                        detached ? 1u : 0u,
                                                        {NULL, 0}},
                           &external, &settings, &workspace, &work, &found),
                       ==, expected);
      if (expected != TC_X509_PATH_VALID)
        munit_assert_memory_equal(sizeof found, &found, &saved);
      BIO_free(named_content);
      CMS_ContentInfo_free(named);
    }
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* identifiers[] = {"issuer-serial", "key-id", NULL};
  static char* contents[] = {"attached", "detached", "empty-attached", "empty-detached", NULL};
  static char* key_types[] = {"ec", "rsa", NULL};
  static MunitParameterEnum identifier_params[] = {
      {"identifier", identifiers}, {"content", contents}, {"key", key_types}, {NULL, NULL}};
  MunitTest tests[] = {{"/signer-find", signer_find, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {"/credential-workflow", credential_workflow, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {"/signer-path-build", signer_path_build, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {"/signer-path-failures", signer_path_failures, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {"/signer-retries", signer_retries, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {"/revocations", revocations, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {"/signed-attributes", signed_attributes, path_setup, path_teardown,
                        MUNIT_TEST_OPTION_NONE, identifier_params},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms/path", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
